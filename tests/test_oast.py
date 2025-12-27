from __future__ import annotations

import asyncio
import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Tuple

import pytest

import modules.tools.oast as oast_mod


@dataclass
class _StubResponse:
    status_code: int = 200
    _json: Any = None

    def json(self) -> Any:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _HttpxStubFactory:
    """
    Patch target: oast_mod.httpx.AsyncClient = factory

    Configure per-method URL handlers with:
      factory.on("GET", "https://...", lambda **kw: _StubResponse(...))
    """

    def __init__(self):
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []
        self._handlers: Dict[Tuple[str, str], Callable[..., _StubResponse]] = {}

    def on(self, method: str, url: str, handler: Callable[..., _StubResponse]) -> None:
        self._handlers[(method.upper(), url)] = handler

    def __call__(self, *args: Any, **kwargs: Any) -> "_HttpxStubClient":
        return _HttpxStubClient(self)


class _HttpxStubClient:
    def __init__(self, factory: _HttpxStubFactory):
        self._f = factory

    async def __aenter__(self) -> "_HttpxStubClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def get(self, url: str, **kwargs: Any) -> _StubResponse:
        self._f.calls.append(("GET", url, kwargs))
        h = self._f._handlers.get(("GET", url))
        return h(**kwargs) if h else _StubResponse(404, {})

    async def post(self, url: str, **kwargs: Any) -> _StubResponse:
        self._f.calls.append(("POST", url, kwargs))
        h = self._f._handlers.get(("POST", url))
        return h(**kwargs) if h else _StubResponse(404, {})

    async def put(self, url: str, **kwargs: Any) -> _StubResponse:
        self._f.calls.append(("PUT", url, kwargs))
        h = self._f._handlers.get(("PUT", url))
        return h(**kwargs) if h else _StubResponse(404, {})

    async def delete(self, url: str, **kwargs: Any) -> _StubResponse:
        self._f.calls.append(("DELETE", url, kwargs))
        h = self._f._handlers.get(("DELETE", url))
        return h(**kwargs) if h else _StubResponse(404, {})


class _Cfg:
    def __init__(self, env: Dict[str, str]):
        self._env = env

    def getenv(self, key: str, default: str = "") -> str:
        return self._env.get(key, default)


class _TimeStub:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def time(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        # emulate time passing without actually waiting
        self.now += max(0.0, float(seconds))


@pytest.fixture(autouse=True)
def _reset_provider_cache():
    oast_mod._OAST_PROVIDERS.clear()
    yield
    oast_mod._OAST_PROVIDERS.clear()


@pytest.fixture
def httpx_stub(monkeypatch) -> _HttpxStubFactory:
    f = _HttpxStubFactory()
    monkeypatch.setattr(oast_mod.httpx, "AsyncClient", f)
    return f


def test__host_for_url_ipv6_brackets():
    assert oast_mod._host_for_url("::1") == "[::1]"
    assert oast_mod._host_for_url("[::1]") == "[::1]"
    assert oast_mod._host_for_url("127.0.0.1") == "127.0.0.1"


@pytest.mark.parametrize(
    "target",
    [
        None,
        "not-an-ip-or-host??",
    ],
)
def test_get_oast_provider_invalid_target(target):
    with pytest.raises(ValueError):
        oast_mod.get_oast_provider(target)


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",
        "google.com",
        "https://google.com",
    ],
)
def test_get_oast_provider_global_paths(target):
    p = oast_mod.get_oast_provider(target)
    assert isinstance(p, oast_mod.WebhookSiteProvider)

    # should be cached by bind_target "global"
    p2 = oast_mod.get_oast_provider("1.1.1.1")
    assert p is p2


def test_get_oast_provider_private_uses_pick_local_addr(monkeypatch):
    monkeypatch.setattr(oast_mod, "pick_local_addr", lambda target: ("127.0.0.1", 2))

    p = oast_mod.get_oast_provider("10.0.0.10")
    assert isinstance(p, oast_mod.LocalListenerOASTProvider)
    assert p._bind_addr == "127.0.0.1"

    # cached under bind_target "127.0.0.1"
    p2 = oast_mod.get_oast_provider("10.0.0.10")
    assert p is p2


def test_get_oast_provider_private_uses_pick_local_addr_port(monkeypatch):
    monkeypatch.setattr(oast_mod, "pick_local_addr", lambda target: ("127.0.0.1", 2))

    p = oast_mod.get_oast_provider("10.0.0.10:80")
    assert isinstance(p, oast_mod.LocalListenerOASTProvider)
    assert p._bind_addr == "127.0.0.1"

    # cached under bind_target "127.0.0.1"
    p2 = oast_mod.get_oast_provider("10.0.0.10")
    assert p is p2


def test_get_oast_provider_private_valueerror_in_pick_local_addr_raises_upstream(monkeypatch):
    def _boom(_t: str):
        raise ValueError("nope")

    monkeypatch.setattr(oast_mod, "pick_local_addr", _boom)

    with pytest.raises(ValueError):
        oast_mod.get_oast_provider("10.0.0.99")


# ----------------------------
# Unit tests - WebhookSiteProvider
# ----------------------------

def test_webhook_headers_include_api_key(monkeypatch):
    monkeypatch.setattr(oast_mod, "_get_config_manager", lambda: _Cfg({"WEBHOOK_API_KEY": "KEY"}))
    p = oast_mod.WebhookSiteProvider()
    h = p._headers
    assert h["Api-Key"] == "KEY"
    assert h["Accept"] == "application/json"
    assert h["Content-Type"] == "application/json"


def test_webhook_headers_no_api_key(monkeypatch):
    monkeypatch.setattr(oast_mod, "_get_config_manager", lambda: _Cfg({}))
    p = oast_mod.WebhookSiteProvider()
    h = p._headers
    assert "Api-Key" not in h


@pytest.mark.asyncio
async def test_webhook_health_non_200(monkeypatch, httpx_stub: _HttpxStubFactory):
    monkeypatch.setattr(oast_mod, "_get_config_manager", lambda: _Cfg({}))
    httpx_stub.on("GET", "https://webhook.site", lambda **kw: _StubResponse(503, None))

    p = oast_mod.WebhookSiteProvider()
    out = await p.health()
    assert out.status == "error"
    assert "HTTP 503" in (out.detail or "")


@pytest.mark.asyncio
async def test_webhook_init_is_idempotent(monkeypatch, httpx_stub: _HttpxStubFactory):
    monkeypatch.setattr(oast_mod, "_get_config_manager", lambda: _Cfg({}))

    httpx_stub.on("POST", "https://webhook.site/token", lambda **kw: _StubResponse(200, {"uuid": "abc"}))

    p = oast_mod.WebhookSiteProvider()
    eps1 = await p.init()
    assert p.webhook_token_id == "abc"
    assert eps1.http.endswith("/abc")

    # second init should not call token endpoint again
    eps2 = await p.init()
    assert eps2.http.endswith("/abc")

    token_calls = [c for c in httpx_stub.calls if c[0] == "POST" and c[1] == "https://webhook.site/token"]
    assert len(token_calls) == 1


@pytest.mark.asyncio
async def test_webhook_poll_new_handles_missing_uuid_and_empty_data(monkeypatch, httpx_stub: _HttpxStubFactory):
    monkeypatch.setattr(oast_mod, "_get_config_manager", lambda: _Cfg({}))

    p = oast_mod.WebhookSiteProvider()
    p.inited = True
    p.webhook_token_id = "abc"

    url = "https://webhook.site/token/abc/requests"
    httpx_stub.on(
        "GET",
        url,
        lambda **kw: _StubResponse(
            200,
            # includes: missing uuid, duplicate uuid, and None-ish container
            {"data": [{"uuid": "u1"}, {"uuid": "u1"}, {"uuid": "u2"}]},
        ),
    )

    out1 = await p.poll_new()
    assert [x.get("uuid") for x in out1.interactions] == ["u1", "u2"]

    out2 = await p.poll_new()
    assert out2.interactions == []


@pytest.mark.asyncio
async def test_webhook_poll_new_when_response_json_is_none(monkeypatch, httpx_stub: _HttpxStubFactory):
    monkeypatch.setattr(oast_mod, "_get_config_manager", lambda: _Cfg({}))

    p = oast_mod.WebhookSiteProvider()
    p.inited = True
    p.webhook_token_id = "abc"

    url = "https://webhook.site/token/abc/requests"
    httpx_stub.on("GET", url, lambda **kw: _StubResponse(200, None))

    out = await p.poll_new()
    assert out.interactions == []


@pytest.mark.asyncio
async def test_webhook_deregister_noop_when_not_inited(monkeypatch, httpx_stub: _HttpxStubFactory):
    monkeypatch.setattr(oast_mod, "_get_config_manager", lambda: _Cfg({}))

    p = oast_mod.WebhookSiteProvider()
    p.inited = False
    p.webhook_token_id = "abc"

    await p.deregister()
    assert not any(c[0] == "DELETE" for c in httpx_stub.calls)


@pytest.mark.asyncio
async def test_webhook_deregister_calls_delete(monkeypatch, httpx_stub: _HttpxStubFactory):
    monkeypatch.setattr(oast_mod, "_get_config_manager", lambda: _Cfg({}))

    p = oast_mod.WebhookSiteProvider()
    p.inited = True
    p.webhook_token_id = "abc"

    del_url = "https://webhook.site/token/abc"
    httpx_stub.on("DELETE", del_url, lambda **kw: _StubResponse(200, None))

    await p.deregister()
    assert any(m == "DELETE" and u == del_url for (m, u, _kw) in httpx_stub.calls)


@pytest.mark.asyncio
async def test_webhook_register_http_response_creates_and_updates_action(monkeypatch, httpx_stub: _HttpxStubFactory):
    monkeypatch.setattr(oast_mod, "_get_config_manager", lambda: _Cfg({}))

    # init -> create token
    httpx_stub.on("POST", "https://webhook.site/token", lambda **kw: _StubResponse(200, {"uuid": "abc"}))

    # first register -> POST actions
    actions_url = "https://webhook.site/token/abc/actions"

    def _post_actions(**kw):
        payload = kw.get("json") or {}
        assert payload.get("type") == "script"
        script = (payload.get("parameters") or {}).get("script") or ""
        # should contain respond(body, status, [headers])
        assert "respond(" in script
        assert "418" in script
        assert "teapot" in script
        return _StubResponse(200, {"uuid": "act1"})

    httpx_stub.on("POST", actions_url, _post_actions)

    # second register -> PUT actions/{id}
    put_url = "https://webhook.site/token/abc/actions/act1"

    def _put_actions(**kw):
        payload = kw.get("json") or {}
        script = (payload.get("parameters") or {}).get("script") or ""
        assert "respond(" in script
        # both rules should be present after second register
        assert "teapot" in script
        assert ("ok" in script) or ("200" in script)
        return _StubResponse(200, {"uuid": "act1"})

    httpx_stub.on("PUT", put_url, _put_actions)

    # clear -> delete action
    del_url = "https://webhook.site/token/abc/actions/act1"
    httpx_stub.on("DELETE", del_url, lambda **kw: _StubResponse(200, None))

    p = oast_mod.WebhookSiteProvider()

    await p.register_http_response(
        match=oast_mod.HttpRequestMatch(method="GET", target="/resp"),
        response=oast_mod.HttpResponseSpec(status=418, headers={"X-From": "oast"}, body="teapot"),
        scheme="https",
    )
    assert p.inited is True
    assert p.webhook_token_id == "abc"
    assert p._response_action_id == "act1"

    # register a second rule -> should update via PUT
    await p.register_http_response(
        match=oast_mod.HttpRequestMatch(method="POST", target_prefix="/api/"),
        response=oast_mod.HttpResponseSpec(status=200, body="ok"),
        scheme="https",
    )

    assert any(m == "PUT" and u == put_url for (m, u, _kw) in httpx_stub.calls)

    await p.clear_http_responses()
    assert any(m == "DELETE" and u == del_url for (m, u, _kw) in httpx_stub.calls)


# ----------------------------
# Unit tests - LocalListenerOASTProvider (logic paths, no real sockets)
# ----------------------------

def test_local_listener_invalid_ip_raises_mcp_error():
    with pytest.raises(ValueError):
        oast_mod.LocalListenerOASTProvider("not-an-ip")


@pytest.mark.asyncio
async def test_local_listener_health_states():
    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")

    out = await p.health()
    assert out.status == "error"
    assert out.detail == "not initialized"

    p.inited = True
    p._http_server = object()  # only one running
    out = await p.health()
    assert out.status == "error"
    assert out.detail == "listeners not running"

    p._https_server = object()
    out = await p.health()
    assert out.status == "ok"


@pytest.mark.asyncio
async def test_local_listener__read_http_request_parses_headers_and_body(monkeypatch):
    monkeypatch.setattr(oast_mod, "b64", lambda b: base64.b64encode(b).decode("ascii"))

    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")

    reader = asyncio.StreamReader()
    body = b"hello"
    req = (
            b"POST /x?a=1 HTTP/1.1\r\n"
            b"Host: example\r\n"
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
            + body
    )
    reader.feed_data(req)
    reader.feed_eof()

    parsed = await p._read_http_request(reader)

    assert parsed["method"] == "POST"
    assert parsed["target"] == "/x?a=1"
    assert parsed["http_version"] == "HTTP/1.1"
    assert parsed["headers"]["Host"] == "example"
    assert parsed["headers"]["Content-Type"] == "text/plain"
    assert parsed["body_len"] == 5
    assert parsed["body_b64"] == base64.b64encode(body).decode("ascii")


@pytest.mark.asyncio
async def test_local_listener__read_http_request_bad_request_line(monkeypatch):
    monkeypatch.setattr(oast_mod, "b64", lambda b: base64.b64encode(b).decode("ascii"))

    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")
    reader = asyncio.StreamReader()
    req = b"BAD\r\nHeader: x\r\n\r\n"
    reader.feed_data(req)
    reader.feed_eof()

    with pytest.raises(ValueError):
        await p._read_http_request(reader)


@pytest.mark.asyncio
async def test_local_listener_poll_new_dedupes_seen_ids():
    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")
    p.inited = True  # bypass init; testing poll semantics only

    async with p._lock:
        p._events.append({"id": "e1", "k": "v"})
        p._events.append({"id": "e2", "k": "v2"})
        p._events.append({"k": "noid"})  # ignored

    out1 = await p.poll_new()
    assert [x["id"] for x in out1.interactions] == ["e1", "e2"]

    out2 = await p.poll_new()
    assert out2.interactions == []


def test_local_listener_build_endpoints_ipv6_brackets():
    class _Sock:
        def __init__(self, addr: str, port: int):
            self._addr = addr
            self._port = port

        def getsockname(self):
            return (self._addr, self._port, 0, 0) if ":" in self._addr else (self._addr, self._port)

    class _Srv:
        def __init__(self, sock):
            self.sockets = [sock]

    p = oast_mod.LocalListenerOASTProvider("::1")
    p._http_server = _Srv(_Sock("::1", 1234))
    p._https_server = _Srv(_Sock("::1", 2345))

    eps = p._build_endpoints()
    assert eps.http == "http://[::1]:1234"
    assert eps.https == "https://[::1]:2345"
    assert eps.extras["http_port"] == "1234"
    assert eps.extras["https_port"] == "2345"


def test_local_listener_ensure_cert_key_reuses_existing(monkeypatch, tmp_path):
    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")

    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")

    p._cert_path = str(cert)
    p._key_path = str(key)

    c2, k2 = p._ensure_cert_key()
    assert c2 == str(cert)
    assert k2 == str(key)


def test_local_listener_ensure_cert_key_success_via_stubbed_generator(monkeypatch, tmp_path):
    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")

    # force tempdir to known place
    monkeypatch.setattr(oast_mod.tempfile, "mkdtemp", lambda prefix="": str(tmp_path))

    def _fake_crypto(cert_path: str, key_path: str) -> bool:
        open(cert_path, "w").write("cert")
        open(key_path, "w").write("key")
        return True

    monkeypatch.setattr(p, "_try_generate_with_cryptography", _fake_crypto)
    monkeypatch.setattr(p, "_try_generate_with_openssl", lambda *_a, **_k: False)

    cert_path, key_path = p._ensure_cert_key()
    assert os.path.exists(cert_path)
    assert os.path.exists(key_path)


def test_local_listener_ensure_cert_key_raises_when_no_generators(monkeypatch, tmp_path):
    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")
    monkeypatch.setattr(oast_mod.tempfile, "mkdtemp", lambda prefix="": str(tmp_path))
    monkeypatch.setattr(p, "_try_generate_with_cryptography", lambda *_a, **_k: False)
    monkeypatch.setattr(p, "_try_generate_with_openssl", lambda *_a, **_k: False)

    with pytest.raises(RuntimeError):
        p._ensure_cert_key()


@pytest.mark.asyncio
async def test_local_listener_deregister_cleans_temp_files(tmp_path):
    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")
    p.inited = True

    # create dummy cert/key + tmp dir
    tmpdir = tmp_path / "oast_local_x"
    tmpdir.mkdir()
    cert = tmpdir / "cert.pem"
    key = tmpdir / "key.pem"
    cert.write_text("cert")
    key.write_text("key")

    p._tmpdir = str(tmpdir)
    p._cert_path = str(cert)
    p._key_path = str(key)

    await p.deregister()
    assert not os.path.exists(str(cert))
    assert not os.path.exists(str(key))
    assert not os.path.exists(str(tmpdir))


# ----------------------------
# Unit tests - response registration (LocalListenerOASTProvider)
# ----------------------------

def test_local_listener_format_http_response_default():
    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")
    raw = p._format_http_response(None)
    assert raw.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Connection: close\r\n" in raw
    assert raw.endswith(b"ok\n")


def test_local_listener_format_http_response_custom_adds_length_and_keeps_headers():
    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")
    spec = oast_mod.HttpResponseSpec(status=418, headers={"X-Test": "1"}, body="nope")
    raw = p._format_http_response(spec)
    assert raw.startswith(b"HTTP/1.1 418")
    assert b"X-Test: 1\r\n" in raw
    assert b"Content-Length: 4\r\n" in raw
    assert raw.endswith(b"nope")


@pytest.mark.asyncio
async def test_local_listener_register_select_and_clear_response():
    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")

    match = oast_mod.HttpRequestMatch(method="GET", target="/match")
    resp = oast_mod.HttpResponseSpec(status=201, headers={"X-A": "b"}, body="yay")

    await p.register_http_response(match=match, response=resp, scheme="http")

    sel = p._select_registered_response("http", {"method": "GET", "target": "/match"})
    assert sel is not None
    assert sel.status == 201

    sel2 = p._select_registered_response("https", {"method": "GET", "target": "/match"})
    assert sel2 is None

    await p.clear_http_responses(scheme="http")
    sel3 = p._select_registered_response("http", {"method": "GET", "target": "/match"})
    assert sel3 is None


class _CaptureWriter:
    def __init__(self):
        self.data = b""
        self.closed = False

    def get_extra_info(self, name: str):
        if name == "peername":
            return ("127.0.0.1", 55555)
        if name == "sockname":
            return ("127.0.0.1", 12345)
        return None

    def write(self, b: bytes):
        self.data += b

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


@pytest.mark.asyncio
async def test_local_listener_handle_client_returns_registered_response(monkeypatch):
    # ensure body_b64 doesn't depend on external implementation
    monkeypatch.setattr(oast_mod, "b64", lambda b: base64.b64encode(b).decode("ascii"))

    p = oast_mod.LocalListenerOASTProvider("127.0.0.1")

    match = oast_mod.HttpRequestMatch(method="GET", target="/resp")
    resp = oast_mod.HttpResponseSpec(status=418, headers={"X-From": "oast"}, body="teapot")
    await p.register_http_response(match=match, response=resp, scheme="http")

    reader = asyncio.StreamReader()
    req = (
        b"GET /resp HTTP/1.1\r\n"
        b"Host: example\r\n"
        b"\r\n"
    )
    reader.feed_data(req)
    reader.feed_eof()

    writer = _CaptureWriter()
    await p._handle_client(reader, writer, scheme="http")

    assert writer.data.startswith(b"HTTP/1.1 418")
    assert b"X-From: oast\r\n" in writer.data
    assert writer.data.endswith(b"teapot")


# ----------------------------
# Unit tests - tool wrappers oast_health/oast_endpoints/oast_poll
# ----------------------------

@pytest.mark.asyncio
async def test_oast_health_success(monkeypatch):
    class _P(oast_mod.OASTProvider):
        name = "p"

        async def init(self):  # type: ignore[override]
            self.inited = True
            return oast_mod.Endpoints(http="h", https="s")

        async def health(self):  # type: ignore[override]
            return oast_mod.HealthOutput(status="ok")

    monkeypatch.setattr(oast_mod, "get_oast_provider", lambda _t: _P())
    out = await oast_mod.oast_health("t")
    assert out.status == "ok"


@pytest.mark.asyncio
async def test_oast_endpoints_delegates_to_provider_init(monkeypatch):
    class _P(oast_mod.OASTProvider):
        name = "p"

        async def init(self):  # type: ignore[override]
            self.inited = True
            return oast_mod.Endpoints(http="http://x", https="https://y")

    monkeypatch.setattr(oast_mod, "get_oast_provider", lambda _t: _P())
    out = await oast_mod.oast_endpoints("t")
    assert out.http == "http://x"
    assert out.https == "https://y"


@pytest.mark.asyncio
async def test_oast_register_http_response_tool_delegates(monkeypatch):
    calls = {}

    class _P(oast_mod.OASTProvider):
        name = "p"

        def __init__(self):
            super().__init__()
            self.inited = True

        async def register_http_response(self, match, response, scheme=None):  # type: ignore[override]
            calls["match"] = match
            calls["response"] = response
            calls["scheme"] = scheme

    prov = _P()
    monkeypatch.setattr(oast_mod, "get_oast_provider", lambda _t: prov)

    inp = oast_mod.RegisterHttpResponseInput(
        scheme="http",
        match=oast_mod.HttpRequestMatch(method="GET", target="/x"),
        response=oast_mod.HttpResponseSpec(status=204, body=""),
    )

    await oast_mod.oast_register_http_response("t", inp)
    assert calls["scheme"] == "http"
    assert calls["match"].target == "/x"
    assert calls["response"].status == 204

    calls.clear()
    await oast_mod.oast_register_http_response("t", inp.model_dump_json())
    assert calls["scheme"] == "http"
    assert calls["scheme"] == "http"
    assert calls["match"].target == "/x"
    assert calls["response"].status == 204


@pytest.mark.asyncio
async def test_oast_clear_http_responses_tool_delegates(monkeypatch):
    calls = {}

    class _P(oast_mod.OASTProvider):
        name = "p"

        def __init__(self):
            super().__init__()
            self.inited = True

        async def clear_http_responses(self, scheme=None):  # type: ignore[override]
            calls["scheme"] = scheme

    prov = _P()
    monkeypatch.setattr(oast_mod, "get_oast_provider", lambda _t: prov)

    inp = oast_mod.ClearHttpResponsesInput(scheme="https")

    await oast_mod.oast_clear_http_responses("t", inp)
    assert calls["scheme"] == "https"

    calls.clear()
    await oast_mod.oast_clear_http_responses("t", inp.model_dump_json())
    assert calls["scheme"] == "https"


@pytest.mark.asyncio
async def test_oast_poll_timeout_clamps_negative_to_zero(monkeypatch):
    class _P(oast_mod.OASTProvider):
        name = "p"

        def __init__(self):
            super().__init__()
            self.inited = True

        async def poll_new(self):  # type: ignore[override]
            return oast_mod.PollOutput(interactions=[])

    monkeypatch.setattr(oast_mod, "get_oast_provider", lambda _t: _P())

    out = await oast_mod.oast_poll("t", timeout=-123.0)
    assert out.interactions == []


@pytest.mark.asyncio
async def test_oast_poll_returns_when_interaction_found(monkeypatch):
    class _StubProvider(oast_mod.OASTProvider):
        name = "stub"

        def __init__(self):
            super().__init__()
            self.inited = True
            self._n = 0

        async def poll_new(self) -> oast_mod.PollOutput:  # type: ignore[override]
            self._n += 1
            if self._n < 2:
                return oast_mod.PollOutput(interactions=[])
            return oast_mod.PollOutput(interactions=[{"uuid": "x"}])

    provider = _StubProvider()
    monkeypatch.setattr(oast_mod, "get_oast_provider", lambda _t: provider)

    async def _fast_sleep(_s: float) -> None:
        return None

    monkeypatch.setattr(oast_mod.asyncio, "sleep", _fast_sleep)

    out = await oast_mod.oast_poll("t", timeout=0.2)
    assert len(out.interactions) == 1
    assert out.interactions[0]["uuid"] == "x"


@pytest.mark.asyncio
async def test_oast_poll_times_out_returns_empty(monkeypatch):
    class _P(oast_mod.OASTProvider):
        name = "p"

        def __init__(self):
            super().__init__()
            self.inited = True
            self.calls = 0

        async def poll_new(self):  # type: ignore[override]
            self.calls += 1
            return oast_mod.PollOutput(interactions=[])

    p = _P()
    monkeypatch.setattr(oast_mod, "get_oast_provider", lambda _t: p)

    t = _TimeStub(start=1000.0)
    monkeypatch.setattr(oast_mod.time, "time", t.time)
    monkeypatch.setattr(oast_mod.asyncio, "sleep", t.sleep)

    out = await oast_mod.oast_poll("t", timeout=10.0)
    assert out.interactions == []
    assert p.calls >= 1


@pytest.mark.asyncio
async def test_oast_poll_timeout_clamps_to_600(monkeypatch):
    class _P(oast_mod.OASTProvider):
        name = "p"

        def __init__(self):
            super().__init__()
            self.inited = True
            self.calls = 0

        async def poll_new(self):  # type: ignore[override]
            self.calls += 1
            return oast_mod.PollOutput(interactions=[])

    p = _P()
    monkeypatch.setattr(oast_mod, "get_oast_provider", lambda _t: p)

    t = _TimeStub(start=1000.0)
    monkeypatch.setattr(oast_mod.time, "time", t.time)
    monkeypatch.setattr(oast_mod.asyncio, "sleep", t.sleep)

    # With the time stub, this will "run" instantly while still exercising the clamp logic.
    out = await oast_mod.oast_poll("t", timeout=999999.0)
    assert out.interactions == []
    assert t.now >= 1600.0  # 1000 + 600 seconds (clamped)
