import asyncio
import socket
import sys
import threading
from urllib.parse import urlparse

import httpx
import functools
import ipaddress
import logging
import os
import tempfile
import time
import uuid
from typing import Optional, Dict, List, Any, Set, Deque, Union
from collections import deque

import validators
from pydantic import BaseModel, Field, ValidationError
import json
from http import HTTPStatus

from strands import tool

from modules.handlers import b64
from modules.utils.pick_nic import pick_local_addr

logger = logging.getLogger(__name__)


def _get_config_manager():
    """Lazy import to avoid circular dependency."""
    from modules.config.manager import get_config_manager
    return get_config_manager()


# TODO: allow oast endpoints to be passed in to support host VPNs
# Example: run an interactsh server on the host

class Endpoints(BaseModel):
    # Optional fields to support heterogeneous providers
    dns: Optional[str] = None
    http: Optional[str] = None
    https: Optional[str] = None
    smtp: Optional[str] = None
    smtp_domain: Optional[str] = None
    ldap: Optional[str] = None
    # provider-specific extras
    extras: Dict[str, str] = Field(default_factory=dict)


class PollOutput(BaseModel):
    interactions: List[Dict[str, Any]] = Field(default_factory=list)


class HealthOutput(BaseModel):
    status: str = Field(description='"ok" if provider is reachable, "error" otherwise')
    detail: Optional[str] = Field(None, description="Optional error message")


class HttpRequestMatch(BaseModel):
    """Match criteria for an inbound HTTP request."""

    scheme: Optional[str] = Field(None, description='Optional scheme filter: "http" or "https"')
    method: Optional[str] = Field(None, description='Optional HTTP method filter, e.g. "GET"')
    target: Optional[str] = Field(
        None,
        description=(
            "Optional exact match for the request target/path, e.g. '/cb' or '/cb?x=1'. "
            "For webhook.site this is matched as a substring of the full request URL."
        ),
    )
    target_prefix: Optional[str] = Field(
        None,
        description=(
            "Optional prefix match for the request target/path, e.g. '/api/'. "
            "For webhook.site this is matched as a substring of the full request URL."
        ),
    )

    def matches_local(self, scheme: str, method: str, target: str) -> bool:
        if self.scheme and self.scheme.lower() != (scheme or "").lower():
            return False
        if self.method and self.method.upper() != (method or "").upper():
            return False
        if self.target is not None and self.target != target:
            return False
        if self.target_prefix is not None and not (target or "").startswith(self.target_prefix):
            return False
        return True


class HttpResponseSpec(BaseModel):
    """HTTP response to return when a match is found."""

    status: int = Field(200, description="HTTP status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    body: Optional[str] = Field(None, description="Response body as UTF-8 text")


class RegisterHttpResponseInput(BaseModel):
    scheme: Optional[str] = Field(None, description='Optional scheme filter: "http" or "https"')
    match: HttpRequestMatch
    response: HttpResponseSpec


class ClearHttpResponsesInput(BaseModel):
    scheme: Optional[str] = Field(None, description='Optional scheme filter: "http" or "https"')


class OASTProvider:
    def __init__(self):
        self.inited = False
        self.seen_ids: Set[str] = set()

    def _check_inited(self):
        if not self.inited:
            raise Exception(f"{self.name} session not initialized")

    async def health(self) -> HealthOutput: ...

    async def init(self) -> Endpoints: ...

    async def endpoints(self) -> Endpoints: ...

    async def poll_new(self) -> PollOutput: ...

    async def deregister(self) -> None: ...

    async def register_http_response(self, match: HttpRequestMatch, response: HttpResponseSpec,
                                     scheme: Optional[str] = None) -> None:
        raise NotImplementedError(f"{self.name} does not support registering HTTP responses")

    async def clear_http_responses(self, scheme: Optional[str] = None) -> None:
        # default no-op for providers that don't support it
        return


class WebhookSiteProvider(OASTProvider):
    def __init__(self):
        super().__init__()
        self.webhook_token_id = None
        self._response_rules: List[RegisterHttpResponseInput] = []
        self._response_action_id: Optional[str] = None

        config_manager = _get_config_manager()
        self._headers = {"Accept": "application/json", "Content-Type": "application/json"}
        webhook_api_key = config_manager.getenv("WEBHOOK_API_KEY", "")
        if webhook_api_key:
            self._headers["Api-Key"] = webhook_api_key

    def _ws_rule_to_script_if(self, tid: str, rule: RegisterHttpResponseInput) -> str:
        """Generate a WebhookScript if-block for a single rule."""
        # request.method and request.url are available runtime variables.
        parts: List[str] = []

        # scheme check based on request.url prefix
        if rule.scheme:
            sc = rule.scheme.lower()
            parts.append(f"string_contains(url, {json.dumps(sc + '://')})")

        if rule.match.method:
            parts.append(f"method == {json.dumps(rule.match.method.upper())}")

        # For webhook.site, we match against the full URL.
        # The token appears in the URL path: https://webhook.site/<tid>/...
        if rule.match.target is not None:
            needle = f"/{tid}{rule.match.target}" if rule.match.target.startswith(
                "/") else f"/{tid}/{rule.match.target}"
            parts.append(f"string_contains(url, {json.dumps(needle)})")

        if rule.match.target_prefix is not None:
            needle = f"/{tid}{rule.match.target_prefix}" if rule.match.target_prefix.startswith(
                "/") else f"/{tid}/{rule.match.target_prefix}"
            parts.append(f"string_contains(url, {json.dumps(needle)})")

        cond = " && ".join(parts) if parts else "true"

        # headers as an array of "K: V" strings
        hdrs = [f"{k}: {v}" for k, v in (rule.response.headers or {}).items()]
        hdrs_js = "[" + ", ".join(json.dumps(h) for h in hdrs) + "]"

        body = rule.response.body or ""
        status = int(rule.response.status or 200)

        return (
                "if (" + cond + ") {\n"
                + f"    respond({json.dumps(body)}, {status}, {hdrs_js})\n"
                + "}\n"
        )

    def _build_webhookscript(self, tid: str) -> str:
        """Build a full WebhookScript that returns registered responses when matched."""
        header = (
            "// Auto-generated by Local OAST provider integration\n"
            "method = var('request.method')\n"
            "url = var('request.url')\n\n"
        )
        rules = "".join(self._ws_rule_to_script_if(tid, r) for r in self._response_rules)
        if not rules:
            # no rules: do nothing, default response is used
            return header + "// No registered response rules\n"
        return header + rules

    async def _sync_custom_response_action(self) -> None:
        """Create or update a Webhook.site Custom Action (WebhookScript) that returns dynamic responses."""
        self._check_inited()
        tid = self.webhook_token_id
        assert tid

        script = self._build_webhookscript(tid)
        payload = {
            "type": "script",
            "order": 1,
            "disabled": False,
            "parameters": {"script": script},
        }

        async with httpx.AsyncClient() as client:
            if not self._response_action_id:
                r = await client.post(
                    f"https://webhook.site/token/{tid}/actions",
                    headers=self._headers,
                    json=payload,
                    timeout=20,
                )
                r.raise_for_status()
                js = r.json() or {}
                self._response_action_id = js.get("uuid")
            else:
                r = await client.put(
                    f"https://webhook.site/token/{tid}/actions/{self._response_action_id}",
                    headers=self._headers,
                    json=payload,
                    timeout=20,
                )
                r.raise_for_status()

    async def register_http_response(self, match: HttpRequestMatch, response: HttpResponseSpec,
                                     scheme: Optional[str] = None) -> None:
        # Ensure token exists, then install/update WebhookScript action.
        if not self.inited:
            await self.init()

        rule = RegisterHttpResponseInput(scheme=scheme, match=match, response=response)
        self._response_rules.append(rule)
        await self._sync_custom_response_action()

    async def clear_http_responses(self, scheme: Optional[str] = None) -> None:
        # Clear locally and remove the Custom Action from the token if present.
        if scheme:
            self._response_rules = [r for r in self._response_rules if (r.scheme or "").lower() != scheme.lower()]
        else:
            self._response_rules = []

        if not self.inited:
            return
        tid = self.webhook_token_id
        if tid and self._response_action_id:
            async with httpx.AsyncClient() as client:
                try:
                    await client.delete(
                        f"https://webhook.site/token/{tid}/actions/{self._response_action_id}",
                        headers=self._headers,
                        timeout=20,
                    )
                except Exception:
                    pass
        self._response_action_id = None

    async def health(self) -> HealthOutput:
        async with httpx.AsyncClient() as client:
            r = await client.get("https://webhook.site", timeout=5)
            if r.status_code == 200:
                return HealthOutput(status="ok")
            return HealthOutput(status="error", detail=f"HTTP {r.status_code}")

    async def init(self) -> Endpoints:
        if self.inited:
            return await self.endpoints()

        # Create a new token (works without Api-Key; with key it associates to your account)
        async with httpx.AsyncClient() as client:
            r = await client.post("https://webhook.site/token", headers=self._headers, timeout=20)
        r.raise_for_status()
        js = r.json()
        token_id = js["uuid"]
        self.inited = True
        self.webhook_token_id = token_id
        return await self.endpoints()

    async def endpoints(self) -> Endpoints:
        self._check_inited()
        tid = self.webhook_token_id
        # expose common OAST-ish surfaces where applicable
        return Endpoints(
            http=f"http://webhook.site/{tid}",
            https=f"https://webhook.site/{tid}",
            dns=f"{tid}.dnshook.site",  # DNSHook (works where available)
            smtp=f"{tid}@emailhook.site",  # Emailhook address
            extras={
                "http_subdomain": f"https://{tid}.webhook.site",
                "token_id": tid
            }
        )

    async def poll_new(self) -> PollOutput:
        self._check_inited()
        tid = self.webhook_token_id
        # newest-first, single page is fine for polling loops
        url = f"https://webhook.site/token/{tid}/requests"
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=self._headers, params={"sorting": "newest"}, timeout=20)
        r.raise_for_status()
        data = r.json() or {}
        items = data.get("data") or []
        out: List[Dict[str, Any]] = []
        seen: set[str] = self.seen_ids
        for it in items:
            uid = it.get("uuid")
            if uid and uid in seen:
                continue
            if uid:
                seen.add(uid)
            out.append(it)
        self.seen_ids = seen
        return PollOutput(interactions=out)

    async def deregister(self) -> None:
        if not self.inited:
            return
        self._response_rules = []
        self._response_action_id = None
        tid = self.webhook_token_id
        url = f"https://webhook.site/token/{tid}"
        async with httpx.AsyncClient() as client:
            await client.delete(url, params={"password": ""}, headers=self._headers, timeout=20)


def _host_for_url(host: str) -> str:
    # RFC 3986: IPv6 literals must be in brackets.
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


class LocalListenerOASTProvider(OASTProvider):
    """
    Local OAST provider:
      - constructor takes a specific IPv4 or IPv6 address (string)
      - spins up HTTP and HTTPS listeners bound to that address on random free ports
      - collects inbound requests and returns them on poll_new()
    """

    name = "local-listener"

    def __init__(self, bind_addr: str):
        super().__init__()
        self._ip = ipaddress.ip_address(bind_addr)

        self._bind_addr = bind_addr
        self._endpoints: Optional[Endpoints] = None

        self._http_server: Optional[asyncio.AbstractServer] = None
        self._https_server: Optional[asyncio.AbstractServer] = None

        self._lock = asyncio.Lock()
        self._events: Deque[Dict[str, Any]] = deque()
        self._response_rules: List[RegisterHttpResponseInput] = []

        self._tmpdir: Optional[str] = None
        self._cert_path: Optional[str] = None
        self._key_path: Optional[str] = None

    def _select_registered_response(self, scheme: str, req: Dict[str, Any]) -> Optional[HttpResponseSpec]:
        method = (req.get("method") or "").upper()
        target = req.get("target") or ""
        for rule in self._response_rules:
            if rule.scheme and rule.scheme.lower() != (scheme or "").lower():
                continue
            if rule.match.matches_local(scheme=scheme, method=method, target=target):
                return rule.response
        return None

    def _format_http_response(self, spec: Optional[HttpResponseSpec]) -> bytes:
        # default response
        if spec is None:
            body = b"ok\n"
            status = 200
            hdrs: Dict[str, str] = {"Content-Type": "text/plain; charset=utf-8"}
        else:
            status = int(spec.status or 200)
            body = (spec.body or "").encode("utf-8")
            hdrs = dict(spec.headers or {})
            if body and not any(k.lower() == "content-type" for k in hdrs):
                hdrs["Content-Type"] = "text/plain; charset=utf-8"

        try:
            reason = HTTPStatus(status).phrase
        except Exception:
            reason = "OK"

        # enforce connection close + content-length
        headers_out = {k: v for k, v in hdrs.items() if k.lower() not in ("content-length", "connection")}
        headers_out["Content-Length"] = str(len(body))
        headers_out["Connection"] = "close"

        head = f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")
        for k, v in headers_out.items():
            head += f"{k}: {v}\r\n".encode("utf-8")
        head += b"\r\n"
        return head + body

    async def health(self) -> HealthOutput:
        if not self.inited:
            return HealthOutput(status="error", detail="not initialized")
        if not self._http_server or not self._https_server:
            return HealthOutput(status="error", detail="listeners not running")
        return HealthOutput(status="ok")

    async def init(self) -> Endpoints:
        if self.inited:
            return await self.endpoints()

        try:
            # Requests are not returning. Could be a malformed request is holding up the thread, add a timeout. Reading could be incorrect.
            await self._start_http()
            await self._start_https()
            self._endpoints = self._build_endpoints()
            self.inited = True
            return self._endpoints
        except Exception as e:
            logger.exception("Failed to init %s", self.name)
            await self.deregister()
            raise e

    async def endpoints(self) -> Endpoints:
        self._check_inited()
        assert self._endpoints is not None
        return self._endpoints

    async def poll_new(self) -> PollOutput:
        self._check_inited()

        async with self._lock:
            out: List[Dict[str, Any]] = []
            for ev in list(self._events):
                ev_id = ev.get("id")
                if not ev_id:
                    continue
                if ev_id in self.seen_ids:
                    continue
                self.seen_ids.add(ev_id)
                out.append(ev)
            return PollOutput(interactions=out)

    async def deregister(self) -> None:
        self.inited = False
        self._endpoints = None

        if self._http_server:
            self._http_server.close()
            self._http_server = None

        if self._https_server:
            self._https_server.close()
            self._https_server = None

        if self._tmpdir:
            try:
                # tempfile.TemporaryDirectory() would be nicer, but we manage explicitly.
                for p in (self._cert_path, self._key_path):
                    if p and os.path.exists(p):
                        os.unlink(p)
                if os.path.isdir(self._tmpdir):
                    os.rmdir(self._tmpdir)
            except Exception:
                pass

        self._tmpdir = None
        self._cert_path = None
        self._key_path = None

    # ----------------------------
    # Listener startup
    # ----------------------------

    async def _start_http(self) -> None:
        cb = functools.partial(self._handle_client, scheme="http")
        self._http_server = await asyncio.start_server(cb, host=self._bind_addr, port=0)

    async def _start_https(self) -> None:
        import ssl

        cert_path, key_path = self._ensure_cert_key()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        cb = functools.partial(self._handle_client, scheme="https")
        self._https_server = await asyncio.start_server(cb, host=self._bind_addr, port=0, ssl=ctx)

    def _build_endpoints(self) -> Endpoints:
        assert self._http_server and self._https_server

        http_sock = self._http_server.sockets[0]
        https_sock = self._https_server.sockets[0]

        http_port = int(http_sock.getsockname()[1])
        https_port = int(https_sock.getsockname()[1])

        host = _host_for_url(self._bind_addr)
        return Endpoints(
            http=f"http://{host}:{http_port}",
            https=f"https://{host}:{https_port}",
            extras={
                "bind_addr": self._bind_addr,
                "http_port": str(http_port),
                "https_port": str(https_port),
            },
        )

    # ----------------------------
    # Request parsing + capture
    # ----------------------------

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, scheme: str) -> None:
        peer = writer.get_extra_info("peername")
        sock = writer.get_extra_info("sockname")

        try:
            async with asyncio.timeout(10.0):
                req = await self._read_http_request(reader)
                interaction = {
                    "id": str(uuid.uuid4()),
                    "ts": time.time(),
                    "scheme": scheme,
                    "local": {"addr": sock[0], "port": sock[1]} if sock else None,
                    "remote": {"addr": peer[0], "port": peer[1]} if peer else None,
                    **req,
                }
                async with self._lock:
                    while len(self._events) > 100:
                        self._events.popleft()
                    self._events.append(interaction)

                # If a registered response matches, return it; otherwise return a simple 200 OK.
                resp_spec = self._select_registered_response(scheme, req)
                resp = self._format_http_response(resp_spec)
                writer.write(resp)
                await writer.drain()
        except TimeoutError:
            logger.debug("Client handler timeout")
        except Exception as e:
            logger.debug("Client handler error (%s): %s", scheme, e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def register_http_response(self, match: HttpRequestMatch, response: HttpResponseSpec,
                                     scheme: Optional[str] = None) -> None:
        # Can be called before or after init.
        rule = RegisterHttpResponseInput(scheme=scheme, match=match, response=response)
        async with self._lock:
            self._response_rules.append(rule)

    async def clear_http_responses(self, scheme: Optional[str] = None) -> None:
        async with self._lock:
            if scheme:
                self._response_rules = [r for r in self._response_rules if (r.scheme or "").lower() != scheme.lower()]
            else:
                self._response_rules = []

    # ---------------------------
    # Tool functions
    # ---------------------------

    async def _read_http_request(self, reader: asyncio.StreamReader) -> Dict[str, Any]:
        # Read headers
        head = await reader.readuntil(b"\r\n\r\n")
        head_text = head.decode("iso-8859-1", errors="replace")
        lines = head_text.split("\r\n")

        # Request line
        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 3:
            raise ValueError(f"Bad request line: {request_line!r}")
        method, target, version = parts[0], parts[1], parts[2]

        # Headers
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

        # Body (best-effort)
        body = b""
        cl = headers.get("Content-Length") or headers.get("content-length")
        if cl:
            try:
                n = int(cl)
                if n > 0:
                    body = await reader.readexactly(n)
            except Exception:
                body = b""

        return {
            "method": method,
            "target": target,
            "http_version": version,
            "headers": headers,
            "body_b64": b64(body) if body else None,
            "body_len": len(body),
        }

    # ----------------------------
    # TLS cert generation
    # ----------------------------

    def _ensure_cert_key(self) -> tuple[str, str]:
        if self._cert_path and self._key_path and os.path.exists(self._cert_path) and os.path.exists(self._key_path):
            return self._cert_path, self._key_path

        self._tmpdir = tempfile.mkdtemp(prefix="oast_local_")
        self._cert_path = os.path.join(self._tmpdir, "cert.pem")
        self._key_path = os.path.join(self._tmpdir, "key.pem")

        # Prefer cryptography; fallback to openssl CLI; else error.
        if self._try_generate_with_cryptography(self._cert_path, self._key_path):
            return self._cert_path, self._key_path
        if self._try_generate_with_openssl(self._cert_path, self._key_path):
            return self._cert_path, self._key_path

        raise RuntimeError(
            "Unable to create HTTPS listener (no TLS cert). "
            "Install 'cryptography' or ensure 'openssl' is available on PATH."
        )

    def _try_generate_with_cryptography(self, cert_path: str, key_path: str) -> bool:
        try:
            from datetime import datetime, timedelta, timezone

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except Exception:
            return False

        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local OAST"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "local-oast"),
                ]
            )

            san_ips = {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1"), self._ip}
            san = x509.SubjectAlternativeName([x509.IPAddress(ip) for ip in sorted(san_ips, key=str)])

            now = datetime.now(timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=30))
                .add_extension(san, critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(private_key=key, algorithm=hashes.SHA256())
            )

            with open(key_path, "wb") as f:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            return True
        except Exception:
            return False

    def _try_generate_with_openssl(self, cert_path: str, key_path: str) -> bool:
        import subprocess

        try:
            # Minimal self-signed cert for IP-based listener; clients can use -k / insecure.
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    key_path,
                    "-out",
                    cert_path,
                    "-days",
                    "30",
                    "-subj",
                    "/C=US/O=Local OAST/CN=local-oast",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return os.path.exists(cert_path) and os.path.exists(key_path)
        except Exception:
            return False


_OAST_LOCK = threading.Lock()
_OAST_PROVIDERS: Dict[str, OASTProvider] = {}

_TARGET_VALIDATION_ERROR = "target IP address or FQDN is required"

def get_oast_provider(target: Optional[str] = None) -> OASTProvider:
    if not target:
        raise ValueError(_TARGET_VALIDATION_ERROR)

    try:
        # IP address given
        if ipaddress.ip_address(target).is_global:
            bind_target = "global"
        else:
            try:
                bind_target, *_ = pick_local_addr(target)
            except OSError:
                bind_target = "global"
    except ValueError:
        try:
            # URL given
            validators.url(target, skip_ipv4_addr=False, skip_ipv6_addr=False, simple_host=True, strict_query=False,
                           consider_tld=False)
            if "://" in target:
                url_parsed = urlparse(target)
            else:
                url_parsed = urlparse("http://" + target)
            if url_parsed.hostname:
                target = url_parsed.hostname
        except ValidationError:
            try:
                # Hostname given
                validators.hostname(target, skip_ipv4_addr=False, skip_ipv6_addr=False, may_have_port=True,
                                    simple_host=True, consider_tld=False)
                target = urlparse("http://" + target).hostname
            except ValidationError:
                raise ValueError(_TARGET_VALIDATION_ERROR)

        try:
            # IP address given in a URL or ip:port
            if ipaddress.ip_address(target).is_global:
                bind_target = "global"
            else:
                try:
                    bind_target, *_ = pick_local_addr(target)
                except OSError:
                    bind_target = "global"
        except ValueError:
            try:
                bind_target = "global"
                for _, _, _, _, ip_address_t, *_ in socket.getaddrinfo(target, 80):
                    ip_address = ip_address_t[0]
                    try:
                        if ipaddress.ip_address(ip_address).is_global:
                            bind_target = "global"
                        else:
                            bind_target, *_ = pick_local_addr(ip_address)
                        target = ip_address
                        print(f"target {ip_address} resolves to {target}")
                        break
                    except OSError:
                        continue
            except socket.gaierror:
                raise ValueError(_TARGET_VALIDATION_ERROR)

    with _OAST_LOCK:
        if bind_target in _OAST_PROVIDERS:
            return _OAST_PROVIDERS.get(bind_target)
        if bind_target == "global":
            provider = WebhookSiteProvider()
        else:
            provider = LocalListenerOASTProvider(bind_target)
        _OAST_PROVIDERS[bind_target] = provider
        return provider


async def close_oast_providers():
    with _OAST_LOCK:
        for provider in _OAST_PROVIDERS.values():
            await provider.deregister()
        _OAST_PROVIDERS.clear()


@tool
async def oast_health(target: str) -> HealthOutput:
    """
    Check the health/reachability of the currently configured OAST provider.

    Args:
        target: the IP address (preferred) or host name of the target, used to select a reachable network address
    """
    try:
        provider = get_oast_provider(target)
        await provider.init()
        return await provider.health()
    except Exception as e:
        return HealthOutput(status="error", detail=str(e))


@tool
async def oast_endpoints(target: str) -> Endpoints:
    """
    Get the endpoints that can be used to test out-of-band interactions from the target (always known as OAST).
    The result is a map of supported service types to endpoint. Service types include http, https, dns, email, etc.

    Invoke this tool when the user wants to use out-of-band services to verify vulnerabilities or run exploits such as
    XSS, blind command injection, etc.

    After using one of the endpoints in the target, the oast.poll tool is used to poll for interactions with the endpoints.
    Payloads in the query string or POST data will be available from the oast.poll tool call. If the email service is
    supported, any emails send to the email address will be available in the oast.poll tool.

    For XSS testing, the payload can be used to exfiltrate sensitive information such as cookies and localStorage by
    passing the values in a query string or POST data.

    Args:
        target: the IP address (preferred) or host name of the target, used to select a reachable network address
    """
    return await get_oast_provider(target).init()


@tool
async def oast_poll(
        target: str,
        timeout: float = 30.0,
) -> PollOutput:
    """
    Retrieve new interactions with the OAST service since the last poll.

    Invoke this tool when the user wants to check for interactions from the target to the OAST service.

    Args:
        target: the IP address (preferred) or host name of the target, used to select a reachable network address
        timeout: The number of seconds to wait for interactions. A value of 0 returns immediately with any pending interactions.
    """
    provider = get_oast_provider(target)
    timeout = max(0.0, min(600.0, timeout))
    time_end = time.time() + timeout
    time_step = 3.0
    last_check = False
    while time.time() < time_end or last_check:
        result = await provider.poll_new()
        if len(result.interactions) > 0:
            logger.info(f"oast_poll returned {len(result.interactions)} interactions")
            return result
        sleep_time = min(time_step, time_end - time.time())
        if sleep_time <= 0:
            break
        if sleep_time < time_step:
            last_check = True
        else:
            last_check = False
        await asyncio.sleep(sleep_time)
    logger.info("oast_poll returned 0 interactions")
    return PollOutput()


@tool
async def oast_register_http_response(
        target: str,
        inp: Union[str, RegisterHttpResponseInput]
) -> None:
    """
    Register a dynamic HTTP response for the OAST http/https endpoint when a matching request is received.
    Args:
        target: the IP address (preferred) or host name of the target, used to select a reachable network address
    """
    provider = get_oast_provider(target)
    if isinstance(inp, str):
        if inp.startswith("{") and inp.endswith("}"):
            inp = RegisterHttpResponseInput(**json.loads(inp))
        else:
            raise ValidationError(
                "Error: Validation failed for input parameters, Input should be a valid dictionary or instance of RegisterHttpResponseInput")
    await provider.register_http_response(inp.match, inp.response, scheme=inp.scheme)


@tool
async def oast_clear_http_responses(
        target: str,
        inp: Optional[Union[str, ClearHttpResponsesInput]] = ClearHttpResponsesInput()
) -> None:
    """
    Clear registered dynamic HTTP responses for the OAST provider.
    Args:
        target: the IP address (preferred) or host name of the target, used to select a reachable network address
    """
    provider = get_oast_provider(target)
    if inp is None:
        inp = ClearHttpResponsesInput()
    elif isinstance(inp, str):
        if inp.startswith("{") and inp.endswith("}"):
            inp = ClearHttpResponsesInput(**json.loads(inp))
        else:
            raise ValidationError(
                "Error: Validation failed for input parameters, Input should be a valid dictionary or instance of ClearHttpResponsesInput")
    await provider.clear_http_responses(scheme=inp.scheme)


async def main(target="127.0.0.1") -> None:
    provider = get_oast_provider(target)
    endpoints = await provider.init()
    print(repr(endpoints))
    try:
        while True:
            await asyncio.sleep(5)
            print(repr(await provider.poll_new()))
    except:
        await provider.deregister()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"))
