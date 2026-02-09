#!/usr/bin/env python3
# tests/test_auth_chain_analyzer.py

import json
from types import SimpleNamespace

import pytest

import modules.operation_plugins.web.tools.auth_chain_analyzer as aca


class DummyResp:
    """Minimal requests.Response stand-in for unit tests."""

    def __init__(self, status_code=200, headers=None, text="", content=b"", raw=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = content
        self.raw = raw


class DummyRawHeaders:
    def __init__(self, set_cookie_list):
        self._cookies = list(set_cookie_list)

    def get_all(self, name):
        if name.lower() == "set-cookie":
            return self._cookies
        return []


class DummyRaw:
    def __init__(self, set_cookie_list=None, prefix_bytes=b""):
        self.headers = DummyRawHeaders(set_cookie_list or [])
        self._prefix = prefix_bytes

    def read(self, n):
        return self._prefix[:n]


def _loads(out: str) -> dict:
    return json.loads(out)


def test_auth_chain_analyzer_adds_scheme_and_emits_json(monkeypatch):
    monkeypatch.setattr(aca, "_discover_auth_endpoints", lambda url: [])
    monkeypatch.setattr(aca, "_analyze_auth_mechanisms", lambda url, eps, auth_type: [])
    monkeypatch.setattr(aca, "_analyze_tokens_and_sessions", lambda url, mechs: {"tokens": [], "session_info": {}})
    monkeypatch.setattr(aca, "_map_authentication_flows",
                        lambda url, results: {"authentication_steps": [], "bypass_opportunities": [],
                                              "privilege_escalation": []})
    monkeypatch.setattr(aca, "_test_advanced_auth_bypasses", lambda url, results: [])
    monkeypatch.setattr(aca, "_generate_auth_recommendations", lambda results: [])

    out = aca.auth_chain_analyzer("example.com", auth_type="auto")
    j = _loads(out)

    assert j["tool"] == "auth_chain_analyzer"
    assert j["target"] == "https://example.com"
    assert j["auth_type"] == "auto"
    assert "timestamp" in j
    assert "summary" in j
    assert "evidence" in j
    assert "findings" in j
    assert "next_steps" in j
    assert "decision" in j


def test_auth_chain_analyzer_handles_bypass_results_none(monkeypatch):
    monkeypatch.setattr(aca, "_discover_auth_endpoints", lambda url: [])
    monkeypatch.setattr(aca, "_analyze_auth_mechanisms", lambda url, eps, auth_type: [])
    monkeypatch.setattr(aca, "_analyze_tokens_and_sessions", lambda url, mechs: {"tokens": [], "session_info": {}})
    monkeypatch.setattr(aca, "_map_authentication_flows",
                        lambda url, results: {"authentication_steps": [], "bypass_opportunities": [],
                                              "privilege_escalation": []})
    monkeypatch.setattr(aca, "_test_advanced_auth_bypasses", lambda url, results: None)
    monkeypatch.setattr(aca, "_generate_auth_recommendations", lambda results: [])

    j = _loads(aca.auth_chain_analyzer("https://t.example", auth_type="auto"))
    assert j["findings"] == []
    assert j["summary"]["confirmed_exploits"] == 0


def test_auth_chain_analyzer_wraps_single_bypass_dict(monkeypatch):
    monkeypatch.setattr(aca, "_discover_auth_endpoints", lambda url: [
        {"path": "/admin", "full_url": url.rstrip("/") + "/admin", "status": "200", "type": "Administrative"}])
    monkeypatch.setattr(aca, "_analyze_auth_mechanisms", lambda url, eps, auth_type: [])
    monkeypatch.setattr(aca, "_analyze_tokens_and_sessions", lambda url, mechs: {"tokens": [], "session_info": {}})
    monkeypatch.setattr(
        aca,
        "_map_authentication_flows",
        lambda url, results: {"authentication_steps": [], "bypass_opportunities": [], "privilege_escalation": [
            {"type": "Administrative Access", "endpoint": "/admin", "description": "x"}]},
    )

    bypass = {
        "technique": "Forced Browsing",
        "endpoint": "/admin",
        "successful": True,
        "description": "Administrative endpoint accessible without authentication",
        "status_code": "200",
        "method": "GET",
    }
    monkeypatch.setattr(aca, "_test_advanced_auth_bypasses", lambda url, results: bypass)
    monkeypatch.setattr(aca, "_generate_auth_recommendations", lambda results: [])

    j = _loads(aca.auth_chain_analyzer("https://t.example", auth_type="auto"))
    assert len(j["findings"]) == 1
    f = j["findings"][0]
    assert f["status"] == "confirmed"
    assert f["category"] == "auth_bypass"
    assert f["severity"] == "critical"
    assert f["technique"] == "Forced Browsing"
    assert f["endpoint"] == "/admin"
    assert j["summary"]["confirmed_exploits"] == 1
    assert j["decision"]["best_attack_surface"] == "exploitation"


def test_decision_logic_prefers_bypass_validation_when_opps_exist(monkeypatch):
    monkeypatch.setattr(aca, "_discover_auth_endpoints", lambda url: [
        {"path": "/login", "full_url": url.rstrip("/") + "/login", "status": "302", "type": "Session-based"}])
    monkeypatch.setattr(aca, "_analyze_auth_mechanisms", lambda url, eps, auth_type: [{"type": "Session-based"}])
    monkeypatch.setattr(aca, "_analyze_tokens_and_sessions", lambda url, mechs: {"tokens": [], "session_info": {}})
    monkeypatch.setattr(
        aca,
        "_map_authentication_flows",
        lambda url, results: {"authentication_steps": [],
                              "bypass_opportunities": [{"type": "X", "description": "Y", "technique": "Z"}],
                              "privilege_escalation": []},
    )
    monkeypatch.setattr(aca, "_test_advanced_auth_bypasses", lambda url, results: [])
    monkeypatch.setattr(aca, "_generate_auth_recommendations", lambda results: [{"id": "x", "confidence": 0.8}])

    j = _loads(aca.auth_chain_analyzer("https://t.example", auth_type="auto"))
    assert j["decision"]["primary_auth"] == "session"
    assert j["decision"]["best_attack_surface"] == "bypass_validation"
    assert j["decision"]["next_phase"] == "bypass_testing"
    assert j["summary"]["high_confidence_hypotheses"] == 1


def test_http_request_wrapper_returns_none_on_exception(monkeypatch):
    def boom(*args, **kwargs):
        raise aca.requests.RequestException("nope")

    monkeypatch.setattr(aca.requests, "request", boom)
    assert aca._http_request("GET", "https://x.example") is None


def test_response_set_cookie_lines_prefers_duplicate_headers_get_all():
    resp = DummyResp(
        status_code=200,
        headers={"Set-Cookie": "only_last=1"},
        raw=SimpleNamespace(headers=DummyRawHeaders(["a=1; Secure", "b=2; HttpOnly"])),
    )
    lines = aca._response_set_cookie_lines(resp)
    assert lines == ["set-cookie: a=1; Secure", "set-cookie: b=2; HttpOnly"]


def test_analyze_cookie_security_flags_and_modern_none_without_secure():
    info = aca._analyze_cookie_security("Set-Cookie: sid=abc; HttpOnly; SameSite=None")
    assert info["name"] == "sid"
    assert info["flags"]["secure"] is False
    assert info["flags"]["httponly"] is True
    assert info["flags"]["samesite"] == "none"
    joined = "\n".join(info["analysis"]).lower()
    assert "samesite=none without secure" in joined


def test_wildcard_baseline_signature_reads_prefix(monkeypatch):
    # Make _http_request return a streaming resp with .raw.read
    raw = DummyRaw(set_cookie_list=[], prefix_bytes=b"HELLO" * 60)
    monkeypatch.setattr(
        aca,
        "_http_request",
        lambda method, url, timeout=6.0, stream=True, **kw: DummyResp(
            status_code=404,
            headers={"Content-Type": "text/html", "Content-Length": "123", "ETag": "W/xyz"},
            raw=raw,
        ),
    )
    sig = aca._wildcard_baseline_signature("https://t.example")
    assert sig["code"] == "404"
    assert sig["clen"] == 123
    assert sig["ctype"] == "text/html"
    assert sig["etag"] == "W/xyz"
    assert isinstance(sig["body_prefix"], str) and len(sig["body_prefix"]) > 0


def test_looks_like_wildcard_by_same_status_and_content_length():
    baseline = {"code": "200", "clen": 777, "ctype": "text/html", "location": "", "etag": "", "body_prefix": ""}
    cand = {"status": "200", "clen": 777}
    assert aca._looks_like_wildcard(cand, baseline) is True


def test_parse_jwt_tool_output_extracts_algorithm_and_claims():
    sample = """
====================
Decoded Token Values:
=====================

Token header values:
[+] typ = "JWT"
[+] alg = "HS256"

Token payload values:
[+] iss = "issuer"
[+] sub = "subject"
[+] aud = "audience"
[+] exp = 123456
[+] iat = 111
"""
    a = aca._parse_jwt_tool_output(sample)
    assert a["algorithm"] == "HS256"
    assert a["claims"]["iss"] == "issuer"
    assert a["claims"]["sub"] == "subject"
    assert a["claims"]["aud"] == "audience"
    assert a["claims"]["exp"] == "123456"
    assert a["claims"]["iat"] == "111"


def test_discover_auth_endpoints_ignores_wildcard_candidates(monkeypatch):
    # Force baseline signature: 200 with length 10 and ctype text/html
    monkeypatch.setattr(
        aca,
        "_wildcard_baseline_signature",
        lambda base_url: {"code": "200", "clen": 10, "ctype": "text/html", "location": "", "etag": "",
                          "body_prefix": ""},
    )

    # Every HEAD probe returns 200 with matching content-length -> treated as wildcard and ignored
    def fake_http(method, url, timeout=5.0, **kw):
        return DummyResp(status_code=200, headers={"Content-Length": "10", "Content-Type": "text/html"})

    monkeypatch.setattr(aca, "_http_request", fake_http)

    # Avoid feroxbuster path entirely by making subprocess.run fail harmlessly
    monkeypatch.setattr(aca.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))

    eps = aca._discover_auth_endpoints("https://t.example")
    assert eps == []


def test_analyze_auth_mechanisms_filters_by_auth_type(monkeypatch):
    endpoints = [
        {"path": "/.well-known/openid-configuration", "full_url": "https://t.example/.well-known/openid-configuration",
         "status": "200", "type": "OAuth"},
        {"path": "/login", "full_url": "https://t.example/login", "status": "200", "type": "Session-based"},
    ]

    # Return content that would trigger both, but auth_type filter should keep only OAuth
    def fake_http(method, url, timeout=10.0, **kw):
        return DummyResp(status_code=200, headers={}, text="client_id=abc oauth authorize redirect_uri")

    monkeypatch.setattr(aca, "_http_request", fake_http)

    mechs = aca._analyze_auth_mechanisms("https://t.example", endpoints, auth_type="oauth")
    assert all(m["type"] == "OAuth" for m in mechs)
    assert len(mechs) >= 1


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/graphql", "GraphQL"),
        ("/api/graphql", "GraphQL"),
        ("/.well-known/openid-configuration", "OAuth"),
        ("/.well-known/jwks.json", "JWT"),
        ("/oauth/authorize", "OAuth"),
        ("/saml/metadata", "SAML"),
        ("/mfa/verify", "Multi-factor"),
        ("/password/reset", "Password Recovery"),
        ("/signin", "Session-based"),
        ("/api/v1/auth", "API Authentication"),
        ("/admin", "Administrative"),
        ("/something-else", "Generic Authentication"),
    ],
)
def test_classify_auth_endpoint(path, expected):
    assert aca._classify_auth_endpoint(path, "") == expected


def test_analyze_cookie_security_rejects_bad_inputs():
    assert aca._analyze_cookie_security("") is None
    assert aca._analyze_cookie_security("set-cookie: ") is None
    assert aca._analyze_cookie_security("set-cookie: just_a_name") is None


def test_analyze_cookie_security_parses_flags_case_insensitive():
    info = aca._analyze_cookie_security("SeT-CoOkIe: SID=abc123; SECURE; HttpOnly; SameSite=Lax")
    assert info["name"] == "SID"
    assert info["flags"]["secure"] is True
    assert info["flags"]["httponly"] is True
    assert info["flags"]["samesite"] == "lax"
    assert info["analysis"] == []


def test_analyze_cookie_security_truncates_value_preview():
    long_val = "A" * 200
    info = aca._analyze_cookie_security(f"set-cookie: sid={long_val}; Secure; HttpOnly; SameSite=Strict")
    assert info["value"].endswith("...")
    assert len(info["value"]) < len(long_val)


def test_analyze_session_security_no_cookies():
    out = aca._analyze_session_security([])
    assert out == ["No session cookies identified"]


def test_analyze_session_security_flags_and_predictable_name():
    cookies = [
        {
            "type": "Cookie",
            "name": "JSESSIONID",
            "security_flags": {"secure": False, "httponly": False, "samesite": "lax"},
        }
    ]
    out = aca._analyze_session_security(cookies)
    joined = "\n".join(out).lower()
    assert "lack secure" in joined
    assert "lack httponly" in joined
    assert "predictable session cookie name" in joined


def test_analyze_tokens_and_sessions_uses_multiple_set_cookie_headers(monkeypatch):
    # Provide a HEAD response with multiple Set-Cookie headers via resp.raw.headers.get_all
    resp = DummyResp(
        status_code=200,
        headers={},
        raw=SimpleNamespace(
            headers=DummyRawHeaders(
                [
                    "sessionid=abc; HttpOnly; SameSite=Lax",
                    "prefs=1; Secure; SameSite=Strict",
                ]
            )
        ),
    )

    monkeypatch.setattr(aca, "_http_request", lambda *a, **k: resp)

    out = aca._analyze_tokens_and_sessions("https://t.example", mechanisms=[])
    assert "tokens" in out
    assert len(out["tokens"]) == 2
    names = sorted([t["name"] for t in out["tokens"]])
    assert names == ["prefs", "sessionid"]
    assert out["session_info"]["session_cookies"] == 1  # sessionid


def test_discover_auth_endpoints_dedupes_paths_between_methods(monkeypatch):
    # Avoid wildcard filtering (baseline != candidate)
    monkeypatch.setattr(
        aca,
        "_wildcard_baseline_signature",
        lambda base_url: {"code": "404", "clen": 1, "ctype": "text/plain", "location": "", "etag": "",
                          "body_prefix": ""},
    )

    # Make direct probing find /admin once
    def fake_http(method, url, timeout=5.0, **kw):
        if url.endswith("/admin"):
            return DummyResp(status_code=200, headers={"Content-Length": "9", "Content-Type": "text/html"})
        return None

    monkeypatch.setattr(aca, "_http_request", fake_http)

    # Ferox returns the same /admin path; ensure it doesn't duplicate
    ferox_lines = "\n".join(
        [
            json.dumps({"type": "response", "status": 200, "url": "https://t.example/admin", "wildcard": False,
                        "content_length": 9}),
        ]
    )
    monkeypatch.setattr(
        aca.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=ferox_lines, stderr=""),
    )

    eps = aca._discover_auth_endpoints("https://t.example")
    paths = [e["path"] for e in eps]
    assert paths.count("/admin") == 1


def test_test_advanced_auth_bypasses_forced_browsing_redirects_classified(monkeypatch):
    results = {
        "auth_endpoints": [
            {"type": "Administrative", "path": "/admin", "full_url": "https://t.example/admin"},
            {"type": "Administrative", "path": "/console", "full_url": "https://t.example/console"},
        ]
    }

    def fake_http(method, url, timeout=10.0, **kw):
        if url.endswith("/admin"):
            return DummyResp(status_code=302, headers={"Location": "https://t.example/login"})
        if url.endswith("/console"):
            return DummyResp(status_code=302, headers={"Location": "https://t.example/somewhere"})
        return None

    monkeypatch.setattr(aca, "_http_request", fake_http)

    out = aca._test_advanced_auth_bypasses("https://t.example", results)
    fb = [x for x in out if x.get("technique") == "Forced Browsing"]
    assert len(fb) == 2

    by_ep = {x["endpoint"]: x for x in fb}
    assert by_ep["/admin"]["successful"] is False
    assert "redirects to authentication" in by_ep["/admin"]["description"].lower()

    assert by_ep["/console"]["successful"] is False
    assert "review redirect target" in by_ep["/console"]["description"].lower()


def test_test_advanced_auth_bypasses_method_bypass_requires_protected_baseline(monkeypatch):
    # One endpoint: GET redirects to login (protected), HEAD returns 200 with different headers (bypass)
    results = {"auth_endpoints": [{"type": "Administrative", "path": "/admin", "full_url": "https://t.example/admin"}]}

    def fake_http(method, url, timeout=8.0, headers=None, **kw):
        if method == "GET" and url.endswith("/admin") and headers is None:
            return DummyResp(
                status_code=302,
                headers={"Location": "https://t.example/login", "Content-Type": "text/html", "Content-Length": "10"},
            )
        if method == "HEAD" and url.endswith("/admin"):
            return DummyResp(status_code=200, headers={"Content-Type": "text/plain", "Content-Length": "2"})
        return DummyResp(status_code=404, headers={})

    monkeypatch.setattr(aca, "_http_request", fake_http)

    out = aca._test_advanced_auth_bypasses("https://t.example", results)
    mb = [x for x in out if x.get("technique") == "HTTP Method Bypass" and x.get("successful") is True]
    assert mb, "Expected at least one HTTP Method Bypass finding"
    assert mb[0]["method"] in {"POST", "PUT", "PATCH", "HEAD", "OPTIONS"}


def test_test_advanced_auth_bypasses_header_manipulation_requires_protected_baseline(monkeypatch):
    results = {"auth_endpoints": [{"type": "Administrative", "path": "/admin", "full_url": "https://t.example/admin"}]}

    def fake_http(method, url, timeout=8.0, headers=None, **kw):
        if method == "GET" and headers is None:
            return DummyResp(status_code=302, headers={"Location": "https://t.example/login"})
        if method == "GET" and headers and any(
                k in headers for k in ["X-Originating-IP", "X-Forwarded-For", "X-Remote-IP", "X-Remote-Addr"]
        ):
            return DummyResp(status_code=200, headers={"Content-Type": "text/html"})
        return DummyResp(status_code=404, headers={})

    monkeypatch.setattr(aca, "_http_request", fake_http)

    out = aca._test_advanced_auth_bypasses("https://t.example", results)
    hm = [x for x in out if x.get("technique") == "Header Manipulation" and x.get("successful") is True]
    assert hm, "Expected a Header Manipulation bypass when baseline is protected"
    assert "127.0.0.1" in hm[0]["header"]


def test_generate_auth_recommendations_prioritizes_confirmed_bypass():
    results = {
        "target": "https://t.example",
        "auth_endpoints": [{"type": "Administrative", "path": "/admin", "full_url": "https://t.example/admin"}],
        "auth_mechanisms": [{"type": "Session-based", "endpoint": "/login"}],
        "tokens_discovered": [],
        "vulnerabilities": [
            {"technique": "Forced Browsing", "endpoint": "/admin", "successful": True, "status_code": "200"}],
        "flow_analysis": {"session_management": {}, "bypass_opportunities": [], "privilege_escalation": []},
    }

    steps = aca._generate_auth_recommendations(results)
    assert steps
    assert any(s.get("priority") == 1 and "EXPLOIT_CONFIRMED" in s.get("id", "") for s in steps)
    assert any(s.get("id") == "TASK_POST_BYPASS_IDOR_PIVOT" and s.get("priority") == 2 for s in steps)


def test_generate_auth_recommendations_fallback_when_no_signal():
    results = {
        "target": "https://t.example",
        "auth_endpoints": [],
        "auth_mechanisms": [],
        "tokens_discovered": [],
        "vulnerabilities": [],
        "flow_analysis": {"session_management": {}, "bypass_opportunities": [], "privilege_escalation": []},
    }

    steps = aca._generate_auth_recommendations(results)
    assert len(steps) == 1
    assert steps[0]["id"] == "TASK_BROADEN_DISCOVERY"
    assert steps[0]["priority"] == 1
