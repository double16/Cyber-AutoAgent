# tests/test_advanced_payload_coordinator.py
#
# Pytest unit tests for advanced_payload_coordinator.py (excluding main()).
# These tests avoid network/tool execution by monkeypatching requests/subprocess.
#
# Some tests are marked xfail(strict=True) where the implementation currently
# diverges from intended behavior (so you get a loud signal without breaking CI).

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

import modules.operation_plugins.web.tools.advanced_payload_coordinator as apc


# -------------------------
# Small helpers
# -------------------------

class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def b64s(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# -------------------------
# _b64
# -------------------------

def test_b64_none_is_empty_string():
    assert apc._b64(None) == ""


def test_b64_bytes_roundtrip():
    raw = b"\xff\x00abc"
    out = apc._b64(raw)
    assert base64.b64decode(out) == raw


def test_b64_str_roundtrip():
    raw = "hello✓"
    out = apc._b64(raw)
    assert base64.b64decode(out).decode("utf-8") == raw


# -------------------------
# _payload_output
# -------------------------

def test_payload_output_basic_includes_expected_fields():
    vuln = {
        "parameter": "name",
        "payload_type": "Reflected XSS (unencoded)",
        "payload": "<script>alert(1)</script>",
        "url": "http://example/page?name=%3Cscript%3E",
    }
    out = apc._payload_output("xss", vuln)
    assert out.startswith("[PAYLOAD]")
    assert "type: xss" in out
    assert "param: name" in out
    assert "payload_type: Reflected XSS (unencoded)" in out
    assert "encoding: base64" in out
    assert f"payload_b64: {b64s(vuln['payload'])}" in out
    assert f"url_b64: {b64s(vuln['url'])}" in out
    assert out.rstrip().endswith("[/PAYLOAD]")


@pytest.mark.xfail(strict=True, reason="Intended: do not emit payload/url fields when value is None (implementation checks key presence only).")
def test_payload_output_does_not_emit_b64_or_plain_when_payload_and_url_are_none_intended():
    vuln = {"parameter": "p", "payload": None, "url": None}
    out = apc._payload_output("xss", vuln)
    assert "encoding: base64" not in out
    assert "payload_b64:" not in out
    assert "payload:" not in out
    assert "url_b64:" not in out
    assert "url:" not in out


# -------------------------
# _add_or_replace_query_param
# -------------------------

def test_add_or_replace_query_param_sets_and_overwrites():
    url = "http://example.test/page?x=1&y=2"
    u2 = apc._add_or_replace_query_param(url, "y", "abc")
    parsed = urlparse(u2)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    assert qs["x"] == ["1"]
    assert qs["y"] == ["abc"]


def test_add_or_replace_query_param_preserves_fragment():
    url = "http://example.test/page#frag"
    u2 = apc._add_or_replace_query_param(url, "q", "1")
    assert urlparse(u2).fragment == "frag"


# -------------------------
# _requests_get_text / _requests_head_raw_headers
# -------------------------

def test_requests_get_text_happy_path(monkeypatch):
    def fake_request(method, url, **kwargs):
        assert method == "GET"
        assert url == "http://example.test/page"
        assert kwargs["params"] == {"a": "1"}
        return SimpleNamespace(text="OK")

    monkeypatch.setattr(apc.requests, "request", fake_request)
    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    assert apc._requests_get_text("http://example.test/page", {"a": "1"}, rc) == "OK"


def test_requests_get_text_returns_none_on_exception(monkeypatch):
    def fake_request(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(apc.requests, "request", fake_request)
    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    assert apc._requests_get_text("http://example.test/page", {"a": "1"}, rc) is None


def test_requests_head_raw_headers_merges_headers(monkeypatch):
    def fake_head(url, headers, **kwargs):
        assert url == "http://example.test/page"
        # request_config.headers plus per-call headers
        assert headers["X-Base"] == "1"
        assert headers["Origin"] == "https://evil.com"
        return SimpleNamespace(headers={"A": "b", "C": "d"})

    monkeypatch.setattr(apc.requests, "head", fake_head)
    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET", headers={"X-Base": "1"})
    out = apc._requests_head_raw_headers("http://example.test/page", {"Origin": "https://evil.com"}, rc)
    assert "A: b" in out
    assert "C: d" in out


# -------------------------
# _parse_sstimap_output
# -------------------------

def test_parse_sstimap_output_body_param_and_capabilities():
    stdout = """
[+] SSTImap identified the following injection point:

  Body parameter: name
  Engine: Eval_generic
  Injection: {{*}}
  Context: text
  OS: undetected
  Technique: rendered
  Capabilities:

    Shell command execution: no
    Bind and reverse shell: no
    File write: no
    File read: no
    Code evaluation: no

[+] Rerun SSTImap providing one of the following options:
"""
    findings = apc._parse_sstimap_output(stdout)
    assert len(findings) == 1
    f = findings[0]
    assert f["vulnerable"] is True
    assert f["injection_type"] == "SSTI"
    assert f["parameter"] == "name"
    assert f["param_location"] == "body"
    assert f["payload"] == "{{*}}"
    assert f["engine"] == "Eval_generic"
    assert f["context"] == "text"
    assert f["os"] == "undetected"
    assert f["technique"] == "rendered"
    assert f["capabilities"]["Shell command execution"] == "no"


def test_parse_sstimap_output_query_param():
    stdout = """
[+] SSTImap identified the following injection point:

  GET parameter: q
  Engine: Jinja2
  Injection: {{7*7}}
  Context: text
  OS: undetected
  Technique: rendered

[+] Rerun SSTImap providing one of the following options:
"""
    findings = apc._parse_sstimap_output(stdout)
    assert len(findings) == 1
    assert findings[0]["parameter"] == "q"
    assert findings[0]["param_location"] == "query"
    assert findings[0]["payload"] == "{{7*7}}"


def test_parse_sstimap_output_no_marker_returns_empty():
    assert apc._parse_sstimap_output("nothing here") == []


# -------------------------
# _setup_payload_tools
# -------------------------

def test_setup_payload_tools_marks_failed_on_install_nonzero(monkeypatch):
    # which fails for all tools, pip fails for one tool
    calls = []

    def fake_run(cmd, capture_output=False, text=False, timeout=None, env=None):
        calls.append(cmd)
        if cmd[:2] == ["which", cmd[2] if len(cmd) > 2 else ""]:
            return FakeCompleted(returncode=1)
        if cmd[:2] == ["which", "dalfox"]:
            return FakeCompleted(returncode=1)
        if cmd[:2] == ["go", "install"]:
            return FakeCompleted(returncode=1, stderr="nope")
        if cmd[:2] == ["pip3", "install"]:
            # fail the first pip install, succeed others if needed
            pkg = cmd[2]
            return FakeCompleted(returncode=1 if pkg == "arjun" else 0)
        return FakeCompleted(returncode=0)

    monkeypatch.setattr(apc.subprocess, "run", fake_run)

    st = apc._setup_payload_tools()
    assert st["success"] is False
    assert st["failed"], "expected at least one failed tool"


# -------------------------
# _advanced_parameter_discovery
# -------------------------

def test_advanced_parameter_discovery_arjun_reads_output_file_intended(monkeypatch, tmp_path):
    # Force arjun path and ensure file exists with JSON output
    # Intended: created temp file should remain until parsed.

    def fake_run(cmd, capture_output=False, text=True, timeout=300):
        # arjun wrote JSON to -oJ <file>
        out_path = cmd[cmd.index("-oJ") + 1]
        data = {"http://example.test/page": {"params": ["a", "b"]}}
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return FakeCompleted(returncode=0, stdout="")

    monkeypatch.setattr(apc.subprocess, "run", fake_run)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    params = apc._advanced_parameter_discovery(rc, provided_params=None, tools=["arjun"])
    assert "a" in params and "b" in params


def test_advanced_parameter_discovery_extracts_from_url_query_even_if_no_tools():
    rc = apc.RequestConfig(target_url="http://example.test/page?x=1&y=2")
    params = apc._advanced_parameter_discovery(rc, tools=[])
    assert "x" in params
    assert "y" in params


def test_advanced_parameter_discovery_adds_provided_params():
    rc = apc.RequestConfig(target_url="http://example.test/page")
    params = apc._advanced_parameter_discovery(rc, provided_params="a, b ,c", tools=[])
    assert set(params) >= {"a", "b", "c"}


def test_advanced_parameter_discovery_common_params_only_if_none_found(monkeypatch):
    # Set up baseline request to succeed and make a status_code difference for one common param.
    seen = []

    def fake_request(method, url, **kwargs):
        seen.append(kwargs.get("params"))
        params = kwargs.get("params") or {}
        if not params:
            return SimpleNamespace(status_code=200, headers={"Content-Length": "100"})
        if "name" in params:
            return SimpleNamespace(status_code=404, headers={"Content-Length": "100"})
        return SimpleNamespace(status_code=200, headers={"Content-Length": "100"})

    monkeypatch.setattr(apc.requests, "request", fake_request)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    params = apc._advanced_parameter_discovery(rc, tools=[])
    assert "name" in params  # discovered via status code delta


# -------------------------
# _coordinate_xss_testing
# -------------------------

def test_coordinate_xss_testing_parses_dalfox_json_array(monkeypatch):
    # DalFox returns a JSON array; one vuln event and one non-vuln (or none).
    events = [
        {
            "type": "V",
            "param": "name",
            "inject_type": "inHTML",
            "data": "http://example.test/page?name=PAY",
            "payload": "<img src=x onerror=alert(1)>",
            "message_str": "Triggered",
        },
        {"type": "I", "param": "other"},
    ]

    def fake_run(cmd, capture_output=True, text=True, timeout=None):
        return FakeCompleted(returncode=0, stdout=json.dumps(events))

    monkeypatch.setattr(apc.subprocess, "run", fake_run)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._coordinate_xss_testing(rc, parameters=["name"], tools=["dalfox"])

    vulns = [r for r in res if r.get("vulnerable")]
    assert len(vulns) == 1
    v = vulns[0]
    assert v["parameter"] == "name"
    assert v["url"] == "http://example.test/page?name=PAY"
    assert v["payload"] == "<img src=x onerror=alert(1)>"


@pytest.mark.xfail(strict=True, reason="Intended: when test_url is built, request should be sent to that exact URL and not duplicate query params.")
def test_coordinate_xss_testing_custom_requests_exact_poc_url_intended(monkeypatch):
    # Force no dalfox path
    calls = []

    def fake_get_text(url, params, request_config, timeout=10):
        calls.append((url, params))
        return "<html><script>alert(1)</script></html>"

    monkeypatch.setattr(apc, "_requests_get_text", fake_get_text)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._coordinate_xss_testing(rc, parameters=["name"], tools=[])

    vulns = [r for r in res if r.get("vulnerable")]
    assert vulns
    v = vulns[0]
    assert calls, "expected at least one request call"
    first_url, first_params = calls[0]
    assert first_url == v["url"]
    assert first_params in (None, {})


# -------------------------
# _test_cors_configurations
# -------------------------

def test_test_cors_configurations_manual_detects_permissive(monkeypatch):
    # Disable corsy by passing tools=[]
    def fake_head_raw_headers(url, headers, request_config, timeout=10):
        # Return allow-origin reflecting the Origin
        origin = headers["Origin"]
        return f"Access-Control-Allow-Origin: {origin}\nVary: Origin"

    monkeypatch.setattr(apc, "_requests_head_raw_headers", fake_head_raw_headers)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._test_cors_configurations(rc, tools=[])
    vulns = [r for r in res if r.get("vulnerable")]
    assert vulns
    assert vulns[0]["issue_type"] == "Permissive CORS"


def test_test_cors_configurations_manual_negative_when_no_headers(monkeypatch):
    def fake_head_raw_headers(url, headers, request_config, timeout=10):
        return "Server: test\n"

    monkeypatch.setattr(apc, "_requests_head_raw_headers", fake_head_raw_headers)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._test_cors_configurations(rc, tools=[])
    assert res and res[0]["vulnerable"] is False


# -------------------------
# _coordinate_injection_testing (custom + sstimap)
# -------------------------

def test_coordinate_injection_testing_custom_detects_command_indicator(monkeypatch):
    calls = []

    def fake_get_text(url, params, request_config, timeout=10):
        calls.append((url, params))
        return "uid=1000 gid=1000 groups=1000"

    monkeypatch.setattr(apc, "_requests_get_text", fake_get_text)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._coordinate_injection_testing(rc, parameters=["name"], tools=[])

    vulns = [r for r in res if r.get("vulnerable")]
    assert vulns
    assert any(v["injection_type"] == "Command Injection" for v in vulns)


def test_coordinate_injection_testing_sstimap_parses_and_discards_param(monkeypatch):
    # Ensure sstimap tool path triggers and parser returns a finding,
    # and that param is removed from parameters_under_test.
    sstimap_stdout = """
[+] SSTImap identified the following injection point:

  Body parameter: name
  Engine: Eval_generic
  Injection: {{7*7}}
  Context: text
  OS: undetected
  Technique: rendered

[+] Rerun SSTImap providing one of the following options:
"""

    def fake_run(cmd, capture_output=True, text=True, timeout=300):
        return FakeCompleted(returncode=0, stdout=sstimap_stdout)

    monkeypatch.setattr(apc.subprocess, "run", fake_run)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._coordinate_injection_testing(rc, parameters=["name"], tools=["sstimap"])

    vulns = [r for r in res if r.get("vulnerable")]
    assert vulns
    assert vulns[0]["tool"] == "sstimap"
    assert vulns[0]["parameter"] == "name"
    assert "url" in vulns[0]


@pytest.mark.xfail(strict=True, reason="Intended: request should be made to the canonical PoC URL that is reported (implementation requests target_url and stores test_url).")
def test_coordinate_injection_testing_custom_requests_exact_poc_url_intended(monkeypatch):
    calls = []

    def fake_get_text(url, params, request_config, timeout=10):
        calls.append((url, params))
        return "uid=1000 gid=1000"

    monkeypatch.setattr(apc, "_requests_get_text", fake_get_text)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._coordinate_injection_testing(rc, parameters=["name"], tools=[])

    vulns = [r for r in res if r.get("vulnerable")]
    assert vulns
    v = vulns[0]
    first_url, first_params = calls[0]
    assert first_url == v["url"]
    assert first_params in (None, {})


# -------------------------
# _analyze_payload_intelligence
# -------------------------

def test_analyze_payload_intelligence_counts_and_dedupes():
    payload_results = [
        {"vulnerable": True, "payload_type": "Advanced XSS (inHTML)", "payload": "<svg/onload=alert(1)>"},
        {"vulnerable": True, "injection_type": "Command Injection", "payload": "; whoami"},
        {"vulnerable": False, "issue_type": "CORS Configuration"},
        {"vulnerable": True, "issue_type": "Permissive CORS"},
    ]
    intel = apc._analyze_payload_intelligence(payload_results)
    assert "Advanced XSS" in str(intel["severity_distribution"])
    assert "Client-side code injection via XSS" in intel["attack_vectors"]
    assert "Server-side command execution" in intel["attack_vectors"]
    assert "Cross-origin resource sharing abuse" in intel["attack_vectors"]
    # Deduped lists
    assert len(intel["attack_vectors"]) == len(set(intel["attack_vectors"]))


# -------------------------
# _generate_payload_recommendations
# -------------------------

def test_generate_payload_recommendations_when_no_vulns():
    results = {"payload_results": [], "intelligence": {"severity_distribution": {}, "attack_vectors": [], "bypass_techniques": [], "exploitation_chains": []}}
    recs = apc._generate_payload_recommendations(results)
    assert recs
    assert "No critical vulnerabilities detected" in recs[0]


def test_generate_payload_recommendations_when_high_severity_present():
    results = {
        "payload_results": [{"vulnerable": True, "payload_type": "Advanced XSS (inHTML)"}],
        "intelligence": {"severity_distribution": {"Advanced XSS (inHTML)": 1}, "attack_vectors": ["Client-side code injection via XSS"], "bypass_techniques": [], "exploitation_chains": []},
    }
    recs = apc._generate_payload_recommendations(results)
    assert any("CRITICAL" in r for r in recs)
    assert any("output encoding" in r.lower() for r in recs)


# -------------------------
# advanced_payload_coordinator (top-level orchestration)
# -------------------------

def test_advanced_payload_coordinator_orchestrates_phases_and_formats_output(monkeypatch):
    # Stub all heavy internals so we only test orchestration and formatting.
    monkeypatch.setattr(apc, "_setup_payload_tools", lambda: {"success": True, "tools": ["dalfox"], "failed": []})
    monkeypatch.setattr(apc, "_advanced_parameter_discovery", lambda rc, provided, tools=None: ["name"])
    monkeypatch.setattr(apc, "_coordinate_xss_testing", lambda rc, params, tools=None: [
        {"parameter": "name", "vulnerable": True, "payload_type": "Advanced XSS (inHTML)", "payload": "PAY", "url": "http://t/?name=PAY"}
    ])
    monkeypatch.setattr(apc, "_test_cors_configurations", lambda rc, tools=None: [])
    monkeypatch.setattr(apc, "_coordinate_injection_testing", lambda rc, params, tools=None: [])
    monkeypatch.setattr(apc, "_analyze_payload_intelligence", lambda payload_results: {"severity_distribution": {"Advanced XSS (inHTML)": 1}, "attack_vectors": ["Client-side code injection via XSS"], "bypass_techniques": [], "exploitation_chains": []})
    monkeypatch.setattr(apc, "_generate_payload_recommendations", lambda results: ["REC1", "REC2"])

    out = apc.advanced_payload_coordinator("http://example.test/page", test_type="comprehensive")
    assert "Advanced Payload Coordinator:" in out
    assert "Phase 1:" in out
    assert "Phase 2:" in out
    assert "Phase 3:" in out
    assert "Phase 6:" in out
    assert "[PAYLOAD]" in out
    assert "EXPLOITATION COORDINATION:" in out
    assert "1. REC1" in out
    assert "2. REC2" in out
