from __future__ import annotations

import base64
import json
from subprocess import DEVNULL
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

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

    def fake_run(cmd, capture_output=True, text=True, stdin=DEVNULL, timeout=300):
        # arjun wrote JSON to -oJ <file>
        out_path = cmd[cmd.index("-oJ") + 1]
        data = {"http://example.test/page": {"params": ["a", "b"]}}
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return FakeCompleted(returncode=0, stdout=""" Analysing HTTP response for anomalies
 Extracted 4 parameters from response for testing: user_token, Login, username, password
 Logicforcing the URL endpoint
 """)

    monkeypatch.setattr(apc.subprocess, "run", fake_run)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    params = apc._advanced_parameter_discovery(rc, provided_params=None, tools=["arjun"])
    assert "a" in params
    assert "b" in params
    assert "user_token" in params
    assert "Login" in params
    assert "username" in params
    assert "password" in params


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

    def fake_run(cmd, capture_output=True, text=True, stdin=DEVNULL, timeout=None):
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

def test_coordinate_xss_testing_parses_dalfox_jsonl(monkeypatch):
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

    stdout = "[\n" + "\n".join(json.dumps(event) for event in events) + "\n]"

    def fake_run(cmd, capture_output=True, text=True, stdin=DEVNULL, timeout=None):
        return FakeCompleted(returncode=0, stdout=stdout)

    monkeypatch.setattr(apc.subprocess, "run", fake_run)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._coordinate_xss_testing(rc, parameters=["name"], tools=["dalfox"])

    vulns = [r for r in res if r.get("vulnerable")]
    assert len(vulns) == 1
    v = vulns[0]
    assert v["parameter"] == "name"
    assert v["url"] == "http://example.test/page?name=PAY"
    assert v["payload"] == "<img src=x onerror=alert(1)>"


def test_coordinate_xss_testing_processes_timeout_stdout_and_skips_negative_results(monkeypatch):
    # On subprocess timeout, dalfox stdout should still be parsed.
    # Additionally, when dalfox times out, the implementation intentionally avoids adding
    # negative "XSS tested" rows for remaining params.
    event = {
        "type": "V",
        "param": "name",
        "inject_type": "inHTML",
        "data": "http://example.test/page?name=PAY",
        "payload": "<img src=x onerror=alert(1)>",
        "message_str": "Triggered",
    }

    def fake_run(cmd, capture_output=True, text=True, stdin=DEVNULL, timeout=None):
        raise apc.subprocess.TimeoutExpired(cmd=cmd, timeout=timeout or 0, output=json.dumps([event]))

    monkeypatch.setattr(apc.subprocess, "run", fake_run)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._coordinate_xss_testing(rc, parameters=["name", "other"], tools=["dalfox"])

    vulns = [r for r in res if r.get("vulnerable")]
    assert len(vulns) == 1
    assert vulns[0]["parameter"] == "name"

    negatives = [r for r in res if r.get("vulnerable") is False and r.get("tool") == "dalfox"]
    assert negatives == [], "On timeout, expected no dalfox negative results to be appended"


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


def test_coordinate_injection_testing_commix_parses_timeout_stdout(monkeypatch):
    # Command injection should be detected via commix tool output, even when the process times out.
    commix_stdout = """
[+] Testing if GET parameter 'name' is vulnerable
[+] Parameter 'name' is vulnerable
"""

    def fake_run(cmd, capture_output=True, text=True, input=None, timeout=300):
        # Ensure we are invoking commix
        assert cmd and cmd[0] == "commix"
        raise apc.subprocess.TimeoutExpired(cmd=cmd, timeout=timeout, output=commix_stdout)

    monkeypatch.setattr(apc.subprocess, "run", fake_run)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._coordinate_injection_testing(rc, parameters=["name"], tools=["commix"])

    vulns = [r for r in res if r.get("vulnerable")]
    assert vulns, "Expected a commix-derived command injection finding"
    v = vulns[0]
    assert v["tool"] == "commix"
    assert v["injection_type"] == "Command Injection"
    assert v["parameter"] == "name"
    assert v.get("method") == "GET"


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

    def fake_run(cmd, capture_output=True, text=True, stdin=DEVNULL, timeout=300):
        return FakeCompleted(returncode=0, stdout=sstimap_stdout)

    monkeypatch.setattr(apc.subprocess, "run", fake_run)

    rc = apc.RequestConfig(target_url="http://example.test/page", http_method="GET")
    res = apc._coordinate_injection_testing(rc, parameters=["name"], tools=["sstimap"])

    vulns = [r for r in res if r.get("vulnerable")]
    assert vulns
    assert vulns[0]["tool"] == "sstimap"
    assert vulns[0]["parameter"] == "name"
    assert "url" in vulns[0]
    assert all(v.get("tool") != "commix" for v in res)


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
    assert "xss" in intel["attack_vectors"]
    assert "cmd_injection" in intel["attack_vectors"]
    assert "cors" in intel["attack_vectors"]
    # Deduped lists
    assert len(intel["attack_vectors"]) == len(set(intel["attack_vectors"]))


# -------------------------
# _generate_payload_recommendations
# -------------------------

def test_generate_payload_recommendations_when_no_vulns():
    results = {"payload_results": [], "intelligence": {"severity_distribution": {}, "attack_vectors": [], "bypass_techniques": [], "exploitation_chains": []}}
    recs = apc._generate_payload_recommendations("comprehensive", results)
    assert recs
    assert "rerun_with_auth_if_possible" in recs[0]


def test_generate_payload_recommendations_when_high_severity_present():
    results = {
        "payload_results": [{"vulnerable": True, "payload_type": "Advanced XSS (inHTML)"}],
        "intelligence": {"severity_distribution": {"Advanced XSS (inHTML)": 1}, "attack_vectors": ["xss"], "bypass_techniques": [], "exploitation_chains": []},
    }
    recs = apc._generate_payload_recommendations("comprehensive", results)
    assert any('prioritize_high_severity' in r for r in recs)
    assert any('classify_xss_type_reflected_stored_dom' in r.lower() for r in recs)


# -------------------------
# advanced_payload_coordinator (top-level orchestration)
# -------------------------

def test_advanced_payload_coordinator_orchestrates_phases_and_formats_output(monkeypatch):
    # Stub all heavy internals so we only test orchestration and formatting.
    monkeypatch.setattr(apc, "_setup_payload_tools", lambda: {"success": True, "tools": ["dalfox"], "failed": []})
    monkeypatch.setattr(apc, "_advanced_parameter_discovery", lambda rc, provided_params=None, tools=None: ["name"])
    monkeypatch.setattr(apc, "_coordinate_xss_testing", lambda rc, params, tools=None: [
        {"parameter": "name", "vulnerable": True, "payload_type": "Advanced XSS (inHTML)", "payload": "PAY", "url": "http://t/?name=PAY"}
    ])
    monkeypatch.setattr(apc, "_test_cors_configurations", lambda rc, tools=None: [])
    monkeypatch.setattr(apc, "_coordinate_injection_testing", lambda rc, params, tools=None: [])
    monkeypatch.setattr(apc, "_analyze_payload_intelligence", lambda payload_results: {"severity_distribution": {"Advanced XSS (inHTML)": 1}, "attack_vectors": ["xss"], "bypass_techniques": [], "exploitation_chains": []})
    monkeypatch.setattr(apc, "_generate_payload_recommendations", lambda test_type, results: ["REC1", "REC2"])

    out = apc.advanced_payload_coordinator("http://example.test/page", test_type="comprehensive")
    data = json.loads(out)
    assert data["target"] == "http://example.test/page"
    assert data["test_type"] == "comprehensive"

    # tooling + param discovery routed through
    assert data["tools"]["success"] is True
    assert data["tools"]["tools"] == ["dalfox"]
    assert data["parameters_discovered"] == ["name"]

    # payload/vuln aggregation + counts
    assert data["counts"]["payload_results"] == 1
    assert data["counts"]["vulnerabilities"] == 1
    assert data["vulnerabilities"][0]["parameter"] == "name"
    assert data["vulnerabilities"][0]["vulnerable"] is True

    # analysis + recs forwarded
    assert data["intelligence"]["attack_vectors"] == ["xss"] or "xss" in data["intelligence"]["attack_vectors"]
    assert data["recommendations"] == ["REC1", "REC2"]

    # should not emit prose anymore
    assert "Phase 1:" not in out
    assert "[PAYLOAD]" not in out


def test_coordinator_retries_post_when_get_produces_no_param_results(monkeypatch):
    calls = {"param_discovery": [], "xss": []}

    # Phase 1: tools setup (keep empty to avoid tool execution)
    monkeypatch.setattr(
        apc,
        "_setup_payload_tools",
        lambda: {"success": True, "tools": [], "failed": []},
    )

    # Phase 2: parameter discovery
    def fake_param_discovery(request_config: apc.RequestConfig, provided_params=None, tools=None):
        # record which method was used
        calls["param_discovery"].append(request_config.http_method)
        # GET yields no results -> should trigger POST retry
        if request_config.http_method.upper() == "GET":
            return []
        return ["name"]

    monkeypatch.setattr(apc, "_advanced_parameter_discovery", fake_param_discovery)

    # Phase 3: XSS testing
    def fake_xss_testing(request_config: apc.RequestConfig, parameters, tools=None):
        calls["xss"].append(request_config.http_method)
        # GET yields no vulns -> should trigger POST retry
        if request_config.http_method.upper() == "GET":
            return [{"parameter": "name", "vulnerable": False, "payload_type": "XSS tested", "tool": "fake"}]
        # POST yields a vuln
        return [
            {
                "parameter": "name",
                "vulnerable": True,
                "payload_type": "Advanced XSS (fake)",
                "payload": "\"><img src=x onerror=alert(1)>",
                "url": "http://example.test/page?name=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
                "method": request_config.http_method,
                "tool": "fake",
            }
        ]

    monkeypatch.setattr(apc, "_coordinate_xss_testing", fake_xss_testing)

    # Avoid unrelated phases doing anything complicated
    monkeypatch.setattr(apc, "_test_cors_configurations", lambda *a, **k: [])
    monkeypatch.setattr(apc, "_coordinate_injection_testing", lambda *a, **k: [])

    # Keep analysis/recs deterministic
    monkeypatch.setattr(
        apc,
        "_analyze_payload_intelligence",
        lambda payload_results: {
            "severity_distribution": {"Advanced XSS (fake)": 1},
            "attack_vectors": ["xss"],
            "bypass_techniques": [],
            "exploitation_chains": [],
        },
    )
    monkeypatch.setattr(apc, "_generate_payload_recommendations", lambda test_type, results: ["REC"])

    out = apc.advanced_payload_coordinator(
        "http://example.test/page",
        test_type="xss",
        http_method="GET",
    )

    # ---- Assertions: intended fallback behavior ----
    # Parameter discovery: GET first, then POST (because GET produced no results)
    assert calls["param_discovery"] == ["GET", "POST"]

    # XSS testing: should also try GET then POST (because GET produced no vulns)
    assert calls["xss"] == ["POST"]

    data = json.loads(out)

    assert data["http_method"] == "POST"
    assert data["parameters_discovered"] == ["name"]

    # should contain the POST vuln
    assert data["counts"]["vulnerabilities"] == 1
    assert any(v.get("parameter") == "name" and v.get("vulnerable") is True for v in data["vulnerabilities"])
    assert any(r.get("parameter") == "name" and r.get("method") == "POST" and r.get("vulnerable") is True for r in data["payload_results"])


def test_coordinator_retries_post_when_get_produces_no_xss_results(monkeypatch):
    calls = {"param_discovery": [], "xss": []}

    # Phase 1: tools setup (keep empty to avoid tool execution)
    monkeypatch.setattr(
        apc,
        "_setup_payload_tools",
        lambda: {"success": True, "tools": [], "failed": []},
    )

    # Phase 2: parameter discovery
    def fake_param_discovery(request_config: apc.RequestConfig, provided_params=None, tools=None):
        # record which method was used
        calls["param_discovery"].append(request_config.http_method)
        # GET yields no results -> should trigger POST retry
        return ["name"]

    monkeypatch.setattr(apc, "_advanced_parameter_discovery", fake_param_discovery)

    # Phase 3: XSS testing
    def fake_xss_testing(request_config: apc.RequestConfig, parameters, tools=None):
        calls["xss"].append(request_config.http_method)
        # GET yields no vulns -> should trigger POST retry
        if request_config.http_method.upper() == "GET":
            return [{"parameter": "name", "vulnerable": False, "payload_type": "XSS tested", "tool": "fake"}]
        # POST yields a vuln
        return [
            {
                "parameter": "name",
                "vulnerable": True,
                "payload_type": "Advanced XSS (fake)",
                "payload": "\"><img src=x onerror=alert(1)>",
                "url": "http://example.test/page?name=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E",
                "method": request_config.http_method,
                "tool": "fake",
            }
        ]

    monkeypatch.setattr(apc, "_coordinate_xss_testing", fake_xss_testing)

    # Avoid unrelated phases doing anything complicated
    monkeypatch.setattr(apc, "_test_cors_configurations", lambda *a, **k: [])
    monkeypatch.setattr(apc, "_coordinate_injection_testing", lambda *a, **k: [])

    # Keep analysis/recs deterministic
    monkeypatch.setattr(
        apc,
        "_analyze_payload_intelligence",
        lambda payload_results: {
            "severity_distribution": {"Advanced XSS (fake)": 1},
            "attack_vectors": ["xss"],
            "bypass_techniques": [],
            "exploitation_chains": [],
        },
    )
    monkeypatch.setattr(apc, "_generate_payload_recommendations", lambda test_type, results: ["REC"])

    out = apc.advanced_payload_coordinator(
        "http://example.test/page",
        test_type="xss",
        http_method="GET",
    )

    # ---- Assertions: intended fallback behavior ----
    # Parameter discovery: GET first, then POST (because GET produced no results)
    assert calls["param_discovery"] == ["GET"]

    # XSS testing: should also try GET then POST (because GET produced no vulns)
    assert calls["xss"] == ["GET", "POST"]

    data = json.loads(out)

    assert data["http_method"] == "POST"
    assert data["parameters_discovered"] == ["name"]

    # should contain the POST vuln
    assert data["counts"]["vulnerabilities"] == 1
    assert any(v.get("parameter") == "name" and v.get("vulnerable") is True for v in data["vulnerabilities"])
    assert any(
        r.get("parameter") == "name"
        and r.get("method") == "POST"
        and r.get("vulnerable") is True
        for r in data["payload_results"]
    )


def test_coordinator_phase5_retries_post_when_get_produces_no_injection_vulns(monkeypatch):
    calls = {"inj": [], "xss": [], "param_discovery": []}

    # Phase 1: tools setup (keep empty to avoid tool execution)
    monkeypatch.setattr(
        apc,
        "_setup_payload_tools",
        lambda: {"success": True, "tools": [], "failed": []},
    )

    # Phase 2: parameter discovery should return something on GET so we actually proceed cleanly.
    def fake_param_discovery(request_config: apc.RequestConfig, provided_params=None, tools=None):
        calls["param_discovery"].append(request_config.http_method)
        return ["name"]

    monkeypatch.setattr(apc, "_advanced_parameter_discovery", fake_param_discovery)

    # Phase 3: XSS can be quiet; return vulns (don’t trigger POST retry here).
    def fake_xss_testing(request_config: apc.RequestConfig, parameters, tools=None):
        calls["xss"].append(request_config.http_method)
        return [{"parameter": "name", "vulnerable": True, "payload_type": "XSS tested", "tool": "fake"}]

    monkeypatch.setattr(apc, "_coordinate_xss_testing", fake_xss_testing)

    # Phase 4: no-op
    monkeypatch.setattr(apc, "_test_cors_configurations", lambda *a, **k: [])

    # Phase 5: injection testing — GET yields *no vulns*, POST yields a vuln
    def fake_injection_testing(request_config: apc.RequestConfig, parameters, tools=None):
        calls["inj"].append(request_config.http_method)

        if request_config.http_method.upper() == "GET":
            # No vulnerabilities on GET
            return [
                {
                    "vulnerable": False,
                    "injection_type": "Multiple injection types",
                    "parameter": "name",
                    "tool": "fake",
                }
            ]

        # Vulnerability appears on POST retry
        return [
            {
                "vulnerable": True,
                "injection_type": "Command Injection",
                "parameter": "name",
                "payload": "; whoami",
                "url": "http://example.test/page?name=%3B%20whoami",
                "method": request_config.http_method,
                "evidence": "Command execution indicators detected",
                "tool": "fake",
            }
        ]

    monkeypatch.setattr(apc, "_coordinate_injection_testing", fake_injection_testing)

    # Keep analysis/recs deterministic (don’t care about exact content beyond not crashing)
    monkeypatch.setattr(
        apc,
        "_analyze_payload_intelligence",
        lambda payload_results: {
            "severity_distribution": {"Command Injection": 1},
            "attack_vectors": ["cmd_injection"],
            "bypass_techniques": [],
            "exploitation_chains": [],
        },
    )
    monkeypatch.setattr(apc, "_generate_payload_recommendations", lambda test_type, results: ["REC"])

    out = apc.advanced_payload_coordinator(
        "http://example.test/page",
        test_type="comprehensive",
        http_method="GET",
    )

    # ---- Assertions: Phase 5 intended fallback behavior ----
    # Parameter discovery ran once (no retry needed)
    assert calls["param_discovery"] == ["GET"]

    # XSS ran once and stayed GET (no vulns, but we intentionally didn't trigger retry path here)
    assert calls["xss"] == ["GET"]

    # Injection should run GET then POST (because GET produced no injection vulns)
    assert calls["inj"] == ["GET", "POST"]

    data = json.loads(out)

    # Coordinator should end in POST due to Phase 5 retry
    assert data["http_method"] == "POST"

    # We should have at least the POST command injection vuln present
    assert any(
        v.get("vulnerable") is True
        and v.get("injection_type") == "Command Injection"
        and v.get("parameter") == "name"
        and v.get("method") == "POST"
        for v in data["vulnerabilities"]
    ) or any(
        r.get("vulnerable") is True
        and r.get("injection_type") == "Command Injection"
        and r.get("parameter") == "name"
        and r.get("method") == "POST"
        for r in data["payload_results"]
    )

    # Counts should reflect at least 1 vuln
    assert data["counts"]["vulnerabilities"] >= 1
