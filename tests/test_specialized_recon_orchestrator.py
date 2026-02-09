import subprocess
import json
from typing import Any, Dict, List

import pytest

import modules.operation_plugins.web.tools.specialized_recon_orchestrator as sro


class _CP:
    """Simple stand-in for subprocess.CompletedProcess-like object."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _Resp:
    def __init__(self, ok=True, text="", status_code=200, headers=None, json_obj=None):
        self.ok = ok
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self._json_obj = json_obj

    def json(self):
        if self._json_obj is None:
            raise ValueError("no json")
        return self._json_obj


def _as_json(result_str: str) -> Dict[str, Any]:
    assert isinstance(result_str, str)
    return json.loads(result_str)


@pytest.fixture
def fake_subprocess(monkeypatch):
    """
    Provides a programmable subprocess.run mock.
    Configure behavior by setting `state["handlers"]`.
    """
    state = {"calls": [], "handlers": []}

    def _run(cmd, capture_output=False, text=False, stdin=None, timeout=None, env=None):
        state["calls"].append({"cmd": cmd, "timeout": timeout, "env": env})
        # handlers are (predicate, responder)
        for pred, resp in state["handlers"]:
            if pred(cmd):
                return resp(cmd)
        return _CP(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sro.subprocess, "run", _run)
    return state


@pytest.fixture
def fake_requests(monkeypatch):
    """
    Provides programmable requests.get/head mocks.
    Configure behavior via returned dict.
    """
    state = {"get_calls": [], "head_calls": [], "get_handler": None, "head_handler": None}

    def _get(url, *args, **kwargs):
        state["get_calls"].append({"url": url, "kwargs": kwargs})
        if state["get_handler"]:
            return state["get_handler"](url, kwargs)
        return _Resp(ok=True, text="", status_code=200)

    def _head(url, *args, **kwargs):
        state["head_calls"].append({"url": url, "kwargs": kwargs})
        if state["head_handler"]:
            return state["head_handler"](url, kwargs)
        return _Resp(ok=True, text="", status_code=200)

    monkeypatch.setattr(sro.requests, "get", _get)
    monkeypatch.setattr(sro.requests, "head", _head)
    return state


def test_canonicalize_url_strips_fragment_and_lowercases_scheme_host():
    u = "HTTPS://Example.COM:443/a/b?Q=1#frag"
    c = sro._canonicalize_url(u)
    assert "#frag" not in c
    assert c.startswith("https://example.com:443/")
    # query case preserved except host/scheme; we don't rewrite query keys/values
    assert "Q=1" in c


def test_target_normalization_domain_and_url_inputs(fake_subprocess, fake_requests, monkeypatch):
    # Avoid trying to install tools: make _setup_specialized_tools no-op
    monkeypatch.setattr(sro, "_setup_specialized_tools",
                        lambda errors=None: {"success": True, "tools": [], "failed": []})
    monkeypatch.setattr(sro, "_advanced_subdomain_enum", lambda target, errors=None: [])
    monkeypatch.setattr(sro, "_analyze_live_hosts", lambda hosts, errors=None: {"hosts": [], "technologies": []})
    monkeypatch.setattr(sro, "_deep_web_intelligence",
                        lambda live_hosts, errors=None: {"endpoints": [], "js_files": [], "parameters": []})
    monkeypatch.setattr(sro, "_analyze_attack_surface", lambda results: results.get("intelligence", {}))
    monkeypatch.setattr(sro, "_generate_recon_tasks", lambda results: [])
    monkeypatch.setattr(sro, "_generate_recon_recommendations", lambda results: [])

    out1 = _as_json(sro.specialized_recon_orchestrator("Example.com", recon_type="web"))
    assert out1["target"] == "example.com"

    out2 = _as_json(sro.specialized_recon_orchestrator("https://Example.com/some/path", recon_type="web"))
    assert out2["target"] == "example.com"

    out3 = _as_json(sro.specialized_recon_orchestrator("Example.com/another/path", recon_type="web"))
    assert out3["target"] == "example.com"


def test_analyze_attack_surface_endpoint_field_selection_and_summary_counts():
    results = {
        "subdomains": ["webmail.trip.com", "dev.trip.com", "secure.trip.com"],
        "live_hosts": ["https://dev.trip.com", "https://secure.trip.com:8443"],
        "endpoints": [
            "https://we.ctrip.com/account/login",
            "https://api.trip.com/v1/users?auth=1",
            "https://portal.trip.com/path",
        ],
        "technologies": [],
    }
    intel = sro._analyze_attack_surface(results)

    # Ensure structured fields exist
    assert "high_value_targets" in intel
    assert "high_value_summary" in intel
    assert "ranked_targets" in intel

    # Field selection checks
    hv = intel["high_value_targets"]
    # login appears in path
    assert any(
        x["type"] == "endpoint"
        and x["value"].endswith("/account/login")
        and x["matches"][0]["keyword"] == "login"
        and x["matches"][0]["field"] == "path"
        for x in hv
    )
    # api appears in hostname OR path; here it's hostname ("api.trip.com")
    assert any(
        x["type"] == "endpoint"
        and "api.trip.com" in x["value"]
        and x["matches"][0]["keyword"] == "api"
        and x["matches"][0]["field"] == "hostname"
        for x in hv
    )
    # auth appears in query for the api URL
    assert any(
        x["type"] == "endpoint"
        and "auth=1" in x["value"]
        and x["matches"][0]["keyword"] == "auth"
        and x["matches"][0]["field"] == "query"
        for x in hv
    )

    # Summary counts include keywords used above
    by_kw = intel["high_value_summary"]["counts_by_keyword"]
    assert by_kw.get("login", 0) >= 1
    assert by_kw.get("api", 0) >= 1
    assert by_kw.get("auth", 0) >= 1

    by_type = intel["high_value_summary"]["counts_by_type"]
    assert by_type.get("endpoint", 0) >= 3
    assert by_type.get("subdomain", 0) >= 1

    # ranked_targets sorted by score desc then confidence desc
    ranked = intel["ranked_targets"]
    assert ranked, "ranked_targets should not be empty"
    scores = [int(x.get("score") or 0) for x in ranked]
    assert scores == sorted(scores, reverse=True)


def test_hidden_services_structured_and_ranked_list_is_small():
    results = {
        "subdomains": [],
        "endpoints": [],
        "technologies": [],
        "live_hosts": [
            "https://dev.example.com",
            "https://secure.example.com:8443",
            "https://vpn.example.com",
        ],
    }
    intel = sro._analyze_attack_surface(results)

    hs = intel.get("hidden_services", [])
    assert hs
    assert all(isinstance(x, dict) for x in hs)
    assert "ranked_hidden_services" in intel
    assert len(intel["ranked_hidden_services"]) <= sro.HIDDEN_SERVICES_LIMIT

    # Must include nonstandard_port object for :8443
    assert any(x.get("type") == "nonstandard_port" and x.get("port") == 8443 for x in hs)


def test_recommendations_are_agent_directives_minimal_and_sorted():
    results = {
        "subdomains": ["a.example.com"],
        "live_hosts": ["https://a.example.com"],
        "endpoints": [],
        "js_files": [],
        "parameters": [],
        "technologies": [],
        "meta": {
            "limits": {"crawl_hosts": 5},
            "coverage": {
                "subdomains_discovered": 1,
                "live_hosts_discovered": 1,
                "endpoints_discovered": 0,
                "js_files_discovered": 0,
                "parameters_discovered": 0,
            },
        },
        "intelligence": {
            "ranked_targets": [
                {"type": "endpoint", "value": "https://a.example.com/login", "score": 90, "confidence": 0.8,
                 "matches": [{"keyword": "login"}]},
            ],
            "ranked_hidden_services": [],
            "high_value_summary": {"counts_by_keyword": {"login": 1}, "counts_by_type": {"endpoint": 1}},
            "technology_risks": [],
        },
    }

    directives = sro._generate_recon_recommendations(results)
    assert directives
    assert all(isinstance(d, dict) for d in directives)

    # Required directive keys
    for d in directives:
        assert "id" in d
        assert "priority" in d
        assert "goal" in d
        assert "capabilities" in d
        assert "selectors" in d

    # Sorted by priority then id
    keys = [(d["priority"], d["id"]) for d in directives]
    assert keys == sorted(keys)


def test_orchestrator_end_to_end_happy_path_with_mocked_tools(fake_subprocess, fake_requests, monkeypatch):
    # Setup tools: "which <tool>" should fail so orchestrator tries go install, but we can just pretend install fails gracefully.
    def pred_which(cmd):
        return cmd and cmd[0] == "which"

    def resp_which(cmd):
        return _CP(returncode=1, stdout="", stderr="not found")

    def pred_go_install(cmd):
        return cmd[:2] == ["go", "install"]

    def resp_go_install(cmd):
        # pretend installs succeed quickly
        return _CP(returncode=0, stdout="ok", stderr="")

    # subfinder
    def pred_subfinder(cmd):
        return cmd and cmd[0] == "subfinder"

    def resp_subfinder(cmd):
        return _CP(returncode=0, stdout="a.example.com\nwebmail.example.com\n", stderr="")

    # assetfinder
    def pred_assetfinder(cmd):
        return cmd and cmd[0] == "assetfinder"

    def resp_assetfinder(cmd):
        return _CP(returncode=0, stdout="dev.example.com\n", stderr="")

    # waybackurls
    def pred_wayback(cmd):
        return cmd and cmd[0] == "waybackurls"

    def resp_wayback(cmd):
        return _CP(returncode=0, stdout="https://a.example.com/index\nhttps://api.example.com/v1\n", stderr="")

    # httpx JSONL output
    def pred_httpx(cmd):
        return cmd and cmd[0] == "httpx"

    def resp_httpx(cmd):
        lines = [
            json.dumps({"url": "https://a.example.com", "tech": ["nginx", "php"]}),
            json.dumps({"url": "https://dev.example.com:8443", "tech": ["tomcat"]}),
        ]
        return _CP(returncode=0, stdout="\n".join(lines) + "\n", stderr="")

    # katana JSONL output
    def pred_katana(cmd):
        return cmd and cmd[0] == "katana"

    def resp_katana(cmd):
        lines = [
            json.dumps({"request": {"endpoint": "https://a.example.com/account/login"}}),
            json.dumps({"request": {"endpoint": "https://a.example.com/static/app.js"}}),
            json.dumps({"request": {"endpoint": "https://a.example.com/search?q=1"}}),
        ]
        return _CP(returncode=0, stdout="\n".join(lines) + "\n", stderr="")

    fake_subprocess["handlers"] = [
        (pred_which, resp_which),
        (pred_go_install, resp_go_install),
        (pred_subfinder, resp_subfinder),
        (pred_assetfinder, resp_assetfinder),
        (pred_wayback, resp_wayback),
        (pred_httpx, resp_httpx),
        (pred_katana, resp_katana),
    ]

    # crt.sh request (called even if tools succeed)
    fake_requests["get_handler"] = lambda url, kwargs: _Resp(ok=True, text="[]", json_obj=[])

    out = _as_json(sro.specialized_recon_orchestrator("example.com", recon_type="comprehensive"))

    assert out["target"] == "example.com"
    assert out["recon_type"] == "comprehensive"

    # Meta coverage updated
    cov = out["meta"]["coverage"]
    assert cov["subdomains_discovered"] > 0
    assert cov["live_hosts_discovered"] > 0
    assert cov["endpoints_discovered"] > 0

    # Intelligence includes ranked lists
    intel = out["intelligence"]
    assert "ranked_targets" in intel
    assert "ranked_hidden_services" in intel

    # Tasks have selector-based inputs (not big embedded lists)
    tasks = out["tasks"]
    assert isinstance(tasks, list)
    assert any(t["id"] == "asset_inventory" for t in tasks)
    for t in tasks:
        assert "inputs" in t
        if t["inputs"]:
            assert "select" in t["inputs"]

    # Recommendations present and machine-readable
    recs = out.get("recommendations", [])
    assert isinstance(recs, list)
    if recs:
        r0 = recs[0]
        assert "capabilities" in r0
        assert "selectors" in r0


def test_generate_recon_tasks_prioritize_high_value_evidence_is_objects():
    # Current implementation builds hv_evidence as objects; ensure stable shape
    results = {
        "subdomains": [],
        "live_hosts": ["https://a.example.com"],
        "endpoints": ["https://a.example.com/login"],
        "js_files": [],
        "parameters": [],
        "technologies": [],
        "intelligence": {
            "high_value_targets": [
                {"type": "endpoint", "value": "https://a.example.com/login",
                 "matches": [{"keyword": "login", "field": "path"}], "signals": ["auth_surface"], "score": 90}
            ],
            "ranked_targets": [
                {"type": "endpoint", "value": "https://a.example.com/login",
                 "matches": [{"keyword": "login", "field": "path"}], "signals": ["auth_surface"], "score": 90}
            ],
            "hidden_services": [],
            "technology_risks": [],
        },
    }
    tasks = sro._generate_recon_tasks(results)
    t = next(x for x in tasks if x["id"] == "prioritize_high_value")
    assert isinstance(t["evidence"], list)
    assert t["evidence"], "evidence should not be empty"
    assert isinstance(t["evidence"][0], dict)
    assert "keyword" in t["evidence"][0] or "signals" in t["evidence"][0]
    assert "inputs" in t and "select" in t["inputs"]


def test_dedup_list_by_key_basic_and_errors():
    # Basic dedupe
    assert sro._dedup_list_by_key(["a", "a", "b", "a"]) == ["a", "b"]

    # Key-based dedupe (first wins)
    data = [{"k": 1, "v": "a"}, {"k": 1, "v": "b"}, {"k": 2, "v": "c"}]
    out = sro._dedup_list_by_key(data, key=lambda x: x["k"])
    assert out == [{"k": 1, "v": "a"}, {"k": 2, "v": "c"}]

    # Key function exception should skip element
    out2 = sro._dedup_list_by_key([{"x": 1}, {"bad": True}, {"x": 2}], key=lambda x: x["x"])
    assert out2 == [{"x": 1}, {"x": 2}]


def test_dedup_canonicalized_urls_strips_fragments_and_preserves_first_seen():
    urls = [
        "https://EXAMPLE.com/a#one",
        "https://example.com/a#two",
        "https://example.com/b?x=1#frag",
        "https://example.com/b?x=1",
    ]
    out = sro._dedup_canonicalized_urls(urls)
    assert out == ["https://example.com/a", "https://example.com/b?x=1"]


def test_append_tool_error_includes_tails_only():
    errors: List[Dict[str, Any]] = []
    big = "x" * 6000
    sro._append_tool_error(
        errors,
        "phase",
        "tool",
        "msg",
        returncode=2,
        stdout=big,
        stderr=big,
        timed_out=True,
    )
    assert len(errors) == 1
    e = errors[0]
    assert e["phase"] == "phase"
    assert e["tool"] == "tool"
    assert e["returncode"] == 2
    assert e["timed_out"] is True
    assert "stdout_tail" in e and len(e["stdout_tail"]) <= 4096
    assert "stderr_tail" in e and len(e["stderr_tail"]) <= 4096


def test_setup_specialized_tools_records_errors_on_nonzero(fake_subprocess):
    # which fails, go install fails
    def pred_which(cmd):
        return cmd and cmd[0] == "which"

    def resp_which(cmd):
        return _CP(returncode=1, stdout="", stderr="")

    def pred_go_install(cmd):
        return cmd[:2] == ["go", "install"]

    def resp_go_install(cmd):
        return _CP(returncode=1, stdout="out", stderr="err")

    fake_subprocess["handlers"] = [(pred_which, resp_which), (pred_go_install, resp_go_install)]

    errors: List[Dict[str, Any]] = []
    status = sro._setup_specialized_tools(errors=errors)

    assert status["failed"], "Should mark tools as failed when go install returns non-zero"
    assert errors, "Should record tool error"
    assert any(e.get("phase") == "setup" and e.get("tool") for e in errors)


def test_setup_specialized_tools_timeout_records_error(fake_subprocess):
    # which fails then go install times out
    def pred_which(cmd):
        return cmd and cmd[0] == "which"

    def resp_which(cmd):
        return _CP(returncode=1, stdout="", stderr="")

    def pred_go_install(cmd):
        return cmd[:2] == ["go", "install"]

    def resp_go_install(cmd):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=120)

    fake_subprocess["handlers"] = [(pred_which, resp_which), (pred_go_install, resp_go_install)]

    errors: List[Dict[str, Any]] = []
    status = sro._setup_specialized_tools(errors=errors)

    assert status["failed"], "Timeout should mark tools as failed"
    assert any(e.get("timed_out") for e in errors if e.get("phase") == "setup")


def test_advanced_subdomain_enum_records_tool_errors(fake_subprocess, fake_requests):
    # subfinder non-zero
    def pred_subfinder(cmd):
        return cmd and cmd[0] == "subfinder"

    def resp_subfinder(cmd):
        return _CP(returncode=2, stdout="", stderr="boom")

    # assetfinder ok
    def pred_assetfinder(cmd):
        return cmd and cmd[0] == "assetfinder"

    def resp_assetfinder(cmd):
        return _CP(returncode=0, stdout="a.example.com\n", stderr="")

    # wayback non-zero
    def pred_wayback(cmd):
        return cmd and cmd[0] == "waybackurls"

    def resp_wayback(cmd):
        return _CP(returncode=3, stdout="", stderr="nope")

    fake_subprocess["handlers"] = [
        (pred_subfinder, resp_subfinder),
        (pred_assetfinder, resp_assetfinder),
        (pred_wayback, resp_wayback),
    ]

    # crtsh returns empty list
    fake_requests["get_handler"] = lambda url, kwargs: _Resp(ok=True, text="[]", json_obj=[])

    errors: List[Dict[str, Any]] = []
    subs = sro._advanced_subdomain_enum("example.com", errors=errors)

    assert "a.example.com" in subs
    assert any(e.get("phase") == "subdomain_enum" and e.get("tool") == "subfinder" for e in errors)
    assert any(e.get("phase") == "subdomain_enum" and e.get("tool") == "waybackurls" for e in errors)


def test_advanced_subdomain_enum_crtsh_json_parse_error_recorded(fake_subprocess, fake_requests):
    fake_subprocess["handlers"] = []

    class _BadResp(_Resp):
        def json(self):
            raise ValueError("bad json")

    fake_requests["get_handler"] = lambda url, kwargs: _BadResp(ok=True, text="not-json", status_code=200)

    errors: List[Dict[str, Any]] = []
    subs = sro._advanced_subdomain_enum("example.com", errors=errors)

    assert isinstance(subs, list)
    assert any(e.get("tool") == "crtsh" for e in errors)


def test_analyze_live_hosts_httpx_nonzero_records_error(fake_subprocess):
    def pred_httpx(cmd):
        return cmd and cmd[0] == "httpx"

    def resp_httpx(cmd):
        return _CP(returncode=1, stdout="", stderr="err")

    fake_subprocess["handlers"] = [(pred_httpx, resp_httpx)]

    errors: List[Dict[str, Any]] = []
    out = sro._analyze_live_hosts(["a.example.com"], errors=errors)

    assert "hosts" in out and "technologies" in out
    assert any(e.get("phase") == "live_hosts" and e.get("tool") == "httpx" for e in errors)


def test_analyze_live_hosts_fallback_requests_adds_server_header(fake_subprocess, fake_requests):
    # httpx gives no output => fallback requests runs
    def pred_httpx(cmd):
        return cmd and cmd[0] == "httpx"

    def resp_httpx(cmd):
        return _CP(returncode=1, stdout="", stderr="")

    fake_subprocess["handlers"] = [(pred_httpx, resp_httpx)]

    def head_handler(url, kwargs):
        return _Resp(ok=True, status_code=200, headers={"Server": "nginx"})

    fake_requests["head_handler"] = head_handler

    out = sro._analyze_live_hosts(["a.example.com"], errors=[])

    assert any(h.endswith("://a.example.com") for h in out["hosts"])
    assert any("nginx" in str(t).lower() for t in out["technologies"])


def test_deep_web_intelligence_katana_nonzero_fallback_parses_html(fake_subprocess, fake_requests):
    def pred_katana(cmd):
        return cmd and cmd[0] == "katana"

    def resp_katana(cmd):
        return _CP(returncode=2, stdout="", stderr="fail")

    fake_subprocess["handlers"] = [(pred_katana, resp_katana)]

    html = """
    <html>
      <head>
        <script src="/static/app.js"></script>
        <script src="app2.js"></script>
      </head>
      <body>
        <a href="/login">Login</a>
        <a href="mailto:test@example.com">Mail</a>
        <a href="javascript:void(0)">JS</a>
        <form>
          <input name="username" />
          <input name="password" />
        </form>
      </body>
    </html>
    """

    fake_requests["get_handler"] = lambda url, kwargs: _Resp(ok=True, text=html, status_code=200)

    errors: List[Dict[str, Any]] = []
    out = sro._deep_web_intelligence(["https://a.example.com"], errors=errors)

    assert "https://a.example.com/static/app.js" in out["js_files"]
    assert "https://a.example.com/app2.js" in out["js_files"]
    assert "https://a.example.com/login" in out["endpoints"]
    assert "username" in out["parameters"]
    assert "password" in out["parameters"]
    assert any(e.get("phase") == "web_intel" and e.get("tool") == "katana" for e in errors)


def test_deep_web_intelligence_katana_jsonl_extracts_params_and_js(fake_subprocess):
    def pred_katana(cmd):
        return cmd and cmd[0] == "katana"

    def resp_katana(cmd):
        lines = [
            json.dumps({"request": {"endpoint": "https://a.example.com/search?q=1&x=2"}}),
            json.dumps({"request": {"endpoint": "https://a.example.com/app.js"}}),
            json.dumps({"request": {"endpoint": "https://a.example.com/auth.css"}}),
            "{bad json",
        ]
        return _CP(returncode=0, stdout="\n".join(lines) + "\n", stderr="")

    fake_subprocess["handlers"] = [(pred_katana, resp_katana)]

    out = sro._deep_web_intelligence(["https://a.example.com"], errors=[])

    assert "https://a.example.com/search?q=1&x=2" in out["endpoints"]
    assert "https://a.example.com/auth.css" not in out["endpoints"]
    assert "https://a.example.com/app.js" in out["js_files"]
    assert "q" in out["parameters"]
    assert "x" in out["parameters"]


def test_orchestrator_records_phase_errors_and_continues(monkeypatch):
    # Force subdomain enum to raise, live host analysis to raise; ensure output still returns.
    monkeypatch.setattr(sro, "_setup_specialized_tools",
                        lambda errors=None: {"success": True, "tools": [], "failed": []})

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(sro, "_advanced_subdomain_enum", boom)
    monkeypatch.setattr(sro, "_analyze_live_hosts", boom)
    monkeypatch.setattr(sro, "_deep_web_intelligence", boom)

    monkeypatch.setattr(
        sro,
        "_analyze_attack_surface",
        lambda results: {
            "attack_surface_size": 0,
            "high_value_targets": [],
            "ranked_targets": [],
            "high_value_summary": {"counts_by_type": {}, "counts_by_keyword": {}},
            "technology_risks": [],
            "hidden_services": [],
            "ranked_hidden_services": [],
        },
    )
    monkeypatch.setattr(sro, "_generate_recon_tasks", lambda results: [])
    monkeypatch.setattr(sro, "_generate_recon_recommendations", lambda results: [])

    out = _as_json(sro.specialized_recon_orchestrator("example.com", recon_type="comprehensive"))
    phases = {e.get("phase") for e in out.get("errors", [])}
    assert "subdomain_enum" in phases
    assert "live_hosts" in phases
    assert out["target"] == "example.com"
    assert "intelligence" in out


def test_meta_coverage_updates_for_web_recon(monkeypatch):
    monkeypatch.setattr(sro, "_setup_specialized_tools",
                        lambda errors=None: {"success": True, "tools": [], "failed": []})
    monkeypatch.setattr(sro, "_analyze_live_hosts",
                        lambda hosts, errors=None: {"hosts": ["https://a.example.com"], "technologies": ["nginx"]})
    monkeypatch.setattr(sro, "_analyze_attack_surface", lambda results: results.get("intelligence", {}))
    monkeypatch.setattr(sro, "_generate_recon_tasks", lambda results: [])
    monkeypatch.setattr(sro, "_generate_recon_recommendations", lambda results: [])

    out = _as_json(sro.specialized_recon_orchestrator("example.com", recon_type="web"))
    cov = out["meta"]["coverage"]
    assert cov["live_hosts_discovered"] == 1
    assert cov["subdomains_discovered"] == 0


def test_meta_coverage_updates_for_comprehensive(monkeypatch):
    monkeypatch.setattr(sro, "_setup_specialized_tools",
                        lambda errors=None: {"success": True, "tools": [], "failed": []})
    monkeypatch.setattr(sro, "_advanced_subdomain_enum",
                        lambda target, errors=None: ["a.example.com", "dev.example.com"])
    monkeypatch.setattr(sro, "_analyze_live_hosts",
                        lambda hosts, errors=None: {"hosts": ["https://a.example.com"], "technologies": ["nginx"]})
    monkeypatch.setattr(sro, "_deep_web_intelligence",
                        lambda live_hosts, errors=None: {"endpoints": ["https://a.example.com/login"], "js_files": [],
                                                         "parameters": []})
    monkeypatch.setattr(sro, "_analyze_attack_surface", lambda results: results.get("intelligence", {}))
    monkeypatch.setattr(sro, "_generate_recon_tasks", lambda results: [])
    monkeypatch.setattr(sro, "_generate_recon_recommendations", lambda results: [])

    out = _as_json(sro.specialized_recon_orchestrator("example.com", recon_type="comprehensive"))
    cov = out["meta"]["coverage"]
    assert cov["subdomains_discovered"] == 2
    assert cov["live_hosts_discovered"] == 1
    assert cov["endpoints_discovered"] == 1


def test_recommendations_broaden_enumeration_when_no_discovery():
    results = {
        "subdomains": [],
        "live_hosts": [],
        "endpoints": [],
        "js_files": [],
        "parameters": [],
        "technologies": [],
        "meta": {
            "limits": {"crawl_hosts": 5},
            "coverage": {
                "subdomains_discovered": 0,
                "live_hosts_discovered": 0,
                "endpoints_discovered": 0,
                "js_files_discovered": 0,
                "parameters_discovered": 0,
            },
        },
        "intelligence": {
            "ranked_targets": [],
            "ranked_hidden_services": [],
            "high_value_summary": {"counts_by_keyword": {}, "counts_by_type": {}},
            "technology_risks": [],
        },
    }

    recs = sro._generate_recon_recommendations(results)
    assert any(r["id"] == "broaden_enumeration" for r in recs)


def test_recommendations_include_parameter_driven_testing_and_js_analysis_and_tech():
    results = {
        "subdomains": ["a.example.com"],
        "live_hosts": ["https://a.example.com"],
        "endpoints": ["https://a.example.com/search?q=1"],
        "js_files": ["https://a.example.com/app.js"],
        "parameters": ["q"],
        "technologies": ["wordpress"],
        "meta": {
            "limits": {"crawl_hosts": 5},
            "coverage": {
                "subdomains_discovered": 1,
                "live_hosts_discovered": 1,
                "endpoints_discovered": 1,
                "js_files_discovered": 1,
                "parameters_discovered": 1,
            },
        },
        "intelligence": {
            "ranked_targets": [
                {"type": "endpoint", "value": "https://a.example.com/login", "score": 90, "confidence": 0.8,
                 "matches": [{"keyword": "login"}]}],
            "ranked_hidden_services": [],
            "high_value_summary": {"counts_by_keyword": {"login": 1}, "counts_by_type": {"endpoint": 1}},
            "technology_risks": ["wordpress"],
        },
    }

    recs = sro._generate_recon_recommendations(results)
    ids = {r["id"] for r in recs}
    assert "parameter_driven_testing" in ids
    assert "js_bundle_analysis" in ids
    assert "tech_version_and_vuln_verification" in ids


def test_generate_recon_tasks_asset_inventory_selectors_present():
    results = {
        "subdomains": ["a.example.com"],
        "live_hosts": ["https://a.example.com"],
        "endpoints": ["https://a.example.com/"],
        "js_files": [],
        "parameters": [],
        "technologies": [],
        "intelligence": {"high_value_targets": [], "ranked_targets": [], "hidden_services": [], "technology_risks": []},
    }

    tasks = sro._generate_recon_tasks(results)
    ai = next(t for t in tasks if t["id"] == "asset_inventory")
    assert "select" in ai["inputs"]
    assert any(sel.get("from") == "subdomains" for sel in ai["inputs"]["select"])
    assert any(sel.get("from") == "endpoints" for sel in ai["inputs"]["select"])


def test_generate_recon_tasks_hidden_services_evidence_and_selectors():
    results = {
        "subdomains": [],
        "live_hosts": ["https://dev.example.com:8443"],
        "endpoints": [],
        "js_files": [],
        "parameters": [],
        "technologies": [],
        "intelligence": {
            "high_value_targets": [],
            "ranked_targets": [],
            "hidden_services": [
                {"type": "nonstandard_port", "value": "https://dev.example.com:8443", "port": 8443, "score": 55,
                 "confidence": 0.75}],
            "technology_risks": [],
        },
    }

    tasks = sro._generate_recon_tasks(results)
    hs = next(t for t in tasks if t["id"] == "verify_hidden_services")
    assert hs["evidence"], "hidden service evidence should be present"
    assert "select" in hs["inputs"]
    assert any(sel.get("from") == "intelligence.hidden_services" for sel in hs["inputs"]["select"])
