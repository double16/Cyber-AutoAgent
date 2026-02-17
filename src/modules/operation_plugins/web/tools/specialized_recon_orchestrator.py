#!/usr/bin/env python3
"""Specialized Reconnaissance Orchestrator - Coordinates advanced subdomain and web recon tools"""

import argparse
import json
import os
import re
import subprocess
import tempfile
import urllib3
from urllib.parse import urlparse, parse_qs, urljoin, urlunparse
import requests
from typing import Any, Dict, List, Callable, Optional

from strands import tool

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SUBDOMAIN_LIMIT = 200
LIVE_HOSTS_LIMIT = 10
HIDDEN_SERVICES_LIMIT = 50
HIGH_VALUE_TARGET_LIMIT = 25
ENDPOINTS_LIMIT = 100
PARAMETER_LIMIT = 300


def _coerce_str(arg: bytes | str | None) -> str:
    if arg is None:
        return ""
    if isinstance(arg, str):
        return arg
    if isinstance(arg, bytes):
        return arg.decode('utf-8', errors='ignore')
    return str(arg)


@tool
def specialized_recon_orchestrator(target: str, recon_type: str = "comprehensive") -> str:
    """
    Run focused recon for a target and return agent-ready JSON.

    Input:
    - Accepts domain or URL; normalizes to domain.

    Reuse vs run:
    - Reuse existing `recon_result_v1` for same target if sufficient.
    - Otherwise run recon.

    Sufficiency (reuse) if ALL:
    - same target/scope
    - subdomains_discovered > 0 (or tight known scope)
    - live_hosts_discovered > 0
    - for web work: endpoints_discovered >= 50 (or evidence of deeper crawl)
    - no major phase errors (subdomain_enum/live_hosts/web_intel)

    Stale (rerun) if ANY:
    - predates current assessment window / recency unknown
    - sparse coverage (e.g., endpoints_discovered < 50 when web testing needed)
    - key phase errors indicate partial results

    Modes (`recon_type`):
    - subdomain: subdomain enumeration only
    - web: live host probing + basic tech fingerprint
    - comprehensive: subdomain + live hosts + endpoint/js/parameter discovery + prioritization

    Return:
    JSON string with keys:
    - subdomains, live_hosts, technologies, endpoints, js_files, parameters
    - intelligence (ranked targets/hidden services)
    - tasks (capability-tagged next steps)
    - recommendations (machine directives)
    - meta (limits + coverage), errors (per-phase)
    """
    if not target:
        raise ValueError("target is required")

    # Normalize target: accept domain, URL, or host/path
    if target.startswith(("http://", "https://")):
        target = urlparse(target).netloc
    else:
        # Handle inputs like example.com/path (no scheme)
        target = target.split("/", 1)[0]

    target = target.strip().lower()
    if not target:
        raise ValueError("target is required")

    if recon_type not in ["subdomain", "web", "comprehensive"]:
        recon_type = "comprehensive"
    recon_type = recon_type.lower()

    results = {
        "target": target,
        "recon_type": recon_type,
        "subdomains": [],
        "live_hosts": [],
        "technologies": [],
        "endpoints": [],
        "js_files": [],
        "parameters": [],
        "intelligence": {
            "attack_surface_size": 0,
            "high_value_targets": [],
            "technology_risks": [],
            "hidden_services": [],
            "ranked_hidden_services": [],
        },
        "errors": [],
        "tasks": [],
        "meta": {
            "format": "recon_result_v1",
            "generated_by": "specialized_recon_orchestrator",
            "limits": {
                "crawl_hosts": LIVE_HOSTS_LIMIT,
            },
            "coverage": {
                "subdomains_discovered": 0,
                "live_hosts_discovered": 0,
                "endpoints_discovered": 0,
                "js_files_discovered": 0,
                "parameters_discovered": 0,
            },
        },
    }

    def _err(phase: str, error: str, tool: str | None = None, returncode: int | None = None, stdout: str | None = None,
             stderr: str | None = None, timed_out: bool | None = None) -> None:
        def _tail(s: str | None, n: int = 4096) -> str | None:
            if s is None:
                return None
            s = str(s)
            return s[-n:] if len(s) > n else s

        entry: Dict[str, Any] = {"phase": phase, "error": str(error)}
        if tool:
            entry["tool"] = tool
        if returncode is not None:
            entry["returncode"] = int(returncode)
        if timed_out is not None:
            entry["timed_out"] = bool(timed_out)
        if stdout:
            entry["stdout_tail"] = _tail(stdout)
        if stderr:
            entry["stderr_tail"] = _tail(stderr)
        results["errors"].append(entry)

    try:
        # Phase 1: Install and setup specialized tools
        try:
            tools_setup = _setup_specialized_tools(errors=results["errors"])
            results["tools"] = tools_setup
        except Exception as e:
            _err("setup", str(e))
            results["tools"] = {"success": False, "tools": [], "failed": []}

        # Phase 2: Subdomain enumeration using multiple specialized tools
        if recon_type in ["subdomain", "comprehensive"]:
            try:
                subdomains = _advanced_subdomain_enum(target, errors=results["errors"])
                results["subdomains"] = subdomains
            except Exception as e:
                _err("subdomain_enum", str(e))

        # Phase 3: Live host detection and technology fingerprinting
        if recon_type in ["web", "comprehensive"]:
            try:
                live_analysis = _analyze_live_hosts(results["subdomains"] or [target], errors=results["errors"])
                results["live_hosts"] = live_analysis["hosts"]
                results["technologies"] = live_analysis["technologies"]
                # Update meta coverage after Phase 3 if only web recon runs
                if recon_type == "web":
                    results["meta"]["coverage"].update(
                        {
                            "subdomains_discovered": len(results.get("subdomains", []) or []),
                            "live_hosts_discovered": len(results.get("live_hosts", []) or []),
                            "endpoints_discovered": len(results.get("endpoints", []) or []),
                            "js_files_discovered": len(results.get("js_files", []) or []),
                            "parameters_discovered": len(results.get("parameters", []) or []),
                        }
                    )
            except Exception as e:
                _err("live_hosts", str(e))

        # Phase 4: Advanced endpoint and parameter discovery
        if recon_type == "comprehensive":
            try:
                web_intel = _deep_web_intelligence(results["live_hosts"], errors=results["errors"])
                results["endpoints"] = web_intel["endpoints"]
                results["js_files"] = web_intel["js_files"]
                results["parameters"] = web_intel["parameters"]
                # Update meta coverage after Phase 4 completes
                results["meta"]["coverage"].update(
                    {
                        "subdomains_discovered": len(results.get("subdomains", []) or []),
                        "live_hosts_discovered": len(results.get("live_hosts", []) or []),
                        "endpoints_discovered": len(results.get("endpoints", []) or []),
                        "js_files_discovered": len(results.get("js_files", []) or []),
                        "parameters_discovered": len(results.get("parameters", []) or []),
                    }
                )
            except Exception as e:
                _err("web_intel", str(e))

        # Phase 5: Intelligence analysis and prioritization
        try:
            intelligence = _analyze_attack_surface(results)
            results["intelligence"] = intelligence
        except Exception as e:
            _err("analysis", str(e))

        # Task plan
        try:
            results["tasks"] = _generate_recon_tasks(results)
        except Exception as e:
            _err("tasks", str(e))

        # Recommendations
        try:
            results["recommendations"] = _generate_recon_recommendations(results)
        except Exception as e:
            _err("recommendations", str(e))
    except Exception as e:
        _err("orchestration", str(e))

    return json.dumps(results, indent=2)


def _generate_recon_tasks(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate a structured task plan optimized for an LLM agent to infer next steps."""

    def _task(task_id: str, title: str, priority: int, goal: str, evidence: List[Any], capabilities: List[str],
              inputs: Dict[str, Any] | None = None) -> Dict[str, Any]:
        return {
            "id": task_id,
            "title": title,
            "priority": int(priority),
            "goal": goal,
            "evidence": evidence,
            "capabilities": capabilities,
            "inputs": inputs or {},
        }

    tasks: List[Dict[str, Any]] = []

    subdomains = results.get("subdomains", [])
    live_hosts = results.get("live_hosts", [])
    endpoints = results.get("endpoints", [])
    js_files = results.get("js_files", [])
    parameters = results.get("parameters", [])
    technologies = results.get("technologies", [])
    intel = results.get("intelligence", {})

    # 1) Confirm asset inventory (foundation)
    tasks.append(
        _task(
            "asset_inventory",
            "Confirm asset inventory and scope",
            1,
            "Ensure discovered assets are in-scope and prioritize by exposure.",
            [
                {
                    "subdomains": len(subdomains),
                    "live_hosts": len(live_hosts),
                    "endpoints": len(endpoints)
                }
            ],
            ["osint", "web_recon", "network_recon"],
            {
                "select": [
                    {"from": "subdomains", "limit": SUBDOMAIN_LIMIT},
                    {"from": "live_hosts", "limit": LIVE_HOSTS_LIMIT},
                    {"from": "endpoints", "limit": ENDPOINTS_LIMIT},
                ]
            },
        )
    )

    # 2) High-value targets first
    hv = intel.get("high_value_targets", []) or []
    if hv:
        hv_evidence: List[Dict[str, Any]] = []
        for item in hv[:HIGH_VALUE_TARGET_LIMIT]:
            try:
                t = item.get("type")
                v = item.get("value")
                m0 = (item.get("matches") or [{}])[0]
                k = m0.get("keyword")
                f = m0.get("field")
                score = item.get("score")
                sig = (item.get("signals") or [])
                hv_evidence.append({
                    t: v,
                    "keyword": k,
                    "field": f,
                    "score": score,
                    "signals": sig,
                })
            except Exception:
                continue

        tasks.append(
            _task(
                "prioritize_high_value",
                "Prioritize high-value targets",
                1,
                "Rank admin/API/auth surfaces for deeper verification and test planning.",
                hv_evidence,
                ["web_recon", "web_crawling", "proxying"],
                {
                    "select": [
                        {"from": "intelligence.ranked_targets", "limit": HIGH_VALUE_TARGET_LIMIT}
                    ]
                },
            )
        )

    # 3) Verify non-standard ports / hidden services
    hidden = intel.get("hidden_services", []) or []
    if hidden:
        hidden_evidence: List[Dict[str, Any]] = []
        for item in hidden[:HIDDEN_SERVICES_LIMIT]:
            try:
                t = item.get("type")
                v = item.get("value")
                port = item.get("port")
                if port:
                    hidden_evidence.append({
                        t: v,
                        "port": port,
                    })
                else:
                    hidden_evidence.append({t: v})
            except Exception:
                continue

        tasks.append(
            _task(
                "verify_hidden_services",
                "Verify hidden services and non-standard ports",
                2,
                "Confirm reachability, auth boundaries, and exposure for services on unusual ports or dev/staging hosts.",
                hidden_evidence,
                ["network_recon", "web_recon", "proxying"],
                {
                    "select": [
                        {"from": "intelligence.hidden_services", "limit": HIDDEN_SERVICES_LIMIT},
                        {"from": "live_hosts", "limit": LIVE_HOSTS_LIMIT},
                    ]
                },
            )
        )

    # 4) Crawl/expand endpoints (if sparse)
    if live_hosts and len(endpoints) < 50:
        tasks.append(
            _task(
                "expand_crawl",
                "Expand crawling and endpoint discovery",
                2,
                "Increase endpoint coverage, include authenticated paths when possible.",
                [{"endpoints": len(endpoints), "live_hosts": len(live_hosts)}],
                ["web_crawling", "web_fuzzing", "web_scanning"],
                {
                    "select": [
                        {"from": "live_hosts", "limit": LIVE_HOSTS_LIMIT}
                    ]
                },
            )
        )

    # 5) Parameter-based testing (injection/XSS)
    if parameters:
        tasks.append(
            _task(
                "param_attack_surface",
                "Enumerate and classify parameters for testing",
                2,
                "Classify parameters by context (query/body/header) and identify candidates for injection/XSS/SSRF.",
                [{"parameters": len(parameters)}],
                ["web_recon", "injection_testing", "xss_testing", "ssrf"],
                {
                    "select": [
                        {"from": "parameters", "limit": PARAMETER_LIMIT},
                        {"from": "endpoints", "limit": HIGH_VALUE_TARGET_LIMIT},
                    ]
                },
            )
        )

    # 6) JS analysis for secrets and hidden routes
    if js_files:
        tasks.append(
            _task(
                "js_analysis",
                "Analyze JavaScript for secrets and hidden routes",
                3,
                "Extract API base URLs, routes, feature flags, and potential secrets from JS bundles.",
                [{"js_files": len(js_files)}],
                ["web_recon", "web_crawling", "osint"],
                {
                    "select": [
                        {"from": "js_files", "limit": 200}
                    ]
                },
            )
        )

    # 7) Tech-driven exploit verification
    risks = intel.get("technology_risks", []) or []
    if risks or technologies:
        tasks.append(
            _task(
                "tech_verification",
                "Verify technology versions and known exploit paths",
                3,
                "Confirm versions/configs for identified tech and attempt safe verification checks for known vuln classes.",
                (risks[:25] if risks else [{"technologies": len(technologies)}]),
                ["web_scanning", "sast", "exploitation_framework"],
                {
                    "select": [
                        {"from": "technologies", "limit": 200},
                        {"from": "intelligence.technology_risks", "limit": 200},
                    ]
                },
            )
        )

    # 8) Nuclei style templated checks when assets exist
    if live_hosts:
        tasks.append(
            _task(
                "template_scan",
                "Run targeted template checks",
                4,
                "Run focused checks against live hosts and high-value endpoints to quickly validate common exposures.",
                [{"live_hosts": len(live_hosts)}],
                ["web_scanning"],
                {
                    "select": [
                        {"from": "live_hosts", "limit": LIVE_HOSTS_LIMIT},
                        {"from": "endpoints", "limit": HIGH_VALUE_TARGET_LIMIT},
                    ]
                },
            )
        )

    # Stable ordering by priority then id
    tasks.sort(key=lambda t: (t["priority"], t["id"]))
    return tasks


def _append_tool_error(errors: List[Dict[str, Any]] | None, phase: str, tool: str, message: str,
                       returncode: int | None = None, stdout: str | None = None, stderr: str | None = None,
                       timed_out: bool | None = None) -> None:
    if errors is None:
        return

    def _tail(s: str | None, n: int = 4096) -> str | None:
        if s is None:
            return None
        s = str(s)
        return s[-n:] if len(s) > n else s

    entry: Dict[str, Any] = {"phase": phase, "tool": tool, "error": str(message)}
    if returncode is not None:
        entry["returncode"] = int(returncode)
    if timed_out is not None:
        entry["timed_out"] = bool(timed_out)
    if stdout:
        entry["stdout_tail"] = _tail(stdout)
    if stderr:
        entry["stderr_tail"] = _tail(stderr)
    errors.append(entry)


def _setup_specialized_tools(errors: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """Install specialized reconnaissance tools using modern Go module paths"""
    tools_status = {"success": True, "tools": [], "failed": []}

    # Modern ProjectDiscovery + community tools with @latest for latest versions
    go_tools = [
        ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("katana", "github.com/projectdiscovery/katana/cmd/katana@latest"),
        ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("assetfinder", "github.com/tomnomnom/assetfinder@latest"),
        ("waybackurls", "github.com/tomnomnom/waybackurls@latest"),
        ("gau", "github.com/lc/gau/v2/cmd/gau@latest"),
    ]

    for tool_name, install_path in go_tools:
        try:
            # Check if tool already exists
            check_cmd = ["which", tool_name]
            if subprocess.run(check_cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                              timeout=5).returncode == 0:
                tools_status["tools"].append(tool_name)
                continue

            # Use modern 'go install' for modules (not deprecated 'go get')
            install_cmd = ["go", "install", install_path]
            result = subprocess.run(install_cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120,
                                    env=os.environ | {"GOBIN": "/usr/local/bin"})

            if result.returncode == 0:
                tools_status["tools"].append(tool_name)
            else:
                # Installation failed but continue with available tools
                tools_status["failed"].append(tool_name)
                _append_tool_error(errors, "setup", tool_name, "go install failed", returncode=result.returncode,
                                   stdout=result.stdout, stderr=result.stderr)
        except subprocess.TimeoutExpired:
            tools_status["failed"].append(tool_name)
            _append_tool_error(errors, "setup", tool_name, "go install timed out", timed_out=True)
        except Exception as e:
            tools_status["failed"].append(tool_name)
            _append_tool_error(errors, "setup", tool_name, str(e))

    # Mark success as true even if some tools failed (graceful degradation)
    tools_status["success"] = len(tools_status["tools"]) > 0

    return tools_status


def _advanced_subdomain_enum(target: str, errors: List[Dict[str, Any]] | None = None) -> List[str]:
    """Advanced subdomain enumeration using multiple specialized tools"""
    all_subdomains = set()

    # Method 1: subfinder (if available)
    subfinder_out = ""
    try:
        cmd = ["subfinder", "-d", target, "-silent", "-timeout", "60"]
        result = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=90)
        if result.returncode == 0:
            subfinder_out = result.stdout
        else:
            _append_tool_error(errors, "subdomain_enum", "subfinder", "tool returned non-zero",
                               returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired as e:
        subfinder_out = _coerce_str(e.stdout)
        _append_tool_error(errors, "subdomain_enum", "subfinder", "tool timed out", timed_out=True)
    except Exception as e:
        _append_tool_error(errors, "subdomain_enum", "subfinder", str(e))
    if subfinder_out:
        subdomains = [line.strip() for line in subfinder_out.splitlines() if line.strip()]
        all_subdomains.update(subdomains)

    # Method 2: assetfinder (if available)
    assetfinder_out = ""
    try:
        cmd = ["assetfinder", "-subs-only", target]
        result = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        if result.returncode == 0:
            assetfinder_out = result.stdout
        else:
            _append_tool_error(errors, "subdomain_enum", "assetfinder", "tool returned non-zero",
                               returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired as e:
        assetfinder_out = _coerce_str(e.stdout)
        _append_tool_error(errors, "subdomain_enum", "assetfinder", "tool timed out", timed_out=True)
    except Exception as e:
        _append_tool_error(errors, "subdomain_enum", "assetfinder", str(e))
    if assetfinder_out:
        subdomains = [line.strip() for line in assetfinder_out.splitlines() if line.strip()]
        all_subdomains.update(subdomains)

    # Method 3: waybackurls for historical subdomains (if available)
    waybackurls_out = ""
    try:
        cmd = ["waybackurls", target]
        result = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        if result.returncode == 0:
            waybackurls_out = result.stdout
        else:
            _append_tool_error(errors, "subdomain_enum", "waybackurls", "tool returned non-zero",
                               returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired as e:
        waybackurls_out = _coerce_str(e.stdout)
        _append_tool_error(errors, "subdomain_enum", "waybackurls", "tool timed out", timed_out=True)
    except Exception as e:
        _append_tool_error(errors, "subdomain_enum", "waybackurls", str(e))
    if waybackurls_out:
        # Extract unique subdomains from URLs
        for line in waybackurls_out.splitlines():
            line = line.strip()
            if line:
                try:
                    parsed = urlparse(line)
                    if parsed.netloc and target in parsed.netloc:
                        all_subdomains.add(parsed.netloc)
                except Exception:
                    continue

    # Method 4: Certificate transparency fallback using requests
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        resp = requests.get(url, timeout=30, verify=False)
        if resp.ok and resp.text:
            try:
                cert_data = resp.json()
                for cert in cert_data:
                    if "name_value" in cert:
                        names = str(cert["name_value"]).splitlines()
                        for name in names:
                            name = name.strip()
                            if name.endswith(target) and "*" not in name:
                                all_subdomains.add(name)
            except Exception as e:
                _append_tool_error(errors, "subdomain_enum", "crtsh", "json parse failed", stdout=None, stderr=str(e))
    except Exception as e:
        _append_tool_error(errors, "subdomain_enum", "crtsh", "request failed", stdout=None, stderr=str(e))

    return sorted(list(all_subdomains))


def _analyze_live_hosts(hosts: List[str], errors: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """Analyze live hosts and identify technologies"""
    live_analysis = {"hosts": [], "technologies": []}

    if not hosts:
        return live_analysis

    # Use httpx for live host detection and tech identification
    httpx_out = ""
    hosts_file = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            for host in hosts:
                f.write(f"{host}\n")
            hosts_file = f.name

        # Use httpx to probe hosts
        cmd = ["httpx", "-l", hosts_file, "-title", "-tech-detect", "-status-code", "-silent", "-json", "-timeout",
               "10"]

        result = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=300)

        if result.returncode == 0:
            httpx_out = result.stdout
        else:
            _append_tool_error(errors, "live_hosts", "httpx", "tool returned non-zero", returncode=result.returncode,
                               stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired as e:
        httpx_out = _coerce_str(e.stdout)
        _append_tool_error(errors, "live_hosts", "httpx", "tool timed out", timed_out=True)
    except Exception as e:
        _append_tool_error(errors, "live_hosts", "httpx", str(e))
    finally:
        if hosts_file:
            os.unlink(hosts_file)

    if httpx_out:
        for line in httpx_out.splitlines():
            line = line.strip()
            if line:
                try:
                    httpx_line_parsed = json.loads(line)
                except Exception:
                    continue
                # Parse httpx output for live hosts and technologies
                url = httpx_line_parsed.get("url")
                if not url:
                    continue
                live_analysis["hosts"].append(url)

                for tech in httpx_line_parsed.get("tech", []) or []:
                    if tech:
                        live_analysis["technologies"].append(str(tech).lower())
    else:
        # Fallback to simple requests checks
        for host in hosts[:LIVE_HOSTS_LIMIT]:  # Limit to first 10 for performance
            for protocol in ["https", "http"]:
                try:
                    test_url = f"{protocol}://{host}"
                    # HEAD first, then GET as fallback (some servers block HEAD)
                    try:
                        r = requests.head(test_url, timeout=5, verify=False, allow_redirects=True)
                    except Exception:
                        r = requests.get(test_url, timeout=5, verify=False, allow_redirects=True)

                    if getattr(r, "status_code", 0):
                        live_analysis["hosts"].append(test_url)

                        server = r.headers.get("Server")
                        if server:
                            live_analysis["technologies"].append(f"Server: {server}")
                        break
                except Exception:
                    continue

    # Deduplicate while preserving order
    live_analysis["hosts"] = list(dict.fromkeys(live_analysis["hosts"]))
    live_analysis["technologies"] = list(dict.fromkeys(live_analysis["technologies"]))

    return live_analysis


def _dedup_list_by_key(input_list: List, key: Optional[Callable[[Any], Any]] = None) -> List:
    if not input_list:
        return []
    seen = set()
    canon = []
    for e in input_list:
        if e is None:
            continue
        if key is not None:
            try:
                k = key(e)
            except Exception:
                continue
        else:
            k = e
        if k is None or k in seen:
            continue
        seen.add(k)
        canon.append(e)
    return canon


def _canonicalize_url(u: str) -> str:
    """Canonicalize URLs for stable dedupe (strip fragments, normalize scheme/host casing)."""
    try:
        p = urlparse(u)
        scheme = (p.scheme or "").lower()
        netloc = (p.netloc or "").lower()
        path = p.path or ""
        params = p.params or ""
        query = p.query or ""
        # Strip fragments entirely
        fragment = ""
        return urlunparse((scheme, netloc, path, params, query, fragment))
    except Exception:
        return u


def _dedup_canonicalized_urls(input_list: List[str]) -> List[str]:
    if not input_list:
        return []
    input_list = [_canonicalize_url(e) for e in filter(bool, map(str.strip, input_list)) if e is not None]
    return _dedup_list_by_key(input_list)


def _deep_web_intelligence(live_hosts: List[str], errors: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """Deep web crawling and parameter discovery"""
    web_intel = {"endpoints": [], "js_files": [], "parameters": []}

    if not live_hosts:
        return web_intel

    # Limit to first 5 hosts for performance
    test_hosts = live_hosts[:LIVE_HOSTS_LIMIT]

    # Method 1: Use katana for crawling (if available)
    katana_out = ""
    hosts_file = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            for host in test_hosts:
                f.write(f"{host}\n")
            hosts_file = f.name

        cmd = ["katana", "-list", hosts_file, "-js-crawl", "-depth", "2", "-silent", "-jsonl"]

        result = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)

        if result.returncode == 0:
            katana_out = result.stdout
        else:
            _append_tool_error(errors, "web_intel", "katana", "tool returned non-zero", returncode=result.returncode,
                               stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired as e:
        katana_out = _coerce_str(e.stdout)
        _append_tool_error(errors, "web_intel", "katana", "tool timed out", timed_out=True)
    except Exception as e:
        _append_tool_error(errors, "web_intel", "katana", str(e))
    finally:
        if hosts_file:
            os.unlink(hosts_file)

    if katana_out:
        for line in katana_out.splitlines():
            try:
                katana_parsed = json.loads(line)
            except Exception:
                continue
            url = katana_parsed.get("request", {}).get("endpoint", "")
            if not url:
                continue
            try:
                parsed = urlparse(url)
            except Exception:
                continue

            ext = parsed.path.lower().split(".")[-1]
            if ext in ["css", "woff", "woff2"]:
                continue

            web_intel["endpoints"].append(url)

            if ".js" in url:
                web_intel["js_files"].append(url)

            # Extract parameters from URLs
            if "?" in url:
                params = parse_qs(parsed.query)
                web_intel["parameters"].extend(list(params.keys()))
    else:
        # Fallback to basic requests-based discovery
        for host in test_hosts:
            try:
                # Get the main page
                resp = requests.get(host, timeout=10, verify=False)
                if resp.ok:
                    html = resp.text

                    # Extract JavaScript files
                    js_pattern = r'src=["\'][^"\']*\.js["\']'
                    js_matches = re.findall(js_pattern, html)
                    for match in js_matches:
                        js_url = match.replace("src=", "").strip("\"'")
                        # Normalize JS URLs
                        js_url = urljoin(host, js_url)
                        web_intel["js_files"].append(js_url)

                    # Extract form parameters
                    form_pattern = r'name=["\']([^"\']*)["\']'
                    form_params = re.findall(form_pattern, html)
                    web_intel["parameters"].extend(form_params)

                    # Extract endpoint patterns
                    link_pattern = r'href=["\']([^"\']*)["\']'
                    links = re.findall(link_pattern, html)
                    for link in links:
                        if not link or link.startswith("javascript:") or link.startswith("mailto:"):
                            continue
                        endpoint = urljoin(host, link)
                        web_intel["endpoints"].append(endpoint)

            except Exception:
                continue

    # Canonicalize + deduplicate while preserving order
    canon_endpoints = _dedup_canonicalized_urls(web_intel.get("endpoints", []))
    web_intel["endpoints"] = canon_endpoints

    canon_js = _dedup_canonicalized_urls(web_intel.get("js_files", []))
    web_intel["js_files"] = canon_js

    # Parameters are case-sensitive in some apps, but normalize obvious whitespace and preserve order
    canon_params = _dedup_list_by_key(list(filter(bool, map(str.strip, web_intel.get("parameters", []) or []))))
    web_intel["parameters"] = canon_params

    return web_intel


def _analyze_attack_surface(results: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze and prioritize the attack surface"""
    intelligence = {
        "attack_surface_size": (
                len(results.get("subdomains", [])) + len(results.get("live_hosts", [])) + len(
            results.get("endpoints", []))
        ),
        "high_value_targets": [],
        "ranked_targets": [],
        "high_value_summary": {"counts_by_type": {}, "counts_by_keyword": {}},
        "technology_risks": [],
        "hidden_services": [],
        "ranked_hidden_services": []
    }

    # Identify high-value targets
    def _add_hv(target_type: str, value: str, keyword: str, field: str) -> None:
        kw = (keyword or "").lower()
        # Heuristic weights for routing/prioritization
        weights = {
            "login": 90,
            "auth": 85,
            "admin": 85,
            "dashboard": 80,
            "panel": 80,
            "api": 75,
            "portal": 70,
            "vpn": 70,
            "database": 70,
            "db": 65,
            "mail": 60,
            "ftp": 60,
            "ssh": 60,
            "secure": 55,
            "internal": 55,
            "staging": 45,
            "dev": 40,
            "test": 35,
        }
        signals_map = {
            "login": ["auth_surface"],
            "auth": ["auth_surface"],
            "admin": ["admin_surface"],
            "dashboard": ["admin_surface"],
            "panel": ["admin_surface"],
            "api": ["api_surface"],
            "portal": ["portal_surface"],
            "vpn": ["network_access"],
            "database": ["data_store"],
            "db": ["data_store"],
            "mail": ["email_service"],
            "ftp": ["file_transfer"],
            "ssh": ["remote_admin"],
            "secure": ["security_boundary"],
            "internal": ["internal_surface"],
            "staging": ["nonprod_surface"],
            "dev": ["nonprod_surface"],
            "test": ["nonprod_surface"],
        }

        score = int(weights.get(kw, 50))
        confidence = 0.7
        if field in ("path", "hostname"):
            confidence = 0.8
        if kw in ("dev", "test", "staging"):
            confidence = 0.6

        intelligence["high_value_targets"].append(
            {
                "type": target_type,
                "value": value,
                "matches": [
                    {
                        "keyword": keyword,
                        "field": field,
                        "reason": "high_value_keyword",
                    }
                ],
                "signals": signals_map.get(kw, ["high_value_keyword"]),
                "score": score,
                "confidence": confidence,
            }
        )

    high_value_keywords = [
        "admin",
        "api",
        "dev",
        "test",
        "staging",
        "internal",
        "vpn",
        "mail",
        "ftp",
        "ssh",
        "database",
        "db",
        "portal",
        "panel",
        "dashboard",
        "login",
        "auth",
        "secure",
    ]

    def _summarize_hv() -> None:
        counts_by_type: Dict[str, int] = {}
        counts_by_keyword: Dict[str, int] = {}
        for item in intelligence.get("high_value_targets", []) or []:
            t = item.get("type")
            if t:
                counts_by_type[t] = counts_by_type.get(t, 0) + 1
            for m in item.get("matches", []) or []:
                k = m.get("keyword")
                if k:
                    counts_by_keyword[k] = counts_by_keyword.get(k, 0) + 1
        intelligence["high_value_summary"] = {
            "counts_by_type": counts_by_type,
            "counts_by_keyword": counts_by_keyword,
        }

    for subdomain in results.get("subdomains", []):
        for keyword in high_value_keywords:
            if keyword in subdomain.lower():
                _add_hv("subdomain", subdomain, keyword, "hostname")
                break

    for endpoint in results.get("endpoints", []):
        e = str(endpoint).strip()
        if not e:
            continue
        try:
            p = urlparse(e)
            host = (p.hostname or "").lower()
            path = (p.path or "").lower()
            query = (p.query or "").lower()
        except Exception:
            host = ""
            path = e.lower()
            query = ""

        for keyword in high_value_keywords:
            if keyword in host:
                _add_hv("endpoint", e, keyword, "hostname")
            elif keyword in path:
                _add_hv("endpoint", e, keyword, "path")
            elif query and keyword in query:
                _add_hv("endpoint", e, keyword, "query")

    # Analyze technology risks with exploitation context
    risky_technologies = {
        "wordpress": "CMS - check /wp-admin, /wp-login.php, xmlrpc.php, plugin vulns",
        "drupal": "CMS - Drupalgeddon vectors, admin/config exposure",
        "joomla": "CMS - /administrator access, component vulns",
        "apache": "Web server - .htaccess bypass, mod_cgi exploits",
        "nginx": "Web server - alias traversal, off-by-slash",
        "php": "Interpreted - LFI/RFI, deserialization, type juggling",
        "mysql": "Database - check port 3306 exposure, SQLi",
        "jenkins": "CI/CD - script console at /script, unauthenticated builds",
        "grafana": "Monitoring - CVE-2021-43798 path traversal, default creds admin:admin",
        "kibana": "Analytics - timelion RCE, prototype pollution",
        "tomcat": "App server - /manager/html default creds, WAR upload",
        "spring": "Framework - Spring4Shell, actuator endpoints",
        "flask": "Framework - debug mode, SSTI in templates",
        "django": "Framework - debug mode info disclosure, admin panel",
    }

    technologies = set(results.get("technologies", []) or [])
    intelligence["technology_risks"] = {
        risky_tech: risk_desc
        for risky_tech, risk_desc in risky_technologies.items()
        if risky_tech in technologies
    }

    # Identify hidden services (non-standard ports, dev/staging environments)
    for host in results.get("live_hosts", []):
        try:
            parsed = urlparse(host)
            hostname = (parsed.hostname or "").lower()
            port = parsed.port

            if any(keyword in hostname for keyword in ["dev", "staging", "test", "internal", "ftp", "ssh", "vpn"]):
                intelligence["hidden_services"].append(
                    {
                        "type": "nonprod_or_internal",
                        "value": host,
                        "hostname": hostname,
                        "reason": "hostname_keyword",
                        "signals": ["nonprod_surface"],
                        "score": 45,
                        "confidence": 0.65,
                    }
                )

            if port and port not in (80, 443):
                intelligence["hidden_services"].append(
                    {
                        "type": "nonstandard_port",
                        "value": host,
                        "hostname": hostname,
                        "port": port,
                        "reason": "explicit_port",
                        "signals": ["alt_port"],
                        "score": 55,
                        "confidence": 0.75,
                    }
                )
        except Exception:
            continue

    # Deduplicate lists to reduce noise
    # Deduplicate high_value_targets (stable, type+value+keyword)
    def key_hv(item):
        t = item.get("type")
        v = item.get("value")
        m0 = (item.get("matches") or [{}])[0]
        k = m0.get("keyword")
        return t, v, k

    deduped_hv = _dedup_list_by_key(intelligence.get("high_value_targets", []), key=key_hv)
    intelligence["high_value_targets"] = deduped_hv
    _summarize_hv()
    # Pre-sort targets for deterministic prioritization
    try:
        intelligence["ranked_targets"] = sorted(
            intelligence.get("high_value_targets", []) or [],
            key=lambda x: (
                -(int(x.get("score") or 0)),
                -(float(x.get("confidence") or 0.0)),
                str(x.get("type") or ""),
                str(x.get("value") or ""),
            ),
        )
    except Exception:
        intelligence["ranked_targets"] = intelligence.get("high_value_targets", []) or []

    intelligence["technology_risks"] = list(dict.fromkeys(intelligence["technology_risks"]))

    # Deduplicate hidden services (stable, type+value+port)
    def key_hs(item):
        t = item.get("type")
        v = item.get("value")
        p = item.get("port")
        return t, v, p

    deduped_hs = _dedup_list_by_key(intelligence.get("hidden_services", []), key=key_hs)
    intelligence["hidden_services"] = deduped_hs

    # Pre-sort a small list for deterministic prioritization
    try:
        ranked = sorted(
            intelligence.get("hidden_services", []) or [],
            key=lambda x: (
                -(int(x.get("score") or 0)),
                -(float(x.get("confidence") or 0.0)),
                str(x.get("type") or ""),
                str(x.get("value") or ""),
            ),
        )
        intelligence["ranked_hidden_services"] = ranked[:HIDDEN_SERVICES_LIMIT]
    except Exception:
        intelligence["ranked_hidden_services"] = (intelligence.get("hidden_services", []) or [])[:HIDDEN_SERVICES_LIMIT]

    return intelligence


def _generate_recon_recommendations(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate agent-optimized next-step directives.

    Returns a list of machine-readable directives an agent can translate into tool invocations.
    """

    intel: Dict[str, Any] = results.get("intelligence", {}) or {}
    meta: Dict[str, Any] = results.get("meta", {}) or {}

    subdomains_n = int(
        meta.get("coverage", {}).get("subdomains_discovered", len(results.get("subdomains", []) or [])) or 0)
    live_hosts_n = int(
        meta.get("coverage", {}).get("live_hosts_discovered", len(results.get("live_hosts", []) or [])) or 0)
    endpoints_n = int(
        meta.get("coverage", {}).get("endpoints_discovered", len(results.get("endpoints", []) or [])) or 0)
    js_n = int(meta.get("coverage", {}).get("js_files_discovered", len(results.get("js_files", []) or [])) or 0)
    params_n = int(meta.get("coverage", {}).get("parameters_discovered", len(results.get("parameters", []) or [])) or 0)

    hv_summary: Dict[str, Any] = intel.get("high_value_summary", {}) or {}
    hv_counts_by_kw: Dict[str, int] = hv_summary.get("counts_by_keyword", {}) or {}

    ranked_targets: List[Dict[str, Any]] = (intel.get("ranked_targets", []) or [])
    ranked_hidden: List[Dict[str, Any]] = (intel.get("ranked_hidden_services", []) or [])

    directives: List[Dict[str, Any]] = []

    def _d(did: str, priority: int, goal: str, capabilities: List[str], selectors: List[Dict[str, Any]] | None = None,
           constraints: Dict[str, Any] | None = None, success_criteria: List[str] | None = None,
           evidence: Dict[str, Any] | None = None) -> Dict[str, Any]:
        return {
            "id": did,
            "priority": int(priority),
            "goal": goal,
            "capabilities": capabilities,
            "selectors": selectors or [],
            "constraints": constraints or {},
            "success_criteria": success_criteria or [],
            "evidence": evidence or {},
        }

    # 1) Coverage expansion when constrained by limits
    limits: Dict[str, Any] = meta.get("limits", {}) or {}
    if live_hosts_n > 0 and endpoints_n < 50:
        directives.append(
            _d(
                "expand_endpoint_coverage",
                2,
                "Expand endpoint discovery coverage to reduce blind spots before vulnerability verification.",
                ["web_crawling", "web_fuzzing", "web_scanning"],
                selectors=[{"from": "live_hosts",
                            "limit": int(limits.get("crawl_hosts", LIVE_HOSTS_LIMIT) or LIVE_HOSTS_LIMIT)}],
                constraints={"depth": 3, "include_js_crawl": True},
                success_criteria=["endpoints_discovered >= 200", "js_files_discovered >= 20"],
                evidence={"live_hosts": live_hosts_n, "endpoints": endpoints_n, "limits": limits},
            )
        )

    # 2) Prioritize highest scoring auth/admin/api surfaces
    if ranked_targets:
        directives.append(
            _d(
                "prioritize_high_value_surfaces",
                1,
                "Focus on highest scoring surfaces (auth/admin/api) for immediate verification and exploit chain discovery.",
                ["web_recon", "proxying", "web_crawling"],
                selectors=[{"from": "intelligence.ranked_targets", "limit": 25}],
                constraints={"sort": "score_desc_confidence_desc"},
                success_criteria=["identify_auth_flows", "map_role_boundaries", "collect_session_tokens"],
                evidence={"high_value_counts_by_keyword": hv_counts_by_kw},
            )
        )

    # 3) Non-standard ports / non-prod surfaces verification
    if ranked_hidden:
        directives.append(
            _d(
                "verify_hidden_services",
                2,
                "Verify exposure and access control of non-standard ports and non-prod/internal surfaces.",
                ["network_recon", "web_recon", "proxying"],
                selectors=[{"from": "intelligence.ranked_hidden_services", "limit": HIDDEN_SERVICES_LIMIT}],
                constraints={"confirm_port_reachability": True, "capture_banner": True},
                success_criteria=["confirm_reachability", "identify_auth_boundary"],
                evidence={"ranked_hidden": len(ranked_hidden)},
            )
        )

    # 4) Parameter-driven testing when parameter surface exists
    if params_n > 0:
        directives.append(
            _d(
                "parameter_driven_testing",
                2,
                "Classify parameters by context and prioritize candidates for injection/XSS/SSRF validation.",
                ["web_recon", "injection_testing", "xss_testing", "ssrf"],
                selectors=[
                    {"from": "parameters", "limit": PARAMETER_LIMIT},
                    {"from": "endpoints", "limit": ENDPOINTS_LIMIT},
                ],
                constraints={"max_candidates": 50, "prefer_high_value_endpoints": True},
                success_criteria=["candidate_list_created", "top_10_validated"],
                evidence={"parameters": params_n},
            )
        )

    # 5) JS analysis when JS footprint exists
    if js_n > 0:
        directives.append(
            _d(
                "js_bundle_analysis",
                3,
                "Analyze JS bundles for hidden routes, API base URLs, and potential secrets/feature flags.",
                ["web_recon", "osint", "web_crawling"],
                selectors=[{"from": "js_files", "limit": 200}],
                constraints={"extract": ["routes", "api_base", "tokens", "keys"]},
                success_criteria=["route_candidates_extracted", "api_hosts_identified"],
                evidence={"js_files": js_n},
            )
        )

    # 6) Tech-driven verification if technologies present
    tech_risks = intel.get("technology_risks", []) or []
    if tech_risks or results.get("technologies", []):
        directives.append(
            _d(
                "tech_version_and_vuln_verification",
                3,
                "Confirm versions/config and run targeted checks for known vulnerability classes implied by detected tech.",
                ["web_scanning", "sast", "exploitation_framework"],
                selectors=[
                    {"from": "technologies", "limit": 200},
                    {"from": "intelligence.technology_risks", "limit": 200},
                ],
                constraints={"prefer_safe_checks": True},
                success_criteria=["versions_confirmed", "at_least_one_vuln_class_verified"],
                evidence={"technologies": len(results.get("technologies", []) or []),
                          "technology_risks": len(tech_risks)},
            )
        )

    # 7) If nothing discovered, instruct agent to broaden enumeration
    if subdomains_n == 0 and live_hosts_n == 0:
        directives.append(
            _d(
                "broaden_enumeration",
                1,
                "Broaden enumeration inputs and retry discovery with alternate sources and permutations.",
                ["osint", "dns_recon", "web_recon"],
                selectors=[],
                constraints={"use_permutations": True, "include_ct": True},
                success_criteria=["subdomains_discovered > 0", "live_hosts_discovered > 0"],
                evidence={"subdomains": subdomains_n, "live_hosts": live_hosts_n},
            )
        )

    directives.sort(key=lambda d: (d.get("priority", 99), d.get("id", "")))
    return directives


# CLI entrypoint for running specialized_recon_orchestrator directly

def main() -> int:
    """CLI entrypoint for running the Specialized Reconnaissance Orchestrator directly."""
    parser = argparse.ArgumentParser(
        description="Run the Specialized Reconnaissance Orchestrator against a target"
    )
    parser.add_argument(
        "target",
        help="Target domain or URL (e.g., example.com or https://example.com)",
    )
    parser.add_argument(
        "--recon-type",
        dest="recon_type",
        default="comprehensive",
        choices=["subdomain", "web", "comprehensive"],
        help="Type of recon to run (default: comprehensive)",
    )

    args = parser.parse_args()
    print(specialized_recon_orchestrator(args.target, recon_type=args.recon_type))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
