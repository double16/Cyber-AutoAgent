#!/usr/bin/env python3
"""Authentication Chain Analyzer - Intelligent analysis of complex authentication flows"""

import argparse
import json
import os
import re
import subprocess
import tempfile
import urllib3
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

from strands import tool

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _coerce_str(arg: bytes | str | None) -> str:
    if arg is None:
        return ""
    if isinstance(arg, str):
        return arg
    if isinstance(arg, bytes):
        return arg.decode('utf-8', errors='ignore')
    return str(arg)


@tool
def auth_chain_analyzer(target_url: str, auth_type: str = "auto") -> str:
    """
    Map auth flows + identify/validate auth bypass surfaces for a target. Returns JSON ONLY.

    CALL WHEN
    - Auth blocks progress (30x→login/SSO, 401/403 on key pages/APIs), or you need auth-flow mapping.
    - You see signals of session/JWT/OAuth/SAML (Set-Cookie, Bearer/JWT strings, /.well-known/*, jwks, oauth/saml paths).
    - You need structured next steps for bypass verification/exploitation.

    DO NOT CALL
    - If you already have recent auth mapping + bypass validation for this same target, unless new endpoints/flows were found.

    BEHAVIOR NOTES
    - Redirects are NOT auto-followed (30x is evidence).
    - Performs lightweight validation: forced browsing (admin), HTTP method variations, limited header bypass checks.

    ARGS
    - target_url: base URL/domain (scheme optional; https assumed)
    - auth_type: "jwt"|"oauth"|"saml"|"session"|"auto" (use specific type to reduce noise)

    RETURNS (JSON)
    - summary: mechanism/token types, confirmed_exploits count
    - evidence: endpoints/mechanisms/tokens/flow mapping
    - findings[]: observed/confirmed auth bypass or controls + evidence
    - next_steps[]: prioritized, capability-tagged tasks
    - decision: routing hints (best_attack_surface, next_phase)

    HOW TO USE
    - If summary.confirmed_exploits > 0: exploit findings (technique+endpoint) and prove impact.
    - Else: execute next_steps in priority order; use evidence to reproduce/justify.
    - Absence of findings is not proof of security
    """
    if not target_url:
        raise ValueError("target_url is required")
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    if auth_type not in ["jwt", "oauth", "saml", "session", "auto"]:
        auth_type = "auto"
    auth_type = auth_type.lower()

    results = {
        "target": target_url,
        "auth_type": auth_type,
        "auth_endpoints": [],
        "auth_mechanisms": [],
        "tokens_discovered": [],
        "vulnerabilities": [],
        "flow_analysis": {
            "authentication_steps": [],
            "session_management": {},
            "bypass_opportunities": [],
            "privilege_escalation": [],
        },
    }

    report: Dict[str, Any] = {
        "tool": "auth_chain_analyzer",
        "target": target_url,
        "auth_type": auth_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {},
        "evidence": {},
        "findings": [],
        "next_steps": [],
    }

    output = ""

    try:
        # Phase 1: Authentication endpoint discovery
        auth_endpoints = _discover_auth_endpoints(target_url)
        results["auth_endpoints"] = auth_endpoints

        report["evidence"]["auth_endpoints"] = {
            "count_total": len(auth_endpoints),
            "top": auth_endpoints[:10],
        }

        # Phase 2: Authentication mechanism analysis
        auth_mechanisms = _analyze_auth_mechanisms(target_url, auth_endpoints, auth_type)
        results["auth_mechanisms"] = auth_mechanisms

        report["evidence"]["auth_mechanisms"] = {
            "count_total": len(auth_mechanisms),
            "items": auth_mechanisms,
        }

        # Phase 3: Token and session analysis
        token_analysis = _analyze_tokens_and_sessions(target_url, auth_mechanisms)
        results["tokens_discovered"] = token_analysis.get("tokens", [])
        results["flow_analysis"]["session_management"] = token_analysis.get("session_info", {})

        report["evidence"]["tokens_discovered"] = {
            "count_total": len(results.get("tokens_discovered", []) or []),
            "items": results.get("tokens_discovered", []) or [],
        }

        # Phase 4: Authentication flow mapping
        flow_analysis = _map_authentication_flows(target_url, results)
        results["flow_analysis"].update(flow_analysis)

        report["evidence"]["flow_analysis"] = {
            "authentication_steps": {
                "count": len(flow_analysis.get("authentication_steps", []) or []),
                "items": flow_analysis.get("authentication_steps", []) or [],
            },
            "bypass_opportunities": {
                "count": len(flow_analysis.get("bypass_opportunities", []) or []),
                "items": flow_analysis.get("bypass_opportunities", []) or [],
            },
            "privilege_escalation": {
                "count": len(flow_analysis.get("privilege_escalation", []) or []),
                "items": flow_analysis.get("privilege_escalation", []) or [],
            },
        }

        # Phase 5: Advanced bypass testing
        bypass_results = _test_advanced_auth_bypasses(target_url, results)

        # Normalize bypass_results to a list to avoid type/iteration bugs.
        if bypass_results is None:
            bypass_results = []
        elif not isinstance(bypass_results, list):
            bypass_results = [bypass_results]

        # Preserve any previously discovered vulnerabilities; append bypass test results.
        results["vulnerabilities"].extend(bypass_results)

        successful_bypasses = [b for b in bypass_results if isinstance(b, dict) and b.get("successful", False)]

        # Convert bypass results into structured findings for the agent.
        for b in bypass_results:
            if not isinstance(b, dict):
                continue
            report["findings"].append(
                {
                    "id": f"FINDING_{(b.get('technique') or 'UNKNOWN').upper().replace(' ', '_')}_{(b.get('endpoint') or '').strip('/').replace('/', '_') or 'TARGET'}",
                    "status": "confirmed" if b.get("successful") else "observed",
                    "category": "auth_bypass" if b.get("successful") else "auth_control",
                    "severity": "critical" if b.get("successful") else "info",
                    "confidence": 0.9 if b.get("successful") else 0.6,
                    "technique": b.get("technique"),
                    "endpoint": b.get("endpoint"),
                    "method": b.get("method"),
                    "description": b.get("description"),
                    "evidence": {
                        "status_code": b.get("status_code"),
                        "redirect_to": b.get("redirect_to"),
                        "baseline": b.get("baseline"),
                        "header": b.get("header"),
                    },
                }
            )

        # Generate agent-oriented next steps (capability-tagged)
        next_steps = _generate_auth_recommendations(results)
        report["next_steps"] = next_steps

        # High-level summary and routing hints
        mech_types = [m.get("type") for m in (results.get("auth_mechanisms") or []) if
                      isinstance(m, dict) and m.get("type")]
        token_types = [t.get("type") for t in (results.get("tokens_discovered") or []) if
                       isinstance(t, dict) and t.get("type")]
        confirmed = [f for f in report.get("findings", []) if isinstance(f, dict) and f.get("status") == "confirmed"]

        report["summary"] = {
            "auth_endpoints": len(results.get("auth_endpoints", []) or []),
            "mechanisms": sorted(list(set(mech_types))),
            "tokens": sorted(list(set(token_types))),
            "confirmed_exploits": len(confirmed),
            "high_confidence_hypotheses": len(
                [s for s in next_steps if isinstance(s, dict) and (s.get("confidence", 0) or 0) >= 0.7]),
        }

        # Decision hints for downstream agent branching
        primary_auth = "unknown"
        if "Session-based" in report["summary"]["mechanisms"]:
            primary_auth = "session"
        elif "OAuth" in report["summary"]["mechanisms"]:
            primary_auth = "oauth"
        elif "SAML" in report["summary"]["mechanisms"]:
            primary_auth = "saml"
        elif "JWT" in report["summary"]["mechanisms"]:
            primary_auth = "jwt"

        best_surface = "discovery"
        if any(f.get("status") == "confirmed" for f in confirmed):
            best_surface = "exploitation"
        elif (results.get("flow_analysis", {}) or {}).get("bypass_opportunities"):
            best_surface = "bypass_validation"
        elif (results.get("auth_endpoints") or []):
            best_surface = "endpoint_mapping"

        report["decision"] = {
            "primary_auth": primary_auth,
            "best_attack_surface": best_surface,
            "next_phase": "bypass_testing" if best_surface in {"bypass_validation", "exploitation"} else "recon",
        }

        # Output JSON only
        output = json.dumps(report, ensure_ascii=False, indent=2)

    except Exception as e:
        output = json.dumps(
            {
                "tool": "auth_chain_analyzer",
                "target": target_url,
                "auth_type": auth_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e),
            },
            ensure_ascii=False,
            indent=2,
        )

    return output


def _append_unique(list: List, item: Any):
    if item not in list:
        list.append(item)


def _http_request(
    method: str,
    url: str,
    *,
    headers: Dict[str, str] | None = None,
    timeout: float = 10.0,
    stream: bool = False,
    verify_tls: bool = False,
) -> requests.Response | None:
    """Small wrapper around requests.

    - Does not follow redirects (matches curl without -L)
    - Defaults to verify_tls=False (curl -k equivalent)
    - Returns None on network/SSL/timeout errors
    """
    try:
        return requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            stream=stream,
            verify=verify_tls,
        )
    except requests.RequestException:
        return None



def _response_set_cookie_lines(resp: requests.Response) -> List[str]:
    """Return Set-Cookie lines (supports multiple Set-Cookie headers)."""
    lines: List[str] = []

    # urllib3 HTTPHeaderDict supports getlist/get_all for duplicate headers.
    raw_headers = getattr(resp, "raw", None)
    raw_hdrs = getattr(raw_headers, "headers", None)

    if raw_hdrs is not None:
        get_all = getattr(raw_hdrs, "get_all", None)
        if callable(get_all):
            for v in (get_all("Set-Cookie") or []):
                lines.append(f"set-cookie: {v}")
            return lines

        getlist = getattr(raw_hdrs, "getlist", None)
        if callable(getlist):
            for v in (getlist("Set-Cookie") or []):
                lines.append(f"set-cookie: {v}")
            return lines

    # Fallback: requests' normalized headers only preserve the last Set-Cookie value.
    v = resp.headers.get("Set-Cookie")
    if v:
        lines.append(f"set-cookie: {v}")

    return lines


# Wildcard baseline/wildcard detection helpers
def _wildcard_baseline_signature(base_url: str) -> Dict[str, Any]:
    """Create a baseline signature for a URL that is extremely unlikely to exist.

    Some targets respond with the same status/body/headers for unknown paths (wildcard).
    We compare candidate endpoints against this baseline to avoid false positives.
    """
    # Use a stable but very unlikely path; include pid and a random-ish component.
    probe_path = f"/__caa_wildcard_probe_{os.getpid()}_{abs(hash(base_url)) % 10_000_000}__"
    probe_url = base_url.rstrip("/") + probe_path

    sig: Dict[str, Any] = {
        "url": probe_url,
        "path": probe_path,
        "code": None,
        "location": "",
        "ctype": "",
        "clen": None,
        "etag": "",
        "body_prefix": "",
    }

    try:
        # GET is more reliable than HEAD for wildcard detection.
        resp = _http_request("GET", probe_url, timeout=6.0, stream=True)
        if resp is None:
            return sig

        sig["code"] = str(resp.status_code)
        sig["location"] = resp.headers.get("Location", "")
        sig["ctype"] = resp.headers.get("Content-Type", "")

        clen = resp.headers.get("Content-Length")
        if clen is not None:
            try:
                sig["clen"] = int(clen)
            except Exception:
                sig["clen"] = None

        sig["etag"] = resp.headers.get("ETag", "")

        # Read a small prefix to fingerprint wildcard bodies without large downloads.
        try:
            prefix = resp.raw.read(256) if getattr(resp, "raw", None) is not None else resp.content[:256]
            if isinstance(prefix, bytes):
                sig["body_prefix"] = prefix[:256].hex()
            else:
                sig["body_prefix"] = str(prefix)[:256]
        except Exception:
            pass

    except Exception:
        pass

    return sig


def _looks_like_wildcard(candidate: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
    """Heuristic comparison of a candidate endpoint response to a wildcard baseline."""
    if not baseline or baseline.get("code") is None:
        return False

    c_code = str(candidate.get("status", "") or candidate.get("code", "") or "")
    b_code = str(baseline.get("code") or "")
    if not c_code or c_code != b_code:
        return False

    # Prefer strong signals first.
    c_clen = candidate.get("content_length")
    if c_clen is None:
        c_clen = candidate.get("clen")
    b_clen = baseline.get("clen")
    if isinstance(c_clen, str):
        try:
            c_clen = int(c_clen)
        except Exception:
            c_clen = None

    # If both lengths are known and equal, it is a strong wildcard indicator.
    if b_clen is not None and c_clen is not None and b_clen == c_clen:
        return True

    # Compare content-type when available.
    c_ctype = (candidate.get("content_type") or candidate.get("ctype") or "")
    b_ctype = (baseline.get("ctype") or "")
    if c_ctype and b_ctype and c_ctype.split(";")[0].strip().lower() == b_ctype.split(";")[0].strip().lower():
        # If status and content-type match, check location/etag if present.
        c_loc = candidate.get("location") or ""
        b_loc = baseline.get("location") or ""
        if c_loc and b_loc and c_loc == b_loc:
            return True

        c_etag = candidate.get("etag") or ""
        b_etag = baseline.get("etag") or ""
        if c_etag and b_etag and c_etag == b_etag:
            return True

    # Body prefix match is very strong when present.
    c_body = candidate.get("body_prefix") or ""
    b_body = baseline.get("body_prefix") or ""
    if c_body and b_body and c_body == b_body:
        return True

    # Ferox gives word/line counts; use them if present.
    b_words = baseline.get("word_count")
    b_lines = baseline.get("line_count")
    c_words = candidate.get("word_count")
    c_lines = candidate.get("line_count")
    if all(isinstance(x, int) for x in [b_words, c_words, b_lines, c_lines]):
        if b_words == c_words and b_lines == c_lines:
            return True

    return False


def _discover_auth_endpoints(target_url: str) -> List[Dict[str, Any]]:
    """Discover authentication-related endpoints"""
    auth_endpoints = []
    seen_paths: set[str] = set()

    # Modern authentication endpoint wordlist (includes GraphQL, API gateways)
    auth_paths = [
        # Traditional auth
        "/login",
        "/signin",
        "/auth",
        "/authenticate",
        "/sso",
        # OAuth/OIDC
        "/oauth",
        "/oauth2",
        "/oauth/authorize",
        "/oauth/token",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/oidc",
        "/callback",
        # SAML
        "/saml",
        "/saml/metadata",
        "/saml2",
        "/metadata",
        # API authentication
        "/api/auth",
        "/api/login",
        "/api/oauth",
        "/api/token",
        "/api/v1/auth",
        "/api/v2/auth",
        "/v1/auth",
        "/v2/auth",
        # GraphQL
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        # JWT specific
        "/jwt",
        "/token",
        "/refresh",
        "/api/refresh",
        # Admin/privileged
        "/admin",
        "/admin/login",
        "/administrator",
        "/portal",
        "/dashboard",
        "/console",
        # User management
        "/profile",
        "/account",
        "/user",
        "/users",
        "/register",
        "/signup",
        # Password/recovery
        "/reset",
        "/forgot",
        "/password",
        "/recovery",
        # MFA
        "/mfa",
        "/2fa",
        "/otp",
        "/verify",
        # Session
        "/logout",
        "/signout",
        "/session",
    ]

    # Method 1: Direct endpoint probing
    base_url = target_url.rstrip("/")
    # Baseline signature for wildcard responders.
    wildcard_baseline = _wildcard_baseline_signature(base_url)
    for path in auth_paths:
        try:
            test_url = base_url + path
            resp = _http_request("HEAD", test_url, timeout=5.0)
            if resp is not None:
                status_code = str(resp.status_code)

                # Build a lightweight signature for comparison against wildcard baseline.
                cand_sig = {
                    "status": status_code,
                    "location": resp.headers.get("Location", ""),
                    "ctype": resp.headers.get("Content-Type", ""),
                    "clen": resp.headers.get("Content-Length", None),
                    "etag": resp.headers.get("ETag", ""),
                }

                # If candidate looks like the wildcard baseline, ignore it.
                if _looks_like_wildcard(cand_sig, wildcard_baseline):
                    continue

                if status_code in {"200", "302", "401"}:
                    # Determine endpoint type
                    endpoint_type = _classify_auth_endpoint(path, "")

                    norm_path = urlparse(path).path.rstrip("/") or "/"
                    if norm_path in seen_paths:
                        continue
                    seen_paths.add(norm_path)

                    auth_endpoints.append(
                        {
                            "path": norm_path,
                            "full_url": test_url,
                            "status": status_code,
                            "type": endpoint_type,
                        }
                    )
        except Exception:
            continue

    # Method 2: Use feroxbuster for deeper directory discovery (if available)
    feroxbuster_out = ""
    wordlist_path = None
    try:
        # Create a focused auth wordlist
        auth_wordlist = "\n".join(
            [
                "admin",
                "login",
                "auth",
                "oauth",
                "signin",
                "portal",
                "dashboard",
                "user",
                "account",
                "profile",
                "session",
                "token",
                "sso",
                "saml",
            ]
        )

        with tempfile.NamedTemporaryFile(prefix="auth_wordlist_", suffix=".txt", delete=False, mode="w") as f:
            f.write(auth_wordlist)
            wordlist_path = f.name

        cmd = [
            "feroxbuster",
            "-u",
            target_url,
            "-w",
            wordlist_path,
            "-t",
            "20",
            "-C",
            "404",
            "--silent",
            "--json",
            "--no-recursion",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)

        if result.returncode == 0:
            feroxbuster_out = result.stdout
    except subprocess.TimeoutExpired as e:
        feroxbuster_out = _coerce_str(e.stdout)
    except Exception:
        pass
    finally:
        if wordlist_path:
            try:
                os.remove(wordlist_path)
            except Exception:
                pass

    if feroxbuster_out:
        for line in feroxbuster_out.splitlines():
            try:
                parsed = json.loads(line)
                if parsed.get("type", "") != "response":
                    continue
                status_code = str(parsed.get("status", ""))
                if status_code in {"200", "302", "401"}:
                    # Ferox can flag wildcards directly.
                    if parsed.get("wildcard", False) is True:
                        continue

                    url = parsed.get("url", "")
                    if not url:
                        continue
                    norm_path = (urlparse(url).path or "/").rstrip("/") or "/"

                    # Compare against wildcard baseline (status + content-length + headers when available)
                    cand_sig = {
                        "status": status_code,
                        "content_length": parsed.get("content_length"),
                        "word_count": parsed.get("word_count"),
                        "line_count": parsed.get("line_count"),
                        "content_type": (parsed.get("headers", {}) or {}).get("content-type", ""),
                        "etag": (parsed.get("headers", {}) or {}).get("etag", ""),
                        "location": (parsed.get("headers", {}) or {}).get("location", ""),
                    }
                    if _looks_like_wildcard(cand_sig, wildcard_baseline):
                        continue

                    # Avoid duplicates (shared across discovery methods)
                    if norm_path in seen_paths:
                        continue
                    seen_paths.add(norm_path)

                    endpoint_type = _classify_auth_endpoint(norm_path, "")
                    auth_endpoints.append(
                        {"path": norm_path, "full_url": url, "status": status_code, "type": endpoint_type}
                    )
            except Exception:
                continue

    return auth_endpoints


def _classify_auth_endpoint(path: str, headers: str) -> str:
    """Classify authentication endpoint type with modern auth patterns"""
    path_lower = path.lower()

    # GraphQL (check first as it's often API-based too)
    if any(keyword in path_lower for keyword in ["graphql", "/query"]):
        return "GraphQL"

    # OIDC well-known endpoints
    if "/.well-known/openid-configuration" in path_lower:
        return "OAuth"

    # JWKS endpoints are strongly indicative of JWT key material
    if "jwks" in path_lower:
        return "JWT"

    # OAuth/OIDC-related
    if any(keyword in path_lower for keyword in ["oauth", "authorize", "callback", "oidc", "openid"]):
        return "OAuth"

    # SAML-related
    if any(keyword in path_lower for keyword in ["saml", "sso", "metadata"]):
        return "SAML"

    # Multi-factor
    if any(keyword in path_lower for keyword in ["mfa", "2fa", "otp", "verify"]):
        return "Multi-factor"

    # Password recovery
    if any(keyword in path_lower for keyword in ["reset", "forgot", "recovery"]):
        return "Password Recovery"

    # Session-based
    if any(keyword in path_lower for keyword in ["login", "signin", "session", "logout", "signout"]):
        return "Session-based"

    # Token-ish endpoints: don't assume JWT unless we have stronger signals
    if "token" in path_lower or "refresh" in path_lower:
        if "jwt" in path_lower:
            return "JWT"
        if "/oauth" in path_lower or "oauth" in path_lower or "oidc" in path_lower:
            return "OAuth"
        return "API Authentication"

    # API authentication (generic)
    if "/api/" in path_lower and any(keyword in path_lower for keyword in ["auth", "login"]):
        return "API Authentication"

    # Admin/privileged
    if any(keyword in path_lower for keyword in ["admin", "administrator", "portal", "dashboard", "console"]):
        return "Administrative"

    return "Generic Authentication"


def _analyze_auth_mechanisms(target_url: str, auth_endpoints: List[Dict], auth_type: str) -> List[Dict[str, Any]]:
    """Analyze authentication mechanisms in detail"""
    mechanisms = []

    for endpoint in auth_endpoints[:10]:  # Analyze first 10 endpoints
        try:
            # Get the endpoint content
            resp = _http_request("GET", endpoint["full_url"], timeout=10.0)
            if resp is not None:
                content = resp.text or ""

                # If a specific auth_type is requested, skip non-matching endpoint types.
                # Map user-facing auth_type values to internal endpoint classifications.
                type_map = {
                    "jwt": "JWT",
                    "oauth": "OAuth",
                    "saml": "SAML",
                    "session": "Session-based",
                }
                requested = type_map.get(auth_type.lower(), None) if isinstance(auth_type, str) else None
                if requested and endpoint.get("type") != requested:
                    continue

                # Analyze based on endpoint type and content
                if endpoint["type"] == "JWT":
                    jwt_mechanism = _analyze_jwt_mechanism(endpoint, content)
                    if jwt_mechanism:
                        mechanisms.append(jwt_mechanism)

                elif endpoint["type"] == "OAuth":
                    oauth_mechanism = _analyze_oauth_mechanism(endpoint, content)
                    if oauth_mechanism:
                        mechanisms.append(oauth_mechanism)

                elif endpoint["type"] == "SAML":
                    saml_mechanism = _analyze_saml_mechanism(endpoint, content)
                    if saml_mechanism:
                        mechanisms.append(saml_mechanism)

                elif endpoint["type"] == "Session-based":
                    session_mechanism = _analyze_session_mechanism(endpoint, content)
                    if session_mechanism:
                        mechanisms.append(session_mechanism)
        except Exception:
            continue

    # Auto-detect only when requested
    if auth_type == "auto" and not mechanisms:
        # Try to detect mechanisms from main page
        try:
            resp = _http_request("GET", target_url, timeout=10.0)
            if resp is not None:
                content = resp.text or ""

                # Look for authentication indicators
                if "jwt" in content.lower() or "bearer" in content.lower():
                    _append_unique(mechanisms,
                        {
                            "type": "JWT",
                            "description": "JWT tokens detected in application",
                            "location": "Application JavaScript/Headers",
                            "confidence": "medium",
                        }
                    )

                if "oauth" in content.lower() or "client_id" in content.lower():
                    _append_unique(mechanisms,
                        {
                            "type": "OAuth",
                            "description": "OAuth flow indicators detected",
                            "location": "Application content",
                            "confidence": "medium",
                        }
                    )

                if any(keyword in content.lower() for keyword in ["session", "csrf", "xsrf"]):
                    _append_unique(mechanisms,
                        {
                            "type": "Session-based",
                            "description": "Session-based authentication detected",
                            "location": "Form/Cookie analysis",
                            "confidence": "high",
                        }
                    )
        except Exception:
            pass

    return mechanisms


def _analyze_jwt_mechanism(endpoint: Dict, content: str) -> Dict[str, Any]:
    """Analyze JWT authentication mechanism"""
    jwt_info = {
        "type": "JWT",
        "endpoint": endpoint["path"],
        "description": "JSON Web Token authentication",
        "confidence": "medium",
        "properties": {},
    }

    # Look for JWT-specific patterns
    if "jwks" in endpoint["path"].lower():
        jwt_info["description"] = "JWKS endpoint for JWT key verification"
        jwt_info["confidence"] = "high"
        jwt_info["properties"]["jwks_endpoint"] = True

        # Try to parse JWKS content
        try:
            if content.startswith("{"):
                jwks_data = json.loads(content)
                if "keys" in jwks_data:
                    jwt_info["properties"]["key_count"] = len(jwks_data["keys"])
        except Exception:
            pass

    elif "token" in endpoint["path"].lower():
        jwt_info["description"] = "JWT token endpoint"
        jwt_info["properties"]["token_endpoint"] = True

    # Look for JWT patterns in content
    jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    jwt_matches = re.findall(jwt_pattern, content)
    if jwt_matches:
        jwt_info["properties"]["sample_tokens"] = jwt_matches[:2]  # Keep first 2
        jwt_info["confidence"] = "high"

    return jwt_info


def _analyze_oauth_mechanism(endpoint: Dict, content: str) -> Dict[str, Any]:
    """Analyze OAuth authentication mechanism"""
    oauth_info = {
        "type": "OAuth",
        "endpoint": endpoint["path"],
        "description": "OAuth authentication flow",
        "confidence": "medium",
        "properties": {},
    }

    # Look for OAuth-specific patterns
    oauth_params = ["client_id", "redirect_uri", "response_type", "scope", "state"]
    found_params = []

    for param in oauth_params:
        if param in content.lower():
            found_params.append(param)

    if found_params:
        oauth_info["properties"]["oauth_params"] = found_params
        oauth_info["confidence"] = "high"

    # Check for OAuth providers
    oauth_providers = ["google", "facebook", "github", "microsoft", "twitter", "linkedin"]
    found_providers = []

    for provider in oauth_providers:
        if provider in content.lower():
            found_providers.append(provider)

    if found_providers:
        oauth_info["properties"]["providers"] = found_providers

    # Look for OAuth endpoints
    if "authorize" in endpoint["path"].lower():
        oauth_info["description"] = "OAuth authorization endpoint"
    elif "callback" in endpoint["path"].lower():
        oauth_info["description"] = "OAuth callback endpoint"

    return oauth_info


def _analyze_saml_mechanism(endpoint: Dict, content: str) -> Dict[str, Any]:
    """Analyze SAML authentication mechanism"""
    saml_info = {
        "type": "SAML",
        "endpoint": endpoint["path"],
        "description": "SAML SSO authentication",
        "confidence": "medium",
        "properties": {},
    }

    # Look for SAML-specific patterns
    if "metadata" in endpoint["path"].lower():
        saml_info["description"] = "SAML metadata endpoint"
        saml_info["confidence"] = "high"

        # Look for XML content
        if "<" in content and "xmlns" in content:
            saml_info["properties"]["xml_metadata"] = True

    # Look for SAML elements
    saml_elements = ["samlp:", "saml:", "entityid", "assertionconsumerservice"]
    found_elements = []

    for element in saml_elements:
        if element in content.lower():
            found_elements.append(element)

    if found_elements:
        saml_info["properties"]["saml_elements"] = found_elements
        saml_info["confidence"] = "high"

    return saml_info


def _analyze_session_mechanism(endpoint: Dict, content: str) -> Dict[str, Any]:
    """Analyze session-based authentication mechanism"""
    session_info = {
        "type": "Session-based",
        "endpoint": endpoint["path"],
        "description": "Traditional session-based authentication",
        "confidence": "medium",
        "properties": {},
    }

    # Look for form-based authentication
    if "<form" in content.lower():
        session_info["properties"]["form_auth"] = True

        # Look for password fields
        if 'type="password"' in content.lower() or "type='password'" in content.lower():
            session_info["confidence"] = "high"
            session_info["properties"]["password_field"] = True

        # Look for CSRF tokens
        csrf_patterns = ["csrf", "xsrf", "_token"]
        for pattern in csrf_patterns:
            if pattern in content.lower():
                session_info["properties"]["csrf_protection"] = True
                break

    return session_info


def _analyze_tokens_and_sessions(target_url: str, mechanisms: List[Dict]) -> Dict[str, Any]:
    """Analyze tokens and session management"""
    token_analysis = {"tokens": [], "session_info": {}}

    # Test with a simple request to gather session information
    try:
        resp = _http_request("HEAD", target_url, timeout=10.0, stream=True)
        if resp is not None:
            cookie_lines = _response_set_cookie_lines(resp)

            for cookie_line in cookie_lines:
                cookie_info = _analyze_cookie_security(cookie_line)
                if cookie_info:
                    token_analysis["tokens"].append(
                        {
                            "type": "Cookie",
                            "location": "HTTP Header",
                            "name": cookie_info["name"],
                            "security_flags": cookie_info["flags"],
                            "analysis": cookie_info["analysis"],
                        }
                    )

            # Analyze session management
            session_cookies = [
                token
                for token in token_analysis["tokens"]
                if any(
                    keyword in token.get("name", "").lower() for keyword in ["session", "sess", "auth", "token", "jwt"]
                )
            ]

            token_analysis["session_info"] = {
                "session_cookies": len(session_cookies),
                "security_analysis": _analyze_session_security(session_cookies),
            }

    except Exception:
        pass

    # Use jwt_tool if available for JWT analysis
    jwt_mechanisms = [m for m in mechanisms if m["type"] == "JWT"]
    if jwt_mechanisms:
        jwt_tokens = _analyze_jwt_with_tools(target_url, jwt_mechanisms)
        token_analysis["tokens"].extend(jwt_tokens)

    return token_analysis


def _analyze_cookie_security(cookie_line: str) -> Dict[str, Any] | None:
    """Analyze cookie security properties"""
    cookie_line = re.sub(r"^set-cookie:\s*", "", cookie_line, flags=re.I)
    parts = cookie_line.strip().split(";")
    if not parts:
        return None

    cookie_name_value = parts[0].split("=", 1)
    if len(cookie_name_value) != 2:
        return None

    cookie_name = cookie_name_value[0].strip()
    cookie_value = cookie_name_value[1].strip()

    # Analyze security flags
    flags = {"secure": False, "httponly": False, "samesite": None}

    for part in parts[1:]:
        part_lower = part.strip().lower()
        if part_lower == "secure":
            flags["secure"] = True
        elif part_lower == "httponly":
            flags["httponly"] = True
        elif part_lower.startswith("samesite="):
            flags["samesite"] = part_lower.split("=")[1]

    # Security analysis
    analysis = []
    if not flags["secure"]:
        analysis.append("Missing Secure flag - cookie can be sent over HTTP")
    if not flags["httponly"]:
        analysis.append("Missing HttpOnly flag - accessible to JavaScript")
    if not flags["samesite"]:
        analysis.append("Missing SameSite attribute - CSRF risk")
    # Modern browsers require Secure when SameSite=None; also increases session exposure if absent.
    if flags["samesite"] == "none" and not flags["secure"]:
        analysis.append("SameSite=None without Secure - cookie likely rejected by browsers and increases exposure")

    return {
        "name": cookie_name,
        "value": cookie_value[:20] + "..." if len(cookie_value) > 20 else cookie_value,
        "flags": flags,
        "analysis": analysis,
    }


def _analyze_session_security(session_cookies: List[Dict]) -> List[str]:
    """Analyze overall session security"""
    analysis = []

    if not session_cookies:
        analysis.append("No session cookies identified")
        return analysis

    # Check for security flags across all session cookies
    missing_secure = any(not cookie.get("security_flags", {}).get("secure", False) for cookie in session_cookies)
    missing_httponly = any(not cookie.get("security_flags", {}).get("httponly", False) for cookie in session_cookies)

    if missing_secure:
        analysis.append("Some session cookies lack Secure flag")
    if missing_httponly:
        analysis.append("Some session cookies lack HttpOnly flag")

    # Check session cookie naming
    predictable_names = ["session", "sess", "sessionid", "jsessionid"]
    for cookie in session_cookies:
        cookie_name = cookie.get("name", "").lower()
        if cookie_name in predictable_names:
            analysis.append(f"Predictable session cookie name: {cookie_name}")

    return analysis


def _analyze_jwt_with_tools(target_url: str, jwt_mechanisms: List[Dict]) -> List[Dict[str, Any]]:
    """Analyze JWT tokens using jwt_tool if available"""
    jwt_tokens = []
    jwt_tool = None

    # Check if jwt_tool is available
    for command_try in ["jwt-tool", "jwt_tool", "jwt_tool.py"]:
        try:
            result = subprocess.run([command_try, "--help"], capture_output=True, stdin=subprocess.DEVNULL, timeout=10)
            if result.returncode == 0:
                jwt_tool = command_try
        except Exception:
            pass
    if not jwt_tool:
        return jwt_tokens

    # Extract sample tokens from mechanisms
    for mechanism in jwt_mechanisms:
        sample_tokens = mechanism.get("properties", {}).get("sample_tokens", [])

        for token in sample_tokens[:2]:  # Analyze first 2 tokens
            try:
                # Use jwt_tool to analyze the token
                cmd = [jwt_tool, token]
                result = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)

                if result.returncode == 0 and result.stdout:
                    jwt_analysis = _parse_jwt_tool_output(result.stdout)

                    jwt_tokens.append(
                        {
                            "type": "JWT",
                            "location": mechanism["endpoint"],
                            "token_preview": token[:50] + "...",
                            "analysis": jwt_analysis,
                        }
                    )

            except Exception:
                continue

    return jwt_tokens


def _parse_jwt_tool_output(output: str) -> Dict[str, Any]:
    """Parse jwt_tool output for key information.

====================
Decoded Token Values:
=====================

Token header values:
[+] typ = "JWT"
[+] alg = "HS256"

Token payload values:
[+] login = "ticarpi"

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
    """
    analysis = {"algorithm": "unknown", "vulnerabilities": [], "claims": {}}

    lines = output.split("\n")

    for line in lines:
        line_lower = line.lower()

        # Extract algorithm
        alg_match = re.search(r'alg\s*=\s*"([^"]*)"', line, re.IGNORECASE)
        if alg_match:
            analysis["algorithm"] = alg_match.group(1)

        # Look for vulnerability indicators
        if any(vuln in line_lower for vuln in ["vulnerability", "weak", "none", "algorithm"]):
            analysis["vulnerabilities"].append(line.strip())

        # Extract key claims
        for claim in ["iss", "sub", "aud", "exp", "iat"]:
            claim_match = re.search(f'{claim}\\s*=\\s*"?([^",}}]*)"?', line)
            if claim_match:
                analysis["claims"][claim] = claim_match.group(1)

    return analysis


def _map_authentication_flows(target_url: str, results: Dict) -> Dict[str, Any]:
    """Map complete authentication flows and identify vulnerabilities"""
    flow_analysis = {"authentication_steps": [], "bypass_opportunities": [], "privilege_escalation": []}

    # Map authentication steps based on discovered mechanisms
    for mechanism in results.get("auth_mechanisms", []):
        steps = _generate_auth_steps(mechanism)
        flow_analysis["authentication_steps"].extend(steps)

    # Identify bypass opportunities
    bypass_opportunities = []

    # Check for weak session management
    session_info = results.get("flow_analysis", {}).get("session_management", {})
    if session_info.get("security_analysis"):
        for issue in session_info["security_analysis"]:
            if "secure flag" in issue.lower():
                _append_unique(bypass_opportunities,
                    {
                        "type": "Session Hijacking",
                        "description": "Session cookies without Secure flag can be intercepted",
                        "technique": "Man-in-the-middle attack",
                    }
                )
            elif "httponly flag" in issue.lower():
                _append_unique(bypass_opportunities,
                    {
                        "type": "XSS to Session Theft",
                        "description": "Session cookies accessible to JavaScript",
                        "technique": "Cross-site scripting",
                    }
                )

    # Check for JWT vulnerabilities
    jwt_tokens = [token for token in results.get("tokens_discovered", []) if token.get("type") == "JWT"]
    for token in jwt_tokens:
        jwt_analysis = token.get("analysis", {})
        if "none" in jwt_analysis.get("algorithm", "").lower():
            _append_unique(bypass_opportunities,
                {
                    "type": "JWT None Algorithm",
                    "description": "JWT accepts 'none' algorithm - signature bypass possible",
                    "technique": "JWT none algorithm attack",
                }
            )

        if jwt_analysis.get("vulnerabilities"):
            for vuln in jwt_analysis["vulnerabilities"]:
                _append_unique(bypass_opportunities,
                    {"type": "JWT Vulnerability", "description": vuln, "technique": "JWT exploitation"}
                )

    flow_analysis["bypass_opportunities"] = bypass_opportunities

    # Identify privilege escalation opportunities
    admin_endpoints = [ep for ep in results.get("auth_endpoints", []) if ep.get("type") == "Administrative"]

    for endpoint in admin_endpoints:
        flow_analysis["privilege_escalation"].append(
            {
                "type": "Administrative Access",
                "endpoint": endpoint["path"],
                "description": "Administrative endpoint may allow privilege escalation",
            }
        )

    return flow_analysis


def _generate_auth_steps(mechanism: Dict) -> List[Dict[str, Any]]:
    """Generate authentication flow steps for a mechanism"""
    steps = []

    mech_type = mechanism.get("type", "")

    if mech_type == "Session-based":
        steps = [
            {"step": 1, "action": "GET login form", "description": "Retrieve login form with CSRF token"},
            {"step": 2, "action": "POST credentials", "description": "Submit username/password with CSRF token"},
            {
                "step": 3,
                "action": "Receive session cookie",
                "description": "Server sets session cookie on successful auth",
            },
            {
                "step": 4,
                "action": "Access protected resources",
                "description": "Use session cookie for subsequent requests",
            },
        ]

    elif mech_type == "JWT":
        steps = [
            {
                "step": 1,
                "action": "POST credentials to token endpoint",
                "description": "Submit credentials to obtain JWT",
            },
            {"step": 2, "action": "Receive JWT token", "description": "Server returns signed JWT token"},
            {"step": 3, "action": "Include JWT in requests", "description": "Send JWT in Authorization header"},
            {"step": 4, "action": "Server validates JWT", "description": "Server verifies JWT signature and claims"},
        ]

    elif mech_type == "OAuth":
        steps = [
            {
                "step": 1,
                "action": "Redirect to authorization server",
                "description": "User redirected to OAuth provider",
            },
            {
                "step": 2,
                "action": "User authorizes application",
                "description": "User grants permissions to application",
            },
            {
                "step": 3,
                "action": "Receive authorization code",
                "description": "OAuth provider returns authorization code",
            },
            {
                "step": 4,
                "action": "Exchange code for token",
                "description": "Application exchanges code for access token",
            },
            {"step": 5, "action": "Use access token", "description": "Include access token in API requests"},
        ]

    return steps


def _test_advanced_auth_bypasses(target_url: str, results: Dict) -> List[Dict[str, Any]]:
    """Test advanced authentication bypass techniques"""
    bypass_results = []

    # Test 1: Direct endpoint access (forced browsing)
    admin_endpoints = [ep for ep in results.get("auth_endpoints", []) if ep.get("type") == "Administrative"]

    for endpoint in admin_endpoints:
        try:
            resp = _http_request("GET", endpoint["full_url"], timeout=10.0)
            if resp is not None:
                status_code = str(resp.status_code)
                location = resp.headers.get("Location", "")

                # Classify
                if status_code == "200":
                    bypass_results.append(
                        {
                            "technique": "Forced Browsing",
                            "endpoint": endpoint["path"],
                            "successful": True,
                            "description": "Administrative endpoint accessible without authentication",
                            "status_code": status_code,
                        }
                    )
                elif status_code and status_code.startswith("3") and location:
                    loc_lower = location.lower()
                    # Heuristic: redirects to login/SSO pages are typically a sign of protection.
                    if any(k in loc_lower for k in ["login", "signin", "sso", "oauth", "saml", "auth"]):
                        bypass_results.append(
                            {
                                "technique": "Forced Browsing",
                                "endpoint": endpoint["path"],
                                "successful": False,
                                "description": "Endpoint redirects to authentication (likely protected)",
                                "status_code": status_code,
                                "redirect_to": location,
                            }
                        )
                    else:
                        bypass_results.append(
                            {
                                "technique": "Forced Browsing",
                                "endpoint": endpoint["path"],
                                "successful": False,
                                "description": "Endpoint redirects (review redirect target)",
                                "status_code": status_code,
                                "redirect_to": location,
                            }
                        )
                else:
                    bypass_results.append(
                        {
                            "technique": "Forced Browsing",
                            "endpoint": endpoint["path"],
                            "successful": False,
                            "description": "Endpoint returned non-200 response (likely protected)",
                            "status_code": status_code or "unknown",
                        }
                    )
        except Exception:
            continue

    # Test 2: HTTP method bypass
    # Focus on likely protected resources (admin/privileged + dashboards), not login/token endpoints.
    protected_endpoints = [
        ep
        for ep in results.get("auth_endpoints", [])
        if ep.get("type") in {"Administrative"} or any(k in (ep.get("path") or "").lower() for k in ["/admin", "dashboard", "portal", "console"])
    ]

    for endpoint in protected_endpoints:
        methods = ["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"]  # skip: DELETE

        # Baseline GET to understand whether this endpoint is already public or redirects to auth.
        baseline = {"code": "", "location": "", "ctype": "", "clen": "", "authy": False}
        try:
            base_resp = _http_request("GET", endpoint["full_url"], timeout=8.0)
            if base_resp is not None:
                baseline["code"] = str(base_resp.status_code)
                baseline["location"] = base_resp.headers.get("Location", "")
                baseline["ctype"] = base_resp.headers.get("Content-Type", "")
                baseline["clen"] = base_resp.headers.get("Content-Length", "")

                loc_lower = (baseline["location"] or "").lower()
                baseline["authy"] = (
                    (baseline["code"].startswith("3") and any(k in loc_lower for k in ["login", "signin", "sso", "oauth", "saml", "auth"]))
                    or baseline["code"] in {"401", "403"}
                )
        except Exception:
            pass

        for method in methods:
            if method == "GET":
                continue

            try:
                resp = _http_request(method, endpoint["full_url"], timeout=8.0)
                if resp is None:
                    continue

                status_code = str(resp.status_code)
                location = resp.headers.get("Location", "")
                ctype = resp.headers.get("Content-Type", "")
                clen = resp.headers.get("Content-Length", "")

                # Heuristics: only call it a bypass when the non-GET meaningfully changes auth gating.
                #
                # Count as bypass if:
                #   - GET looks protected (401/403 or redirect to auth),
                #   - and non-GET is 200 (or 204), and
                #   - non-GET is NOT redirecting to auth,
                #   - and headers suggest a different response than the login redirect baseline.
                loc_lower = (location or "").lower()
                method_authy = (
                    (status_code.startswith("3") and any(k in loc_lower for k in ["login", "signin", "sso", "oauth", "saml", "auth"]))
                    or status_code in {"401", "403"}
                )

                # If baseline is already public, don't call this a bypass.
                if baseline["code"] == "200" and not baseline["authy"]:
                    continue

                # If baseline indicates protection but method returns success without authy redirect, it's suspicious.
                if baseline["authy"] and status_code in {"200", "204"} and not method_authy:
                    # Extra guard: if non-GET looks identical to baseline redirect/login-ish headers, skip.
                    # (We can't see body, so use coarse header diffs.)
                    header_changed = (
                        (baseline.get("location") != location)
                        or (baseline.get("ctype") != ctype)
                        or (baseline.get("clen") != clen)
                    )
                    if not header_changed:
                        continue

                    bypass_results.append(
                        {
                            "technique": "HTTP Method Bypass",
                            "endpoint": endpoint["path"],
                            "method": method,
                            "successful": True,
                            "description": f"Endpoint appears protected via GET but accessible via {method}",
                            "status_code": status_code,
                            "baseline": {
                                "get_code": baseline.get("code"),
                                "get_location": baseline.get("location"),
                            },
                        }
                    )
                    break  # Found bypass, no need to test other methods

            except Exception:
                continue

    # Test 3: Parameter pollution and header manipulation
    # This is a simplified test - in practice would be more comprehensive
    if results.get("auth_endpoints"):
        # Prefer an administrative endpoint for bypass header testing when available.
        admin_eps = [ep for ep in results.get("auth_endpoints", []) if ep.get("type") == "Administrative"]
        test_endpoint = (admin_eps[0] if admin_eps else results["auth_endpoints"][0])["full_url"]

        # Test with common bypass headers
        bypass_headers = [
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Remote-Addr", "127.0.0.1"),
        ]

        # Baseline request (no special headers)
        baseline = {"code": "", "location": "", "authy": False}
        try:
            base_resp = _http_request("GET", test_endpoint, timeout=8.0)
            if base_resp is not None:
                baseline["code"] = str(base_resp.status_code)
                baseline["location"] = base_resp.headers.get("Location", "")
                loc_lower = (baseline["location"] or "").lower()
                baseline["authy"] = (
                    (baseline["code"].startswith("3") and any(k in loc_lower for k in ["login", "signin", "sso", "oauth", "saml", "auth"]))
                    or baseline["code"] in {"401", "403"}
                )
        except Exception:
            pass

        for header_name, header_value in bypass_headers[:2]:  # Test first 2 headers
            try:
                resp = _http_request("GET", test_endpoint, headers={header_name: header_value}, timeout=8.0)
                if resp is None:
                    continue

                status_code = str(resp.status_code)
                location = resp.headers.get("Location", "")

                loc_lower = (location or "").lower()
                authy = (
                    (status_code.startswith("3") and any(k in loc_lower for k in ["login", "signin", "sso", "oauth", "saml", "auth"]))
                    or status_code in {"401", "403"}
                )

                # Only consider it a bypass if baseline looks protected but header request succeeds.
                if baseline.get("authy") and status_code == "200" and not authy:
                    bypass_results.append(
                        {
                            "technique": "Header Manipulation",
                            "header": f"{header_name}: {header_value}",
                            "successful": True,
                            "description": "Endpoint appears protected normally but accessible with header bypass",
                            "status_code": status_code,
                            "baseline": {
                                "code": baseline.get("code"),
                                "location": baseline.get("location"),
                            },
                        }
                    )
                    break  # Found bypass

            except Exception:
                continue

    return bypass_results


def _generate_auth_recommendations(results: Dict) -> List[Dict[str, Any]]:
    """Generate agent next-steps (structured tasks) to drive discovery, verification, and exploitation.

    Output is designed for machine consumption:
      - priority: integer (1 = highest)
      - capabilities: list[str] (must match runtime tool capability mapping)
      - goal/rationale/success_criteria/artifacts: concise execution guidance
      - confidence: float 0..1
    """

    steps: List[Dict[str, Any]] = []

    target = results.get("target", "")
    endpoints = results.get("auth_endpoints", []) or []
    mechanisms = results.get("auth_mechanisms", []) or []
    tokens = results.get("tokens_discovered", []) or []
    flow = results.get("flow_analysis", {}) or {}

    bypass_opps = flow.get("bypass_opportunities", []) or []
    priv_esc = flow.get("privilege_escalation", []) or []
    vulns = results.get("vulnerabilities", []) or []

    successful = [v for v in vulns if isinstance(v, dict) and v.get("successful", False)]

    def _add(step: Dict[str, Any]):
        # Normalize fields
        step.setdefault("confidence", 0.6)
        step.setdefault("capabilities", [])
        step.setdefault("inputs", {})
        step.setdefault("success_criteria", [])
        step.setdefault("artifacts", [])
        step.setdefault("tags", [])
        steps.append(step)

    # 0) If confirmed bypass exists, prioritize exploitation expansion.
    if successful:
        for i, v in enumerate(successful[:3], 1):
            tech = v.get("technique") or v.get("type") or "bypass"
            ep = v.get("endpoint") or v.get("path") or ""
            _add(
                {
                    "id": f"TASK_EXPLOIT_CONFIRMED_{i}",
                    "priority": 1,
                    "capabilities": ["http_client", "web_recon", "priv_esc"],
                    "goal": f"Exploit confirmed bypass '{tech}'{(' on ' + ep) if ep else ''} and expand access.",
                    "rationale": "A confirmed bypass is the highest-leverage pivot: expand reachable functions and prove impact.",
                    "inputs": {"endpoint": ep or None, "technique": tech},
                    "success_criteria": [
                        "Capture request/response evidence demonstrating access without intended auth",
                        "Enumerate additional protected actions reachable under the bypass context",
                        "Demonstrate privilege impact (admin-only page/action or sensitive object access)",
                    ],
                    "artifacts": ["raw_http", "status_location_matrix", "impact_proof"],
                    "confidence": 0.9,
                    "tags": ["confirmed", "exploitation"],
                }
            )

        _add(
            {
                "id": "TASK_POST_BYPASS_IDOR_PIVOT",
                "priority": 2,
                "capabilities": ["web_recon", "http_client", "priv_esc"],
                "goal": "After bypass, attempt IDOR-style pivots and privilege proof.",
                "rationale": "Bypass contexts often enable lateral access to other users' objects or admin functions.",
                "inputs": {},
                "success_criteria": [
                    "Identify object identifiers used in responses",
                    "Swap identifiers to access other users' objects",
                    "Record differential evidence (user-specific content/IDs)",
                ],
                "artifacts": ["idor_matrix", "raw_http"],
                "confidence": 0.8,
                "tags": ["priv_esc", "idor"],
            }
        )

    # 1) Map auth entrypoints and redirect chains (always useful early).
    if endpoints:
        candidates = []
        for ep in endpoints:
            p = ep.get("path")
            if p and any(k in (p.lower()) for k in
                         ["login", "signin", "oauth", "saml", "callback", "openid", "token", "jwks", "graphql"]):
                candidates.append(p)
        candidates = candidates[:10]

        _add(
            {
                "id": "TASK_MAP_AUTH_ENTRYPOINTS",
                "priority": 3,
                "capabilities": ["web_recon", "http_client", "proxying"],
                "goal": "Map primary auth entrypoints and redirect chains (no auto-follow).",
                "rationale": "Redirect hops and parameters reveal OAuth/SAML/OIDC mechanics and bypass surfaces.",
                "inputs": {"candidate_paths": candidates, "target": target},
                "success_criteria": [
                    "Record full 30x redirect chains and parameters",
                    "Extract state/nonce/redirect_uri/RelayState when present",
                    "Identify IdP domains and token endpoints",
                ],
                "artifacts": ["redirect_chain", "param_capture", "raw_http"],
                "confidence": 0.75,
                "tags": ["recon", "auth_flow"],
            }
        )

    # 2) Validate administrative endpoints for authz bypass.
    admin_eps = [ep for ep in endpoints if ep.get("type") == "Administrative"]
    if admin_eps:
        _add(
            {
                "id": "TASK_ADMIN_ENDPOINT_AUTHZ_MATRIX",
                "priority": 4,
                "capabilities": ["http_client", "web_recon", "web_fuzzing"],
                "goal": "Build an authz matrix for admin endpoints (unauth vs low-priv vs header/method variations).",
                "rationale": "Admin endpoints are high impact; authz matrices quickly expose forced browsing and method/header bypasses.",
                "inputs": {"admin_paths": [ep.get("path") for ep in admin_eps[:10]]},
                "success_criteria": [
                    "For each endpoint, record unauth status/Location/body markers",
                    "Test method and header variations and record deltas",
                    "Flag any 200/204 without auth redirect as exploitable candidates",
                ],
                "artifacts": ["authz_matrix", "raw_http"],
                "confidence": 0.7,
                "tags": ["authz", "forced_browsing"],
            }
        )

    # 3) Session/cookie exploitation paths (only if cookies exist or session issues flagged).
    session_info = flow.get("session_management", {}) or {}
    sess_analysis = session_info.get("security_analysis") or []
    cookie_tokens = [t for t in tokens if isinstance(t, dict) and t.get("type") == "Cookie"]
    if cookie_tokens or (session_info.get("session_cookies", 0) > 0 and sess_analysis):
        _add(
            {
                "id": "TASK_SESSION_REPLAY_AND_FIXATION",
                "priority": 5,
                "capabilities": ["http_client", "proxying", "traffic_capture"],
                "goal": "Attempt session replay and session fixation verification.",
                "rationale": "Cookie flag weaknesses are only meaningful if replay/fixation produces access or persistence.",
                "inputs": {"cookie_names": [t.get("name") for t in cookie_tokens if t.get("name")][:10]},
                "success_criteria": [
                    "Replay captured session cookie from a separate client and confirm identity/role persistence",
                    "Attempt fixation (set cookie pre-auth, authenticate, reuse pre-auth cookie) and verify session binding",
                ],
                "artifacts": ["raw_http", "session_replay_proof"],
                "confidence": 0.7,
                "tags": ["session", "verification"],
            }
        )

    # 4) JWT exploitation paths
    jwt_tokens = [t for t in tokens if isinstance(t, dict) and t.get("type") == "JWT"]
    jwt_mechs = [m for m in mechanisms if isinstance(m, dict) and m.get("type") == "JWT"]
    if jwt_tokens or jwt_mechs:
        _add(
            {
                "id": "TASK_JWT_CLAIM_TAMPER_VERIFY",
                "priority": 6,
                "capabilities": ["jwt", "crypto", "http_client"],
                "goal": "Decode JWTs, tamper privilege claims, and verify acceptance.",
                "rationale": "JWT validation flaws enable privilege escalation when modified tokens are accepted.",
                "inputs": {
                    "token_previews": [t.get("token_preview") for t in jwt_tokens if t.get("token_preview")][:5]},
                "success_criteria": [
                    "Produce a modified token that is accepted by the server",
                    "Demonstrate privilege change or access to protected endpoints",
                ],
                "artifacts": ["token_variants", "raw_http", "impact_proof"],
                "confidence": 0.7,
                "tags": ["jwt", "exploitation"],
            }
        )

    # 5) OAuth/OIDC exploitation paths
    oauth_mechs = [m for m in mechanisms if isinstance(m, dict) and m.get("type") == "OAuth"]
    if oauth_mechs:
        _add(
            {
                "id": "TASK_OAUTH_REDIRECT_AND_STATE_TESTS",
                "priority": 7,
                "capabilities": ["web_recon", "http_client", "web_fuzzing"],
                "goal": "Test OAuth/OIDC redirect_uri and state/nonce enforcement; verify token/code binding failures.",
                "rationale": "Weak redirect/state validation can enable account takeover or token substitution.",
                "inputs": {"oauth_endpoints": [m.get("endpoint") for m in oauth_mechs if m.get("endpoint")][:5]},
                "success_criteria": [
                    "Obtain an auth code/token delivered to an attacker-controlled redirect or session",
                    "Confirm improper state/nonce handling (missing/reused/guessable)",
                ],
                "artifacts": ["oauth_request_samples", "raw_http", "impact_proof"],
                "confidence": 0.65,
                "tags": ["oauth", "verification"],
            }
        )

    # 6) SAML exploitation paths
    saml_mechs = [m for m in mechanisms if isinstance(m, dict) and m.get("type") == "SAML"]
    if saml_mechs:
        _add(
            {
                "id": "TASK_SAML_ASSERTION_VALIDATION_TESTS",
                "priority": 8,
                "capabilities": ["http_client", "web_recon"],
                "goal": "Collect SAML messages and test assertion validation weaknesses.",
                "rationale": "SAML validation errors can allow role/attribute escalation.",
                "inputs": {"saml_endpoints": [m.get("endpoint") for m in saml_mechs if m.get("endpoint")][:5]},
                "success_criteria": [
                    "Capture SAMLResponse/RelayState and identify signed elements",
                    "Verify whether modified attributes/roles are accepted",
                ],
                "artifacts": ["saml_samples", "impact_proof"],
                "confidence": 0.6,
                "tags": ["saml", "verification"],
            }
        )

    # 7) Surface bypass hypotheses as explicit verify tasks
    if bypass_opps:
        for i, opp in enumerate([o for o in bypass_opps if isinstance(o, dict)][:5], 1):
            _add(
                {
                    "id": f"TASK_VERIFY_BYPASS_HYPOTHESIS_{i}",
                    "priority": 9,
                    "capabilities": ["http_client", "web_recon"],
                    "goal": f"Verify bypass hypothesis: {opp.get('type', 'Bypass')}",
                    "rationale": opp.get("description", ""),
                    "inputs": {"technique": opp.get("technique"), "type": opp.get("type")},
                    "success_criteria": [
                        "Reproduce with controlled requests",
                        "Demonstrate access delta vs baseline unauth behavior",
                    ],
                    "artifacts": ["raw_http", "delta_evidence"],
                    "confidence": 0.65,
                    "tags": ["hypothesis", "bypass"],
                }
            )

    # 8) Priv-esc vectors as targeted validation
    if priv_esc:
        eps = [pe.get("endpoint") for pe in priv_esc if isinstance(pe, dict) and pe.get("endpoint")][:10]
        if eps:
            _add(
                {
                    "id": "TASK_PRIV_ESC_TARGETED_VALIDATION",
                    "priority": 10,
                    "capabilities": ["priv_esc", "http_client", "web_recon"],
                    "goal": "Targeted privilege escalation validation against identified endpoints.",
                    "rationale": "Privilege escalation is validated by proving access to admin-only functions or cross-role actions.",
                    "inputs": {"endpoints": eps},
                    "success_criteria": [
                        "Access admin-only endpoint/action without intended privilege",
                        "Capture evidence showing role boundary broken",
                    ],
                    "artifacts": ["raw_http", "impact_proof"],
                    "confidence": 0.6,
                    "tags": ["priv_esc", "verification"],
                }
            )

    # 9) If no signal at all, broaden discovery
    if not steps:
        _add(
            {
                "id": "TASK_BROADEN_DISCOVERY",
                "priority": 1,
                "capabilities": ["web_crawling", "web_recon", "web_fuzzing", "http_client"],
                "goal": "Broaden discovery for auth surfaces and protected resources.",
                "rationale": "Low signal indicates insufficient coverage; expand crawl + fuzzing to uncover auth gates and parameters.",
                "inputs": {"target": target},
                "success_criteria": [
                    "Identify login/SSO entrypoints and protected endpoints",
                    "Collect cookies/headers/tokens used for auth",
                ],
                "artifacts": ["endpoint_inventory", "raw_http"],
                "confidence": 0.6,
                "tags": ["recon"],
            }
        )

    # De-duplicate by id while preserving order; sort by priority then insertion
    seen_ids: set[str] = set()
    uniq: List[Dict[str, Any]] = []
    for s in steps:
        sid = s.get("id")
        if not sid or sid in seen_ids:
            continue
        seen_ids.add(sid)
        uniq.append(s)

    try:
        uniq.sort(key=lambda x: int(x.get("priority", 999)))
    except Exception:
        pass

    return uniq


# CLI entrypoint for running auth_chain_analyzer directly

def main() -> int:
    """CLI entrypoint for running the Authentication Chain Analyzer directly."""
    parser = argparse.ArgumentParser(
        description="Run the Authentication Chain Analyzer against a target URL"
    )
    parser.add_argument(
        "target_url",
        help="Target URL (with or without scheme). Example: https://example.com",
    )
    parser.add_argument(
        "--auth-type",
        dest="auth_type",
        default="auto",
        choices=["jwt", "oauth", "saml", "session", "auto"],
        help="Authentication type to focus on (default: auto)",
    )

    args = parser.parse_args()
    print(auth_chain_analyzer(args.target_url, auth_type=args.auth_type))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
