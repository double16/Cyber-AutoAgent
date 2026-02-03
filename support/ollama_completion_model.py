#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


def http_json(url: str, method: str = "GET", body: Optional[dict] = None, timeout: int = 10) -> Dict[str, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} for {url}: {msg}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to reach {url}: {e}") from e


_PARAM_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([bBmM])\s*$")


def param_to_billions(param_size: str) -> float:
    """
    Convert Ollama details.parameter_size like '70B' or '400M' into billions (float).
    Unknown/empty -> 0.0
    """
    if not param_size:
        return 0.0
    m = _PARAM_RE.match(param_size)
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = m.group(2).lower()
    if unit == "m":
        return val / 1000.0
    return val


def is_cloud_name(name: str) -> bool:
    return "cloud" in name.lower()


def pick_best_model(host: str, timeout: int = 10, verbose: bool = False) -> Tuple[str, str, float]:
    tags = http_json(f"{host}/api/tags", timeout=timeout)
    models: List[Dict[str, Any]] = tags.get("models", [])

    best_name = ""
    best_param_str = ""
    best_param_b = 0.0

    for m in models:
        name = (m.get("name") or "").strip()
        if not name:
            continue
        if is_cloud_name(name):
            if verbose:
                print(f"skip (cloud name): {name}", file=sys.stderr)
            continue

        try:
            show = http_json(f"{host}/api/show", method="POST", body={"model": name}, timeout=timeout)
        except Exception as e:
            if verbose:
                print(f"skip (show failed): {name}: {e}", file=sys.stderr)
            continue

        caps = show.get("capabilities") or []
        if "completion" not in caps:
            if verbose:
                print(f"skip (no completion capability): {name} caps={caps}", file=sys.stderr)
            continue

        param_str = ((show.get("details") or {}).get("parameter_size")) or ""
        param_b = param_to_billions(param_str)

        if verbose:
            print(f"candidate: {name} param_size={param_str or 'unknown'} (~{param_b}B)", file=sys.stderr)

        if param_b > best_param_b:
            best_name = name
            best_param_str = param_str
            best_param_b = param_b

    if not best_name:
        # Fallback: ensure a known completion-capable local model is present.
        fallback = "llama3.2:3b"
        if verbose:
            print(f"no candidates found; pulling fallback model: {fallback}", file=sys.stderr)

        # Pull can take a while; allow a larger timeout than the normal API calls.
        pull_timeout = max(timeout, 600)
        try:
            http_json(
                f"{host}/api/pull",
                method="POST",
                body={"name": fallback, "stream": False},
                timeout=pull_timeout,
            )
        except Exception as e:
            # If pull fails, still return the fallback name so the caller can decide.
            if verbose:
                print(f"fallback pull failed: {e}", file=sys.stderr)
            return fallback, "", 0.0

        # Re-query model details after pull.
        try:
            show = http_json(f"{host}/api/show", method="POST", body={"model": fallback}, timeout=timeout)
            param_str = ((show.get("details") or {}).get("parameter_size")) or ""
            param_b = param_to_billions(param_str)
        except Exception as e:
            if verbose:
                print(f"fallback show failed: {e}", file=sys.stderr)
            return fallback, "", 0.0

        return fallback, param_str, param_b

    return best_name, best_param_str, best_param_b


def main() -> int:
    default_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    ap = argparse.ArgumentParser(
        description="Select the largest local Ollama model that supports completion (via /api/show capabilities)."
    )
    ap.add_argument("--host", default=default_host, help=f"Ollama host (default: {default_host})")
    ap.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds (default: 10)")
    ap.add_argument("--json", action="store_true", help="Output JSON instead of plain text")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose stderr logging")
    args = ap.parse_args()

    host = args.host.rstrip("/")

    name, param_str, param_b = pick_best_model(host, timeout=args.timeout, verbose=args.verbose)

    if args.json:
        print(json.dumps({"model": name, "parameter_size": param_str or None, "parameter_size_billions": param_b}))
    else:
        print(name)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
