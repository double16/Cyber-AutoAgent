#!/usr/bin/env python3
"""XBOW benchmark driver for cyber-autoagent.

Layout assumptions:
  XBOW_ROOT/
    benchmarks/
      XBEN-001-24/
        benchmark.json
        docker-compose.yml

Possible git repos:
    git clone --depth=1 https://github.com/double16/validation-benchmarks.git
    git clone --depth=1 https://github.com/schniggie/validation-benchmarks.git
    git clone --depth=1 https://github.com/xbow-engineering/validation-benchmarks.git
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Literal


def _run(
    argv: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = False,
    capture: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """Run a subprocess with consistent defaults."""
    return subprocess.run(
        list(argv),
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        check=check,
        capture_output=capture,
        text=text,
    )


def _get_env(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return v if v is not None and v != "" else default


def _print_err(msg: str) -> None:
    sys.stderr.write(msg + "\n")


def ensure_benchmarks_dir(xbow_root: Path) -> None:
    if not (xbow_root / "benchmarks").is_dir():
        _print_err(
            f"[!] benchmarks directory not found at: {xbow_root / 'benchmarks'}\n"
            "    git clone --depth=1 https://github.com/schniggie/validation-benchmarks.git"
        )
        raise SystemExit(1)


def _git_rev_parse_head() -> str:
    cp = _run(["git", "rev-parse", "HEAD"], capture=True)
    if cp.returncode != 0:
        return "unknown"
    return (cp.stdout or "").strip() or "unknown"


def _docker_exec_env(container: str, varname: str) -> str:
    cp = _run(["docker", "exec", container, "/bin/bash", "-c", f"echo ${varname}"], capture=True)
    if cp.returncode != 0:
        return ""
    return (cp.stdout or "").strip()


@lru_cache
def _read_benchmark_json(xbow_root: Path, bench_id: str) -> Dict[str, Any]:
    bench_json = xbow_root / "benchmarks" / bench_id / "benchmark.json"
    if not bench_json.is_file():
        _print_err(f"[!] benchmark.json not found for {bench_id} at {bench_json}")
        raise FileNotFoundError(str(bench_json))
    with bench_json.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_description(xbow_root: Path, bench_id: str) -> str:
    try:
        data = _read_benchmark_json(xbow_root, bench_id)
    except FileNotFoundError:
        return ""
    desc = data.get("description")
    return desc if isinstance(desc, str) else ""


def get_tags_list(xbow_root: Path, bench_id: str) -> List[str]:
    try:
        data = _read_benchmark_json(xbow_root, bench_id)
    except FileNotFoundError:
        return []
    tags = data.get("tags")
    if isinstance(tags, list):
        out: List[str] = []
        for t in tags:
            if isinstance(t, str) and t.strip():
                out.append(t.strip())
        return out
    return []


def get_tags_csv(xbow_root: Path, bench_id: str) -> str:
    return ", ".join(get_tags_list(xbow_root, bench_id))


def bench_has_tag(xbow_root: Path, bench_id: str, tag: str) -> bool:
    if not tag:
        return False
    tags = get_tags_list(xbow_root, bench_id)
    return tag in tags


def get_flag(bench_id: str) -> str:
    if "FLAG" in os.environ:
        return os.environ["FLAG"]
    h = hashlib.sha256(f"caa_{bench_id}".encode("utf-8")).hexdigest()
    return h


def list_benchmarks(xbow_root: Path) -> None:
    ensure_benchmarks_dir(xbow_root)
    benches_dir = xbow_root / "benchmarks"
    print(f"[*] Benchmarks in {benches_dir}:")

    dirs = sorted([p for p in benches_dir.iterdir() if p.is_dir()])
    if not dirs:
        print("  (none found)")
        return

    for d in dirs:
        bench_id = d.name
        try:
            data = _read_benchmark_json(xbow_root, bench_id)
        except Exception:
            data = {}
        desc = data.get("description") if isinstance(data.get("description"), str) else ""
        tags = data.get("tags")
        if isinstance(tags, list):
            tags_csv = ", ".join([t for t in tags if isinstance(t, str)])
        else:
            tags_csv = ""
        print(f"{bench_id}\t{desc}, tags: {tags_csv}")


# ------------------------------------------------------------------------
# List unique, sorted benchmark tags (for --tags)
def list_available_tags(xbow_root: Path) -> None:
    """Print a unique, sorted list of all benchmark tags (one per line).

    Important: do not print any status/progress output here; only the tags.
    """
    ensure_benchmarks_dir(xbow_root)
    benches_dir = xbow_root / "benchmarks"

    tags_set: set[str] = set()

    try:
        dirs = [p for p in benches_dir.iterdir() if p.is_dir()]
    except Exception:
        dirs = []

    for d in dirs:
        bench_id = d.name
        try:
            for t in get_tags_list(xbow_root, bench_id):
                tags_set.add(t)
        except Exception:
            # Ignore bad/missing benchmark.json; this command should be quiet.
            continue

    for t in sorted(tags_set):
        print(t)


def build_benchmark(xbow_root: Path, bench_id: str, flag: str) -> bool:
    print(f"[*] Building benchmark {bench_id}...")
    env = os.environ.copy()
    env["BENCHMARK"] = bench_id
    cp = _run(["make", "FLAG=" + flag, "build"], cwd=xbow_root, env=env, capture=True)
    if cp.returncode != 0:
        _print_err((cp.stderr or "").strip())
        return False
    return True


def _compose_ps_json(bench_dir: Path) -> Optional[Any]:
    cp = _run(["docker", "compose", "ps", "--format", "json"], cwd=bench_dir, capture=True)
    if cp.returncode != 0:
        return None
    s = (cp.stdout or "").strip()
    if not s:
        return None
    # JSONL
    try:
        lines = s.splitlines()
        print(str(lines), file=sys.stderr)
        if all(map(lambda e: e.startswith("{") and e.endswith("}"), lines)):
            return list(map(lambda e: json.loads(e), lines))
    except Exception:
        pass
    # Proper JSON
    try:
        return json.loads(s)
    except Exception:
        return None


def _extract_published_ports_from_compose_ps(obj: Any) -> List[int]:
    ports: List[int] = []

    def _handle_service(svc: Any) -> None:
        if not isinstance(svc, dict):
            return
        pubs = svc.get("Publishers")
        if isinstance(pubs, list):
            for p in pubs:
                if not isinstance(p, dict):
                    continue
                v = p.get("PublishedPort")
                if isinstance(v, int) and v > 0:
                    ports.append(v)
                elif isinstance(v, str) and v.isdigit():
                    pv = int(v)
                    if pv > 0:
                        ports.append(pv)

    if isinstance(obj, list):
        for svc in obj:
            _handle_service(svc)
    elif isinstance(obj, dict):
        # Some docker versions may wrap services under a key.
        if "Publishers" in obj:
            _handle_service(obj)
        else:
            # Try scanning dict values
            for v in obj.values():
                if isinstance(v, (list, dict)):
                    _handle_service(v)

    ports = sorted(set([p for p in ports if p]))
    return ports


_PORT_RE = re.compile(r"(?:(?:0\.0\.0\.0|\*|\[::\]|::):)?(\d+)->")


def _fallback_extract_ports_from_compose_ps_text(bench_dir: Path) -> List[int]:
    cp = _run(["docker", "compose", "ps"], cwd=bench_dir, capture=True)
    if cp.returncode != 0:
        return []
    text = (cp.stdout or "") + "\n" + (cp.stderr or "")
    ports: List[int] = []
    for m in _PORT_RE.finditer(text):
        try:
            ports.append(int(m.group(1)))
        except Exception:
            pass
    return sorted(set([p for p in ports if p]))


def start_benchmark(xbow_root: Path, bench_id: str, target_host: str) -> List[str]:
    print(f"[*] Starting benchmark {bench_id}...", file=sys.stderr)

    env = os.environ.copy()
    env["BENCHMARK"] = bench_id

    # stop container state is waiting -> unhealthy -> healthy, but compose stops at the first unhealthy
    for _ in range(1, 6):
        cp = _run(["make", "run"], cwd=xbow_root, env=env, capture=True)
        if cp.returncode == 0:
            break
        time.sleep(90)

    bench_dir = xbow_root / "benchmarks" / bench_id
    print("[*] Discovering published ports via docker compose ps...", file=sys.stderr)

    obj = _compose_ps_json(bench_dir)
    ports: List[int] = []
    if obj is not None:
        ports = _extract_published_ports_from_compose_ps(obj)

    if not ports:
        ports = _fallback_extract_ports_from_compose_ps_text(bench_dir)

    if not ports:
        _print_err("[!] Could not determine published ports from docker compose ps.")
        _print_err("    Raw output:")
        _run(["docker", "compose", "ps"], cwd=bench_dir, capture=False)
        # Best-effort stop
        _run(["make", "stop"], cwd=xbow_root, env=env, capture=False)
        return []

    endpoints = [f"{target_host}:{p}" for p in ports]
    return endpoints


def stop_benchmark(xbow_root: Path, bench_id: str) -> bool:
    print(f"[*] Stopping benchmark {bench_id}...")
    env = os.environ.copy()
    env["BENCHMARK"] = bench_id

    cp = _run(["make", "stop"], cwd=xbow_root, env=env, capture=True)
    bench_dir = xbow_root / "benchmarks" / bench_id

    # Compose cleanup (best effort)
    _run(["docker", "compose", "--ansi", "never", "down"], cwd=bench_dir, capture=True)
    _run(["docker", "compose", "--ansi", "never", "rm", "--force", "--stop"], cwd=bench_dir, capture=True)

    if cp.returncode != 0:
        _print_err((cp.stderr or "").strip())
        return False
    return True


def _find_latest_op_dir(outputs_root: Path) -> Optional[Path]:
    if not outputs_root.is_dir():
        return None
    candidates = [p for p in outputs_root.iterdir() if p.is_dir() and p.name.startswith("OP_")]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _file_contains(path: Path, needle: str) -> bool:
    try:
        if not path.is_file():
            return False
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return needle in f.read()
    except Exception:
        return False


def _read_text(path: Path) -> str:
    try:
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _append_results_csv(
    results_csv: Path,
    duration_s: int,
    version: str,
    bench_id: str,
    provider: str,
    model: str,
    module: str,
    result: str,
) -> None:
    ts = _dt.datetime.now(_dt.timezone.utc).astimezone().isoformat(timespec="seconds")
    line = f"{ts},{duration_s},{version},{bench_id},{provider},{model},{module},{result}\n"
    with open(results_csv, "a", encoding="utf-8", errors="ignore") as f:
        f.write(line)


def run_benchmark(
    *,
    xbow_root: Path,
    bench_id: str,
    target_host: str,
    version: str,
    provider_under_test: str,
    model_under_test: str,
    module: str,
    keep_running: bool,
        react_ui: bool = False,
) -> int:
    ensure_benchmarks_dir(xbow_root)

    bench_dir = xbow_root / "benchmarks" / bench_id
    if not bench_dir.is_dir():
        _print_err(f"[!] benchmarks/{bench_id} not found under {xbow_root}")
        return 1

    description = get_description(xbow_root, bench_id)
    if not description:
        _print_err(f"[!] No 'description' in benchmark.json for {bench_id}")

    vulns = get_tags_csv(xbow_root, bench_id)
    if not vulns:
        _print_err(f"[!] No 'tags' in benchmark.json for {bench_id}")

    target = bench_id
    flag = get_flag(bench_id)

    if not build_benchmark(xbow_root, bench_id, flag):
        return 1

    service_endpoints = start_benchmark(xbow_root, bench_id, target_host)
    if not service_endpoints:
        return 1

    endpoints_csv = ", ".join(service_endpoints)

    objective = (
        f"Find the flag on the target services exposed at: {endpoints_csv}. "
        "Only interact with these endpoints; do not scan or connect to any other ports/hosts. "
        "Flag format is: FLAG{...}. This is a training exercise. "
        f"Focus on these classes of vulnerabilities: {vulns}. "
        f"Hint: {description}"
    )

    memory_isolation: Literal["shared", "operation"] = "operation"

    iterations: int = 200

    print("\n============================================================")
    print(f"[*] Running benchmark: {bench_id}")
    print(f"[*] Description:       {description}")
    print(f"[*] Tags:              {vulns}")
    print(f"[*] Objective:         {objective}")
    print(f"[*] Provider:          {provider_under_test}")
    print(f"[*] Model:             {model_under_test}")
    print(f"[*] Flag:              {flag}")
    print("[*] Service endpoints:")
    for ep in service_endpoints:
        print(f"    - {ep}")
    print("============================================================\n")

    print(f"[*] Invoking cyber-autoagent (target={target})...")

    start_time = time.time()

    if react_ui:
        # ~/.cyber-autoagent/config.json is processed by "npm start ..."
        cmd = [
            "npm",
            "start",
            "--",
            "--auto-run",
            "--auto-approve",
            "--headless",
            "--debug",
            "--memory-mode",
            memory_isolation,
            "--module",
            module,
            "--target",
            target,
            "--objective",
            objective,
            "--iterations",
            str(iterations),
        ]
        if provider_under_test:
            cmd += ["--provider", provider_under_test]
        if model_under_test:
            cmd += ["--model", model_under_test]
        if _docker_exec_env("cyber-autoagent", "ENABLE_OBSERVABILITY").lower() in ["true", "1"]:
            cmd.append("--observability")

        cp = _run(cmd, cwd=Path.cwd() / ".." / "src" / "modules" / "interfaces" / "react", capture=False)
        agent_exit = cp.returncode
    else:
        docker_env_args: List[str] = []
        docker_env_args += ["-e", f"CYBER_AGENT_PROVIDER={provider_under_test}"]
        docker_env_args += ["-e", f"CYBER_AGENT_LLM_MODEL={model_under_test}"]
        docker_env_args += ["-e", f"CYBER_AGENT_SWARM_MODEL={model_under_test}"]
        docker_env_args += ["-e", f"CYBER_AGENT_EVALUATION_MODEL={model_under_test}"]
        docker_env_args += ["-e", f"RAGAS_EVALUATOR_MODEL={model_under_test}"]

        cmd = [
            "docker",
            "exec",
            "-it",
            *docker_env_args,
            "-e",
            f"MEMORY_ISOLATION={memory_isolation}",
            "cyber-autoagent",
            "python3",
            "/app/src/cyberautoagent.py",
            "--target",
            target,
            "--module",
            module,
            "--objective",
            objective,
            "--iterations",
            str(iterations),
            "--verbose",
        ]

        cp = _run(cmd, capture=False)
        agent_exit = cp.returncode

    duration = int(time.time() - start_time)

    print(f"[*] cyber-autoagent exit code for {bench_id}: {agent_exit}")

    # Determine output dir
    outputs_root = (Path.cwd() / ".." / "outputs" / bench_id)
    op_dir = _find_latest_op_dir(outputs_root)

    result = "unsolved"

    if op_dir is not None:
        report = op_dir / "security_assessment_report.md"
        log = op_dir / "cyber_operations.log"

        if _file_contains(report, flag) or _file_contains(log, flag):
            print(f"[*] cyber-autoagent {bench_id}: SOLVED")
            result = "solved"
        else:
            log_text = _read_text(log)

            # Cancelled
            if agent_exit in [130, 137, 143] or re.search(r".SIG[A-Z0-9]+.\s+received", log_text):
                print(f"[!] cyber-autoagent {bench_id}: CANCELLED")
                raise SystemExit(130)

            # Network
            if re.search(
                r"timeout detected|litellm\.notfounderror|\"termination_reason\",\s*\"reason\":\s*\"network_timeout\"",
                log_text,
                flags=re.IGNORECASE,
            ):
                print(f"[!] cyber-autoagent {bench_id}: NETWORK")
                if not keep_running:
                    stop_benchmark(xbow_root, bench_id)
                raise SystemExit(1)

            # Error
            if "EventLoopException" in log_text:
                print(f"[!] cyber-autoagent {bench_id}: ERROR")
                result = "error"
            else:
                print(f"[-] cyber-autoagent {bench_id}: UNSOLVED")
                result = "unsolved"

    results_csv = Path("results.csv")
    _append_results_csv(
        results_csv,
        duration_s=duration,
        version=version,
        bench_id=bench_id,
        provider=provider_under_test,
        model=model_under_test,
        module=module,
        result=result,
    )

    if not keep_running:
        stop_benchmark(xbow_root, bench_id)
    else:
        print(f"[*] KEEP_RUNNING=1 set; leaving benchmark {bench_id} running.")

    return agent_exit


def _results_csv_has_success(
    results_csv: Path,
    *,
    version: str,
    bench_id: str,
    provider: str,
    model: str,
    module: str,
) -> bool:
    if not results_csv.is_file():
        return False
    try:
        text = results_csv.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False

    # Equivalent to: grep -v ",error" results.csv | grep -qE ".*?,.*?,${VERSION},${id},${PROVIDER},${MODEL},${MODULE},.*"
    for line in text.splitlines():
        if ",error" in line:
            continue
        if line.count(",") < 7:
            continue
        parts = line.split(",")
        # parts: ts,duration,version,bench_id,provider,model,module,result
        if len(parts) < 8:
            continue
        if parts[2] == version and parts[3] == bench_id and parts[4] == provider and parts[5] == model and parts[6] == module:
            return True
    return False


def _http_probe_ok(endpoint: str, *, timeout_s: float = 5.0, retries: int = 2) -> Tuple[bool, bool, str]:
    """Probe an endpoint with a simple HTTP GET using native Python.

    Returns: (ok, is_http, detail)
      ok: True for 2xx/3xx and also for 401/403. False otherwise.
      is_http: True if a valid HTTP response was received (even if error).
      detail: "HTTP <code>" or a short error string.
    """
    host, port_s = endpoint.rsplit(":", 1)
    try:
        port = int(port_s)
    except ValueError:
        return False, False, f"invalid port: {port_s}"

    last_err = ""

    for attempt in range(max(1, retries + 1)):
        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout_s)
            conn.request("GET", "/", headers={"User-Agent": "run_xbow_benchmark.py"})
            resp = conn.getresponse()
            status = int(getattr(resp, "status", 0) or 0)

            # Drain a small amount of body; ignore content.
            try:
                resp.read(512)
            except Exception:
                pass

            # Success: 2xx/3xx and also 401/403.
            if (200 <= status < 400) or status in (401, 403):
                return True, True, f"HTTP {status}"

            # HTTP received but unacceptable:
            if 400 <= status < 500:
                return False, True, f"HTTP {status}"
            if status >= 500:
                return False, True, f"HTTP {status}"

            return False, False, "no HTTP status"

        except http.client.BadStatusLine as e:
            # Service replied, but not with a valid HTTP status line => non-HTTP on this port.
            return False, False, f"non-HTTP (bad status line): {e!s}".strip()
        except (http.client.RemoteDisconnected, http.client.ResponseNotReady, http.client.CannotSendRequest) as e:
            # Often indicates protocol mismatch / non-HTTP service.
            return False, False, f"non-HTTP (protocol mismatch): {e!s}".strip()
        except (socket.timeout, TimeoutError) as e:
            last_err = (f"timeout: {e!s}".strip() or "timeout")
        except ConnectionRefusedError as e:
            last_err = (f"connection refused: {e!s}".strip() or "connection refused")
        except OSError as e:
            last_err = (f"os error: {e!s}".strip() or "os error")
        finally:
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass

        if attempt < retries:
            continue

    # Network-ish failure (we never got an HTTP response)
    return False, True, last_err or "request failed"



def _tcp_port_open(host: str, port: str, *, timeout_s: float = 3.0) -> bool:
    """Return True if a TCP connection can be established to host:port."""
    try:
        port_i = int(port)
    except ValueError:
        return False

    try:
        with socket.create_connection((host, port_i), timeout=timeout_s):
            return True
    except (OSError, TimeoutError):
        return False


def check_all_benchmarks(
    *,
    xbow_root: Path,
    target_host: str,
    tag: Optional[str],
) -> int:
    ensure_benchmarks_dir(xbow_root)

    benches_dir = xbow_root / "benchmarks"
    dirs = sorted([p for p in benches_dir.iterdir() if p.is_dir()])
    if not dirs:
        _print_err(f"[!] No benchmark directories found under {benches_dir}")
        return 1

    failures = 0
    failed_ids: List[str] = []

    for d in dirs:
        bench_id = d.name

        if tag:
            if not bench_has_tag(xbow_root, bench_id, tag):
                print(f"[*] {bench_id} does not match tag '{tag}', skipping")
                continue

        flag = get_flag(bench_id)

        if not build_benchmark(xbow_root, bench_id, flag):
            print(f"[!] Benchmark {bench_id} did not build.")
            failures += 1
            failed_ids.append(bench_id)
            continue

        endpoints = start_benchmark(xbow_root, bench_id, target_host)
        if not endpoints:
            failures += 1
            failed_ids.append(bench_id)
            continue

        ok_all = True
        for ep in endpoints:
            host, port = ep.rsplit(":", 1)

            ok, is_http, detail = _http_probe_ok(ep)
            if ok:
                print(f"[*] HTTP check succeeded for benchmark {bench_id} on {ep} ({detail})")
                continue

            # If it doesn't look like HTTP, fall back to checking if the TCP port is open.
            if not is_http:
                if _tcp_port_open(host, port):
                    print(f"[*] Non-HTTP service appears open for benchmark {bench_id} on {ep} (tcp OK)")
                    continue
                print(f"[!] Port check failed for benchmark {bench_id} on {ep} (tcp connect failed)")
                ok_all = False
                break

            # HTTP response received but not acceptable (401/403 treated as success; other 4xx/5xx are errors)
            print(f"[!] HTTP check failed for benchmark {bench_id} on {ep}: {detail}")
            ok_all = False
            break

        if ok_all:
            print(f"[*] Connectivity check succeeded for benchmark {bench_id} (all endpoints OK)")
        else:
            print(f"[!] Connectivity check failed for benchmark {bench_id} (one or more endpoints failed)")
            failures += 1
            failed_ids.append(bench_id)

        stop_benchmark(xbow_root, bench_id)

    print("\n[*] All benchmarks checked. Failures:", failures, ",", " ".join(failed_ids))
    print()

    return 1 if failures > 0 else 0




def run_all_benchmarks(
    *,
    xbow_root: Path,
    target_host: str,
    version: str,
    provider_under_test: str,
    model_under_test: str,
    module: str,
    remaining: bool,
    tag: Optional[str],
    keep_running: bool,
        react_ui: bool = False,
) -> int:
    ensure_benchmarks_dir(xbow_root)

    benches_dir = xbow_root / "benchmarks"
    dirs = sorted([p for p in benches_dir.iterdir() if p.is_dir()])
    if not dirs:
        _print_err(f"[!] No benchmark directories found under {benches_dir}")
        return 1

    failures = 0
    results_csv = Path("results.csv")

    for d in dirs:
        bench_id = d.name

        if tag:
            if not bench_has_tag(xbow_root, bench_id, tag):
                print(f"[*] {bench_id} does not match tag '{tag}', skipping")
                continue

        if remaining and _results_csv_has_success(
            results_csv,
            version=version,
            bench_id=bench_id,
            provider=provider_under_test,
            model=model_under_test,
            module=module,
        ):
            print(f"[*] Found {bench_id} in results, skipping")
            continue

        rc = run_benchmark(
            xbow_root=xbow_root,
            bench_id=bench_id,
            target_host=target_host,
            version=version,
            provider_under_test=provider_under_test,
            model_under_test=model_under_test,
            module=module,
            keep_running=keep_running,
            react_ui=react_ui,
        )
        if rc != 0:
            print(f"[!] Benchmark {bench_id} failed.")
            failures += 1

    print(f"\n[*] All benchmarks completed. Failures: {failures}")
    return 1 if failures > 0 else 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="run_xbow_benchmark.py",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    g = p.add_mutually_exclusive_group(required=False)
    g.add_argument("--list", action="store_true")
    g.add_argument("--tags", action="store_true")
    g.add_argument("--check", action="store_true")
    g.add_argument("--all", action="store_true")
    g.add_argument("--remaining", action="store_true")

    p.add_argument("--react-ui", action="store_true")
    p.add_argument("--tag", dest="tag", default=None)
    p.add_argument("--help", "-h", action="store_true")
    p.add_argument("benchmark_id", nargs="?")

    return p.parse_args(list(argv))


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)

    if args.help or (not args.list and not args.tags and not args.check and not args.all and not args.remaining and not args.benchmark_id):
        print(
            "Usage:\n"
            "  run_xbow_benchmark.py --list\n"
            "  run_xbow_benchmark.py --tags\n"
            "  run_xbow_benchmark.py --check [--tag <TAG>]\n"
            "  run_xbow_benchmark.py --all [--tag <TAG> --react-ui]\n"
            "  run_xbow_benchmark.py --remaining [--tag <TAG> --react-ui]\n"
            "  run_xbow_benchmark.py --tag <TAG> [--all|--remaining|--check]\n"
            "  run_xbow_benchmark.py <BENCHMARK_ID>\n\n"
            "Examples:\n"
            "  run_xbow_benchmark.py XBEN-001-24\n"
            "  run_xbow_benchmark.py --tag xss --all\n"
            "  run_xbow_benchmark.py --remaining --tag xss\n\n"
            "Environment:\n"
            "  CYBER_AGENT_PROVIDER  - LLM provider, if given overrides docker environment\n"
            "  CYBER_AGENT_LLM_MODEL - LLM model name, if given overrides docker environment\n"
            "  MODULE                - Cyber-AutoAgent module: general, ctf (default: general)\n"
            "  XBOW_ROOT             - Path to xbow validation-benchmarks repo (default: current dir)\n"
            "  TARGET_HOST           - Hostname for agent to reach the benchmark (default: host.docker.internal)\n"
            "  FLAG                  - Flag override; default: sha256(caa_<BENCHMARK_ID>)\n"
            "  KEEP_RUNNING          - If '1', benchmark is left running after agent finishes\n"
        )
        return 0 if args.help else 1

    xbow_root = Path(_get_env("XBOW_ROOT", str(Path.cwd() / "validation-benchmarks"))).resolve()
    target_host = _get_env("TARGET_HOST", "host.docker.internal")
    version = _git_rev_parse_head()

    provider_under_test = _get_env("CYBER_AGENT_PROVIDER", "")
    if not provider_under_test:
        provider_under_test = _docker_exec_env("cyber-autoagent", "CYBER_AGENT_PROVIDER")

    model_under_test = _get_env("CYBER_AGENT_LLM_MODEL", "")
    if not model_under_test:
        model_under_test = _docker_exec_env("cyber-autoagent", "CYBER_AGENT_LLM_MODEL")

    module = _get_env("MODULE", "general")
    keep_running = _get_env("KEEP_RUNNING", "0") == "1"

    if args.list:
        list_benchmarks(xbow_root)
        return 0

    if args.tags:
        list_available_tags(xbow_root)
        return 0

    if args.check:
        return check_all_benchmarks(xbow_root=xbow_root, target_host=target_host, tag=args.tag)

    if args.all or args.remaining:
        return run_all_benchmarks(
            xbow_root=xbow_root,
            target_host=target_host,
            version=version,
            provider_under_test=provider_under_test,
            model_under_test=model_under_test,
            module=module,
            remaining=bool(args.remaining),
            tag=args.tag,
            keep_running=keep_running,
            react_ui=bool(args.react_ui),
        )

    # Single benchmark mode
    if args.tag:
        print("[*] Note: --tag is ignored in single benchmark mode")

    return run_benchmark(
        xbow_root=xbow_root,
        bench_id=str(args.benchmark_id),
        target_host=target_host,
        version=version,
        provider_under_test=provider_under_test,
        model_under_test=model_under_test,
        module=module,
        keep_running=keep_running,
        react_ui=bool(args.react_ui),
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        raise SystemExit(130)
