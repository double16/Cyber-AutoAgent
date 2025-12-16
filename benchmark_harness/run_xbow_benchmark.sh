#!/usr/bin/env bash
set -euo pipefail

# XBOW benchmark driver for cyber-autoagent
#
#   Checkout benchmarks (only one of these):
#     - git clone --depth=1 https://github.com/schniggie/validation-benchmarks.git
#     - git clone --depth=1 https://github.com/xbow-engineering/validation-benchmarks.git
#
# Layout assumptions:
#   XBOW_ROOT/
#     benchmarks/
#       XBEN-001-24/
#         benchmark.json   # has "description" property
#         docker-compose.yml
#
# Usage:
#   List benchmarks:
#     ./run_xbow_benchmark.sh --list
#
#   Run all benchmarks:
#     ./run_xbow_benchmark.sh --all
#
#   Run a single benchmark:
#     ./run_xbow_benchmark.sh XBEN-001-24
#
# Behavior:
#   - Reads description from benchmarks/<ID>/benchmark.json
#   - Sets target = <ID>
#   - Objective = "<description> on <target>"
#
# Optional environment variables:
#   MODEL        - LLM model name (default: qwen3-coder-30b:48k)
#   XBOW_ROOT    - Path to xbow validation-benchmarks repo (default: current dir)
#   TARGET_HOST  - Hostname for agent to reach the benchmark (default: host.docker.internal)
#   FLAG         - Flag override; default: FLAG{sha256(caa_<BENCHMARK_ID>)}
#   KEEP_RUNNING - If "1", benchmark is left running after agent finishes

PROVIDER="${PROVIDER:-ollama}"
MODEL="${MODEL:-qwen3-coder-30b:48k}"
XBOW_ROOT="${XBOW_ROOT:-$(pwd)/validation-benchmarks}"
TARGET_HOST="${TARGET_HOST:-host.docker.internal}"

usage() {
  cat <<EOF
Usage:
  $0 --list
  $0 --check
  $0 --all
  $0 <BENCHMARK_ID>

Examples:
  $0 XBEN-001-24

Environment:
  MODEL        - LLM model (default: ${MODEL})
  XBOW_ROOT    - XBOW repo root (default: ${XBOW_ROOT})
  TARGET_HOST  - Hostname for target (default: ${TARGET_HOST})
  FLAG         - Flag override (default: FLAG{sha256(caa_<BENCHMARK_ID>)})
  KEEP_RUNNING - If "1", keep benchmark running after agent
EOF
}

ensure_benchmarks_dir() {
  if [[ ! -d "${XBOW_ROOT}/benchmarks" ]]; then
    echo -e "[!] benchmarks directory not found at: ${XBOW_ROOT}/benchmarks\n    git clone --depth=1 https://github.com/xbow-engineering/validation-benchmarks.git"
    exit 1
  fi
}

get_description() {
  local bench_id="$1"
  local bench_json="${XBOW_ROOT}/benchmarks/${bench_id}/benchmark.json"

  if [[ ! -f "${bench_json}" ]]; then
    echo "[!] benchmark.json not found for ${bench_id} at ${bench_json}"
    return 1
  fi

  jq -r '.description // empty' "${bench_json}"
}

get_flag() {
  local bench_id="$1"
  if [[ -n "${FLAG+x}" ]]; then
    echo "${FLAG}"
  else
    echo "caa_${bench_id}" | openssl sha256 -r | cut -d' ' -f1
  fi
}

list_benchmarks() {
  ensure_benchmarks_dir
  echo "[*] Benchmarks in ${XBOW_ROOT}/benchmarks:"
  cd "${XBOW_ROOT}/benchmarks"

  shopt -s nullglob
  local dirs=(*/)
  shopt -u nullglob

  if ((${#dirs[@]} == 0)); then
    echo "  (none found)"
    return
  fi

  for d in "${dirs[@]}"; do
    local id="${d%/}"
    [[ -d "${id}" ]] || continue
    local desc
    desc="$(jq -r '.description // ""' "${id}/benchmark.json" 2>/dev/null || true)"
    echo -e "${id}\t${desc}"
  done
}

run_benchmark() {
  local bench_id="$1"

  ensure_benchmarks_dir

  if [[ ! -d "${XBOW_ROOT}/benchmarks/${bench_id}" ]]; then
    echo "[!] benchmarks/${bench_id} not found under ${XBOW_ROOT}"
    return 1
  fi

  local description
  description="$(get_description "${bench_id}")"
  if [[ -z "${description}" || "${description}" == "null" ]]; then
    echo "[!] No 'description' in benchmark.json for ${bench_id}"
    return 1
  fi

  local target="${bench_id}"
  local flag
  flag="$(get_flag "${bench_id}")"

  echo
  echo "============================================================"
  echo "[*] Running benchmark: ${bench_id}"
  echo "[*] Description:       ${description}"
  echo "[*] Target (ID):       ${target}"
  echo "[*] Objective:         ${description}"
  echo "[*] XBOW root:         ${XBOW_ROOT}"
  echo "[*] Model:             ${MODEL}"
  echo "[*] Flag:              ${flag}"
  echo "============================================================"

  cd "${XBOW_ROOT}"

  echo "[*] Building benchmark ${bench_id}..."
  BENCHMARK="${bench_id}" make build FLAG="${flag}"

  echo "[*] Starting benchmark ${bench_id}..."
  BENCHMARK="${bench_id}" make run

  cd "benchmarks/${bench_id}"

  echo "[*] Discovering published port via docker compose ps..."
  local port
  port="$(docker compose ps --format json | jq -r '.Publishers[0].PublishedPort' | grep -v '^0$')"

  if [[ -z "${port}" || "${port}" == "null" ]]; then
    echo "[!] Could not determine published port from docker compose ps."
    echo "    Raw output:"
    docker compose ps
    cd "${XBOW_ROOT}"
    BENCHMARK="${bench_id}" make stop || true
    return 1
  fi

  local service_netloc="${TARGET_HOST}:${port}"
  local objective="Find the flag on ${service_netloc}. Only target port ${port}. ${description}."
  echo "[*] Benchmark service URL: ${service_netloc}"
  echo "[*] Invoking cyber-autoagent (target=${target})..."

  docker exec -it \
    -e CYBER_AGENT_PROVIDER="${PROVIDER}" \
    -e OLLAMA_HOST="${OLLAMA_HOST:-http://127.0.0.1:11434}" \
    -e OLLAMA_API_BASE="${OLLAMA_HOST:-http://127.0.0.1:11434}" \
    -e OLLAMA_TIMEOUT=1800 \
    -e CYBER_AGENT_LLM_MODEL="${MODEL}" \
    -e CYBER_AGENT_SWARM_MODEL="${MODEL}" \
    -e CYBER_AGENT_EVALUATION_MODEL="${MODEL}" \
    -e RAGAS_EVALUATOR_MODEL="${MODEL}" \
    -e MEMORY_ISOLATION=shared \
    -e CYBER_ENABLE_PROMPT_OPTIMIZATION=true \
    -e CYBER_ENABLE_PROMPT_OPTIMIZER=true \
    -e CYBER_MCP_ENABLED=true \
    -e CYBER_MCP_CONNECTIONS="$(jq -c .mcp.connections < ~/.cyber-autoagent/config.json)" \
    cyber-autoagent \
    python3 /app/src/cyberautoagent.py \
      --target "${target}" \
      --module ctf \
      --objective "${objective}" \
      --provider "${PROVIDER}" \
      --verbose

  local agent_exit=$?

  echo "[*] cyber-autoagent exit code for ${bench_id}: ${agent_exit}"

  cd "${XBOW_ROOT}"

  if [[ "${KEEP_RUNNING:-0}" != "1" ]]; then
    echo "[*] Stopping benchmark ${bench_id}..."
    BENCHMARK="${bench_id}" make stop || true
  else
    echo "[*] KEEP_RUNNING=1 set; leaving benchmark ${bench_id} running."
  fi

  return "${agent_exit}"
}

run_all_benchmarks() {
  ensure_benchmarks_dir
  cd "${XBOW_ROOT}/benchmarks"

  shopt -s nullglob
  local dirs=(*/)
  shopt -u nullglob

  if ((${#dirs[@]} == 0)); then
    echo "[!] No benchmark directories found under ${XBOW_ROOT}/benchmarks"
    exit 1
  fi

  local failures=0

  for d in "${dirs[@]}"; do
    local id="${d%/}"
    [[ -d "${id}" ]] || continue
    if ! run_benchmark "${id}"; then
      echo "[!] Benchmark ${id} failed."
      failures=$((failures + 1))
    fi
  done

  echo
  echo "[*] All benchmarks completed. Failures: ${failures}"

  if (( failures > 0 )); then
    return 1
  fi
  return 0
}

check_all_benchmarks() {
  ensure_benchmarks_dir
  cd "${XBOW_ROOT}/benchmarks"

  shopt -s nullglob
  local dirs=(*/)
  shopt -u nullglob

  if ((${#dirs[@]} == 0)); then
    echo "[!] No benchmark directories found under ${XBOW_ROOT}/benchmarks"
    exit 1
  fi

  local failures=0
  local flag

  for d in "${dirs[@]}"; do
    local bench_id="${d%/}"
    [[ -d "${bench_id}" ]] || continue
    flag="$(get_flag "${bench_id}")"
    pushd "${XBOW_ROOT}" >/dev/null
    echo "[*] Building benchmark ${bench_id}..."
    export BENCHMARK="${bench_id}" FLAG="${flag}"
    if ! make build FLAG="${flag}"; then
      echo "[!] Benchmark ${bench_id} did not build."
      failures=$((failures + 1))
    fi
     popd >/dev/null
  done

  echo
  echo "[*] All benchmarks checked. Failures: ${failures}"

  if (( failures > 0 )); then
    return 1
  fi
  return 0
}

# --- Main ----------------------------------------------------------------------

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

case "$1" in
  --list)
    list_benchmarks
    exit 0
    ;;
  --all)
    run_all_benchmarks
    exit $?
    ;;
  --check)
    check_all_benchmarks
    exit $?
    ;;
  --help|-h)
    usage
    exit 0
    ;;
  -*)
    usage
    exit 1
    ;;
esac

# Single benchmark mode: $1 = BENCHMARK_ID
BENCHMARK_ID="$1"
run_benchmark "${BENCHMARK_ID}"
exit $?