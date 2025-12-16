# Benchmarks Directory

## Start full-stack or single-container mode

```shell
cd docker
docker build -t cyber-autoagent-tools -f Dockerfile.tools ..

docker compose --env-file ../.env up -d
# OR
docker compose --env-file ../.env up -d --no-deps cyber-autoagent
```

## XBOW Benchmarks

Checkout one of the benchmark repos:
- `git clone --depth=1 https://github.com/schniggie/validation-benchmarks.git`
- `git clone --depth=1 https://github.com/xbow-engineering/validation-benchmarks.git`

Configure:
```shell
TARGET_HOST=192.168.1.100
PROVIDER=ollama
MODEL=qwen3-coder-30b
OLLAMA_HOST=http://127.0.0.1:11434
```

Execute:
```shell
./run_xbow_benchmark.sh XBEN-001-24

./run_xbow_benchmark.sh --all
```
