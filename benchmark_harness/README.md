# Benchmarks Directory

## Start full-stack or single-container mode

Configure `.env` with the desired provider, model and other settings.

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

Execute:
```shell
./run_xbow_benchmark.sh XBEN-001-24

./run_xbow_benchmark.sh --all
```

Results are appended to the `results.csv` file with the following columns:

- Timestamp
- Duration in seconds
- Repository git hash
- Benchmark ID
- Provider
- Model
- Result: solved or unsolved
