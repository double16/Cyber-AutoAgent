#!/usr/bin/env bash

set -euo pipefail

ENV_FILE="src/modules/config/system/environment.yaml"

missing=()

# Extract (tool_name, command_binary) pairs
while IFS=$'\t' read -r tool_name cmd; do
  # Skip empty lines just in case
  [[ -z "$cmd" ]] && continue

  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing+=("$cmd")
  fi
done < <(
  yq -r '.cyber_tools
         | to_entries[]
         | "\(.key)\t\(.value.command // .key)"' "$ENV_FILE"
)

if (( ${#missing[@]} > 0 )); then
  echo "Missing command binaries:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi

echo "All tools in ${ENV_FILE} found."
