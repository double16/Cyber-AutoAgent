#!/usr/bin/env bash

set -e

grep -i '"max tokens\|prompt token\|reasoning"\|_budget\|system_prompt_payload' "$(find . -name "cyber_operations.log" -print0 | xargs -0 ls -t | head -n 1)" \
  | tail -c 64000 \
  | sed $'1i\\\nYou are a specialist in agentic workflows for security assessments. You analyze agent actions for efficient context window usage. \
  Analyze the following log of an agentic workflow and evaluate context window usage. \
 \
### REAL LOG STARTS AFTER THIS #### \
' \
  | ollama run "$("$(dirname "${0}")/ollama_completion_model.py")"
