#!/usr/bin/env bash

set -e

grep '"tool_start"\|"reasoning"\|system_prompt_payload' "$(find . -name "cyber_operations.log" -print0 | xargs -0 ls -t | head -n 1)" \
  | sed -e 's/__CYBER_EVENT_END__//' -e 's/__CYBER_EVENT__//' \
  | tail -c 64000 \
  | sed $'1i\\\nYou are a specialist in agentic workflows for security assessments. You analyze agent actions for performance improvements. \
  Analyze the following log of an agentic workflow and describe where the agent struggled and offer recommendations for improvements. \
  Provide a summary of the workflow at the beginning to help the reader under the context of your analysis. \
  The system prompt is logged with the tag "system_prompt_payload" as it is optimized by the agent. Include recommendations for improvement to the system prompt. \
  The agent is given a budget of steps. If the agent did not fully utilize the budget, determine the reason and provide recommendations. \
  If specialized tools are included in the system prompt, determine if the agent used those tools effectively and offer recommendations for better specialized tool use. \
  Offer recommendations for writing custom tools that chain together other tools in predicable patterns, only if there is a benefit beyond the model reasoning itself and the custom tool would be generally useful. \
 \
### REAL LOG STARTS AFTER THIS #### \
' \
  | ollama run "$("$(dirname "${0}")/ollama_completion_model.py")"
