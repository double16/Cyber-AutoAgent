# Support Tools

The `support` directory contains sundry tools for diagnostic information.

## `cyberops-journal.sh`

**Requires**: Ollama install with a completion model, like llama3.2 or qwen3-coder.

Reads the most recent `cyber_operations.log` file in the current directory tree and outputs a human-readable "journal"
of what happened. Points out areas where the agent struggled.

## `cyberops-diagnose.sh`

**Requires**: Ollama install with a completion model, like llama3.2 or qwen3-coder.

Reads the most recent `cyber_operations.log` file in the current directory tree and outputs a human-readable
assessment of agent performance. The focus is on identifying areas of improvement.

