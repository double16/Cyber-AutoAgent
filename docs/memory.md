# Memory System

Cyber-AutoAgent implements persistent memory using Mem0 with automatic reflection, strategic planning, and evidence categorization. The system supports multiple backend configurations for different deployment scenarios.

## Key Features

- **Operation Scoping**: Memories are automatically scoped to the current operation via `run_id`
- **Cross-Operation Learning**: Query across all operations using `cross_operation=True`
- **Thread-Safe Writes**: FAISS backend uses locking for safe concurrent writes (swarm mode)
- **Category Validation**: Invalid categories are auto-corrected to prevent empty reports
- **Status Validation**: Contradictory status fields are automatically reconciled

## Architecture

```mermaid
graph LR
    A[Agent] --> B[mem0_memory Tool]
    B --> C{Backend Selection}

    C -->|MEM0_API_KEY set| D[Mem0 Platform]
    C -->|OPENSEARCH_HOST set| E[OpenSearch + AWS]
    C -->|Default| F[FAISS Local]

    D --> G[Cloud Vector Store]
    E --> H[OpenSearch + Bedrock]
    F --> I[Local FAISS Store]

    style B fill:#e3f2fd,stroke:#333,stroke-width:2px
    style F fill:#e8f5e8,stroke:#333,stroke-width:2px
```

## Backend Selection

Backend configuration follows environment-based precedence:

**Priority Order:**
1. **Mem0 Platform**: `MEM0_API_KEY` configured - Cloud-hosted service
2. **OpenSearch**: `OPENSEARCH_HOST` configured - AWS managed search
3. **FAISS**: Default - Local vector storage

Backend selection occurs at memory initialization and remains fixed for operation duration.

## Memory Operations

```mermaid
sequenceDiagram
    participant Agent
    participant Tool
    participant Backend
    participant Storage

    Agent->>Tool: store(content, metadata)
    Tool->>Backend: Generate embedding
    Backend->>Storage: Persist vector + metadata
    Storage-->>Tool: Confirmation

    Agent->>Tool: retrieve(query)
    Tool->>Backend: Vector similarity search
    Backend->>Storage: Query execution
    Storage-->>Backend: Matching vectors
    Backend-->>Agent: Ranked results
```

## Backend Configurations

### FAISS Backend
**Default Configuration:**
- **Storage Location**:
  - Default (operation isolation): `./outputs/<target>/memory/<operation_id>/`
  - Shared mode (`MEMORY_ISOLATION=shared`): `./outputs/<target>/memory/`
- **Embedder**: AWS Bedrock Titan Text v2 (1024 dimensions)
- **LLM**: Claude 3.5 Sonnet
- **Characteristics**: Local persistence, no external dependencies, thread-safe writes

### OpenSearch Backend
**AWS Managed Configuration:**
- **Storage**: AWS OpenSearch Service
- **Embedder**: AWS Bedrock Titan Text v2 (1024 dimensions)
- **LLM**: Claude 3.5 Sonnet
- **Characteristics**: Scalable search, managed infrastructure

### Mem0 Platform
**Cloud Service Configuration:**
- **Storage**: Mem0 managed infrastructure
- **Configuration**: Platform-managed
- **Characteristics**: Zero-setup, fully managed

## Memory Categorization

Evidence storage employs structured metadata for efficient retrieval and analysis:

```python
# Finding storage with metadata
mem0_memory(
    action="store",
    content="[WHAT] SQL injection [WHERE] /login [IMPACT] Auth bypass [EVIDENCE] payload",
    user_id="cyber_agent",
    metadata={
        "category": "finding",
        "severity": "CRITICAL",
        "confidence": "95%",
        "status": "verified"
    }
)
```

### Category Taxonomy

**Report-Generating Categories** (appear in final reports):
- **finding**: Exploited vulnerabilities, extracted data, confirmed security issues
- **signal**: Security signals that warrant attention
- **observation**: Reconnaissance data, failed attempts, recon findings
- **discovery**: Techniques learned, patterns identified

**Internal Categories** (not in reports):
- **plan**: Strategic assessment roadmaps
- **decision**: Tactical decisions and pivot reasoning

**Category Decision Tree** (CRITICAL - wrong category = empty report):
```
Q: Did you EXPLOIT something or extract sensitive data?
   YES → category="finding" (SQLi data dump, auth bypass, flag, RCE, creds)
   NO  → Q: Did you CONFIRM a vulnerability exists?
            YES → category="finding" (XSS fires, IDOR returns other user data)
            NO  → category="observation" (recon, tech stack, failed attempts)
```

**Severity Levels** (for findings):
- **CRITICAL**: Remote code execution, authentication bypass, data breach
- **HIGH**: Significant security impact, privilege escalation
- **MEDIUM**: Moderate risk, information disclosure
- **LOW**: Minor security concerns, informational

## Advanced Features

### Budget Checkpoints

Plan evaluation triggers at budget checkpoints:

**Checkpoint Actions:**
- At 20%, 40%, 60%, 80% budget: `get_plan` → evaluate → update if needed
- High severity findings may trigger immediate plan reassessment
- Phase transitions tracked via plan status updates

```python
# Budget checkpoint workflow
plan = mem0_memory(action="get_plan")
# Evaluate: Is current phase criteria met?
# If yes: Update phase status to "done", advance current_phase
# Store updated plan
```

### Strategic Plan Management

Hierarchical planning with phase tracking:

```python
# Plan storage (required format)
mem0_memory(
    action="store_plan",
    content={
        "objective": "Compromise web application",
        "current_phase": 1,
        "total_phases": 3,
        "phases": [
            {"id": 1, "title": "Reconnaissance", "status": "in_progress", "criteria": "Map attack surface"},
            {"id": 2, "title": "Exploitation", "status": "pending", "criteria": "Exploit vulnerabilities"},
            {"id": 3, "title": "Post-Exploitation", "status": "pending", "criteria": "Lateral movement"}
        ]
    }
)

# Plan retrieval
current_plan = mem0_memory(action="get_plan")
```

**Required Plan Fields:**
- `objective`: Overall mission goal
- `current_phase`: Active phase number
- `total_phases`: Total number of phases
- `phases`: List of phase objects with `id`, `title`, `status`, `criteria`

### Reflection via Plan Updates

Tactical pivots are managed through plan updates:

```python
# Update plan with new strategy after reflection
mem0_memory(
    action="store_plan",
    content={
        "objective": "Compromise web application",
        "current_phase": 2,
        "total_phases": 3,
        "phases": [
            {"id": 1, "title": "Reconnaissance", "status": "done", "criteria": "Attack surface mapped"},
            {"id": 2, "title": "API Testing", "status": "in_progress", "criteria": "Pivoting from web to API"},
            {"id": 3, "title": "Exploitation", "status": "pending", "criteria": "Achieve access"}
        ]
    }
)

## Storage Structure

### FAISS Backend Layout (Default - Per-Operation Isolation)
```
./outputs/<target>/memory/<operation_id>/
├── mem0.faiss           # Vector embeddings (FAISS index)
└── mem0.pkl             # Metadata storage (pickle: docstore + ID mapping)
```

### FAISS Backend Layout (Shared Mode)
```
./outputs/<target>/memory/
├── mem0.faiss           # Vector embeddings (FAISS index)
└── mem0.pkl             # Metadata storage (pickle: docstore + ID mapping)
```

### Operation Output Structure
```
./outputs/<target>/<operation_id>/
├── artifacts/           # Operation artifacts
├── report.md            # Final assessment report
└── logs/               # Operation logs
    └── cyber_operations.log
```

## Memory Tool Usage

The unified `mem0_memory` tool handles all operations:

### Basic Operations
```python
# Store finding with metadata
mem0_memory(
    action="store",
    content="[WHAT] RCE [WHERE] /upload [IMPACT] Shell access [EVIDENCE] shell.php",
    metadata={"category": "finding", "severity": "critical", "confidence": "98%"}
)

# Search memories  
mem0_memory(action="retrieve", query="SQL injection")

# List all memories
mem0_memory(action="list", user_id="cyber_agent")

# Get specific memory
mem0_memory(action="get", memory_id="mem_123")

# Delete memory
mem0_memory(action="delete", memory_id="mem_123")
```

### Advanced Operations
```python
# Store strategic plan (dict format required)
mem0_memory(
    action="store_plan",
    content={
        "objective": "Compromise web application",
        "current_phase": 1,
        "total_phases": 3,
        "phases": [
            {"id": 1, "title": "Recon", "status": "in_progress", "criteria": "Map attack surface"},
            {"id": 2, "title": "Exploit", "status": "pending", "criteria": "Find and exploit vulns"},
            {"id": 3, "title": "Persist", "status": "pending", "criteria": "Maintain access"}
        ]
    }
)

# Get current plan
current_plan = mem0_memory(action="get_plan")

# Update plan after tactical pivot
mem0_memory(
    action="store_plan",
    content={
        "objective": "Compromise web application",
        "current_phase": 2,
        "total_phases": 3,
        "phases": [
            {"id": 1, "title": "Recon", "status": "done", "criteria": "Attack surface mapped"},
            {"id": 2, "title": "API Testing", "status": "in_progress", "criteria": "Web fortified, pivot to API"},
            {"id": 3, "title": "Exploit", "status": "pending", "criteria": "Achieve access"}
        ]
    }
)
```

### Memory Query Patterns
```python
# Semantic search (current operation only - default)
mem0_memory(action="retrieve", query="SQL injection vulnerabilities")

# Search with metadata filter
mem0_memory(
    action="retrieve",
    query="authentication bypass",
    metadata={"category": "finding", "severity": "CRITICAL"}
)

# Cross-operation learning (search ALL operations)
mem0_memory(
    action="retrieve",
    query="SQL injection techniques",
    cross_operation=True  # Enables cross-learning
)

# List memories from current operation
mem0_memory(action="list", user_id="cyber_agent")

# List all memories across operations
mem0_memory(action="list", user_id="cyber_agent", cross_operation=True)
```

### Cross-Operation Learning
```python
# Learn from past successful exploits
mem0_memory(
    action="retrieve",
    query="successful exploitation techniques",
    metadata={"status": "verified"},
    cross_operation=True
)

# Find what blocked previous attempts
mem0_memory(
    action="retrieve",
    query="blocked or filtered",
    metadata={"category": "observation"},
    cross_operation=True
)
```

## Configuration

### Local Mode (Ollama)
```python
config = {
    "embedder": {"provider": "ollama", "config": {"model": "mxbai-embed-large"}},
    "llm": {"provider": "ollama", "config": {"model": "llama3.2:3b"}}
}
```

### Remote Mode (AWS Bedrock)
```python
config = {
    "embedder": {"provider": "aws_bedrock", "config": {"model": "amazon.titan-embed-text-v2:0"}},
    "llm": {"provider": "aws_bedrock", "config": {"model": "us.anthropic.claude-3-5-sonnet-20241022-v2:0"}}
}
```

## Operational Guidelines

### Finding Documentation Format

Structured finding format ensures consistent evidence collection:

```
[WHAT] Vulnerability classification
[WHERE] Precise location identifier
[IMPACT] Business and technical impact
[EVIDENCE] Reproduction steps and proof
```

### Metadata Standards

**Required Fields:**
- **category**: Taxonomy classification (finding, observation, discovery, signal) - **REQUIRED, missing category raises error**
- **severity**: Risk level for findings (CRITICAL/HIGH/MEDIUM/LOW)
- **confidence**: Assessment certainty (percentage, e.g., "85%")

> **Note**: The `category` field is mandatory for store operations. Attempting to store without a category will raise a `ValueError` with guidance on proper categorization.

**Optional Fields:**
- **status**: Verification state (hypothesis, unverified, verified)
- **validation_status**: Submission state (hypothesis, submission_accepted)
- **technique**: Exploitation technique used
- **challenge_id**: CTF challenge identifier

### Status Validation

The memory system automatically validates and corrects inconsistent status fields:

```python
# These contradictions are auto-corrected:
# status="verified" + validation_status="hypothesis" → validation_status="verified"
# validation_status="submission_accepted" + status="hypothesis" → status="verified"

# FORBIDDEN: status="solved" is ambiguous and auto-converts to "hypothesis"
# Use status="verified" for confirmed findings
```

### Plan Management

**Lifecycle:**
1. Initialize plan at operation start
2. Update phase status during execution
3. Adapt strategy through reflection

### Plan-Based Strategy Updates

**Operational Flow:**
- Check plan status at budget checkpoints (20%, 40%, 60%, 80%)
- Update phase status when criteria met
- Store updated plan with `store_plan` action

### Query Optimization

**Efficiency Techniques:**
- Pre-query deduplication checks
- Metadata-based filtering
- Specific query construction
- Result ranking utilization

## Configuration Options

### Command Line Arguments

```bash
# Specify memory path
--memory-path ./outputs/<target>/memory/

# Memory persistence (default: enabled)
--keep-memory

# Memory storage location
# Format: ./outputs/<target>/memory/
```

### Memory Persistence

**Default Behavior (Operation Isolation):**
- Each operation gets its own isolated memory store
- No automatic cross-operation contamination
- Use `cross_operation=True` to explicitly query across operations

**Shared Mode (`MEMORY_ISOLATION=shared`):**
- All operations share a single memory store per target
- Automatic cross-operation learning
- Use `run_id` filtering for operation-specific queries

**Storage Path Patterns:**
```
# Default (operation isolation)
./outputs/<target>/memory/<operation_id>/

# Shared mode
./outputs/<target>/memory/
```

### Environment Variables

| Variable             | Default        | Description                                                |
|----------------------|----------------|------------------------------------------------------------|
| `MEMORY_ISOLATION`   | `operation`    | `operation` for isolated stores, `shared` for single store |
| `CYBER_OPERATION_ID` | Auto-generated | Operation identifier for scoping                           |
| `MEM0_LIST_LIMIT`    | `100`          | Default limit for list/retrieve operations                 |

Memory isolation ensures target-specific knowledge remains separated while enabling explicit cross-operation learning when needed via the `cross_operation` parameter.