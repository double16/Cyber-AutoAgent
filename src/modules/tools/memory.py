#!/usr/bin/env python3
"""
Tool for managing memories using Mem0 (store, delete, list, get, and retrieve)

This module provides comprehensive memory management capabilities using
Mem0 as the backend. It handles all aspects of memory management with
a user-friendly interface and proper error handling.

Key Features:
------------
1. Memory Management:
   • store: Add new memories with automatic ID generation and metadata
   • delete: Remove existing memories using memory IDs
   • list: Retrieve all memories for a user or agent
   • get: Retrieve specific memories by memory ID
   • retrieve: Perform semantic search across all memories

2. Safety Features:
   • User confirmation for mutative operations
   • Content previews before storage
   • Warning messages before deletion
   • BYPASS_TOOL_CONSENT mode for bypassing confirmations in tests

3. Advanced Capabilities:
   • Automatic memory ID generation
   • Structured memory storage with metadata
   • Semantic search with relevance filtering
   • Rich output formatting
   • Support for both user and agent memories
   • Multiple vector database backends (OpenSearch, Mem0 Platform, FAISS)

4. Error Handling:
   • Memory ID validation
   • Parameter validation
   • Graceful API error handling
   • Clear error messages

5. Configurable Components:
   • Embedder (AWS Bedrock, Ollama, OpenAI)
   • LLM (AWS Bedrock, Ollama, OpenAI)
   • Vector Store (FAISS, OpenSearch, Mem0 Platform)

Plan & Reflection:
- Plan lifecycle: store_plan (create), get_plan (retrieve), update via store_plan (new version)
- Evaluation cadence: Every ~20 steps → get_plan, assess criteria, update phases if satisfied
- Phase transitions: Criteria met → status="done", advance current_phase, next status="active", store_plan
- Post-reflection: Evaluate plan, update if phase complete or pivot needed
- Stuck detection: Phase >40% budget → force advance with context note

Adaptation Tracking:
- After failed attempts: store("[OBSERVATION] Approach X blocked at endpoint Y", metadata={"category": "observation", "blocker": "WAF", "retry_count": n})
- Include what was blocked (script tags, specific chars, etc.) and next strategy
- After 3 retries with same approach, mandatory pivot to different technique

Plan Storage - CRITICAL: Pass as dict/object, NOT string! (serializes to TOON internally)

**━━━ EXACT FORMAT (copy this structure) ━━━**

```python
mem0_memory(
  action="store_plan",
  content={
    "objective": "Comprehensive security assessment",
    "current_phase": 1,
    "total_phases": 3,
    "phases": [
      {"id": 1, "title": "Reconnaissance", "status": "active", "criteria": "tech stack identified"},
      {"id": 2, "title": "Testing", "status": "pending", "criteria": "vulns validated with PoC"},
      {"id": 3, "title": "Exploitation", "status": "pending", "criteria": "flag extracted"}
    ]
  }
)
```

**Phase fields (REQUIRED - use EXACT names):**
- id: int (NOT "phase")
- title: str (NOT "name")
- status: str (active/pending/done)
- criteria: str (NOT "completion_criteria" or "tasks")

**Common mistakes to AVOID:**
✗ Passing content="string..." (must be dict!)
✗ Using {"phase": 1, "name": "X"} (use id/title)
✗ Adding extra fields like tasks, budget_percent (invalid)

**Internal TOON storage** (30-60% more token-efficient than JSON):
```
plan_overview[1]{objective,current_phase,total_phases}:
  Comprehensive security assessment,1,3
plan_phases[3]{id,title,status,criteria}:
  1,Reconnaissance,active,tech stack identified
  2,Testing,pending,vulns validated with PoC
  3,Exploitation,pending,flag extracted
```

Required: objective, current_phase, total_phases, phases (each with: id, title, status, criteria)

Proof Pack policy:
- For any HIGH/CRITICAL finding stored via mem0_memory, include Proof Pack in metadata:
  • proof_pack: {"artifacts": ["path1", "path2"], "rationale": "one-line explanation"}
  • All artifact paths MUST exist and be >200 bytes (authentic tool outputs)
  • Rationale links artifacts to the claim with technical explanation
- If no valid proof_pack exists:
  • Set validation_status="hypothesis" (NOT "verified" or "unverified")
  • Set status="hypothesis" (NOT "verified" or "solved")
  • Confidence capped at 60% automatically
  • Include next steps to obtain proof in content
- For FLAGS specifically:
  • MUST include artifact_hash (sha256 of artifact containing flag)
  • MUST include extraction_line (line number where flag found)
  • status="verified" ONLY after submission API returns success
- Recommended metadata keys: severity, confidence, validation_status, status, proof_pack, artifact_hash

Capability gaps (Ask-Enable-Retry):
- If a missing capability blocks progress (e.g., web3), the LLM should:
  1) Ask: state why it is required and the minimal package(s)
  2) Enable: propose a minimal, temporary, non-interactive enablement (e.g., ephemeral venv under outputs/<target>/<op>/venv)
  3) Retry: re-run once and store resulting artifacts
- If enablement is not permitted, store the next steps instead of escalating severity.

Usage:
- Keep entries concise. For large artifacts (HTML/JS/logs), save files to outputs/<target>/OP_<id>/artifacts and store only the file path in memory.
- See tool schema below.
"""

import json
import logging
import os
import re
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import boto3
from mem0 import Memory as Mem0Memory
from mem0 import MemoryClient
from opensearchpy import AWSV4SignerAuth, RequestsHttpConnection
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from strands import tool

from modules.config.manager import MEM0_PROVIDER_MAP, get_config_manager
from modules.config.system.logger import get_logger

# Set up logging
logger = get_logger("Tools.Memory")

# Initialize Rich console
console = Console()

# Global configuration and client
_MEMORY_CONFIG = None
_MEMORY_CLIENT = None

# Thread lock for FAISS write safety (prevents corruption during concurrent writes)
_FAISS_WRITE_LOCK = threading.Lock()


def _sanitize_toon_value(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\n", " ").replace("\r", " ").strip()
    return text.replace(",", ";")


def _format_plan_as_toon(plan_content: Dict[str, Any]) -> str:
    objective = _sanitize_toon_value(plan_content.get("objective", "Unknown objective"))
    current_phase = plan_content.get("current_phase", 1)
    phases = plan_content.get("phases", [])
    total_phases = plan_content.get("total_phases", len(phases))

    overview_lines = [
        "plan_overview[1]{objective,current_phase,total_phases}:",
        f"  {objective},{current_phase},{total_phases}",
    ]
    phase_lines = [f"plan_phases[{len(phases)}]{{id,title,status,criteria}}:"]
    for phase in phases:
        phase_lines.append(
            "  "
            + ",".join(
                [
                    _sanitize_toon_value(phase.get("id", "")),
                    _sanitize_toon_value(phase.get("title", "")),
                    _sanitize_toon_value(phase.get("status", "")),
                    _sanitize_toon_value(phase.get("criteria", "")),
                ]
            )
        )
    return "\n".join([*overview_lines, *phase_lines]).strip()


TOOL_SPEC = {
    "name": "mem0_memory",
    "description": (
        "Memory management for storing plans, findings, and observations.\n\n"
        "━━━ CRITICAL: store_plan FORMAT ━━━\n"
        "For action='store_plan', content MUST be a dict/object (NOT a string!).\n\n"
        "EXACT FORMAT (copy this structure):\n"
        '  mem0_memory(action="store_plan", content={\n'
        '    "objective": "CTF Challenge 63360",\n'
        '    "current_phase": 1,\n'
        '    "total_phases": 3,\n'
        '    "phases": [\n'
        '      {"id": 1, "title": "Analysis", "status": "active", "criteria": "source reviewed"},\n'
        '      {"id": 2, "title": "Exploit", "status": "pending", "criteria": "flag extracted"},\n'
        '      {"id": 3, "title": "Submit", "status": "pending", "criteria": "flag accepted"}\n'
        "    ]\n"
        "  })\n\n"
        "Phase fields (REQUIRED, do NOT use other field names):\n"
        "  - id: int (NOT 'phase')\n"
        "  - title: str (NOT 'name')\n"
        "  - status: str (active/pending/done)\n"
        "  - criteria: str (NOT 'completion_criteria')\n\n"
        "WRONG (common mistakes):\n"
        '  ✗ content="string..." (must be dict!)\n'
        '  ✗ {"phase": 1} (use "id")\n'
        '  ✗ {"name": "X"} (use "title")\n'
        '  ✗ {"tasks": [...]} (not a valid field)\n'
        '  ✗ {"budget_percent": 10} (not a valid field)\n\n'
        "Actions: store, store_plan, get_plan, list, retrieve, delete.\n"
        "Checkpoints: At 20%/40%/60%/80% budget → get_plan, assess, update if met.\n"
        "Default user_id='cyber_agent'.\n"
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": (
                        "Action to perform (store, store_plan, get_plan, get, list, retrieve, delete)"
                    ),
                    "enum": [
                        "store",
                        "store_plan",
                        "get_plan",
                        "get",
                        "list",
                        "retrieve",
                        "delete",
                    ],
                },
                "content": {
                    "type": ["string", "object"],
                    "description": (
                        "Content to store. For action='store': string. "
                        "For action='store_plan': MUST be object/dict (NOT string) with structure:\n"
                        '{"objective": "...", "current_phase": 1, "total_phases": 3, '
                        '"phases": [{"id": 1, "title": "Phase Name", "status": "active", "criteria": "..."}]}.\n'
                        "Required phase fields: id (int), title (string), status (active/pending/done), criteria (string, optional)."
                    ),
                },
                "memory_id": {
                    "type": "string",
                    "description": "Memory ID (required for get, delete actions)",
                },
                "query": {
                    "type": "string",
                    "description": "Search query (required for retrieve action)",
                },
                "user_id": {
                    "type": "string",
                    "description": "User ID for the memory operations (required for store, list, retrieve actions)",
                },
                "agent_id": {
                    "type": "string",
                    "description": "Agent ID for the memory operations (required for store, list, retrieve actions)",
                },
                "metadata": {
                    "type": "object",
                    "description": (
                        "For store: metadata dict with category (REQUIRED: finding/signal/observation/discovery), "
                        "severity (CRITICAL/HIGH/MEDIUM/LOW), status (verified/hypothesis), validation_status, technique, etc. "
                        "For retrieve: metadata dict used as filters (e.g., {category: 'finding', status: 'verified'}). "
                        "NOTE: category is REQUIRED for store action - missing category will raise an error."
                    ),
                },
                "cross_operation": {
                    "type": "boolean",
                    "description": (
                        "If True, search/list across ALL operations for cross-learning. "
                        "Default False = scoped to current operation only. "
                        "Use True to learn from past operations (e.g., retrieve(query='SQLi techniques', cross_operation=True))."
                    ),
                    "default": False,
                },
            },
            "required": ["action"],
        }
    },
}


class Mem0ServiceClient:
    """Lightweight client for Mem0 operations (store, search, list).

    Supports FAISS, OpenSearch, or Mem0 Platform based on environment.
    """

    @staticmethod
    def _normalise_results_list(payload: Any) -> List[Dict[str, Any]]:
        """Best-effort conversion of Mem0 responses to a list of memory dicts."""
        if payload is None:
            return []
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("results", "memories", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
        return []

    @staticmethod
    def get_default_config(server: str = "bedrock") -> Dict:
        """Get default configuration from ConfigManager."""
        config_manager = get_config_manager()
        mem0_config = config_manager.get_mem0_service_config(server)

        # Add RequestsHttpConnection for OpenSearch if needed
        if mem0_config["vector_store"]["provider"] == "opensearch":
            mem0_config["vector_store"]["config"]["connection_class"] = (
                RequestsHttpConnection
            )

        return mem0_config

    def __init__(
        self,
        config: Optional[Dict] = None,
        has_existing_memories: bool = False,
        silent: bool = False,
    ):
        """Initialize the Mem0 service client.

        Args:
            config: Optional configuration dictionary to override defaults.
                   If provided, it will be merged with the default configuration.
            has_existing_memories: Whether memories already existed before initialization
            silent: If True, suppress initialization output (used during report generation)

        The client will use one of three backends based on environment variables:
        1. Mem0 Platform if MEM0_API_KEY is set
        2. OpenSearch if OPENSEARCH_HOST is set
        3. FAISS (default) if neither MEM0_API_KEY nor OPENSEARCH_HOST is set
        """
        self.region = None  # Initialize region attribute
        self.has_existing_memories = has_existing_memories  # Store existing memory info
        self.silent = silent  # Store silent flag for use in initialization methods
        self.mem0 = self._initialize_client(config)
        self.config = config  # Store config for later use

        # Display memory overview if existing memories are detected (unless silent)
        if not silent:
            self._display_startup_overview()

    def _initialize_client(self, config: Optional[Dict] = None) -> Any:
        """Initialize the appropriate Mem0 client based on environment variables.

        Args:
            config: Optional configuration dictionary to override defaults.

        Returns:
            An initialized Mem0 client (MemoryClient or Mem0Memory instance).
        """
        if os.environ.get("MEM0_API_KEY"):
            if not self.silent:
                print("[+] Memory Backend: Mem0 Platform (cloud)")
                print(
                    f"    API Key: {'*' * 8}{os.environ.get('MEM0_API_KEY', '')[-4:]}"
                )
            logger.debug("Using Mem0 Platform backend (MemoryClient)")
            return MemoryClient()

        # Determine provider type based on environment
        # When OpenSearch is enabled we default to Bedrock for AWS compatibility,
        # otherwise align with the active CYBER_AGENT_PROVIDER (fallback to Ollama)
        active_provider = os.environ.get("CYBER_AGENT_PROVIDER", "ollama").lower()
        if os.environ.get("OPENSEARCH_HOST"):
            server_type = "bedrock"
        elif active_provider in ("litellm", "bedrock", "ollama"):
            server_type = active_provider
        elif active_provider == "gemini":
            server_type = "gemini"
        else:
            server_type = "ollama"

        if os.environ.get("OPENSEARCH_HOST"):
            merged_config = self._merge_config(config, server_type)
            self._realign_provider_configs(merged_config)
            config_manager = get_config_manager()

            # Resolve provider labels
            def _provider_label(p: str) -> str:
                mapping = {
                    "aws_bedrock": "AWS Bedrock",
                    "ollama": "Ollama",
                    "azure_openai": "Azure OpenAI",
                    "openai": "OpenAI",
                    "anthropic": "Anthropic",
                    "cohere": "Cohere",
                    "gemini": "Google Gemini",
                    "huggingface": "Hugging Face",
                    "sagemaker": "Amazon SageMaker",
                    "groq": "Groq",
                }
                return mapping.get(p, p or "unknown")

            embedder_cfg = merged_config.get("embedder", {})
            llm_cfg = merged_config.get("llm", {})
            embedder_provider = embedder_cfg.get("provider", "")
            llm_provider = llm_cfg.get("provider", "")
            embedder_model = embedder_cfg.get("config", {}).get("model")
            llm_model = llm_cfg.get("config", {}).get("model")
            # Prefer dims from vector_store config if present
            dims = (
                merged_config.get("vector_store", {})
                .get("config", {})
                .get("embedding_model_dims", 1024)
            )
            embedder_region = (
                embedder_cfg.get("config", {}).get("aws_region")
                or config_manager.get_default_region()
            )

            if not self.silent:
                print("[+] Memory Backend: OpenSearch")
                print(f"    Host: {os.environ.get('OPENSEARCH_HOST')}")
                # Only show region for AWS-based providers
                if embedder_provider == "aws_bedrock" or llm_provider == "aws_bedrock":
                    print(f"    Region: {embedder_region}")
                print(
                    f"    Embedder: {_provider_label(embedder_provider)} - {embedder_model} ({dims} dims)"
                )
                print(f"    LLM: {_provider_label(llm_provider)} - {llm_model}")
            logger.debug("Using OpenSearch backend (Mem0Memory with OpenSearch)")
            return self._initialize_opensearch_client(config, server_type)

        # FAISS backend
        logger.debug("Using FAISS backend (Mem0Memory with FAISS)")
        return self._initialize_faiss_client(
            config, server_type, self.has_existing_memories
        )

    def _initialize_opensearch_client(
        self, config: Optional[Dict] = None, server: str = "bedrock"
    ) -> Mem0Memory:
        """Initialize a Mem0 client with OpenSearch backend.

        Args:
            config: Optional configuration dictionary to override defaults.
            server: Server type for configuration.

        Returns:
            An initialized Mem0Memory instance configured for OpenSearch.
        """
        # Set up AWS region - prioritize passed config, then environment, then default
        merged_config = self._merge_config(config, server)
        self._realign_provider_configs(merged_config)
        config_manager = get_config_manager()
        config_region = (
            merged_config.get("embedder", {}).get("config", {}).get("aws_region")
        )
        self.region = (
            config_region
            or os.environ.get("AWS_REGION")
            or config_manager.get_default_region()
        )

        if not os.environ.get("AWS_REGION"):
            os.environ["AWS_REGION"] = self.region

        # Set up AWS credentials
        session = boto3.Session()
        credentials = session.get_credentials()
        auth = AWSV4SignerAuth(credentials, self.region, "es")

        # Prepare configuration
        merged_config["vector_store"]["config"].update(
            {"http_auth": auth, "host": os.environ["OPENSEARCH_HOST"]}
        )

        return Mem0Memory.from_config(config_dict=merged_config)

    def _initialize_faiss_client(
        self,
        config: Optional[Dict] = None,
        server: str = "ollama",
        has_existing_memories: bool = False,
    ) -> Mem0Memory:
        """Initialize a Mem0 client with FAISS backend.

        Args:
            config: Optional configuration dictionary to override defaults.
            server: Server type for configuration.

        Returns:
            An initialized Mem0Memory instance configured for FAISS.

        Raises:
            ImportError: If faiss-cpu package is not installed.
        """

        merged_config = self._merge_config(config, server)

        # Initialize store existence flag
        store_existed_before = False

        # Use provided path or create unified output structure path
        if merged_config.get("vector_store", {}).get("config", {}).get("path"):
            # Path already set in config (from args.memory_path)
            faiss_path = merged_config["vector_store"]["config"]["path"]
            # For custom paths, assume it's an existing store (like --memory-path flag)
            store_existed_before = os.path.exists(faiss_path)
        else:
            # Create memory path using unified output structure
            target_name = merged_config.get("target_name", "default_target")
            operation_id = merged_config.get("operation_id", "default_operation")

            # Get output directory from environment or config
            output_dir = os.environ.get("CYBER_AGENT_OUTPUT_DIR") or merged_config.get(
                "output_dir", "outputs"
            )

            # Memory isolation strategy (controlled via MEMORY_ISOLATION env var)
            # Options: "operation" (per-operation, safe for parallel) | "shared" (per-target, cross-learning)
            isolation_mode = os.environ.get("MEMORY_ISOLATION", "operation")

            if isolation_mode == "shared":
                # Shared per-target store (enables automatic cross-learning but parallel-unsafe)
                memory_base_path = os.path.join(output_dir, target_name, "memory")
                faiss_path = memory_base_path
                logger.info(
                    "Memory mode: SHARED per-target at %s (cross-learning enabled, NOT parallel-safe)",
                    memory_base_path
                )
            else:
                # Per-operation isolation (parallel-safe, explicit cross-learning needed)
                # Pattern: ./outputs/<target>/memory/<operation_id>/mem0_faiss
                memory_base_path = os.path.join(output_dir, target_name, "memory", operation_id)
                faiss_path = memory_base_path
                logger.info(
                    "Memory mode: ISOLATED per-operation at %s (parallel-safe)",
                    memory_base_path
                )

            # Check if store existed before we create directories
            store_existed_before = os.path.exists(memory_base_path)

            # Ensure the memory directory exists
            os.makedirs(memory_base_path, exist_ok=True)

        merged_config["vector_store"]["config"]["path"] = faiss_path

        # Display FAISS configuration (unless silent mode for report generation)
        if not self.silent:
            print("[+] Memory Backend: FAISS (local)")
            print(f"    Store Location: {faiss_path}")

            # Display embedder/LLM configuration
            def _provider_label(p: str) -> str:
                mapping = {
                    "aws_bedrock": "AWS Bedrock",
                    "ollama": "Ollama",
                    "azure_openai": "Azure OpenAI",
                    "openai": "OpenAI",
                    "anthropic": "Anthropic",
                    "cohere": "Cohere",
                    "gemini": "Google Gemini",
                    "huggingface": "Hugging Face",
                    "sagemaker": "Amazon SageMaker",
                    "groq": "Groq",
                    "litellm": "LiteLLM",
                }
                return mapping.get(p, p or "unknown")

            embedder_config = merged_config.get("embedder", {})
            llm_config = merged_config.get("llm", {})
            embedder_provider = embedder_config.get("provider", "")
            llm_provider = llm_config.get("provider", "")
            embedder_model = embedder_config.get("config", {}).get("model")
            llm_model = llm_config.get("config", {}).get("model")
            # Prefer dims from vector_store config if present
            dims = (
                merged_config.get("vector_store", {})
                .get("config", {})
                .get("embedding_model_dims", 1024)
            )

            # Derive region only for AWS-based providers
            config_manager = get_config_manager()
            embedder_region = embedder_config.get("config", {}).get(
                "aws_region", config_manager.get_default_region()
            )

            # Show region only when relevant
            if embedder_provider == "aws_bedrock" or llm_provider == "aws_bedrock":
                print(f"    Region: {embedder_region}")

            # Pretty print providers
            print(
                f"    Embedder: {_provider_label(embedder_provider)} - {embedder_model} ({dims} dims)"
            )

            # If using LiteLLM for LLM, try to extract actual provider from model prefix for display
            display_llm_provider = _provider_label(llm_provider)
            if (
                llm_provider in ("", "litellm")
                and isinstance(llm_model, str)
                and "/" in llm_model
            ):
                prefix = llm_model.split("/", 1)[0].lower()
                display_llm_provider = _provider_label(
                    {
                        "bedrock": "aws_bedrock",
                        "azure": "azure_openai",
                        "openai": "openai",
                        "anthropic": "anthropic",
                        "cohere": "cohere",
                        "gemini": "gemini",
                        "sagemaker": "sagemaker",
                        "groq": "groq",
                        "xai": "huggingface",
                        "mistral": "huggingface",
                    }.get(prefix, llm_provider)
                )

            print(f"    LLM: {display_llm_provider} - {llm_model}")

            # Display appropriate message based on whether store existed before initialization
            # Use has_existing_memories parameter which includes proper file size validation
            if has_existing_memories or store_existed_before:
                print(f"    Loading existing FAISS store from: {faiss_path}")
                print("    Memory will persist across operations for this target")
            else:
                # For fresh starts, just show the persistence message
                print("    Memory will persist across operations for this target")

        logger.debug("Initializing Mem0Memory with config: %s", merged_config)
        try:
            mem0_client = Mem0Memory.from_config(config_dict=merged_config)
            logger.debug("Mem0Memory client initialized successfully")
            return mem0_client
        except Exception as e:
            # Check if this is an Ollama network error (model may already exist locally)
            error_msg = str(e)
            if "connection reset" in error_msg or "pull model manifest" in error_msg:
                logger.warning(
                    "Ollama network error during model pull - model may already exist locally, retrying initialization..."
                )
                # Retry once without forcing model pull (Mem0 will use existing local model)
                try:
                    mem0_client = Mem0Memory.from_config(config_dict=merged_config)
                    logger.info(
                        "Mem0Memory initialized successfully on retry (using existing local model)"
                    )
                    return mem0_client
                except Exception as retry_error:
                    logger.error("Retry failed: %s", retry_error)
                    raise retry_error
            elif (
                "Unknown provider in model" in error_msg
                or "Unsupported LLM provider" in error_msg
            ):
                logger.warning(
                    "Mem0 provider mismatch detected (%s). Applying OpenAI-compatible fallback.",
                    error_msg,
                )
                self._realign_provider_configs(merged_config, force_openai=True)
                try:
                    mem0_client = Mem0Memory.from_config(config_dict=merged_config)
                    logger.info(
                        "Mem0Memory initialized successfully after provider fallback"
                    )
                    return mem0_client
                except Exception as retry_error:
                    logger.error("Provider fallback failed: %s", retry_error)
                    raise retry_error
            else:
                logger.error("Failed to initialize Mem0Memory client: %s", e)
                raise

    def _merge_config(
        self, config: Optional[Dict] = None, server: str = "bedrock"
    ) -> Dict:
        """Merge user-provided configuration with default configuration.

        Args:
            config: Optional configuration dictionary to override defaults.
            server: Server type for configuration.

        Returns:
            A merged configuration dictionary.
        """
        merged_config = self.get_default_config(server).copy()
        if not config:
            return merged_config

        # Deep merge the configs
        for key, value in config.items():
            if (
                key in merged_config
                and isinstance(value, dict)
                and isinstance(merged_config[key], dict)
            ):
                merged_config[key].update(value)
            else:
                merged_config[key] = value

        return merged_config

    @staticmethod
    def _split_model_identifier(model_id: Any) -> Tuple[str, str]:
        if not isinstance(model_id, str):
            return "", ""
        if "/" in model_id:
            prefix, remainder = model_id.split("/", 1)
            return prefix.lower(), remainder
        return "", model_id

    def _inject_azure_defaults(
        self, section_config: Dict[str, Any], deployment: str
    ) -> None:
        section_config["azure_kwargs"] = {
            "api_key": os.getenv("AZURE_API_KEY", ""),
            "azure_deployment": deployment,
            "azure_endpoint": os.getenv("AZURE_API_BASE", ""),
            "api_version": os.getenv("AZURE_API_VERSION", ""),
        }
        azure_kwargs = section_config["azure_kwargs"]
        if not all(azure_kwargs.values()):
            logger.warning(
                "Azure OpenAI credentials appear incomplete. Values set: endpoint=%s, deployment=%s",
                azure_kwargs.get("azure_endpoint"),
                azure_kwargs.get("azure_deployment"),
            )

    def _realign_provider_configs(
        self, merged_config: Dict[str, Any], *, force_openai: bool = False
    ) -> None:
        """Ensure Mem0 provider sections match the selected model identifiers."""
        if force_openai and not os.getenv("OPENAI_API_KEY"):
            logger.warning(
                "Skipping OpenAI provider fallback because OPENAI_API_KEY is not set"
            )
            force_openai = False
        for section_key in ("embedder", "llm"):
            section = merged_config.get(section_key)
            if not isinstance(section, dict):
                continue
            config_section = section.setdefault("config", {})
            model_id = config_section.get("model")
            provider = (section.get("provider") or "").lower()

            if force_openai and section_key == "llm":
                section["provider"] = "openai"
                if not isinstance(model_id, str) or "/" in model_id or not model_id:
                    config_section["model"] = os.getenv(
                        "MEM0_FALLBACK_LLM_MODEL", "gpt-4o-mini"
                    )
                continue

            if not isinstance(model_id, str):
                continue
            prefix, remainder = self._split_model_identifier(model_id)
            if not prefix:
                continue
            mapped_provider = MEM0_PROVIDER_MAP.get(prefix)
            if not mapped_provider:
                continue

            if mapped_provider == provider:
                if mapped_provider == "azure_openai" and remainder:
                    config_section["model"] = remainder
                    self._inject_azure_defaults(config_section, remainder)
                continue

            if provider not in ("aws_bedrock", "", "ollama", "litellm"):
                continue

            section["provider"] = mapped_provider
            if remainder:
                config_section["model"] = remainder
            if mapped_provider == "azure_openai":
                self._inject_azure_defaults(
                    config_section, remainder or config_section.get("model", "")
                )
            logger.warning(
                "Aligned Mem0 %s provider from '%s' to '%s' for model '%s'",
                section_key,
                provider or "unknown",
                mapped_provider,
                model_id,
            )

    def store_memory(
        self,
        content: str,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ):
        """Store a memory in Mem0 with native operation scoping via run_id.

        Uses run_id for mem0's native operation isolation instead of manual metadata filtering.
        This provides O(log n) indexed lookups vs O(n) local filtering.
        """
        if not user_id and not agent_id:
            raise ValueError("Either user_id or agent_id must be provided")

        # Default agent_id to user_id to avoid null actor attribution in some backends
        if user_id and not agent_id:
            agent_id = user_id

        metadata = metadata or {}

        # Get operation ID for native session scoping
        op_id = os.getenv("CYBER_OPERATION_ID")

        messages = [{"role": "user", "content": content}]
        try:
            # For cybersecurity findings, use infer=False to ensure all data is stored
            # regardless of mem0's fact filtering (critical for security assessments)
            # Use session_id=operation_id for mem0's native operation isolation
            add_kwargs = {
                "messages": messages,
                "user_id": user_id,
                "agent_id": agent_id,
                "metadata": metadata,
                "infer": False,
            }

            # Add run_id for native operation scoping (mem0 1.0.0 API)
            if op_id:
                add_kwargs["run_id"] = op_id
                metadata["operation_id"] = op_id

            # Debug: Log metadata BEFORE storage
            logger.debug(
                "BEFORE mem0.add() - category=%s, metadata=%s",
                metadata.get("category") if metadata else "none",
                metadata
            )

            # Use thread lock for FAISS write safety (prevents index corruption
            # during concurrent writes from swarm agents)
            with _FAISS_WRITE_LOCK:
                result = self.mem0.add(**add_kwargs)

            # Debug: Verify what was actually stored
            logger.info(
                "Memory stored successfully - run_id=%s, category=%s, result=%s",
                op_id or "none",
                metadata.get("category") if metadata else "none",
                result
            )

            return result
        except Exception as e:
            logger.error("Critical error storing memory: %s", str(e), exc_info=True)
            logger.error("Exception type: %s", type(e).__name__)
            logger.error("Exception args: %s", e.args)
            raise RuntimeError(f"Memory storage failed: {str(e)}") from e

    def get_memory(self, memory_id: str):
        """Get a memory by ID."""
        return self.mem0.get(memory_id)

    def list_memories(
        self,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        *,
        limit: Optional[int] = None,
        page: int = 1,
        run_id: Optional[str] = None,
    ):
        """List memories for a user/agent with safe defaults and pagination.

        Args:
            user_id: User identifier
            agent_id: Agent identifier
            limit: Maximum number of memories to return
            page: Page number for pagination
            run_id: Operation/session ID for scoping (None = all operations)

        Falls back gracefully if backend doesn't support limit/page/run_id.
        """
        if not user_id and not agent_id:
            raise ValueError("Either user_id or agent_id must be provided")

        logger.debug(
            "Calling mem0.get_all with user_id=%s, agent_id=%s, run_id=%s",
            user_id, agent_id, run_id
        )

        # Determine effective limit from env or passed arg (default 100 for report consistency)
        try:
            default_limit = int(os.getenv("MEM0_LIST_LIMIT", "100"))
        except Exception:
            default_limit = 100
        eff_limit = (
            int(limit) if isinstance(limit, int) and limit > 0 else default_limit
        )

        # Build base kwargs
        base_kwargs = {}
        if user_id:
            base_kwargs["user_id"] = user_id
        if agent_id:
            base_kwargs["agent_id"] = agent_id
        if run_id:
            base_kwargs["run_id"] = run_id

        # Try variants: with limit/page, with limit only, then no args
        # Normalize and slice to eff_limit as a last resort
        try:
            try:
                result = self.mem0.get_all(
                    **base_kwargs, limit=eff_limit, page=page
                )
            except TypeError:
                try:
                    result = self.mem0.get_all(
                        **base_kwargs, limit=eff_limit
                    )
                except TypeError:
                    try:
                        result = self.mem0.get_all(**base_kwargs)
                    except TypeError as te:
                        if "run_id" in base_kwargs:
                            no_run_id = base_kwargs.copy()
                            no_run_id.pop("run_id")
                            result = self.mem0.get_all(**no_run_id)
                        else:
                            raise te
            logger.debug("mem0.get_all returned type: %s", type(result))
            # Normalize structures
            normalised = self._normalise_results_list(result)
            if normalised:
                return normalised[:eff_limit]
            if isinstance(result, list):
                return result[:eff_limit]
            return result
        except Exception as e:
            logger.error("Error in mem0.get_all: %s", e)
            raise

    def search_memories(
            self,
            query: str,
            user_id: Optional[str] = None,
            agent_id: Optional[str] = None,
            run_id: Optional[str] = None,
    ):
        """Search memories using semantic search."""
        if not user_id and not agent_id:
            raise ValueError("Either user_id or agent_id must be provided")

        # Delegate to the compatibility search helper for normalized results
        return self.search(
            query=query,
            filters=None,
            limit=20,
            user_id=user_id or "cyber_agent",
            agent_id=agent_id,
            run_id=run_id,
        )

    def search(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        *,
        user_id: str = "cyber_agent",
        agent_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Compatibility wrapper providing Mem0-style search with filter support.

        Args:
            query: Semantic search query
            filters: Metadata filters (legacy - use run_id for operation scoping)
            limit: Maximum results to return (default 100 for report consistency)
            user_id: User identifier
            agent_id: Agent identifier
            run_id: Run/operation ID for native mem0 scoping (recommended)

        Returns:
            List of memory dictionaries with 'memory' and 'metadata' fields
        """

        filters = filters or {}
        top_k = max(int(limit or 100), 1)

        def _coerce_entry(entry: Any) -> Dict[str, Any]:
            """Ensure every entry behaves like a memory dict."""
            if isinstance(entry, dict):
                return entry
            if isinstance(entry, str):
                return {"memory": entry, "metadata": {}}
            if entry is None:
                return {"memory": "", "metadata": {}}
            # Fallback stringify for unexpected types (lists/tuples/etc.)
            try:
                text = (
                    json.dumps(entry)
                    if isinstance(entry, (list, tuple, set))
                    else str(entry)
                )
            except Exception:  # pragma: no cover - defensive conversion
                text = str(entry)
            return {"memory": text, "metadata": {}}

        # Try native Mem0 search first (covers FAISS/OpenSearch/Platform backends)
        if hasattr(self.mem0, "search"):
            search_kwargs: Dict[str, Any] = {"user_id": user_id}
            if agent_id:
                search_kwargs["agent_id"] = agent_id

            # Prefer run_id for operation scoping (mem0 1.0.0 API)
            if run_id:
                search_kwargs["run_id"] = run_id
                logger.debug("Using run_id=%s for native operation scoping", run_id)

            # Pass filters to mem0's native search (supports advanced operators like "in")
            if filters:
                search_kwargs["filters"] = filters

            for size_kw in ("top_k", "limit"):
                try:
                    search_kwargs[size_kw] = top_k
                    results = self.mem0.search(query=query, **search_kwargs)
                    normalised = self._normalise_results_list(results)
                    if normalised:
                        coerced = [_coerce_entry(entry) for entry in normalised]
                        return coerced[:top_k]
                    if isinstance(results, list):
                        coerced = [_coerce_entry(entry) for entry in results]
                        return coerced[:top_k]
                except TypeError:
                    search_kwargs.pop(size_kw, None)
                except Exception as exc:  # pragma: no cover - backend specific
                    logger.debug("Native Mem0 search failed (%s): %s", size_kw, exc)
                    break

        # Fallback: list memories and apply lightweight filtering locally
        try:
            # Pass run_id to list_memories for consistent scoping
            all_memories = self.list_memories(
                user_id=user_id, agent_id=agent_id, run_id=run_id
            )
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.warning("Fallback memory listing failed during search: %s", exc)
            return []

        raw_entries = self._normalise_results_list(all_memories)
        if not raw_entries and isinstance(all_memories, list):
            raw_entries = all_memories

        raw_entries = [_coerce_entry(entry) for entry in raw_entries]

        # If run_id was provided but list_memories didn't filter (backend limitation),
        # apply local filtering by operation_id in metadata
        if run_id:
            raw_entries = [
                e for e in raw_entries
                if e.get("metadata", {}).get("operation_id") == run_id
                or e.get("run_id") == run_id
            ]

        def _matches_filters(entry: Dict[str, Any]) -> bool:
            """Match filters with support for simple list values (FAISS-compatible)."""
            metadata = entry.get("metadata", {}) or {}
            for key, value in filters.items():
                meta_val = metadata.get(key)
                # Handle list filter values (e.g., {"category": ["finding", "observation"]})
                if isinstance(value, list):
                    if meta_val not in value:
                        return False
                elif str(meta_val) != str(value):
                    return False
            return True

        if query:
            terms = [term.lower() for term in re.split(r"\s+", query) if term]
        else:
            terms = []

        results: List[Dict[str, Any]] = []
        for entry in raw_entries:
            if filters and not _matches_filters(entry):
                continue

            if terms:
                text = " ".join(
                    str(part)
                    for part in (
                        entry.get("memory"),
                        entry.get("content"),
                        json.dumps(entry.get("metadata", {}), default=str),
                    )
                    if part
                ).lower()
                if not all(term in text for term in terms):
                    continue

            results.append(entry)
            if len(results) >= top_k:
                break

        return results

    def delete_memory(self, memory_id: str):
        """Delete a memory by ID."""
        return self.mem0.delete(memory_id)

    def get_memory_history(self, memory_id: str):
        """Get the history of a memory by ID."""
        return self.mem0.history(memory_id)

    def _display_startup_overview(self) -> None:
        """Display memory overview at startup if memories exist."""
        try:
            # For Mem0 Platform & OpenSearch - always display (remote backends)
            # For FAISS - only if memories existed before init
            should_display = (
                os.environ.get("MEM0_API_KEY")
                or os.environ.get("OPENSEARCH_HOST")
                or self.has_existing_memories
            )

            if not should_display:
                return

            # Get and display overview
            overview = self.get_memory_overview(user_id="cyber_agent")

            if overview.get("error"):
                print(
                    f"    Warning: Could not retrieve memory overview: {overview['error']}"
                )
                return

            if not overview.get("has_memories"):
                print("    No existing memories found - starting fresh")
                return

            # Display overview
            total = overview.get("total_count", 0)
            categories = overview.get("categories", {})
            recent_findings = overview.get("recent_findings", [])

            print(f"    Found {total} existing memories:")

            # Show category breakdown
            if categories:
                category_parts = [
                    f"{count} {category}" for category, count in categories.items()
                ]
                print(f"      Categories: {', '.join(category_parts)}")

            # Show recent findings
            if recent_findings:
                print("      Recent findings:")
                for i, finding in enumerate(recent_findings[:3], 1):
                    content = finding.get("content", "")
                    if len(content) > 80:
                        content = content[:77] + "..."
                    print(f"        {i}. {content}")

            print("    Memory will be loaded as first action to avoid duplicate work")

        except Exception as e:
            logger.debug("Could not display startup memory overview: %s", str(e))
            print(f"    Note: Could not check existing memories: {str(e)}")

    def store_plan(
        self,
        plan_content: Union[str, Dict],
        user_id: str = "cyber_agent",
        metadata: Optional[Dict] = None,
    ) -> Dict:
        """Store a strategic plan in memory with category='plan'.

        REQUIRES dict format (JSON string is parsed before this method)

        Args:
            plan_content: The strategic plan dict with required fields
            user_id: User ID for memory storage
            metadata: Optional metadata (will be enhanced with category='plan')

        Returns:
            Memory storage result
        """
        # This should always be a dict (mem0_memory parses JSON strings)
        if isinstance(plan_content, str):
            logger.error("Unexpected string in store_plan - should be dict")
            raise ValueError(
                "Internal error: plan_content should be dict at this point. "
                "The mem0_memory function should have parsed any JSON string."
            )

        # Validate required fields
        required_fields = ["objective", "current_phase", "total_phases", "phases"]
        missing = [f for f in required_fields if f not in plan_content]
        if missing:
            logger.error(f"Plan missing required fields: {missing}")
            raise ValueError(
                f"Plan missing required fields: {missing}. See tool docstring for format."
            )

        # Validate phases structure
        if (
            not isinstance(plan_content.get("phases"), list)
            or not plan_content["phases"]
        ):
            raise ValueError("Plan must have 'phases' as non-empty list")

        for idx, phase in enumerate(plan_content["phases"]):
            # Validate each phase is a dict
            if not isinstance(phase, dict):
                raise ValueError(
                    f"Phase at index {idx} must be a dict/object, got {type(phase).__name__}"
                )
            # Make criteria optional with default empty string
            phase_required = ["id", "title", "status"]
            phase_missing = [f for f in phase_required if f not in phase]
            if phase_missing:
                raise ValueError(
                    f"Phase {phase.get('id', '?')} missing fields: {phase_missing}"
                )
            # Set default empty criteria if not provided
            phase.setdefault("criteria", "")

        # Format dict as structured text for storage
        plan_content_str = _format_plan_as_toon(plan_content)
        plan_structured = True

        plan_metadata = metadata or {}
        plan_metadata.update(
            {
                "category": "plan",
                "created_at": datetime.now().isoformat(),
                "type": "strategic_plan",
                "structured": plan_structured,
                "plan_format": "toon",
                "active": True,
                "plan_json": plan_content,  # Store original JSON in metadata
            }
        )
        # Tag with current operation ID (prefer client config, then env)
        op_id = (self.config or {}).get("operation_id") or os.getenv(
            "CYBER_OPERATION_ID"
        )
        if op_id:
            plan_metadata["operation_id"] = op_id

        # Warn if extending plan after marking complete
        try:
            prev = self.get_active_plan(user_id, operation_id=op_id)
            if prev:
                prev_json = prev.get("metadata", {}).get("plan_json", {})
                new_total = int(
                    plan_content.get(
                        "total_phases", len(plan_content.get("phases", []))
                    )
                )
                if prev_json.get("assessment_complete") and new_total > int(
                    prev_json.get("total_phases", 0)
                ):
                    logger.warning(
                        f"Adding phases ({prev_json.get('total_phases')} → {new_total}) after assessment_complete=true. "
                        "Consider stopping and generating report instead."
                    )
        except Exception as e:
            logger.debug(f"Could not check previous plan for extension: {e}")

        # Deactivate previous plans
        try:
            # TODO: change query to filters
            previous_plans = self.search_memories(
                "category:plan active:true", user_id=user_id, run_id=op_id
            )
            if isinstance(previous_plans, list):
                for plan in previous_plans:
                    if plan.get("id"):
                        logger.debug(f"Deactivating plan {plan.get('id')}")
                        # Mark as inactive
                        self.store_memory(
                            content=plan.get("memory", ""),
                            user_id=user_id,
                            metadata={**plan.get("metadata", {}), "active": False},
                        )
        except Exception as e:
            logger.debug(f"Could not deactivate previous plans: {e}")

        # Check if all phases complete and add reminder
        all_done = all(
            p.get("status") == "done" for p in plan_content.get("phases", [])
        )
        add_stop_reminder = False
        if all_done and not plan_content.get("assessment_complete"):
            plan_content["assessment_complete"] = True
            add_stop_reminder = True
            logger.info("All phases complete - set assessment_complete=true")

        result = self.store_memory(
            content=f"[PLAN] {plan_content_str}",
            user_id=user_id,
            metadata=plan_metadata,
        )

        if add_stop_reminder:
            result["_reminder"] = (
                "All phases complete. Call stop('Assessment complete: X phases done, Y findings')"
            )

        return result

    def store_reflection(
        self,
        reflection_content: str,
        plan_id: Optional[str] = None,
        user_id: str = "cyber_agent",
        metadata: Optional[Dict] = None,
    ) -> Dict:
        """Store a reflection on findings and plan progress.

        Args:
            reflection_content: The reflection content
            plan_id: Optional ID of the plan being reflected upon
            user_id: User ID for memory storage
            metadata: Optional metadata (will be enhanced with category='reflection')

        Returns:
            Memory storage result with plan evaluation reminder
        """
        reflection_metadata = metadata or {}
        reflection_metadata.update(
            {
                "category": "reflection",
                "created_at": datetime.now().isoformat(),
                "type": "plan_reflection",
            }
        )
        # Tag with current operation ID when available
        op_id = os.getenv("CYBER_OPERATION_ID")
        if op_id and "operation_id" not in reflection_metadata:
            reflection_metadata["operation_id"] = op_id

        if plan_id:
            reflection_metadata["related_plan_id"] = plan_id

        result = self.store_memory(
            content=f"[REFLECTION] {reflection_content}",
            user_id=user_id,
            metadata=reflection_metadata,
        )

        # Add plan evaluation reminder
        result["_reminder"] = (
            "Reflection stored. Now: get_plan → check if phase criteria met or pivot needed → update if yes"
        )

        return result

    def get_active_plan(
        self, user_id: str = "cyber_agent", operation_id: Optional[str] = None
    ) -> Optional[Dict]:
        """Get the most recent active plan, preferring the current operation.

        This avoids semantic-search drift by listing all memories and selecting the
        newest plan entry (by created_at) with metadata.active == True. If an
        operation_id is provided, only consider plans tagged with that ID.

        Args:
            user_id: User ID to search plans for
            operation_id: Optional operation ID to scope plan selection

        Returns:
            Most recent active plan or None if no plans found
        """
        try:
            # Use run_id scoping to get operation-specific plans
            all_memories = self.list_memories(user_id=user_id, run_id=operation_id, limit=100)

            if isinstance(all_memories, dict):
                raw = (
                    all_memories.get("results", [])
                    or all_memories.get("memories", [])
                    or []
                )
            elif isinstance(all_memories, list):
                raw = all_memories
            else:
                raw = []

            # Filter to plan items from current operation
            plan_items: List[Dict[str, Any]] = []
            for m in raw:
                meta = m.get("metadata", {}) or {}
                if str(meta.get("category", "")) != "plan":
                    continue
                plan_items.append(m)

            if not plan_items:
                return None

            # Sort by created_at (desc). If missing, keep original order.
            def _dt(x: Dict[str, Any]) -> str:
                return str(x.get("metadata", {}).get("created_at", ""))

            plan_items.sort(key=_dt, reverse=True)

            # Prefer the first active plan; if none, return most recent plan
            for m in plan_items:
                meta = m.get("metadata", {}) or {}
                if meta.get("active", False) is True:
                    return m

            return plan_items[0]
        except Exception as e:
            logger.error(f"Error retrieving active plan: {e}")
            return None

    def reflect_on_findings(
        self,
        recent_findings: List[Dict],
        current_plan: Optional[Dict] = None,
        user_id: str = "cyber_agent",
    ) -> str:
        """Generate reflection prompt based on recent findings and current plan.

        Args:
            recent_findings: List of recent findings to reflect on
            current_plan: Current active plan (optional)
            user_id: User ID for memory operations

        Returns:
            Reflection prompt for the agent
        """
        if not recent_findings:
            return "No recent findings to reflect on."

        # Summarize recent findings
        findings_summary = []
        for finding in recent_findings[:5]:  # Last 5 findings
            content = finding.get("memory", finding.get("content", ""))[:100]
            metadata = finding.get("metadata", {})
            severity = str(metadata.get("severity", "unknown"))
            findings_summary.append(f"- [{severity.upper()}] {content}")

        reflection_prompt = f"""
## REFLECTION REQUIRED

**Recent Findings ({len(findings_summary)}):**
{chr(10).join(findings_summary)}

**Current Plan Status:**
"""

        if current_plan:
            plan_content = current_plan.get("memory", current_plan.get("content", ""))[
                :200
            ]
            reflection_prompt += f"""
Active plan: {plan_content}

**Required Actions:**
1. Is current phase criteria satisfied? If YES → mark status="done", advance current_phase, store_plan
2. Should we pivot strategy? If YES → update phases with new approach, store_plan
3. Phase stuck >40% budget? If YES → force advance to next phase
4. Deploy swarms if multiple vectors or <70% budget with no progress

After analysis: get_plan → evaluate → update phases if needed → store_plan → continue
"""
        else:
            reflection_prompt += """
No active plan found.

**Required Action:**
Create strategic plan NOW with store_plan before continuing.
Include: objective, current_phase=1, phases with clear criteria for each.
"""

        return reflection_prompt

    def get_memory_overview(self, user_id: str = "cyber_agent") -> Dict:
        """Get overview of memories for startup display.

        Args:
            user_id: User ID to retrieve memories for

        Returns:
            Dictionary containing memory overview data
        """
        try:
            # Get all memories for the user
            logger.debug("Getting memory overview for user_id: %s", user_id)

            memories_response = self.list_memories(user_id=user_id)
            logger.debug(
                "Memory overview raw response type: %s", type(memories_response)
            )
            logger.debug("Memory overview raw response: %s", memories_response)

            # Parse response format
            if isinstance(memories_response, dict):
                raw_memories = memories_response.get(
                    "memories", memories_response.get("results", [])
                )
                logger.debug("Dict response: found %d memories", len(raw_memories))
            elif isinstance(memories_response, list):
                raw_memories = memories_response
                logger.debug("List response: found %d memories", len(raw_memories))
            else:
                raw_memories = []
                logger.debug("Unexpected response type, using empty list")

            # Analyze memories
            total_count = len(raw_memories)
            categories = {}
            recent_findings = []

            for memory in raw_memories:
                # Extract metadata
                metadata = memory.get("metadata", {})
                category = metadata.get("category", "general")

                # Count by category
                categories[category] = categories.get(category, 0) + 1

                # Collect recent findings
                if category == "finding":
                    recent_findings.append(
                        {
                            "content": (
                                memory.get("memory", "")[:100] + "..."
                                if len(memory.get("memory", "")) > 100
                                else memory.get("memory", "")
                            ),
                            "created_at": memory.get("created_at",
                                                     memory.get("metadata", {}).get("created_at", "Unknown")),
                        }
                    )

            # Sort recent findings by creation date (most recent first)
            recent_findings.sort(key=lambda x: x.get("created_at", ""), reverse=True)

            return {
                "total_count": total_count,
                "categories": categories,
                "recent_findings": recent_findings[:3],  # Top 3 most recent
                "has_memories": total_count > 0,
            }

        except Exception as e:
            logger.error("Error getting memory overview: %s", str(e))
            return {
                "total_count": 0,
                "categories": {},
                "recent_findings": [],
                "has_memories": False,
                "error": str(e),
            }


def format_get_response(memory: Dict) -> Panel:
    """Format get memory response."""
    memory_id = memory.get("id", "unknown")
    content = memory.get("memory", "No content available")
    metadata = memory.get("metadata", {})
    created_at = memory.get("created_at", metadata.get("created_at", "Unknown"))
    user_id = memory.get("user_id", "Unknown")

    result = [
        "✅ Memory retrieved successfully:",
        f"🔑 Memory ID: {memory_id}",
        f"👤 User ID: {user_id}",
        f"🕒 Created: {created_at}",
    ]

    if metadata:
        result.append(f"📋 Metadata: {json.dumps(metadata, indent=2)}")

    result.append(f"\n📄 Memory: {content}")

    return Panel(
        "\n".join(result), title="[bold green]Memory Retrieved", border_style="green"
    )


def format_list_response(memories: List[Dict]) -> Panel:
    """Format list memories response."""
    if not memories:
        return Panel(
            "No memories found.",
            title="[bold yellow]No Memories",
            border_style="yellow",
        )

    table = Table(title="Memories", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan")
    table.add_column("Memory", style="yellow", width=50)
    table.add_column("Created At", style="blue")
    table.add_column("User ID", style="green")
    table.add_column("Metadata", style="magenta")

    for memory in memories:
        metadata = memory.get("metadata", {})
        memory_id = memory.get("id", "unknown")
        content = memory.get("memory", "No content available")
        created_at = memory.get("created_at", metadata.get("created_at", "Unknown"))
        user_id = memory.get("user_id", "Unknown")

        # Truncate content if too long
        content_preview = (
            content[:100] + "..." if content and len(content) > 100 else content
        )

        # Format metadata for display
        metadata_str = json.dumps(metadata, indent=2) if metadata else "None"

        table.add_row(memory_id, content_preview, created_at, user_id, metadata_str)

    return Panel(table, title="[bold green]Memories List", border_style="green")


def format_delete_response(memory_id: str) -> Panel:
    """Format delete memory response."""
    content = [
        "✅ Memory deleted successfully:",
        f"🔑 Memory ID: {memory_id}",
    ]
    return Panel(
        "\n".join(content), title="[bold green]Memory Deleted", border_style="green"
    )


def format_retrieve_response(memories: List[Dict]) -> Panel:
    """Format retrieve response."""
    if not memories:
        return Panel(
            "No memories found matching the query.",
            title="[bold yellow]No Matches",
            border_style="yellow",
        )

    table = Table(title="Search Results", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan")
    table.add_column("Memory", style="yellow", width=50)
    table.add_column("Relevance", style="green")
    table.add_column("Created At", style="blue")
    table.add_column("User ID", style="magenta")
    table.add_column("Metadata", style="white")

    for memory in memories:
        metadata = memory.get("metadata", {})
        memory_id = memory.get("id", "unknown")
        content = memory.get("memory", "No content available")
        score = memory.get("score", 0)
        created_at = memory.get("created_at", metadata.get("created_at", "Unknown"))
        user_id = memory.get("user_id", "Unknown")

        # Truncate content if too long
        content_preview = (
            content[:100] + "..." if content and len(content) > 100 else content
        )

        # Format metadata for display
        metadata_str = json.dumps(metadata, indent=2) if metadata else "None"

        # Color code the relevance score
        if score > 0.8:
            score_color = "green"
        elif score > 0.5:
            score_color = "yellow"
        else:
            score_color = "red"

        table.add_row(
            memory_id,
            content_preview,
            f"[{score_color}]{score}[/{score_color}]",
            created_at,
            user_id,
            metadata_str,
        )

    return Panel(table, title="[bold green]Search Results", border_style="green")


def format_history_response(history: List[Dict]) -> Panel:
    """Format memory history response."""
    if not history:
        return Panel(
            "No history found for this memory.",
            title="[bold yellow]No History",
            border_style="yellow",
        )

    table = Table(title="Memory History", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan")
    table.add_column("Memory ID", style="green")
    table.add_column("Event", style="yellow")
    table.add_column("Old Memory", style="blue", width=30)
    table.add_column("New Memory", style="blue", width=30)
    table.add_column("Created At", style="magenta")

    for entry in history:
        entry_id = entry.get("id", "unknown")
        memory_id = entry.get("memory_id", "unknown")
        event = entry.get("event", "UNKNOWN")
        old_memory = entry.get("old_memory", "None")
        new_memory = entry.get("new_memory", "None")
        created_at = entry.get("created_at", "Unknown")

        # Truncate memory content if too long
        old_memory_preview = (
            old_memory[:100] + "..."
            if old_memory and len(old_memory) > 100
            else old_memory
        )
        new_memory_preview = (
            new_memory[:100] + "..."
            if new_memory and len(new_memory) > 100
            else new_memory
        )

        table.add_row(
            entry_id,
            memory_id,
            event,
            old_memory_preview,
            new_memory_preview,
            created_at,
        )

    return Panel(table, title="[bold green]Memory History", border_style="green")


def format_store_response(results: List[Dict]) -> Panel:
    """Format store memory response."""
    if not results:
        return Panel(
            "No memories stored.",
            title="[bold yellow]No Memories Stored",
            border_style="yellow",
        )

    table = Table(title="Memory Stored", show_header=True, header_style="bold magenta")
    table.add_column("Operation", style="green")
    table.add_column("Content", style="yellow", width=50)

    for memory in results:
        event = memory.get("event")
        text = memory.get("memory")
        # Truncate content if too long
        content_preview = text[:100] + "..." if text and len(text) > 100 else text
        table.add_row(event, content_preview)

    return Panel(table, title="[bold green]Memory Stored", border_style="green")


def initialize_memory_system(
    config: Optional[Dict] = None,
    operation_id: Optional[str] = None,
    target_name: Optional[str] = None,
    has_existing_memories: bool = False,
    silent: bool = False,
) -> None:
    """Initialize the memory system with custom configuration.

    Args:
        config: Optional configuration dictionary with embedder, llm, vector_store settings
        operation_id: Unique operation identifier
        target_name: Sanitized target name for organizing memory by target
        has_existing_memories: Whether memories already existed before initialization
        silent: If True, suppress initialization output (used during report generation)
    """
    global _MEMORY_CONFIG, _MEMORY_CLIENT

    # Create enhanced config with operation context
    enhanced_config = config.copy() if config else {}
    enhanced_config["operation_id"] = (
        operation_id or f"OP_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    enhanced_config["target_name"] = target_name or "default_target"

    # Expose operation context for downstream components that rely on env
    try:
        os.environ["CYBER_OPERATION_ID"] = enhanced_config["operation_id"]
    except Exception:
        pass

    _MEMORY_CONFIG = enhanced_config
    _MEMORY_CLIENT = Mem0ServiceClient(enhanced_config, has_existing_memories, silent)
    logger.info(
        "Memory system initialized for operation %s, target: %s",
        enhanced_config["operation_id"],
        enhanced_config["target_name"],
    )


def get_memory_client(silent: bool = False) -> Optional[Mem0ServiceClient]:
    """Get the current memory client, initializing if needed.

    Args:
        silent: If True, suppress initialization output (used during report generation)

    Returns:
        The memory client instance or None if initialization fails
    """
    global _MEMORY_CLIENT
    if _MEMORY_CLIENT is None:
        # Try to initialize with default config
        try:
            initialize_memory_system(silent=silent)
        except Exception as e:
            logger.error("Failed to auto-initialize memory client: %s", e)
            return None
    return _MEMORY_CLIENT


@tool
def mem0_memory(
    action: str,
    content: Union[str, Dict[str, Any], None] = None,
    memory_id: Optional[str] = None,
    query: Optional[str] = None,
    user_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    metadata: Optional[Dict] = None,
    cross_operation: bool = False,
) -> str:
    """
    Memory management with automatic operation scoping and cross-session learning.

    QUICK START:
        # Store finding ONLY after flag submission succeeds
        mem0_memory(action="store",
            content="[FINDING] Challenge 54373 - Flag: HTB{...} - Technique: buffer_overflow",
            metadata={"category": "finding", "severity": "HIGH", "challenge_id": "54373",
                      "status": "verified", "validation_status": "submission_accepted",
                      "technique": "buffer_overflow", "artifact_hash": "sha256_of_artifact"})

        # Store observation during reconnaissance
        mem0_memory(action="store",
            content="[OBSERVATION] Discovered 15 endpoints, JWT auth, admin panel at /admin returns 403",
            metadata={"category": "observation"})

        # Query verified challenges before attempting (avoid duplicate work)
        mem0_memory(action="retrieve", query="verified challenges",
            metadata={"category": "finding", "status": "verified", "validation_status": "submission_accepted"})

    ACTIONS:
        store       Store finding/observation with content and metadata
        retrieve    Semantic search with optional metadata filters
        list        Get all memories for user/agent
        get         Get specific memory by ID
        delete      Remove memory by ID
        store_plan  Store operation plan with phases
        get_plan    Get current operation plan

    CATEGORIES (report generation):
        finding     Exploits, flags, vulnerabilities - APPEARS IN REPORTS
        signal      Strong indicators, access evidence - APPEARS IN REPORTS
        observation Reconnaissance, artifacts, failed attempts - APPEARS IN REPORTS
        discovery   New techniques, bypasses - APPEARS IN REPORTS
        plan        Strategic planning - internal only, NOT in reports
        decision    Filtering choices - internal only, NOT in reports

    CATEGORY DECISION TREE (CRITICAL - wrong category = empty report):
        Q: Did you EXPLOIT something or extract sensitive data?
           YES → category="finding" (SQLi data dump, auth bypass, flag, RCE, credentials)
           NO  → Q: Did you CONFIRM a vulnerability exists?
                    YES → category="finding" (XSS fires, IDOR returns other user data)
                    NO  → category="observation" (recon, tech stack, failed attempts)

        COMMON MISTAKE: Using category="observation" for successful exploits
        RESULT: Report generator finds 0 findings → NO REPORT GENERATED
        FIX: ANY successful exploit or confirmed vuln = category="finding"

    CROSS-SESSION LEARNING:
        Memory Store: Per-operation FAISS store with logical run_id scoping
        - Default path: ./outputs/<target>/memory/<operation_id>/ (MEMORY_ISOLATION=operation)
        - Shared mode: ./outputs/<target>/memory/ (MEMORY_ISOLATION=shared)
        - Thread-safe: Multiple swarm agents can write concurrently (uses lock)

        Operation Scoping: Memories auto-scoped via run_id (CYBER_OPERATION_ID)
        - store: Auto-tagged with current operation's run_id
        - retrieve: Scoped to current operation by default
        - retrieve(cross_operation=True): Search ALL operations for cross-learning
        - list: Scoped to current operation by default
        - list(cross_operation=True): List ALL operations

        Cross-Learning Query Examples:
        - Learn from past: retrieve(query="SQLi techniques", cross_operation=True)
        - Skip verified: metadata={"status": "verified"} to find solved challenges
        - Learn techniques: metadata={"category": "discovery"}
        - Avoid failures: query for failed_technique or blocker in metadata

    STORAGE RULES:
        1. ONE finding = ONE memory (atomic, not summaries)
        2. Store IMMEDIATELY after success (not batched at end)
        3. Use category="finding" for exploits/flags (required for reports)
        4. Include severity="HIGH" minimum (CRITICAL for auth bypass, RCE, data exfil)
        5. Add technique metadata for pattern-based cross-learning queries
        6. Store observations every 5-10 steps (category="observation")

    STATUS VERIFICATION (prevent hallucination):
        - status="hypothesis" → Flag extracted but NOT verified (requires testing/submission)
        - status="unverified" → Flag in artifact, grep verified, but NOT submitted
        - status="verified" → Flag submission accepted (ONLY use after external validation success)
        - FORBIDDEN: status="solved" (ambiguous - use "verified" or "hypothesis")
        - CRITICAL: Never store status="verified" until submission API returns success
        - Memory contamination: status="solved" + validation_status="hypothesis" = contradiction/hallucination

    Args:
        action: Action to perform (see ACTIONS above)
        content: Content string with [FINDING] or [OBSERVATION] markers
        memory_id: Memory ID for get/delete
        query: Semantic search query for retrieve
        user_id: User ID (defaults to 'cyber_agent')
        agent_id: Agent ID
        metadata: Dict with category (required), severity, technique, challenge_id, status, etc.
        cross_operation: If True, search/list across ALL operations (for cross-learning).
                        Default False = scoped to current operation only.

    Returns:
        JSON/text response with operation result
    """
    global _MEMORY_CLIENT

    if _MEMORY_CLIENT is None:
        # Initialize with default config if not already initialized
        # Always use silent mode for auto-initialization to prevent unwanted output
        initialize_memory_system(silent=True)

    if _MEMORY_CLIENT is None:
        return "Error: Memory client could not be initialized"

    try:
        # Use simple user_id if not provided
        if not user_id and not agent_id:
            user_id = "cyber_agent"

        def _normalize_confidence(conf_val: Any, cap_to: float | None = None) -> str:
            """Normalize confidence to a percentage string, optionally capping at cap_to."""
            try:
                if isinstance(conf_val, str) and conf_val.strip().endswith("%"):
                    num = float(conf_val.strip().rstrip("%"))
                else:
                    num = float(conf_val)
            except Exception:
                num = 0.0
            if cap_to is not None:
                num = min(num, cap_to)
            num = max(0.0, min(100.0, num))
            return f"{num:.1f}%"

        def _is_valid_proof_pack(proof: Any) -> bool:
            """Validate proof_pack structure and artifact existence (fail-closed).

            Expectations:
            - proof_pack is a dict with key 'artifacts': List[str] of file paths (absolute or relative)
            - Optional 'rationale': short string tying artifacts to impact
            - Every listed artifact path MUST exist at validation time

            Notes:
            - No content parsing or domain heuristics are used here; presence of files only
            - Any exception or malformed input results in False (fail-closed)
            """
            if not isinstance(proof, dict):
                return False
            arts = proof.get("artifacts")
            if not isinstance(arts, list) or len(arts) == 0:
                return False
            # All listed artifacts must exist; relative or absolute paths supported
            for p in arts:
                try:
                    if not isinstance(p, str) or not p.strip():
                        return False
                    if not os.path.exists(p):
                        return False
                except Exception:
                    return False
            # Rationale is encouraged but not strictly required for validity here
            return True

        # Check if we're in development mode
        strands_dev = os.environ.get("BYPASS_TOOL_CONSENT", "").lower() == "true"

        # Handle different actions
        if action == "store_plan":
            if not content:
                raise ValueError("content is required for store_plan action")

            # Validate content type
            if isinstance(content, str):
                # Must be valid JSON string
                try:
                    plan_dict = json.loads(content)
                    if not isinstance(plan_dict, dict):
                        raise ValueError("JSON is not an object")
                except ValueError as e:
                    raise ValueError(
                        f"store_plan requires JSON object/dict with fields: objective, current_phase, total_phases, phases. "
                        f"Got string that is not valid JSON: {str(e)}"
                    )
            elif isinstance(content, dict):
                plan_dict = content
            else:
                raise ValueError(
                    f"store_plan content must be object/dict or JSON string, got {type(content).__name__}"
                )

            if isinstance(plan_dict.get("phases", None), list) and not "total_phases" in plan_dict:
                plan_dict["total_phases"] = len(plan_dict.get("phases"))

            results = _MEMORY_CLIENT.store_plan(plan_dict, user_id or "cyber_agent")
            if not strands_dev:
                console.print("[green]Strategic plan stored successfully[/green]")
            return json.dumps(results, indent=2)

        elif action == "get_plan":
            # Scope retrieval to current operation when available to avoid stale plans
            op_id = os.getenv("CYBER_OPERATION_ID")
            plan = _MEMORY_CLIENT.get_active_plan(
                user_id or "cyber_agent", operation_id=op_id
            )
            if plan:
                if not strands_dev:
                    console.print("[green]Active plan retrieved[/green]")
                return json.dumps(plan, indent=2)
            else:
                if not strands_dev:
                    console.print("[yellow]No active plan found[/yellow]")
                return "No active plan found"

        elif action == "store":
            if not content:
                raise ValueError("content is required for store action")

            # Clean content to prevent JSON issues
            cleaned_content = (
                str(content)
                .replace("\x00", "")
                .replace("\n", " ")
                .replace("\r", " ")
                .replace("\t", " ")
                .strip()
            )
            # Also clean multiple spaces
            cleaned_content = re.sub(r"\s+", " ", cleaned_content)
            if not cleaned_content:
                raise ValueError("Content is empty after cleaning")

            # Clean metadata values too
            if metadata:
                cleaned_metadata = {}
                for key, value in metadata.items():
                    if isinstance(value, str):
                        cleaned_value = (
                            str(value)
                            .replace("\x00", "")
                            .replace("\n", " ")
                            .replace("\r", " ")
                            .replace("\t", " ")
                            .strip()
                        )
                        cleaned_value = re.sub(r"\s+", " ", cleaned_value)
                        cleaned_metadata[key] = cleaned_value
                    else:
                        cleaned_metadata[key] = value
                metadata = cleaned_metadata
            else:
                metadata = {}

            # Tag with current operation ID when available
            # Keep operation_id in metadata for backward compatibility and debugging
            # Primary scoping now uses session_id parameter in mem0.add()
            op_id = os.getenv("CYBER_OPERATION_ID")
            if op_id and "operation_id" not in metadata:
                metadata["operation_id"] = op_id
                logger.debug("Tagged memory with operation_id=%s (metadata backup)", op_id)

            # Validate category field exists (CRITICAL for report generation)
            # Category is REQUIRED - agents must explicitly specify finding vs observation
            if "category" not in metadata:
                raise ValueError(
                    "MISSING CATEGORY: metadata must include 'category' field.\n"
                    "  - category='finding' for exploits, vulns, flags (APPEARS IN REPORTS)\n"
                    "  - category='observation' for recon, failed attempts (background context)\n"
                    "Example: metadata={'category': 'finding', 'severity': 'HIGH'}"
                )

            # Validate category is a known value
            VALID_CATEGORIES = {"finding", "signal", "observation", "discovery", "plan", "decision"}
            category_val = str(metadata.get("category", "")).lower()
            if category_val and category_val not in VALID_CATEGORIES:
                logger.warning(
                    "Invalid category '%s'. Valid categories: %s. Defaulting to 'observation'.",
                    category_val, VALID_CATEGORIES
                )
                metadata["category"] = "observation"

            # Debug: Log category before any processing
            logger.debug("Category validation: category=%s", metadata.get("category"))

            # Consolidated validation for findings (single pass)
            if metadata.get("category") == "finding":
                # 0. Warn on forbidden status="solved" (ambiguous - use verified/hypothesis)
                status_val = str(metadata.get("status", "")).lower()
                if status_val == "solved":
                    logger.warning(
                        "FORBIDDEN status='solved' detected - this is ambiguous. "
                        "Use status='verified' (after submission success) or status='hypothesis' (unconfirmed). "
                        "Changing to 'hypothesis' to prevent memory contamination."
                    )
                    metadata["status"] = "hypothesis"

                # 1. Normalize severity
                valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                sev = str(metadata.get("severity", "MEDIUM")).upper()
                if sev not in valid_severities:
                    logger.warning(f"Invalid severity '{sev}', defaulting to MEDIUM")
                    sev = "MEDIUM"
                metadata["severity"] = sev

                # 2. Validate proof_pack for HIGH/CRITICAL findings
                vstat = str(metadata.get("validation_status", "")).lower()
                if sev in {"HIGH", "CRITICAL"}:
                    proof = metadata.get("proof_pack")
                    if _is_valid_proof_pack(proof):
                        # Valid proof_pack exists - respect or default to unverified
                        if vstat not in {"verified", "unverified", "hypothesis"}:
                            metadata["validation_status"] = "unverified"
                    else:
                        # Missing/invalid proof_pack - downgrade to hypothesis and cap confidence
                        metadata["validation_status"] = "hypothesis"
                        metadata["confidence"] = _normalize_confidence(
                            metadata.get("confidence", "60%"), cap_to=60.0
                        )
                else:
                    # Non-critical findings - default validation_status if not set
                    if vstat not in {"verified", "unverified", "hypothesis"}:
                        metadata["validation_status"] = "unverified"

                # 3. Determine evidence_type based on confidence (if not already set)
                if "evidence_type" not in metadata:
                    confidence_str = metadata.get("confidence", "0%")
                    try:
                        confidence_val = float(str(confidence_str).rstrip("%"))
                    except Exception:
                        confidence_val = 0

                    if confidence_val >= 70:
                        metadata["evidence_type"] = "exploited"
                    elif confidence_val >= 50:
                        metadata["evidence_type"] = "behavioral"
                    else:
                        metadata["evidence_type"] = "pattern_match"

                # 4. Cap confidence for pattern matches
                if metadata.get("evidence_type") == "pattern_match":
                    metadata["confidence"] = _normalize_confidence(
                        metadata.get("confidence", "35%"), cap_to=40.0
                    )

            # Cross-field validation: Ensure status and validation_status are consistent
            status_val = str(metadata.get("status", "")).lower()
            validation_status = str(metadata.get("validation_status", "")).lower()

            # If status="verified" but validation_status contradicts, fix it
            if status_val == "verified" and validation_status and validation_status not in ("verified", "submission_accepted"):
                logger.warning(
                    "Inconsistent status fields: status='verified' but validation_status='%s'. "
                    "Setting validation_status='verified' to prevent contradiction.",
                    validation_status
                )
                metadata["validation_status"] = "verified"

            # If validation_status="submission_accepted" but status isn't "verified", fix it
            if validation_status == "submission_accepted" and status_val != "verified":
                logger.warning(
                    "Inconsistent status fields: validation_status='submission_accepted' but status='%s'. "
                    "Setting status='verified'.",
                    status_val
                )
                metadata["status"] = "verified"

            # Suppress mem0's internal error logging during operation
            mem0_logger = logging.getLogger("root")
            original_level = mem0_logger.level
            mem0_logger.setLevel(logging.CRITICAL)

            try:
                results = _MEMORY_CLIENT.store_memory(
                    cleaned_content, user_id, agent_id, metadata
                )
            except Exception as store_error:
                # Handle mem0 library errors - attempt recovery before failing
                error_str = str(store_error)
                if "Extra data" in error_str or "Expecting value" in error_str:
                    # JSON parsing error - try with more aggressive cleaning
                    logger.warning("JSON parsing error in mem0, attempting recovery: %s", error_str)
                    try:
                        # Escape problematic characters and retry
                        escaped_content = json.dumps(cleaned_content)[1:-1]  # Remove outer quotes
                        results = _MEMORY_CLIENT.store_memory(
                            escaped_content, user_id, agent_id, metadata
                        )
                        logger.info("Memory stored after content escaping")
                    except Exception as retry_error:
                        # Recovery failed - log and return error (don't fake success!)
                        logger.error(
                            "Memory storage failed after retry: %s (original: %s)",
                            retry_error, store_error
                        )
                        return json.dumps({
                            "status": "error",
                            "error": f"Storage failed: {store_error}",
                            "content_preview": cleaned_content[:50] + "..."
                        }, indent=2)
                else:
                    raise store_error
            finally:
                # Restore original logging level
                mem0_logger.setLevel(original_level)

            # Normalize to list with better error handling
            if results is None:
                results_list = []
            elif isinstance(results, list):
                results_list = results
            elif isinstance(results, dict):
                results_list = results.get("results", [])
            else:
                results_list = []
            if results_list and not strands_dev:
                panel = format_store_response(results_list)
                console.print(panel)
            return json.dumps(results_list, indent=2)

        elif action == "get":
            if not memory_id:
                raise ValueError("memory_id is required for get action")

            memory = _MEMORY_CLIENT.get_memory(memory_id)
            if not strands_dev:
                panel = format_get_response(memory)
                console.print(panel)
            return json.dumps(memory, indent=2)

        elif action == "list":
            # Respect MEM0_LIST_LIMIT if set, default to 100 (matches retrieve/report limits)
            try:
                list_limit = int(os.getenv("MEM0_LIST_LIMIT", "100"))
            except Exception:
                list_limit = 100

            # Scope to current operation unless cross_operation=True
            op_id = None if cross_operation else os.getenv("CYBER_OPERATION_ID")
            memories = _MEMORY_CLIENT.list_memories(
                user_id, agent_id, limit=list_limit, run_id=op_id
            )

            # Debug logging to understand the response structure
            logger.debug("Memory list raw response type: %s", type(memories))
            logger.debug("Memory list raw response: %s", memories)

            # Normalize to list with better error handling
            if memories is None:
                results_list = []
                logger.debug("memories is None, returning empty list")
            elif isinstance(memories, list):
                results_list = memories
                logger.debug("memories is list with %d items", len(memories))
            elif isinstance(memories, dict):
                # Check for different possible dict structures
                if "results" in memories:
                    results_list = memories.get("results", [])
                    logger.debug("Found 'results' key with %d items", len(results_list))
                elif "memories" in memories:
                    results_list = memories.get("memories", [])
                    logger.debug(
                        "Found 'memories' key with %d items", len(results_list)
                    )
                else:
                    # If dict doesn't have expected keys, treat as single memory
                    results_list = [memories] if memories else []
                    logger.debug(
                        "Dict without expected keys, treating as single memory: %d items",
                        len(results_list),
                    )
            else:
                results_list = []
                logger.debug("Unexpected response type: %s", type(memories))

            if not strands_dev:
                panel = format_list_response(results_list)
                console.print(panel)
            return json.dumps(results_list, indent=2)

        elif action == "retrieve":
            if not query:
                raise ValueError("query is required for retrieve action")

            # Get operation ID for scoped retrieval (matches how store_memory scopes data)
            # If cross_operation=True, don't scope to current operation (enables cross-learning)
            op_id = None if cross_operation else os.getenv("CYBER_OPERATION_ID")

            # Debug: Log retrieval parameters
            logger.debug(
                "RETRIEVE query='%s', metadata_filters=%s, user_id=%s, run_id=%s, cross_operation=%s",
                query,
                metadata,
                user_id,
                op_id,
                cross_operation
            )

            # Use search() directly to support metadata filters (e.g., category, status)
            # Include run_id to scope to current operation (unless cross_operation=True)
            memories = _MEMORY_CLIENT.search(
                query=query,
                filters=metadata,  # Pass metadata as filters for category/status filtering
                limit=100,
                user_id=user_id or "cyber_agent",
                agent_id=agent_id,
                run_id=op_id,  # None if cross_operation=True for cross-learning
            )

            # Normalize to list with better error handling
            if memories is None:
                results_list = []
            elif isinstance(memories, list):
                results_list = memories
            elif isinstance(memories, dict):
                results_list = memories.get("results", [])
            else:
                results_list = []

            # Debug: Verify categories in retrieved memories
            if results_list:
                categories = {}
                for m in results_list:
                    cat = m.get("metadata", {}).get("category", "MISSING")
                    categories[cat] = categories.get(cat, 0) + 1
                logger.info(
                    "RETRIEVE complete: %d memories, categories=%s",
                    len(results_list),
                    categories
                )
            else:
                logger.warning("RETRIEVE returned 0 results for query='%s'", query)

            if not strands_dev:
                panel = format_retrieve_response(results_list)
                console.print(panel)
            return json.dumps(results_list, indent=2)

        elif action == "delete":
            if not memory_id:
                raise ValueError("memory_id is required for delete action")

            _MEMORY_CLIENT.delete_memory(memory_id)
            if not strands_dev:
                panel = format_delete_response(memory_id)
                console.print(panel)
            return f"Memory {memory_id} deleted successfully"

        else:
            raise ValueError(f"Invalid action: {action}")

    except Exception as e:
        error_msg = f"Error: {str(e)}"
        if os.environ.get("BYPASS_TOOL_CONSENT", "").lower() != "true":
            error_panel = Panel(
                Text(str(e), style="red"),
                title="❌ Memory Operation Error",
                border_style="red",
            )
            console.print(error_panel)
        return error_msg
