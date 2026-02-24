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
"""

import json
import logging
import os
import re
import threading
from datetime import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Literal, Union

import boto3
from mem0 import Memory as Mem0Memory
from mem0 import MemoryClient
from opensearchpy import AWSV4SignerAuth, RequestsHttpConnection
from strands import tool

from modules.config.manager import MEM0_PROVIDER_MAP, get_config_manager
from modules.config.system.logger import get_logger
from modules.config.types import get_default_base_dir

# Set up logging
logger = get_logger("Tools.Memory")

# Global configuration and client
_MEMORY_CONFIG = None
_MEMORY_CLIENT: Optional["Mem0ServiceClient"] = None

# Thread lock for FAISS write safety (prevents corruption during concurrent writes)
_FAISS_WRITE_LOCK = threading.Lock()


PlanStatus = Literal["active", "pending", "done"]


@dataclass(frozen=True)
class PlanPhase:
    id: int
    title: str
    status: PlanStatus
    criteria: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.id, int) or self.id < 0:
            raise ValueError("phase.id must be a positive int")
        if not isinstance(self.title, str) or not self.title.strip():
            raise ValueError("phase.title must be a non-empty string")
        if self.status not in ("active", "pending", "done"):
            raise ValueError("phase.status must be one of: active|pending|done")
        if self.criteria is None:
            object.__setattr__(self, "criteria", "")  # type: ignore[misc]
        if not isinstance(self.criteria, str):
            raise ValueError("phase.criteria must be a string")

    @staticmethod
    def from_obj(obj: Any) -> "PlanPhase":
        if not isinstance(obj, dict):
            raise ValueError("phase must be an object/dict")
        return PlanPhase(
            id=int(obj.get("id")),
            title=str(obj.get("title", "")),
            status=str(obj.get("status", "")),  # validated in __post_init__
            criteria=str(obj.get("criteria", "")) if obj.get("criteria") is not None else "",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "criteria": self.criteria,
        }


@dataclass
class OperationPlan:
    objective: str
    current_phase: int
    total_phases: int
    phases: List[PlanPhase] = field(default_factory=list)
    assessment_complete: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.objective, str) or not self.objective.strip():
            raise ValueError("objective must be a non-empty string")
        if not isinstance(self.current_phase, int) or self.current_phase <= 0:
            raise ValueError("current_phase must be a positive int")
        if not isinstance(self.total_phases, int) or self.total_phases <= 0:
            raise ValueError("total_phases must be a positive int")
        if not isinstance(self.phases, list) or not self.phases:
            raise ValueError("phases must be a non-empty list")
        for p in self.phases:
            if not isinstance(p, PlanPhase):
                raise ValueError("phases must contain PlanPhase objects")

        # enforce consistency
        if self.total_phases != len(self.phases):
            raise ValueError("total_phases must equal len(phases)")

        # current_phase must match an existing phase id
        phase_ids = {p.id for p in self.phases}
        if self.current_phase not in phase_ids:
            raise ValueError("current_phase must match one of the phase ids")

        # at most one active phase
        active_count = sum(1 for p in self.phases if p.status == "active")
        if active_count > 1:
            raise ValueError("only one phase may have status='active'")

    @staticmethod
    def from_obj(obj: Any) -> "OperationPlan":
        if isinstance(obj, OperationPlan):
            return obj
        if not isinstance(obj, dict):
            raise ValueError("plan content must be an object/dict")

        phases_raw = obj.get("phases")
        if not isinstance(phases_raw, list):
            raise ValueError("phases must be a list")

        phases = [PlanPhase.from_obj(p) for p in phases_raw]
        phases.sort(key=lambda p: p.id)

        return OperationPlan(
            objective=str(obj.get("objective", "")),
            current_phase=int(obj.get("current_phase")),
            total_phases=len(phases),
            phases=phases,
            assessment_complete=bool(obj.get("assessment_complete", False)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "objective": self.objective,
            "current_phase": self.current_phase,
            "total_phases": self.total_phases,
            "phases": [p.to_dict() for p in self.phases],
            "assessment_complete": self.assessment_complete,
        }


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


def memory_sort_by_create_time(m: Dict[str, Any]) -> str:
    return str(m.get("created_at", ""))


def memory_is_cross_operation() -> bool:
    return os.getenv("MEMORY_ISOLATION", "operation").lower() == "shared"


def _ensure_memory_client() -> "Mem0ServiceClient":
    """Ensure the global memory client is initialized and return it."""
    global _MEMORY_CLIENT
    if _MEMORY_CLIENT is None:
        # Always use silent mode for auto-init to prevent unwanted console output
        initialize_memory_system(silent=True)
    if _MEMORY_CLIENT is None:
        raise RuntimeError("Memory client could not be initialized")
    return _MEMORY_CLIENT


@tool
def mem0_store(
    content: str,
    metadata: Dict[str, Any],
    user_id: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> str:
    """Store a single memory entry.

    Use this for atomic entries (ONE finding/observation per call). Prefer storing immediately after you confirm something.

    REQUIRED:
    - `metadata.category` MUST be set.
      Valid values: finding | signal | observation | discovery | plan | decision
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

    RECOMMENDED for findings:
    - metadata.severity: CRITICAL/HIGH/MEDIUM/LOW
    - metadata.status: hypothesis/unverified/verified (only use verified after external validation)
    - metadata.validation_status: hypothesis/unverified/verified
    - metadata.technique: short snake_case identifier
    - metadata.proof_pack for HIGH/CRITICAL when available

    OPERATION SCOPING:
    - Automatically scoped to the current operation via run_id (CYBER_OPERATION_ID).

    QUICK START:
        # Store finding ONLY after verification succeeds
        mem0_store(content="[FINDING] XSS Vulnerability confirmed on [URL] endpoint with name parameter. - Technique: stored_xss",
            metadata={"category": "finding", "severity": "HIGH",
                      "status": "verified", "validation_status": "verified",
                      "technique": "stored_xss", "artifact_hash": "sha256_of_artifact"})

        # Store observation during reconnaissance
        mem0_store(content="[OBSERVATION] Discovered 15 endpoints, JWT auth, admin panel at /admin returns 403",
            metadata={"category": "observation"})

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
        content: Content string with [FINDING] or [OBSERVATION] markers
        user_id: User ID (defaults to 'cyber_agent')
        agent_id: Agent ID
        metadata: Dict with category (required), severity, technique, status, etc.

    Returns:
        JSON/text with operation result.
    """
    action = "mem0_store"

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

    if not content:
        raise ValueError("content is required for store action")

    # Use simple user_id if not provided
    if not user_id and not agent_id:
        user_id = "cyber_agent"

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
    VALID_CATEGORIES = {"finding", "signal", "observation", "discovery", "plan", "decision"}
    if "category" not in metadata:
        raise ValueError(
            "MISSING CATEGORY: metadata must include 'category' field.\n"
            "  - category='finding' for exploits, vulns, flags (APPEARS IN REPORTS)\n"
            "  - category='observation' for recon, failed attempts (background context)\n"
            f"VALID CATEGORIES: {', '.join(VALID_CATEGORIES)}\n"
            "Example: metadata={'category': 'finding', 'severity': 'HIGH'}"
        )

    # Validate category is a known value
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
    if metadata.get("category") in ["observation", "discovery"] and metadata.get("severity", "INFO") != "INFO":
        logger.warning("category '%s' != 'finding' with severity != 'INFO', changing category to 'finding'", metadata.get("category"))
        metadata["category"] = "finding"
        if isinstance(cleaned_content, str):
            cleaned_content = (cleaned_content
                               .replace("[OBSERVATION]", "[FINDING]")
                               .replace("[DISCOVERY]", "[FINDING]"))

    if metadata.get("category") == "finding":
        # 0. Warn on forbidden status="solved" (ambiguous - use verified/hypothesis)
        status_val = str(metadata.get("status", "")).lower()
        if status_val == "solved":
            logger.warning(
                "FORBIDDEN status='solved' detected - this is ambiguous. "
                "Use status='verified' (after verification/submission success) or status='hypothesis' (unconfirmed). "
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

    client = _ensure_memory_client()

    try:
        results = client.store_memory(
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
                results = client.store_memory(
                    escaped_content, user_id, agent_id, metadata
                )
                logger.info("Memory stored after content escaping")
            except Exception as retry_error:
                # Recovery failed - log and return error (don't fake success!)
                logger.error(
                    "Memory storage failed after retry: %s (original: %s)",
                    retry_error, store_error
                )
                raise RuntimeError(f"Storage failed: {store_error}, content_preview: {cleaned_content[:50]}...")
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
    return json.dumps(results_list, indent=2, sort_keys=True)


@tool
def mem0_store_plan(
    plan: Union[OperationPlan, str, Dict],
    user_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Store the current operation plan.

    NOTE:
    - This stores a structured TOON representation for token efficiency and also keeps the original plan JSON in metadata.

    Args:
        plan: {"objective":"...", "current_phase":X, "total_phases":N, "phases":[{"id":1, "title":"...", "status":"...", "criteria":"..."}, ...]}
        user_id: User identifier

    Returns:
        JSON/text response with operation result
    """
    try:
        client = _ensure_memory_client()
        if not user_id:
            user_id = "cyber_agent"
        if isinstance(plan, str):
            try:
                plan_obj = OperationPlan.from_obj(json.loads(plan))
            except ValueError as e:
                raise ValueError(
                    f"store_plan requires JSON object/dict with fields: objective, current_phase, total_phases, phases. "
                    f"Got string that is not valid JSON: {str(e)}"
                )
        elif isinstance(plan, dict):
            plan_obj = OperationPlan.from_obj(plan)
        elif isinstance(plan, OperationPlan):
            plan_obj = plan
        else:
            plan_obj = None
        if not plan_obj:
            raise ValueError(
                f"mem0_store_plan content must be object/dict or JSON string, got {type(plan).__name__}"
            )
        results = client.store_plan(plan=plan_obj, user_id=user_id, metadata=metadata)
        return json.dumps(results, indent=2)
    except ValueError as ve:
        raise ve
    except Exception as e:
        raise f"Error: {str(e)}"


@tool
def mem0_get_plan(
    user_id: Optional[str] = None,
    cross_operation: bool = False,
) -> Optional[Dict]:
    """Get the most recent active plan.

    By default, this is scoped to the current operation (CYBER_OPERATION_ID).
    Set cross_operation=True to search across all operations (shared learning).

    Returns the full plan memory dict or null if none found.
    """
    client = _ensure_memory_client()
    if not user_id:
        user_id = "cyber_agent"
    op_id = None if cross_operation else os.getenv("CYBER_OPERATION_ID")
    plan = client.get_active_plan(user_id=user_id, operation_id=op_id)
    if not plan:
        return None

    plan_json = (plan.get("metadata", {}) or {}).get("plan_json")
    if isinstance(plan_json, dict):
        try:
            parsed = OperationPlan.from_obj(plan_json)
            return parsed.to_dict()
        except Exception as parse_exc:
            raise ValueError(f"plan_parse_failed: {parse_exc}, plan: {plan_json}")

    return None


@tool
def mem0_get(
    memory_id: str,
) -> str:
    """Get a memory by ID.

    Returns:
        JSON/text response with operation result
    """
    try:
        client = _ensure_memory_client()
        if not memory_id:
            raise ValueError("memory_id is required")
        result = client.get_memory(memory_id)
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def mem0_list(
    user_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    cross_operation: bool = False,
) -> str:
    """List memories for a user/agent.

    Defaults:
    - If user_id and agent_id are both omitted, user_id defaults to "cyber_agent".

    OPERATION SCOPING:
    - Default: scoped to current operation via run_id (CYBER_OPERATION_ID).
    - cross_operation=True: list across all operations.

    CROSS-SESSION LEARNING:
        - mem0_list: Scoped to current operation by default
        - mem0_list(cross_operation=True): List ALL operations

    Returns a list of memory dicts.
    """
    try:
        client = _ensure_memory_client()

        # Respect MEM0_LIST_LIMIT if set, default to 100 (matches retrieve/report limits)
        try:
            list_limit = int(os.getenv("MEM0_LIST_LIMIT", "100"))
        except Exception:
            list_limit = 100

        # Use simple user_id if not provided
        if not user_id and not agent_id:
            user_id = "cyber_agent"

        # Scope to current operation unless cross_operation=True
        op_id = None if cross_operation else os.getenv("CYBER_OPERATION_ID")
        memories = client.list_memories(
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
        return json.dumps(results_list, indent=2)
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def mem0_retrieve(
    query: str,
    metadata: Optional[Dict[str, Any]] = None,
    user_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    cross_operation: bool = False,
) -> str:
    """Semantic search across memories.

    REQUIRED:
    - query: natural language query

    OPTIONAL:
    - metadata: filter dict applied to metadata (e.g., {"category": "finding", "status": "verified"}).

    OPERATION SCOPING:
    - Default: scoped to current operation via run_id (CYBER_OPERATION_ID).
    - cross_operation=True: search across all operations.

    CROSS-SESSION LEARNING:
        - mem0_retrieve: Scoped to current operation by default
        - mem0_retrieve(cross_operation=True): Search ALL operations for cross-learning

        Cross-Learning Query Examples:
        - Learn from past: mem0_retrieve(query="SQLi techniques", cross_operation=True)
        - Skip verified: metadata={"status": "verified"} to find verified findings
        - Learn techniques: metadata={"category": "discovery"}
        - Avoid failures: query for failed_technique or blocker in metadata

    Returns a list of memory dicts.
    """
    try:
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
        client = _ensure_memory_client()
        memories = client.search(
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
        return json.dumps(results_list, indent=2)
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def mem0_delete(
    memory_id: str,
) -> str:
    """Delete a memory by ID.
    WARNING: This is destructive.
    Returns operation result.
    """
    try:
        client = _ensure_memory_client()
        if not memory_id:
            raise ValueError("memory_id is required")
        client.delete_memory(memory_id)
        return f"Memory {memory_id} deleted successfully"
    except Exception as e:
        return f"Error: {str(e)}"


class Mem0ServiceClient:
    """Lightweight client for Mem0 operations (store, search, list).

    Supports FAISS, OpenSearch, or Mem0 Platform based on environment.
    """

    @staticmethod
    def _remove_inactive(payload: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if payload is None:
            return []
        if not isinstance(payload, list):
            return payload
        payload[:] = [
            memory
            for memory in payload
            if not isinstance(memory, dict) or bool(memory.get("metadata", {}).get("active", True))
        ]
        return payload

    @staticmethod
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

    @staticmethod
    def _normalise_results_list(payload: Any) -> List[Dict[str, Any]]:
        """Best-effort conversion of Mem0 responses to a list of memory dicts."""
        if payload is None:
            return []
        if isinstance(payload, list):
            return Mem0ServiceClient._remove_inactive([Mem0ServiceClient._coerce_entry(entry) for entry in payload])
        if isinstance(payload, dict):
            for key in ("results", "memories", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    return Mem0ServiceClient._remove_inactive([Mem0ServiceClient._coerce_entry(entry) for entry in value])
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
                "output_dir", get_default_base_dir()
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
                        "ollama": "ollama",
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
    ) -> List[Dict[str, Any]]:
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
            return normalised[:eff_limit]
        except Exception as e:
            logger.error("Error in mem0.get_all: %s", e)
            raise

    def search_memories(
            self,
            query: str,
            user_id: Optional[str] = None,
            agent_id: Optional[str] = None,
            run_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
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
                        return normalised[:top_k]
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

        # If run_id was provided but list_memories didn't filter (backend limitation),
        # apply local filtering by operation_id in metadata
        if run_id:
            all_memories = [
                e for e in all_memories
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
        for entry in all_memories:
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
        plan: OperationPlan,
        user_id: str = "cyber_agent",
        metadata: Optional[Dict] = None,
    ) -> Dict:
        """Store a strategic plan in memory with category='plan'.

        Args:
            plan: The strategic plan with required fields
            user_id: User ID for memory storage
            metadata: Optional metadata (will be enhanced with category='plan')

        Returns:
            Memory storage result
        """
        # Check if all phases complete and add reminder
        all_done = all(p.status == "done" for p in plan.phases)
        add_stop_reminder = False
        if all_done and not plan.assessment_complete:
            plan.assessment_complete = True
            add_stop_reminder = True
            logger.info("All phases complete - set assessment_complete=true")

        # Format dict as structured text for storage
        plan_dict = plan.to_dict()
        plan_content_str = _format_plan_as_toon(plan_dict)
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
                "plan_json": plan_dict,  # Store original JSON in metadata
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
                prev_plan = OperationPlan.from_obj(prev.get("metadata", {}).get("plan_json", {}))
                new_total = int(plan.total_phases)
                if prev_plan.assessment_complete and new_total > int(prev_plan.total_phases):
                    logger.warning(
                        f"Adding phases ({prev_plan.total_phases} → {new_total}) after assessment_complete=true. "
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
            plan_items.sort(key=memory_sort_by_create_time, reverse=True)

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


def clear_memory_client() -> None:
    global _MEMORY_CLIENT
    _MEMORY_CLIENT = None
