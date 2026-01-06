#!/usr/bin/env python3
"""
Trigger-Based Prompt Rebuild Hook for Cyber-AutoAgent.

Implements adaptive prompt rebuilding for extended operations (400+ steps)
through context-aware rebuild triggers.

Key Features:
- Configurable rebuild intervals (default: 20 steps) for context maintenance
- Automatic execution prompt optimization using memory analysis
- LLM-based interpretation of raw memory content without pattern dependencies
- Plan snapshot and finding injection for context preservation
- Format-agnostic memory processing (handles [SQLI CONFIRMED] and other formats)
"""

import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from strands.hooks.events import BeforeToolCallEvent
from strands.hooks import HookProvider, HookRegistry

from modules.config.system.logger import get_logger

logger = get_logger("Handlers.PromptRebuildHook")


class PromptRebuildHook(HookProvider):
    """Trigger-based prompt rebuilding (not every step).

    Rebuilds system prompt only when:
    - Interval reached (every 20 steps by default)
    - Phase transition detected
    - Execution prompt modified (agent optimized it)
    - External force_rebuild flag set
    """

    def __init__(
        self,
        callback_handler,
        memory_instance,
        config,
        target: str,
        objective: str,
        operation_id: str,
        max_steps: int = 100,
        module: str = "general",
        rebuild_interval: int = 20,
        operation_root: Optional[str] = None,
    ):
        """Initialize the prompt rebuild hook.

        Args:
            callback_handler: Callback handler with current_step tracking
            memory_instance: Memory client for querying findings and plan
            config: Configuration object
            target: Target being assessed
            objective: Assessment objective
            operation_id: Operation identifier
            max_steps: Maximum steps for operation
            module: Module name (e.g., 'general', 'ctf')
            rebuild_interval: Steps between automatic rebuilds (default: 20)
        """
        self.callback_handler = callback_handler
        self.memory = memory_instance
        self.config = config
        self.target = target
        self.objective = objective
        self.operation_id = str(operation_id)
        self.max_steps = max_steps
        self.module = module

        # Rebuild tracking
        self.last_rebuild_step = 0
        self.rebuild_interval = rebuild_interval
        self.force_rebuild = False
        self.last_phase = None
        self.last_exec_prompt_mtime = None

        # Determine operation folder path
        if operation_root:
            self.operation_folder = Path(operation_root)
        else:
            output_dir = Path(getattr(config, "output_dir", "outputs"))
            from modules.handlers.utils import sanitize_target_name

            target_name = sanitize_target_name(target)
            if self.operation_id.startswith("OP_"):
                self.operation_folder = output_dir / target_name / self.operation_id
            else:
                self.operation_folder = (
                        output_dir / target_name / f"OP_{self.operation_id}"
                )

        self.exec_prompt_path = self.operation_folder / "execution_prompt_optimized.txt"
        if self.exec_prompt_path.exists():
            try:
                self.last_exec_prompt_mtime = self.exec_prompt_path.stat().st_mtime
            except Exception:
                self.last_exec_prompt_mtime = None

        logger.info(
            "PromptRebuildHook initialized: interval=%d, operation=%s",
            rebuild_interval,
            self.operation_id,
        )

    def register_hooks(self, registry: HookRegistry):
        """Register BeforeToolCallEvent callback."""
        registry.add_callback(BeforeToolCallEvent, self.check_if_rebuild_needed)
        logger.debug("PromptRebuildHook registered for BeforeToolCallEvent")

    def check_if_rebuild_needed(self, event: BeforeToolCallEvent):
        """Check triggers and rebuild prompt if needed.

        Args:
            event: BeforeToolCallEvent from Strands SDK
        """
        current_step = self.callback_handler.current_step

        # Determine if rebuild needed
        should_rebuild = (
            self.force_rebuild
            or (current_step - self.last_rebuild_step >= self.rebuild_interval)
            or self._phase_changed()
            or self._execution_prompt_modified()
        )

        if not should_rebuild:
            return  # Keep using existing prompt

        logger.info(
            "Prompt rebuild triggered at step %d (last rebuild: step %d)",
            current_step,
            self.last_rebuild_step,
        )

        # Rebuild prompt with fresh context
        try:
            from modules.prompts import get_system_prompt, get_module_loader

            # Query fresh memory and plan
            memory_overview = self._query_memory_overview()
            plan_snapshot = self._query_plan_snapshot()
            plan_current_phase = self._extract_current_phase(plan_snapshot)

            # Build new prompt
            new_prompt = get_system_prompt(
                target=self.target,
                objective=self.objective,
                operation_id=self.operation_id,
                current_step=current_step,
                max_steps=self.max_steps,
                memory_overview=memory_overview,
                plan_snapshot=plan_snapshot,
                plan_current_phase=plan_current_phase,
                provider=getattr(self.config, "provider", None),
                output_config={
                    "base_dir": str(self.operation_folder.parent.parent),
                    "target_name": getattr(self.config, "target", self.target),
                },
            )

            # Reload execution prompt from disk (may have been optimized)
            try:
                module_loader = get_module_loader()
                execution_prompt = module_loader.load_module_execution_prompt(
                    self.module, operation_root=str(self.operation_folder)
                )
                if execution_prompt:
                    new_prompt = (
                        new_prompt
                        + "\n\n## MODULE EXECUTION GUIDANCE\n"
                        + execution_prompt.strip()
                    )
                    logger.debug(
                        "Included execution prompt in rebuild (source: %s)",
                        getattr(
                            module_loader,
                            "last_loaded_execution_prompt_source",
                            "unknown",
                        ),
                    )
            except Exception as e:
                logger.warning(
                    "Failed to reload execution prompt during rebuild: %s", e
                )

            # Check for low findings and inject warning if needed
            findings_warning = self._check_findings_gap(current_step)
            if findings_warning:
                new_prompt = new_prompt + "\n\n" + findings_warning
                logger.warning("Injected findings gap warning at step %d", current_step)

            # CRITICAL: Validate prompt before assignment
            # SDK contract: system_prompt should never be None or empty
            if not new_prompt or not new_prompt.strip():
                logger.error(
                    "Rebuilt prompt is empty or None at step %d. "
                    "Keeping existing prompt to prevent agent failure.",
                    current_step
                )
                return  # Abort rebuild, keep existing prompt

            # Update agent's system prompt
            event.agent.system_prompt = new_prompt

            # Update tracking
            self.last_rebuild_step = current_step
            self.force_rebuild = False

            logger.info(
                "Prompt rebuilt: %d chars (~%d tokens)",
                len(new_prompt),
                len(new_prompt) // 4,
            )

            # AUTO-OPTIMIZE EXECUTION PROMPT (if enabled and step 20+)
            # Disabled by default to prevent LLM-based prompt modifications
            if os.environ.get("CYBER_ENABLE_PROMPT_OPTIMIZER", "false").lower() == "true":
                if current_step >= 20:
                    self._auto_optimize_execution_prompt()

        except Exception as e:
            logger.error("Failed to rebuild prompt: %s", e, exc_info=True)
            # Continue operation with existing prompt on rebuild failure

    def _phase_changed(self) -> bool:
        """Check if assessment plan phase changed.

        Returns:
            True if phase transition detected, False otherwise
        """
        if not self.memory:
            return False

        try:
            plan_snapshot = self._query_plan_snapshot()
            if not plan_snapshot:
                return False

            # Extract current phase using unified extraction method (handles TOON + text)
            current_phase = self._extract_current_phase(plan_snapshot)
            if current_phase is not None:
                if self.last_phase is not None and current_phase != self.last_phase:
                    logger.info(
                        "Phase transition detected: %d -> %d",
                        self.last_phase,
                        current_phase,
                    )
                    self.last_phase = current_phase
                    return True
                self.last_phase = current_phase
        except Exception as e:
            logger.debug("Phase change check failed: %s", e)

        return False

    def _execution_prompt_modified(self) -> bool:
        """Check if execution_prompt_optimized.txt was modified.

        Returns:
            True if file was modified since last check, False otherwise
        """
        if not self.exec_prompt_path.exists():
            return False

        try:
            current_mtime = self.exec_prompt_path.stat().st_mtime
            if (
                self.last_exec_prompt_mtime is not None
                and current_mtime > self.last_exec_prompt_mtime
            ):
                logger.info("Execution prompt modification detected")
                self.last_exec_prompt_mtime = current_mtime
                return True
            self.last_exec_prompt_mtime = current_mtime
        except Exception as e:
            logger.debug("Execution prompt mtime check failed: %s", e)

        return False

    def _check_findings_gap(self, current_step: int) -> Optional[str]:
        """Check if findings count is low compared to progress and inject warning.

        Returns warning message if findings gap detected, None otherwise.
        """
        # Only check at significant progress points (20%, 40%, 60%, 80%)
        progress_pct = (current_step / self.max_steps) * 100
        checkpoint_thresholds = [20, 40, 60, 80]

        # Find nearest checkpoint
        nearest_checkpoint = None
        for threshold in checkpoint_thresholds:
            if progress_pct >= threshold - 5 and progress_pct <= threshold + 5:
                nearest_checkpoint = threshold
                break

        if nearest_checkpoint is None:
            return None

        # Get metrics from callback handler
        try:
            memory_ops = getattr(self.callback_handler, "memory_ops", 0) or 0
            evidence_count = getattr(self.callback_handler, "evidence_count", 0) or 0

            # Also check actual memory for finding category count
            findings_in_memory = 0
            if self.memory and hasattr(self.memory, "list_memories"):
                try:
                    memories = self.memory.list_memories(
                        user_id="cyber_agent",
                        run_id=self.operation_id,
                        limit=100
                    )
                    if isinstance(memories, dict):
                        mem_list = memories.get("results", memories.get("memories", []))
                    else:
                        mem_list = memories or []

                    for m in mem_list:
                        meta = m.get("metadata", {}) or {}
                        if meta.get("category") == "finding":
                            findings_in_memory += 1
                except Exception:
                    pass

            # Use higher of evidence_count or actual findings
            actual_findings = max(evidence_count, findings_in_memory)

            # Calculate expected minimum findings based on progress
            # At 20%: expect at least 0-1, At 40%: 1-2, At 60%: 2-3, At 80%: 3+
            expected_min = {20: 0, 40: 1, 60: 2, 80: 3}.get(nearest_checkpoint, 0)

            # Generate warning if findings are low
            if actual_findings < expected_min and memory_ops > 3:
                warning = f"""<finding_gap_warning>
⚠️ **CRITICAL: LOW FINDINGS DETECTED AT {nearest_checkpoint}% BUDGET**

- Memory operations: {memory_ops}
- Findings stored: {actual_findings}
- Expected minimum at {nearest_checkpoint}%: {expected_min}+

**Problem**: You are storing observations but NOT findings. Exploits won't appear in reports.

**Action Required**:
1. Review your recent work - did you confirm any vulnerabilities?
2. If YES: Store them NOW with `category='finding'`
3. If NO: Focus on exploitation, not just reconnaissance

**Example - Store a finding:**
```
mem0_memory(action="store",
    content="[FINDING] SQL injection in /api/login - extracted admin credentials",
    metadata={{"category": "finding", "severity": "HIGH", "confidence": 85}})
```

Without category='finding', your work will NOT appear in the final report.
</finding_gap_warning>"""
                return warning

        except Exception as e:
            logger.debug("Findings gap check failed: %s", e)

        return None

    def _query_memory_overview(self) -> Optional[Dict[str, Any]]:
        """Query memory for recent findings overview.

        Retrieves recent memories without filtering for pattern-free analysis.
        """
        if not self.memory:
            return None

        try:
            # Retrieve recent memories for contextual analysis
            results = []
            if hasattr(self.memory, "list_memories"):
                memories = self.memory.list_memories(user_id="cyber_agent")
                # Handle both dict and list return types
                if isinstance(memories, dict):
                    results = (
                        memories.get("results", [])
                        or memories.get("memories", [])
                        or []
                    )
                elif isinstance(memories, list):
                    results = memories
                # Limit to 30 most recent
                results = results[:30] if results else []
            elif hasattr(self.memory, "get_all"):
                results = self.memory.get_all(user_id="cyber_agent")[:30]
            else:
                # Fallback to search_memories with empty query
                results = self.memory.search_memories(query="", user_id="cyber_agent")[
                    :30
                ]

            if not results:
                return None

            # Direct memory aggregation for LLM interpretation
            total = len(results)
            recent_summary = []

            for r in results[:5]:  # Top 5 most recent
                memory_text = str(r.get("memory", ""))[:100]
                recent_summary.append(memory_text)

            return {
                "total_count": total,
                "sample": results[:3],  # First 3 for context
                "recent_summary": "\n".join(recent_summary) if recent_summary else None,
            }
        except Exception as e:
            logger.debug("Memory query failed: %s", e)
            return None

    def _query_plan_snapshot(self) -> Optional[str]:
        """Query current assessment plan from memory.

        Retrieves the most recent plan entry for context.
        """
        if not self.memory:
            return None

        try:
            # Use get_active_plan if available (more direct)
            if hasattr(self.memory, "get_active_plan"):
                active_plan = self.memory.get_active_plan(user_id="cyber_agent", operation_id=self.operation_id)
                if active_plan:
                    # Return raw memory content for LLM interpretation
                    return str(active_plan.get("memory", ""))

            # Otherwise, search for any plan-like memory
            results = self.memory.search_memories(
                query="plan objective phase", user_id="cyber_agent"
            )[:1]

            if results:
                # Return first plan-like memory content
                return str(results[0].get("memory", ""))

        except Exception as e:
            logger.debug("Plan query failed: %s", e)

        return None

    def _extract_current_phase(self, plan_snapshot: Optional[str]) -> Optional[int]:
        """Extract phase number from plan snapshot string.

        Handles both TOON format and text format:
        - TOON: "plan_overview[1]{objective,current_phase,total_phases}:\n  ...,2,3"
        - Text: "Phase 2: Exploitation..."

        Args:
            plan_snapshot: Plan snapshot string

        Returns:
            Phase number or None
        """
        if not plan_snapshot:
            return None

        try:
            # Try TOON format first: extract current_phase from CSV row
            # Pattern: "objective,current_phase,total_phases" → "...,2,3"
            toon_match = re.search(
                r'plan_overview\[1\]\{[^}]*current_phase[^}]*\}:\s*\n\s*[^,]+,(\d+),',
                plan_snapshot
            )
            if toon_match:
                return int(toon_match.group(1))

            # Fallback: Try text format "Phase N"
            text_match = re.search(r"Phase (\d+)", plan_snapshot)
            if text_match:
                return int(text_match.group(1))
        except Exception as e:
            logger.debug("Phase extraction failed: %s", e)

        return None

    def set_force_rebuild(self):
        """Allow external components to trigger rebuild on next cycle."""
        self.force_rebuild = True
        logger.debug("Force rebuild flag set")

    def _auto_optimize_execution_prompt(self):
        """Automatically optimize execution prompt based on memory patterns.

        Direct LLM-based approach: Provides raw memories for natural language
        interpretation without hardcoded patterns or extraction logic.
        """
        current_step = self.callback_handler.current_step
        logger.info("Auto-optimizing execution prompt at step %d", current_step)

        # Check if memory is available
        if not self.memory:
            logger.warning(
                "Memory instance not available - cannot perform auto-optimization"
            )
            return

        try:
            # Phase 1: Retrieve recent memories without preprocessing
            logger.info("Gathering recent operation context...")

            recent_memories = []
            try:
                # Try to get all recent memories
                if hasattr(self.memory, "list_memories"):
                    memories = self.memory.list_memories(user_id="cyber_agent")
                    # Handle both dict and list return types
                    if isinstance(memories, dict):
                        recent_memories = (
                            memories.get("results", [])
                            or memories.get("memories", [])
                            or []
                        )
                    elif isinstance(memories, list):
                        recent_memories = memories
                    # Limit to 30 most recent
                    recent_memories = recent_memories[:30] if recent_memories else []
                elif hasattr(self.memory, "get_all"):
                    recent_memories = self.memory.get_all(user_id="cyber_agent")[:30]
                else:
                    # Fallback to search_memories
                    recent_memories = self.memory.search_memories(
                        query="",  # Empty query to get all
                        user_id="cyber_agent",
                    )[:30]
            except Exception as e:
                logger.warning("Could not retrieve memories: %s", e)
                return

            if not recent_memories:
                logger.info("No memories found - skipping optimization")
                return

            logger.info("Found %d recent memories", len(recent_memories))

            # Phase 2: Load current execution prompt
            if not self.exec_prompt_path.exists():
                logger.warning(
                    "Execution prompt not found at %s", self.exec_prompt_path
                )
                return

            current_prompt = self.exec_prompt_path.read_text()

            # Validate prompt is not empty or placeholder
            if not current_prompt.strip() or len(current_prompt) < 100:
                logger.warning(
                    "Execution prompt is empty or too short (%d chars) - skipping optimization",
                    len(current_prompt),
                )
                return

            # Phase 3: Prepare raw memory context for LLM
            import json

            memory_context = json.dumps(recent_memories, indent=2, default=str)[
                :5000
            ]  # Context size limit

            # Phase 4: Execute LLM-based optimization
            logger.info("Initiating LLM-based prompt optimization...")

            try:
                # Import and use the LLM rewriter
                from modules.tools.prompt_optimizer import _llm_rewrite_execution_prompt

                # Direct LLM interpretation of raw context
                optimized = _llm_rewrite_execution_prompt(
                    current_prompt=current_prompt,
                    learned_patterns=memory_context,  # Raw memories as context
                    remove_tactics=[],  # LLM-driven decision
                    focus_tactics=[],  # LLM-driven decision
                )

                logger.info("LLM optimization completed")

                # Validate optimized prompt
                if not optimized or len(optimized) < 100:
                    logger.warning(
                        "Optimized prompt is empty or too short (%d chars) - keeping original",
                        len(optimized) if optimized else 0,
                    )
                    return

            except Exception as llm_error:
                logger.error("LLM optimization failed: %s", llm_error)
                return

            # Phase 5: Persist optimized prompt with error handling
            try:
                # backup the current prompt
                for idx in range(1, 100):
                    backup_path = Path(self.exec_prompt_path.parent, self.exec_prompt_path.name + "." + str(idx))
                    if not backup_path.exists():
                        logger.debug('Saving %s to %s', self.exec_prompt_path, backup_path)
                        shutil.copy(self.exec_prompt_path, backup_path)
                        break

                self.exec_prompt_path.write_text(optimized, encoding="utf-8")
                logger.info("Optimized execution prompt saved to %s", self.exec_prompt_path)
            except PermissionError as perm_err:
                logger.error(
                    "Permission denied writing optimized prompt to %s: %s",
                    self.exec_prompt_path,
                    perm_err
                )
                return  # Abort optimization, keep original
            except OSError as os_err:
                logger.error(
                    "OS error writing optimized prompt to %s: %s",
                    self.exec_prompt_path,
                    os_err
                )
                return  # Abort optimization, keep original

            # Phase 6: Log optimization metrics
            logger.info(
                "AUTO-OPTIMIZATION COMPLETE:\n"
                "  Memories analyzed: %d\n"
                "  Prompt size: %d → %d chars",
                len(recent_memories),
                len(current_prompt),
                len(optimized),
            )

            # Phase 7: Update modification timestamp
            self.last_exec_prompt_mtime = self.exec_prompt_path.stat().st_mtime

        except Exception as e:
            logger.error(
                "Failed to auto-optimize execution prompt: %s", e, exc_info=True
            )
            # Continue operation with current prompt on optimization failure
