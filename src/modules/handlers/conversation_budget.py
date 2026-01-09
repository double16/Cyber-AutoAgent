#!/usr/bin/env python3
"""Shared conversation management and prompt budget helpers."""

from __future__ import annotations

import copy
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Callable, Sequence

from strands import Agent
from strands.agent.conversation_manager import (
    SlidingWindowConversationManager,
    SummarizingConversationManager,
)
from strands.types.content import Message
from strands.types.exceptions import ContextWindowOverflowException
from strands.hooks import BeforeModelCallEvent, AfterModelCallEvent, HookProvider  # type: ignore

from modules.config.models.dev_client import get_models_client

logger = logging.getLogger(__name__)

# Thread-safe shared conversation manager for swarm agents
# This is necessary because swarm agents (created by strands_tools/swarm.py library)
# don't inherit conversation_manager from parent agent
_SHARED_CONVERSATION_MANAGER: Optional[Any] = None
# Lock to protect concurrent access to shared conversation manager
_MANAGER_LOCK = threading.RLock()


def register_conversation_manager(manager: Any) -> None:
    """
    Register a conversation manager to be shared across all agents.

    This is needed because swarm agents created by the strands_tools library
    don't automatically inherit the parent agent's conversation_manager attribute.
    By storing a module-level reference, we can provide the same manager to all
    agents (main and swarm children) for consistent context management.

    Thread-safe implementation using RLock for concurrent access.

    Args:
        manager: The MappingConversationManager instance to share
    """
    global _SHARED_CONVERSATION_MANAGER
    with _MANAGER_LOCK:
        _SHARED_CONVERSATION_MANAGER = manager
    try:
        name = type(manager).__name__ if manager is not None else "None"
    except Exception:
        name = "unknown"
    logger.info("Registered shared conversation manager: %s", name)


def clear_shared_conversation_manager() -> None:
    """Clear the shared conversation manager (test cleanup helper).

    Thread-safe implementation.
    """
    global _SHARED_CONVERSATION_MANAGER
    with _MANAGER_LOCK:
        _SHARED_CONVERSATION_MANAGER = None
    logger.debug("Cleared shared conversation manager")


def get_shared_conversation_manager() -> Optional[Any]:
    """Return the shared conversation manager if one was registered.

    Thread-safe implementation.
    """
    with _MANAGER_LOCK:
        return _SHARED_CONVERSATION_MANAGER


@dataclass
class CompressionMetadata:
    """
    Structured metadata for compressed content.

    Provides LLM-readable indicators of what was compressed and how.
    """

    compressed: bool = False
    original_size: int = 0  # Original size in chars
    compressed_size: int = 0  # Compressed size in chars
    original_token_estimate: int = 0  # Estimated tokens before compression
    compressed_token_estimate: int = 0  # Estimated tokens after compression
    compression_ratio: float = 0.0  # compressed / original
    content_type: str = "unknown"  # "text", "json", "mixed"
    n_original_keys: Optional[int] = None  # For JSON objects
    sample_data: Optional[dict[str, Any]] = None  # Sample of original data

    def to_indicator_json(self) -> dict[str, Any]:
        """Convert to structured JSON indicator for LLM comprehension."""
        indicator = {
            "_compressed": self.compressed,
            "_original_size": self.original_size,
            "_compressed_size": self.compressed_size,
            "_compression_ratio": round(self.compression_ratio, 3),
            "_type": self.content_type,
        }
        if self.n_original_keys is not None:
            indicator["_n_original_keys"] = self.n_original_keys
        if self.sample_data:
            indicator.update(self.sample_data)
        return indicator

    def to_indicator_text(self) -> str:
        """Convert to human-readable text indicator."""
        ratio_pct = int(self.compression_ratio * 100)
        text = f"[Compressed: {self.original_size} → {self.compressed_size} chars ({ratio_pct}%)"
        if self.n_original_keys is not None:
            text += f", {self.n_original_keys} keys"
        text += f", type: {self.content_type}]"
        return text


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except Exception:
        return default


def _get_env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except Exception:
        return default


# Named constants for prompt budget configuration
# CYBER_CONTEXT_LIMIT is the preferred name
def _get_context_limit() -> int:
    """Get context limit."""
    new_val = os.getenv("CYBER_CONTEXT_LIMIT")
    if new_val:
        try:
            return int(new_val)
        except ValueError:
            pass
    return 100000  # Default

CONTEXT_LIMIT = _get_context_limit()
# Legacy alias for backward compatibility
PROMPT_TOKEN_FALLBACK_LIMIT = CONTEXT_LIMIT
PROMPT_TELEMETRY_THRESHOLD = max(
    0.1, min(_get_env_float("CYBER_PROMPT_TELEMETRY_THRESHOLD", 0.65), 0.95)
)
PROMPT_CACHE_RELAX = max(0.0, min(_get_env_float("CYBER_PROMPT_CACHE_RELAX", 0.1), 0.3))
NO_REDUCTION_WARNING_RATIO = 0.8  # Warn when at 80% of limit with no reductions

# Compression threshold - aligned with ToolRouterHook externalization threshold
_TOOL_ARTIFACT_THRESHOLD = 10000
TOOL_COMPRESS_THRESHOLD = _TOOL_ARTIFACT_THRESHOLD
TOOL_COMPRESS_TRUNCATE = _get_env_int("CYBER_TOOL_COMPRESS_TRUNCATE", 8000)

# Token estimation overhead constants for content not in agent.messages
# TODO: This could be estimated once the initial system prompt is built, then updated after prompt optimization.
SYSTEM_PROMPT_OVERHEAD_TOKENS = 8000
# TODO: Calculate based on configured tools
TOOL_DEFINITIONS_OVERHEAD_TOKENS = 15_000
MESSAGE_METADATA_OVERHEAD_TOKENS = 50

# Proactive compression threshold (percentage of window capacity)
PROACTIVE_COMPRESSION_THRESHOLD = 0.7
# Window overflow threshold - force pruning above this
WINDOW_OVERFLOW_THRESHOLD = 1.0  # Force prune when at 100% of window
PRESERVE_FIRST_DEFAULT = _get_env_int("CYBER_CONVERSATION_PRESERVE_FIRST", 1)
# Reduced from 12 to 5 to prevent preservation overlap blocking all pruning
PRESERVE_LAST_DEFAULT = _get_env_int("CYBER_CONVERSATION_PRESERVE_LAST", 5)
_MAX_REDUCTION_HISTORY = 5  # Keep last 5 reduction events for diagnostics
_NO_REDUCTION_ATTR = "_prompt_budget_warned_no_reduction"

# Additional named constants for token estimation and cache management
DEFAULT_CHAR_TO_TOKEN_RATIO = 3.7  # Conservative default for token estimation
JSON_CACHE_MAX_SIZE = 100  # Maximum JSON cache entries before cleanup
JSON_CACHE_KEEP_SIZE = 50  # Entries to keep after cache cleanup
ESCALATION_MAX_PASSES = 2  # Maximum additional reduction passes when escalating
ESCALATION_MAX_TIME_SECONDS = 30.0  # Maximum time for all escalation passes
ESCALATION_THRESHOLD_RATIO = 0.9  # Escalate if still at 90% of limit
MAX_THRESHOLD_RATIO = 0.98  # Maximum threshold ratio (never exceed 98% of limit)
SMALL_CONVERSATION_THRESHOLD = 3  # Skip pruning for conversations with fewer messages
# With preserve_first=1 and preserve_last=5, overlap is 6 messages
PRESERVATION_OVERLAP_THRESHOLD = 6  # Expected overlap for early operations (first+last)


def _record_context_reduction_event(
    agent: Agent,
    *,
    stage: str,
    reason: Optional[str],
    before_msgs: int,
    after_msgs: int,
    before_tokens: Optional[int],
    after_tokens: Optional[int],
) -> None:
    """Persist structured reduction metadata on the agent for diagnostics/tests."""
    payload = {
        "stage": stage,
        "reason": reason,
        "before_messages": before_msgs,
        "after_messages": after_msgs,
        "before_tokens": before_tokens,
        "after_tokens": after_tokens,
        "removed_messages": max(0, before_msgs - after_msgs),
    }
    # Prevent memory leak by ensuring history is always a fresh list
    # Get existing history and validate it's a list
    history = getattr(agent, "_context_reduction_events", None)
    if not isinstance(history, list):
        history = []
    else:
        # Create a copy to avoid unintended aliasing
        history = list(history)

    # Append new event
    history.append(payload)

    # Trim immediately to prevent unbounded growth
    if len(history) > _MAX_REDUCTION_HISTORY:
        history = history[-_MAX_REDUCTION_HISTORY:]

    setattr(agent, "_context_reduction_events", history)

    # Safe attribute deletion with proper error handling
    # Clear the "no reduction" warning flag since we just recorded a reduction
    if hasattr(agent, _NO_REDUCTION_ATTR):
        try:
            delattr(agent, _NO_REDUCTION_ATTR)
        except AttributeError:
            # Attribute doesn't exist anymore (race condition), safe to ignore
            pass
        except Exception as e:
            # Other unexpected errors - log and set to False as fallback
            logger.debug("Failed to delete %s attribute: %s", _NO_REDUCTION_ATTR, e)
            setattr(agent, _NO_REDUCTION_ATTR, False)


class LargeToolResultMapper:
    """
    Compress overly large tool results before they hit the conversation.

    Uses structured compression indicators and rich message context for intelligent
    pruning decisions. Stateless per the Strands SDK MessageMapper protocol.
    """

    def __init__(
        self,
        max_tool_chars: int = TOOL_COMPRESS_THRESHOLD,
        truncate_at: int = TOOL_COMPRESS_TRUNCATE,
        sample_limit: int = 3,
    ) -> None:
        self.max_tool_chars = max_tool_chars
        self.truncate_at = truncate_at
        self.sample_limit = sample_limit
        logger.info("Created LargeToolResultMapper with max_tool_chars=%d, truncate_at=%d, sample_limit=%d",
                    self.max_tool_chars, self.truncate_at, self.sample_limit)
        if self.max_tool_chars < self.truncate_at:
            logger.warning("LargeToolResultMapper expecting max_tool_chars >= truncate_at")

    def __call__(
        self, message: Message, index: int, messages: list[Message]
    ) -> Optional[Message]:
        if not message.get("content"):
            return message

        # Single pass: identify content blocks that need compression
        content_blocks = message.get("content", [])
        indices_to_compress: set[int] = set()

        for idx, content_block in enumerate(content_blocks):
            tool_result = content_block.get("toolResult")
            if tool_result:
                tool_length = self._tool_length(tool_result, idx)
                # Use >= to catch boundary case where tool_length equals threshold
                # (e.g., ToolRouterHook creates exactly 10K inline previews)
                if tool_length >= self.max_tool_chars:
                    logger.debug(
                        "LAYER 2 COMPRESSION: Tool result at message %d block %d exceeds threshold "
                        "(length=%d, threshold=%d)",
                        index,
                        idx,
                        tool_length,
                        self.max_tool_chars,
                    )
                    indices_to_compress.add(idx)

            tool_use = content_block.get("toolUse")
            if tool_use:
                tool_use_length = self._tool_use_length(tool_use)
                if tool_use_length > self.max_tool_chars:
                    logger.debug(
                        "LAYER 2 COMPRESSION: Tool use at message %d block %d exceeds threshold "
                        "(length=%d, threshold=%d)",
                        index,
                        idx,
                        tool_use_length,
                        self.max_tool_chars,
                    )
                    indices_to_compress.add(idx)

        if not indices_to_compress:
            return message

        logger.info(
            "LAYER 2 COMPRESSION: Compressing %d tool result(s) in message %d",
            len(indices_to_compress),
            index,
        )

        # Deep copy message to prevent aliasing bugs (Strands pattern)
        # Shallow copy would share nested dicts/lists with original message
        new_message: Message = copy.deepcopy(message)
        new_blocks = new_message.get("content", [])
        new_content: list[dict[str, Any]] = []

        # Process each content block (use the deep-copied blocks to avoid aliasing)
        for idx, content_block in enumerate(new_blocks):
            if idx not in indices_to_compress:
                # No compression needed, keep as-is
                new_content.append(content_block)
                continue

            # Compress this content block
            tool_result = content_block.get("toolResult")
            tool_use = content_block.get("toolUse")

            if tool_result:
                # Shallow copy the content block, replace only toolResult
                new_content.append(
                    {
                        **content_block,
                        "toolResult": self._compress(tool_result, idx),
                    }
                )
            elif tool_use:
                # Shallow copy the content block, replace only toolUse
                new_content.append(
                    {
                        **content_block,
                        "toolUse": self._compress_tool_use(tool_use),
                    }
                )
            else:
                new_content.append(content_block)

        new_message["content"] = new_content
        return new_message

    def _tool_length(self, tool_result: dict[str, Any], cache_key: int = 0) -> int:
        """Calculate total character length of tool result content."""
        length = 0
        for block in tool_result.get("content", []):
            if "text" in block:
                length += len(block["text"])
            elif "json" in block:
                length += len(str(block["json"]))
        return length

    def _tool_use_length(self, tool_use: dict[str, Any]) -> int:
        """Calculate tool use length."""
        length = 0
        length += len(str(tool_use.get("name", "")))
        length += len(str(tool_use.get("toolUseId", "")))
        input_data = tool_use.get("input", {})
        length += len(str(input_data))
        return length

    def _compress(
        self, tool_result: dict[str, Any], cache_key: int = 0
    ) -> dict[str, Any]:
        """
        Compress tool result with structured metadata indicators.

        Uses both text and JSON indicators for better LLM comprehension
        of what was compressed.

        Includes defensive checks for cache operations and error handling.
        """
        # Validate input
        if not isinstance(tool_result, dict):
            logger.warning("Invalid tool_result type: %s", type(tool_result))
            return tool_result

        try:
            original_size = self._tool_length(tool_result, cache_key)
        except Exception as e:
            # Handle errors gracefully in compression
            logger.warning("Failed to calculate tool result length: %s", e, exc_info=True)
            original_size = 0
        compressed_blocks: list[dict[str, Any]] = []
        json_original_keys = 0
        json_sample: dict[str, Any] = {}
        content_types: list[str] = []

        for block in tool_result.get("content", []):
            if "text" in block:
                content_types.append("text")
                text = block["text"]
                if len(text) > self.truncate_at:
                    if " chars | Inline: " in text:
                        # previously truncated
                        # [Tool output: {original_size:,} chars | Inline: {len(snippet):,} chars | Full: {relative_path}]
                        text_lines = text.splitlines()
                        inline_count = self.truncate_at - len(text_lines[0])
                        last_snippet_line = len(text_lines)
                        if text_lines[-1].startswith("[Complete output saved"):
                            inline_count -= len(text_lines[-1])
                            last_snippet_line -= 1
                        text_lines[0] = re.sub(r' Inline: ([0-9,.]+) chars ', f" Inline: {inline_count:,} chars ",
                                               text_lines[0])
                        truncated = (text_lines[0]
                                     + "\n"
                                     + ("\n".join(text_lines[1:last_snippet_line]))[:inline_count]
                                     + "\n"
                                     + "\n".join(text_lines[last_snippet_line:]))
                    else:
                        truncated = (
                                text[: self.truncate_at]
                                + f"... [truncated from {len(text)} chars]"
                        )
                    compressed_blocks.append({"text": truncated})
                else:
                    compressed_blocks.append(block)

            elif "json" in block:
                content_types.append("json")
                json_data = block["json"]
                payload = str(json_data)
                payload_len = len(payload)

                if payload_len > self.truncate_at:
                    # Create structured compression metadata
                    if isinstance(json_data, dict):
                        json_original_keys = len(json_data)
                        # Sample first few keys with size check (Strands pattern)
                        sample_items = list(json_data.items())[: self.sample_limit]
                        json_sample = {
                            k: (str(v)[:100] + "..." if len(str(v)) > 100 else v)
                            for k, v in sample_items
                        }

                    # Build metadata in two passes so compression_ratio reflects what we actually emit.
                    metadata = CompressionMetadata(
                        compressed=True,
                        original_size=payload_len,
                        compressed_size=0,
                        original_token_estimate=payload_len // 4,
                        compressed_token_estimate=0,
                        compression_ratio=0.0,
                        content_type="json",
                        n_original_keys=json_original_keys if json_original_keys > 0 else None,
                        sample_data=json_sample if json_sample else None,
                    )

                    # First pass indicators (ratio/size placeholders)
                    indicator_text = metadata.to_indicator_text()
                    indicator_json = metadata.to_indicator_json()
                    emitted_size = len(indicator_text) + len(str(indicator_json))
                    ratio = (emitted_size / payload_len) if payload_len > 0 else 0.0

                    # Update metadata with realistic emitted sizes
                    metadata.compressed_size = emitted_size
                    metadata.compressed_token_estimate = emitted_size // 4
                    metadata.compression_ratio = ratio

                    # Second pass indicators (now consistent)
                    compressed_blocks.append({"text": metadata.to_indicator_text()})
                    compressed_blocks.append({"json": metadata.to_indicator_json()})
                else:
                    compressed_blocks.append(block)

            else:
                compressed_blocks.append(block)

        # Calculate final compressed size
        compressed_size = sum(
            len(str(b.get("text", "") or b.get("json", ""))) for b in compressed_blocks
        )

        # Determine overall content type
        content_type = (
            "mixed"
            if len(set(content_types)) > 1
            else (content_types[0] if content_types else "unknown")
        )

        logger.info(
            "Compressed tool result: %d → %d chars (%.1f%% reduction, type=%s, threshold=%d)",
            original_size,
            compressed_size,
            100 * (1 - compressed_size / original_size) if original_size > 0 else 0,
            content_type,
            self.max_tool_chars,
        )

        # Add summary note at the beginning
        note = {
            "text": f"[compressed tool result – {original_size} chars → threshold {self.max_tool_chars}]"
        }
        return {
            **tool_result,
            "content": [note, *compressed_blocks],
        }

    def _compress_tool_use(self, tool_use: dict[str, Any]) -> dict[str, Any]:
        """Compress tool use input."""
        input_data = tool_use.get("input", {})
        if not input_data:
            return tool_use

        original_size = len(str(input_data))
        compressed_input = {}

        # Compress input fields
        for key, value in input_data.items():
            value_str = str(value)
            if len(value_str) > self.truncate_at:
                compressed_input[key] = (
                    value_str[: self.truncate_at]
                    + f"... [truncated from {len(value_str)} chars]"
                )
            else:
                compressed_input[key] = value

        compressed_size = len(str(compressed_input))

        logger.info(
            "Compressed tool use input: %d → %d chars (%.1f%% reduction)",
            original_size,
            compressed_size,
            100 * (1 - compressed_size / original_size) if original_size > 0 else 0,
        )

        return {
            **tool_use,
            "input": compressed_input
        }

    def _summarize_json(self, data: Any, original_len: int) -> str:
        if isinstance(data, dict):
            samples = self._sample_items(data.items())
            return (
                f"[json dict truncated from {original_len} chars, keys={len(data)}"
                f"{', sample: ' + samples if samples else ''}]"
            )
        if isinstance(data, list):
            rendered = self._sample_sequence(data)
            return (
                f"[json list truncated from {original_len} chars, len={len(data)}"
                f"{', sample: ' + rendered if rendered else ''}]"
            )
        return f"[json truncated from {original_len} chars]"

    def _sample_items(self, items: Any) -> str:
        rendered: list[str] = []
        for idx, (key, value) in enumerate(items):
            if idx >= self.sample_limit:
                break
            snippet = str(value)
            if len(snippet) > 80:
                snippet = snippet[:80] + "..."
            rendered.append(f"{key}={snippet}")
        return ", ".join(rendered)

    def _sample_sequence(self, seq: Sequence[Any]) -> str:
        rendered: list[str] = []
        for idx, value in enumerate(seq):
            if idx >= self.sample_limit:
                break
            snippet = str(value)
            if len(snippet) > 80:
                snippet = snippet[:80] + "..."
            rendered.append(snippet)
        return ", ".join(rendered)


class MappingConversationManager(SummarizingConversationManager):
    """Sliding window trimming with summarization fallback and tool compression.

    Follows Strands SDK ConversationManager contract:
    - apply_management(): Proactive compression + sliding window
    - reduce_context(): Reactive cascade: mapper → slide → summarize
    - Messages modified in-place: agent.messages[:] = new
    """

    def __init__(
        self,
        *,
        window_size: int = 30,
        summary_ratio: float = 0.3,
        preserve_recent_messages: Optional[int] = None,
        preserve_first_messages: int = PRESERVE_FIRST_DEFAULT,
        tool_result_mapper: Optional[LargeToolResultMapper] = None,
    ) -> None:
        if window_size < 1:
            logger.warning("Invalid window_size %d, using minimum 1", window_size)
            window_size = 1
        if preserve_first_messages < 0:
            logger.warning("Invalid preserve_first_messages %d, using 0", preserve_first_messages)
            preserve_first_messages = 0

        # Scale preserve_last dynamically with window size (15%, min 8)
        if preserve_recent_messages is None:
            preserve_recent_messages = max(8, int(window_size * 0.15))
            logger.info(
                "Auto-scaled preserve_last to %d (15%% of window_size=%d)",
                preserve_recent_messages, window_size
            )
        elif preserve_recent_messages < 0:
            logger.warning("Invalid preserve_recent_messages %d, using 0", preserve_recent_messages)
            preserve_recent_messages = 0

        # Validate total preservation doesn't exceed 50% of window
        total_preserved = preserve_first_messages + preserve_recent_messages
        max_preserved = int(window_size * 0.5)
        if total_preserved > max_preserved:
            old_preserve_last = preserve_recent_messages
            preserve_recent_messages = max(0, max_preserved - preserve_first_messages)
            logger.warning(
                "Reduced preserve_last from %d to %d (50%% max of window=%d)",
                old_preserve_last, preserve_recent_messages, window_size
            )

        super().__init__(
            summary_ratio=summary_ratio,
            preserve_recent_messages=preserve_recent_messages,
        )
        self._sliding = SlidingWindowConversationManager(
            window_size=window_size,
            should_truncate_results=False,  # Use our layers instead of SDK truncation
        )
        self.mapper = tool_result_mapper or LargeToolResultMapper()
        self.preserve_first = max(0, preserve_first_messages)
        self.preserve_last = max(0, preserve_recent_messages)
        self.removed_message_count = 0
        self._window_size = window_size  # Store for proactive compression check

    def apply_management(self, agent: Agent, **kwargs: Any) -> None:
        """Apply mapper compression then sliding window trimming.

        Called after every event loop cycle for proactive management.
        """
        messages = getattr(agent, "messages", [])
        window_size = self._window_size
        message_count = len(messages)

        if message_count > window_size * PROACTIVE_COMPRESSION_THRESHOLD:
            logger.info(
                "Proactive compression: %d messages (%.0f%% of %d window)",
                message_count,
                message_count / window_size * 100,
                window_size
            )

        # Apply mapper compression first
        self._apply_mapper(agent)

        # Check for window overflow and force prune if needed
        messages = getattr(agent, "messages", [])
        message_count = len(messages)

        if message_count >= window_size * WINDOW_OVERFLOW_THRESHOLD:
            # Target 90% of window to leave room for new messages, but never below preservation minimum
            min_target = self.preserve_first + self.preserve_last + 1
            target_count = max(1, int(window_size * 0.9), min_target)
            prune_count = max(1, message_count - target_count)  # At least 1
            logger.warning(
                "FORCE PRUNING: Window at capacity (%d messages >= %d window). "
                "Pruning %d messages to reach target %d.",
                message_count,
                window_size,
                prune_count,
                target_count
            )
            self._force_prune_oldest(agent, prune_count)

        # Apply sliding window management and sync removal count
        before_sliding = _count_agent_messages(agent)
        self._sliding.apply_management(agent, **kwargs)
        after_sliding = _count_agent_messages(agent)

        sliding_removed = max(0, before_sliding - after_sliding)
        if sliding_removed > 0:
            self.removed_message_count += sliding_removed

    def _force_prune_oldest(self, agent: Agent, count: int) -> None:
        """Force remove oldest messages while preserving tool pairs.

        This is called when window is exceeded to guarantee message count stays bounded.
        Tool pairs (toolUse + toolResult) are kept together to avoid API errors:
        - 'messages with role tool must be a response to a preceeding message with tool_calls'
        - 'toolResult blocks exceeds the number of toolUse blocks of previous turn'
        """
        messages = getattr(agent, "messages", [])
        if not messages or count <= 0:
            return

        # Calculate safe removal range (skip preserved messages)
        start_idx = self.preserve_first
        end_idx = len(messages) - self.preserve_last

        if start_idx >= end_idx:
            logger.warning(
                "Cannot force prune: preservation ranges overlap (first=%d, last=%d, total=%d)",
                self.preserve_first,
                self.preserve_last,
                len(messages)
            )
            return

        # Build set of indices to remove, ensuring we remove complete tool pairs
        indices_to_remove: set[int] = set()
        removed_count = 0

        # Process prunable range, identifying tool pairs
        idx = start_idx
        while idx < end_idx and removed_count < count:
            msg = messages[idx]
            content = msg.get("content", [])

            # Check if this message contains toolUse (assistant message)
            has_tool_use = any(
                isinstance(block, dict) and "toolUse" in block
                for block in content
                if isinstance(block, dict)
            )

            # Check if this message contains toolResult (user message)
            has_tool_result = any(
                isinstance(block, dict) and "toolResult" in block
                for block in content
                if isinstance(block, dict)
            )

            if has_tool_use:
                # This is assistant message with toolUse.
                # Only remove it if we can also remove its paired toolResult within the prunable range.
                next_idx = idx + 1

                # If the paired toolResult would fall outside the prunable range, skip this toolUse
                # to avoid orphaning tool turns.
                if next_idx >= end_idx or next_idx >= len(messages):
                    idx += 1
                    continue

                next_msg = messages[next_idx]
                next_content = next_msg.get("content", [])
                next_has_result = any(
                    isinstance(block, dict) and "toolResult" in block
                    for block in next_content
                    if isinstance(block, dict)
                )

                if next_has_result:
                    indices_to_remove.add(idx)
                    indices_to_remove.add(next_idx)
                    removed_count += 2
                    idx = next_idx + 1
                    continue

                # If we can't confirm a paired toolResult, don't remove the toolUse alone.
                idx += 1
                continue

            elif has_tool_result:
                # Orphaned toolResult - should not happen but remove it safely
                indices_to_remove.add(idx)
                removed_count += 1
            else:
                # Regular message without tool content - safe to remove
                indices_to_remove.add(idx)
                removed_count += 1

            idx += 1

        if not indices_to_remove:
            return

        # Build new message list, skipping marked indices
        new_messages: list[Message] = [
            msg for i, msg in enumerate(messages)
            if i not in indices_to_remove
        ]

        # In-place modification per SDK contract
        before_count = len(messages)
        agent.messages[:] = new_messages
        after_count = len(new_messages)

        # Track removed messages for SDK session management
        # SDK's RepositorySessionManager uses this for offset tracking
        actual_removed = before_count - after_count
        self.removed_message_count += actual_removed

        logger.info(
            "Force pruned %d messages (preserving tool pairs): %d -> %d (total removed: %d)",
            actual_removed,
            before_count,
            after_count,
            self.removed_message_count
        )

    def reduce_context(
        self,
        agent: Agent,
        e: Optional[Exception] = None,
        **kwargs: Any,
    ) -> None:
        messages = getattr(agent, "messages", [])
        window_size = getattr(self._sliding, "window_size", 100) if self._sliding else 100

        if len(messages) > window_size * 1.2:  # 20% buffer
            logger.warning(
                "FORCE PRUNING: Message count %d exceeds window %d with buffer "
                "(token estimation may be inaccurate - V17 was 87x off)",
                len(messages),
                window_size
            )


        # Apply mapper compression
        self._apply_mapper(agent)
        before_msgs = _count_agent_messages(agent)
        # Use estimation to measure reduction impact (not telemetry - see docstring)
        before_tokens = _safe_estimate_tokens(agent)
        stage = "sliding"
        try:
            self._sliding.reduce_context(agent, e, **kwargs)
        except ContextWindowOverflowException as overflow_exc:
            stage = "summarizing"
            logger.warning("Sliding window overflow; invoking summarizing fallback")
            super().reduce_context(agent, e or overflow_exc, **kwargs)
        after_msgs = _count_agent_messages(agent)
        after_tokens = _safe_estimate_tokens(agent)

        # Sync removal count (only for sliding path - summarizing handles its own)
        if stage == "sliding":
            removed_this_cycle = max(0, before_msgs - after_msgs)
            if removed_this_cycle > 0:
                self.removed_message_count += removed_this_cycle

        changed = after_msgs < before_msgs or (
            before_tokens is not None
            and after_tokens is not None
            and after_tokens < before_tokens
        )
        if changed:
            removed = max(0, before_msgs - after_msgs)
            logger.info(
                "Context reduced via %s manager: messages %d->%d (%d removed), est tokens %s->%s",
                stage,
                before_msgs,
                after_msgs,
                removed,
                before_tokens if before_tokens is not None else "unknown",
                after_tokens if after_tokens is not None else "unknown",
            )
        else:
            # SDK Contract: If reduction was not possible, raise exception
            # This allows caller to know context management is exhausted
            logger.warning(
                "Context reduction requested but no change detected for stage=%s "
                "(before=%d, after=%d messages). Reduction may be exhausted.",
                stage,
                before_msgs,
                after_msgs,
            )
            # Check if we're truly exhausted (can't reduce further)
            total_preserved = self.preserve_first + self.preserve_last
            if after_msgs <= total_preserved + 1:
                # All remaining messages are in preservation zone
                raise ContextWindowOverflowException(
                    f"Context reduction exhausted: {after_msgs} messages remaining, "
                    f"{total_preserved} preserved. Cannot reduce further."
                ) from e

        reason = getattr(agent, "_pending_reduction_reason", None)
        # Safe attribute deletion
        if hasattr(agent, "_pending_reduction_reason"):
            try:
                delattr(agent, "_pending_reduction_reason")
            except AttributeError:
                pass  # Already deleted, safe to ignore
            except Exception as e:
                logger.debug("Failed to delete _pending_reduction_reason: %s", e)
        _record_context_reduction_event(
            agent,
            stage=stage,
            reason=reason,
            before_msgs=before_msgs,
            after_msgs=after_msgs,
            before_tokens=before_tokens,
            after_tokens=after_tokens,
        )

    def get_state(self) -> dict[str, Any]:
        state = super().get_state()
        state["sliding_state"] = self._sliding.get_state()
        state["removed_message_count"] = self.removed_message_count
        return state

    def restore_from_session(self, state: dict[str, Any]) -> Optional[list[Message]]:
        sliding_state = (state or {}).get("sliding_state")
        if sliding_state:
            self._sliding.restore_from_session(sliding_state)
        self.removed_message_count = (state or {}).get("removed_message_count", 0)
        return super().restore_from_session(state)


    def _apply_mapper(self, agent: Agent) -> None:
        """Apply tool result compression to messages in prunable range."""
        if not self.mapper:
            logger.debug("LAYER 2 COMPRESSION: Mapper not configured, skipping")
            return

        messages = getattr(agent, "messages", [])
        total = len(messages)

        logger.debug(
            "LAYER 2 COMPRESSION: Checking messages for compression (total=%d, threshold=%d chars)",
            total,
            self.mapper.max_tool_chars,
        )

        # Skip pruning quietly for very small conversations (common for swarm agents)
        if total < SMALL_CONVERSATION_THRESHOLD:
            logger.debug(
                "Skipping pruning for small conversation: %d messages (agent=%s)",
                total,
                getattr(agent, "name", "unknown")
            )
            return

        # Validate preservation ranges don't overlap entire message list
        if self.preserve_first + self.preserve_last >= total:
            log_level = logger.debug if total <= PRESERVATION_OVERLAP_THRESHOLD else logger.warning
            log_level(
                "Cannot prune: preservation ranges (%d first + %d last) cover all %d messages. "
                "Consider reducing CYBER_CONVERSATION_PRESERVE_LAST (currently %d). "
                "Skipping mapper.",
                self.preserve_first,
                self.preserve_last,
                total,
                self.preserve_last,
            )
            return

        # Calculate prunable range explicitly
        start_prune = self.preserve_first
        end_prune = total - self.preserve_last
        prunable_count = end_prune - start_prune

        # Sanity check for valid range
        if start_prune >= end_prune:
            logger.warning(
                "Invalid prunable range: start=%d, end=%d (total=%d). Skipping mapper.",
                start_prune,
                end_prune,
                total,
            )
            return

        logger.debug(
            "LAYER 2 COMPRESSION: Prunable range messages %d-%d (%d prunable out of %d total)",
            start_prune,
            end_prune,
            prunable_count,
            total,
        )

        compressions = 0
        new_messages: list[Message] = []
        for idx, message in enumerate(messages):
            if idx < start_prune or idx >= end_prune:
                # In preservation zone (initial or recent messages)
                # System messages at index 0 are automatically preserved here
                new_messages.append(message)
            else:
                # In prunable zone - apply compression
                before_compression = message
                mapped = self.mapper(message, idx, messages)
                if mapped is None:
                    self.removed_message_count += 1
                elif str(mapped) != str(before_compression):
                    # Use string comparison to detect actual content changes
                    compressions += 1
                    new_messages.append(mapped)
                else:
                    new_messages.append(mapped)

        # In-place modification per SDK ConversationManager contract
        agent.messages[:] = new_messages

        if compressions > 0:
            logger.info(
                "LAYER 2 COMPRESSION: Applied compression to %d message(s) in prunable range",
                compressions,
            )
        else:
            logger.debug("LAYER 2 COMPRESSION: No messages required compression")


def _count_agent_messages(agent: Agent) -> int:
    try:
        messages = getattr(agent, "messages", [])
        if isinstance(messages, list):
            return len(messages)
    except Exception:
        logger.debug("Unable to count agent messages", exc_info=True)
    return 0


def _safe_estimate_tokens(agent: Agent) -> Optional[int]:
    try:
        messages = getattr(agent, "messages", None)
        if messages is None:
            logger.warning(
                "TOKEN ESTIMATION FAILED: agent.messages is None (agent=%s)",
                getattr(agent, "name", "unknown")
            )
            return None

        if not isinstance(messages, list):
            logger.warning(
                "TOKEN ESTIMATION FAILED: agent.messages is not a list (type=%s, agent=%s)",
                type(messages).__name__,
                getattr(agent, "name", "unknown")
            )
            return None

        if len(messages) == 0:
            logger.info(
                "TOKEN ESTIMATION: agent.messages is empty, returning 0 tokens (agent=%s)",
                getattr(agent, "name", "unknown")
            )
            return 0

        estimated = _estimate_prompt_tokens(agent)
        logger.info(
            "TOKEN ESTIMATION: Estimated %d tokens from %d messages (agent=%s)",
            estimated,
            len(messages),
            getattr(agent, "name", "unknown")
        )
        return estimated
    except Exception as e:
        logger.error(
            "TOKEN ESTIMATION ERROR: Exception during estimation (agent=%s, error=%s)",
            getattr(agent, "name", "unknown"),
            str(e),
            exc_info=True
        )
        return None


def _get_prompt_token_limit(agent: Agent) -> Optional[int]:
    limit = getattr(agent, "_prompt_token_limit", None)
    try:
        if isinstance(limit, (int, float)) and limit > 0:
            return int(limit)
    except Exception:
        logger.debug("Invalid prompt token limit on agent", exc_info=True)
    if PROMPT_TOKEN_FALLBACK_LIMIT > 0:
        setattr(agent, "_prompt_token_limit", PROMPT_TOKEN_FALLBACK_LIMIT)
        logger.warning(
            "Prompt token limit unavailable; using fallback limit of %d tokens",
            PROMPT_TOKEN_FALLBACK_LIMIT,
        )
        return PROMPT_TOKEN_FALLBACK_LIMIT
    return None


def _get_metrics_input_tokens(agent: Agent) -> Optional[int]:
    """
    Get per-prompt input tokens from telemetry.

    Supports two sources:
    - SDK EventLoopMetrics.accumulated_usage['inputTokens'] with delta tracking
    - Fallback test/legacy hook: agent.callback_handler.sdk_input_tokens (absolute per-turn)

    Returns per-prompt input token count, or None if unavailable.

    Includes validation to fix potential None dereference in metrics.
    """
    # Validate agent is not None
    if agent is None:
        logger.warning("Cannot get metrics from None agent")
        return None

    # Primary: SDK metrics with delta tracking
    metrics = getattr(agent, "event_loop_metrics", None)
    if metrics is not None and hasattr(metrics, "accumulated_usage"):
        # Safely access accumulated_usage
        try:
            accumulated = metrics.accumulated_usage
        except AttributeError:
            accumulated = None

        if isinstance(accumulated, dict):
            current_total = accumulated.get("inputTokens", 0)
            # Validate current_total is numeric
            if not isinstance(current_total, (int, float)):
                logger.debug("Invalid inputTokens type: %s", type(current_total))
                current_total = 0

            if current_total > 0:
                previous_total = getattr(agent, "_metrics_previous_input_tokens", 0)
                delta = current_total - previous_total
                if delta < 0:
                    logger.warning(
                        "SDK metrics decreased: current=%d, previous=%d. Resetting delta tracking.",
                        current_total,
                        previous_total,
                    )
                    setattr(agent, "_metrics_previous_input_tokens", current_total)
                    return current_total
                setattr(agent, "_metrics_previous_input_tokens", current_total)
                if delta > 0:
                    return delta
    # Fallback: test/legacy callback handler injection (absolute per-turn)
    try:
        cb = getattr(agent, "callback_handler", None)
        if cb is not None and hasattr(cb, "sdk_input_tokens"):
            value = getattr(cb, "sdk_input_tokens")
            if isinstance(value, (int, float)) and int(value) > 0:
                return int(value)
    except Exception:
        pass
    return None


# Module-level cache for char/token ratios to avoid repeated lookups
_RATIO_CACHE: Dict[str, float] = {}


def _get_char_to_token_ratio_dynamic(model_id: str) -> float:
    """Get char/token ratio using models.dev provider detection.

    Different providers use different tokenizers with varying compression:
    - Claude (Anthropic): ~3.7 chars/token (aggressive)
    - GPT (OpenAI): ~4.0 chars/token (balanced)
    - Kimi (Moonshot): ~3.8 chars/token (between)
    - Gemini (Google): ~4.2 chars/token (conservative)

    Args:
        model_id: Model identifier (e.g., "azure/gpt-5", "bedrock/...")

    Returns:
        Character-to-token ratio for estimation
    """
    if not model_id:
        return DEFAULT_CHAR_TO_TOKEN_RATIO  # Conservative default (slight overestimation)

    # Check cache first
    if model_id in _RATIO_CACHE:
        return _RATIO_CACHE[model_id]

    # Compute ratio with default fallback
    ratio = DEFAULT_CHAR_TO_TOKEN_RATIO  # Default
    try:
        client = get_models_client()
        info = client.get_model_info(model_id)

        if info:
            provider = info.provider.lower()

            # Provider-specific ratios based on tokenizer characteristics
            if "anthropic" in provider or ("bedrock" in provider and "claude" in model_id.lower()):
                ratio = DEFAULT_CHAR_TO_TOKEN_RATIO  # Claude tokenizer (3.7)
            elif "google" in provider or "gemini" in provider or "vertex" in provider:
                ratio = 4.2  # Gemini tokenizer (SentencePiece)
            elif "moonshot" in provider or "moonshotai" in provider:
                ratio = 3.8  # Kimi tokenizer
            elif "openai" in provider or "azure" in provider:
                # Check if it's a GPT model
                model_lower = model_id.lower()
                if any(gpt in model_lower for gpt in ["gpt-4", "gpt-5", "gpt4", "gpt5"]):
                    ratio = 4.0  # GPT tokenizer
    except Exception as e:
        logger.debug("models.dev lookup failed for ratio: model=%s, error=%s", model_id, e)

    # Cache and return
    _RATIO_CACHE[model_id] = ratio
    return ratio


def _estimate_prompt_tokens(agent: Agent) -> int:
    """
    Estimate prompt tokens with model-aware character-to-token ratio.

    Includes system overhead constants for content not in agent.messages:
    system prompt, tool definitions, and per-message metadata.
    """
    messages = getattr(agent, "messages", [])

    # Add fixed overhead for content not in agent.messages
    total_tokens = SYSTEM_PROMPT_OVERHEAD_TOKENS + TOOL_DEFINITIONS_OVERHEAD_TOKENS
    total_tokens += len(messages) * MESSAGE_METADATA_OVERHEAD_TOKENS

    total_chars = 0

    for message in messages:
        for block in message.get("content", []):
            if not isinstance(block, dict):
                continue

            if "text" in block:
                total_chars += len(block["text"])

            elif "toolUse" in block:
                tool_use = block["toolUse"]
                # Include tool name and input roughly proportional to their length
                total_chars += len(str(tool_use.get("name", "")))
                tool_input = tool_use.get("input", {})
                total_chars += len(str(tool_input))

            elif "toolResult" in block:
                tool_result = block["toolResult"]
                # Status and metadata
                total_chars += len(str(tool_result.get("status", "")))
                total_chars += len(str(tool_result.get("toolUseId", "")))
                # Result content blocks
                for result_content in tool_result.get("content", []):
                    if "text" in result_content:
                        total_chars += len(result_content["text"])
                    elif "json" in result_content:
                        total_chars += len(str(result_content["json"]))
                    elif "document" in result_content:
                        doc = result_content["document"]
                        total_chars += len(doc.get("name", ""))
                        total_chars += 400  # conservative fixed overhead
                    elif "image" in result_content:
                        total_chars += 600  # conservative fixed overhead

            elif "image" in block:
                total_chars += 600

            elif "document" in block:
                doc = block["document"]
                total_chars += len(doc.get("name", ""))
                total_chars += 400

            elif "reasoningContent" in block:
                # Count reasoning blocks (Kimi K2, GPT-5, Claude Sonnet 4.5)
                reasoning = block["reasoningContent"]
                if isinstance(reasoning, dict):
                    if "reasoningText" in reasoning:
                        total_chars += len(reasoning["reasoningText"].get("text", ""))
                    # Fallback: stringify entire reasoning block
                    elif reasoning:
                        total_chars += len(str(reasoning))

    # Get model-appropriate ratio dynamically from models.dev
    # Extract model_id string from model config (not model object)
    # Validate model attributes before access
    model = getattr(agent, "model", None)
    model_id = ""
    if model is not None:
        if hasattr(model, "config"):
            config = getattr(model, "config", None)
            if isinstance(config, dict):
                model_id = config.get("model_id", "")
            elif config is not None:
                # config might be an object with attributes
                model_id = getattr(config, "model_id", "")
        # Fallback: try to get model_id directly from model object
        if not model_id and hasattr(model, "model_id"):
            model_id = getattr(model, "model_id", "")

    ratio = _get_char_to_token_ratio_dynamic(model_id)

    if ratio <= 0:
        logger.warning("Invalid char/token ratio %.2f, using default %.1f", ratio, DEFAULT_CHAR_TO_TOKEN_RATIO)
        ratio = DEFAULT_CHAR_TO_TOKEN_RATIO

    content_tokens = max(1, int(total_chars / ratio))
    estimated_tokens = total_tokens + content_tokens

    logger.debug(
        "Token estimation: %d chars / %.1f ratio = %d content + %d overhead = %d total (model=%s)",
        total_chars, ratio, content_tokens,
        SYSTEM_PROMPT_OVERHEAD_TOKENS + TOOL_DEFINITIONS_OVERHEAD_TOKENS + len(messages) * MESSAGE_METADATA_OVERHEAD_TOKENS,
        estimated_tokens, model_id
    )

    return estimated_tokens


def _strip_reasoning_content(agent: Agent) -> None:
    # Check agent._allow_reasoning_content attribute (set by _supports_reasoning_model())
    # True: Keep reasoning blocks (reasoning-capable models)
    # False: Strip reasoning blocks (non-reasoning models)
    if getattr(agent, "_allow_reasoning_content", True):
        return

    messages = getattr(agent, "messages", [])
    removed_blocks = 0
    for message in messages:
        content = message.get("content")
        if not isinstance(content, list):
            continue
        original_len = len(content)
        content[:] = [
            block
            for block in content
            if not isinstance(block, dict) or "reasoningContent" not in block
        ]
        removed_blocks += original_len - len(content)
    if removed_blocks:
        logger.warning(
            "Removed %d reasoningContent blocks for model without reasoning support",
            removed_blocks,
        )


def _ensure_prompt_within_budget(agent: Agent) -> None:
    logger.info("BUDGET CHECK: Called for agent=%s", getattr(agent, "name", "unknown"))
    _strip_reasoning_content(agent)
    token_limit = _get_prompt_token_limit(agent)
    if not token_limit or token_limit <= 0:
        logger.info("BUDGET CHECK: Skipped - no token limit (limit=%s)", token_limit)
        return

    fallback_limit = (
        PROMPT_TOKEN_FALLBACK_LIMIT if PROMPT_TOKEN_FALLBACK_LIMIT > 0 else None
    )
    effective_limit = token_limit or fallback_limit

    # Use estimation ONLY for threshold checking (measures current context size)
    # Telemetry provides cumulative totals which don't decrease after reductions
    current_tokens = _safe_estimate_tokens(agent)

    # Get telemetry for diagnostics only (not for threshold checks)
    telemetry_tokens = _get_metrics_input_tokens(agent)
    if telemetry_tokens is not None and current_tokens is not None:
        logger.debug(
            "Token tracking: context_estimated=%d, telemetry_per_turn=%d",
            current_tokens,
            telemetry_tokens,
        )

    if current_tokens is None:
        # Cannot check budget without current context size estimation
        logger.warning(
            "BUDGET CHECK FAILED: Token estimation returned None for agent=%s. "
            "Cannot perform budget enforcement without token count. "
            "This may indicate empty messages or estimation error.",
            getattr(agent, "name", "unknown")
        )

        # Try to use telemetry as fallback
        if telemetry_tokens is not None and telemetry_tokens > 0:
            logger.info(
                "BUDGET CHECK FALLBACK: Using telemetry tokens (%d) as proxy for context size",
                telemetry_tokens
            )
            current_tokens = telemetry_tokens
        else:
            logger.error(
                "BUDGET CHECK ABORT: No estimation and no telemetry available. "
                "Cannot enforce budget. Agent will run unbounded."
            )
            return

    # Calculate threshold for proactive reduction
    limit_for_threshold = effective_limit or token_limit or fallback_limit
    if not limit_for_threshold:
        return

    # Respect a prompt-cache hint to avoid premature reductions when provider caching is enabled
    cache_hint = False
    try:
        cache_hint = bool(getattr(agent, "_prompt_cache_hit", False))
        if not cache_hint:
            cache_hint = os.getenv("CYBER_PROMPT_CACHE_HINT", "").lower() == "true"
    except Exception:
        cache_hint = False

    threshold_ratio = PROMPT_TELEMETRY_THRESHOLD + (
        PROMPT_CACHE_RELAX if cache_hint else 0.0
    )
    threshold_ratio = min(threshold_ratio, MAX_THRESHOLD_RATIO)
    threshold = int(limit_for_threshold * threshold_ratio)
    reduction_reason: Optional[str] = None

    # Check if we've exceeded threshold using current context size (estimation only)
    # Do NOT use telemetry - it reflects cumulative usage, not current context
    if current_tokens >= threshold:
        reduction_reason = f"context size {current_tokens}"
        # Safe division for percentage calculation
        percentage = (
            (current_tokens / limit_for_threshold * 100)
            if limit_for_threshold > 0
            else 0.0
        )
        logger.warning(
            "THRESHOLD EXCEEDED: context=%d, threshold=%d (%.1f%%), limit=%d",
            current_tokens,
            threshold,
            percentage,
            limit_for_threshold,
        )

    # Warning system: alert if near capacity but no reductions yet
    reduction_history = getattr(agent, "_context_reduction_events", [])
    warn_threshold = int(limit_for_threshold * NO_REDUCTION_WARNING_RATIO)

    if (
        current_tokens >= warn_threshold
        and not reduction_history
        and not getattr(agent, _NO_REDUCTION_ATTR, False)
    ):
        logger.warning(
            "Prompt budget near capacity (~%s tokens of %s) but no context reductions recorded yet. "
            "Verify that MappingConversationManager.reduce_context is being called.",
            current_tokens,
            limit_for_threshold,
        )
        setattr(agent, _NO_REDUCTION_ATTR, True)
    elif current_tokens < warn_threshold:
        # Reset warning flag when back under threshold with safe deletion
        if hasattr(agent, _NO_REDUCTION_ATTR):
            try:
                delattr(agent, _NO_REDUCTION_ATTR)
            except AttributeError:
                pass  # Already deleted, safe to ignore
            except Exception as e:
                logger.debug("Failed to delete %s attribute: %s", _NO_REDUCTION_ATTR, e)
                setattr(agent, _NO_REDUCTION_ATTR, False)

    if reduction_reason is None:
        return

    # Try agent's conversation_manager first, then shared singleton (for swarm agents)
    conversation_manager = getattr(agent, "conversation_manager", None)
    if conversation_manager is None:
        conversation_manager = _SHARED_CONVERSATION_MANAGER
        if conversation_manager is None:
            logger.warning(
                "Prompt budget trigger skipped: no conversation manager available "
                "(agent=%s, tokens=%d, threshold=%d). "
                "Ensure register_conversation_manager() was called during agent creation.",
                getattr(agent, "name", "unknown"),
                current_tokens,
                threshold,
            )
            return
        logger.debug(
            "Using shared conversation manager for agent=%s (swarm agent)",
            getattr(agent, "name", "unknown"),
        )

    # Track escalation state on the agent to avoid infinite loops across turns
    escalation_count = int(getattr(agent, "_prompt_budget_escalations", 0))

    before_msgs = _count_agent_messages(agent)
    # Use estimation to measure reduction impact (not telemetry - see _estimate_prompt_tokens docstring)
    before_tokens = _safe_estimate_tokens(agent)
    logger.warning(
        "Prompt budget trigger (%s / limit=%d). Initiating context reduction (escalation=%d).",
        reduction_reason,
        token_limit,
        escalation_count,
    )
    setattr(agent, "_pending_reduction_reason", reduction_reason)

    # Always attempt at least one reduction
    def _attempt_reduce() -> tuple[int, Optional[int]]:
        conversation_manager.reduce_context(agent)
        return _count_agent_messages(agent), _safe_estimate_tokens(agent)

    try:
        after_msgs, after_tokens = _attempt_reduce()
    except ContextWindowOverflowException:
        logger.debug("Context reduction triggered summarization fallback")
        after_msgs, after_tokens = (
            _count_agent_messages(agent),
            _safe_estimate_tokens(agent),
        )
    except Exception:
        logger.exception("Failed to proactively reduce context")
        # Safe attribute deletion and reset escalation counter on error to prevent it from getting stuck
        if hasattr(agent, "_pending_reduction_reason"):
            try:
                delattr(agent, "_pending_reduction_reason")
            except AttributeError:
                pass  # Already deleted
            except Exception as e:
                logger.debug("Failed to delete _pending_reduction_reason: %s", e)

        # Reset escalation counter to prevent infinite escalation
        if hasattr(agent, "_prompt_budget_escalations"):
            try:
                delattr(agent, "_prompt_budget_escalations")
            except AttributeError:
                pass
            except Exception as e:
                logger.debug("Failed to delete _prompt_budget_escalations: %s", e)
                setattr(agent, "_prompt_budget_escalations", 0)
        return

    # Escalate if still near/over threshold; perform up to 2 additional aggressive passes
    # with time budget to prevent hangs
    passes = 0
    escalation_start = time.time()

    while (
        passes < ESCALATION_MAX_PASSES
        and after_tokens is not None
        and limit_for_threshold
        and after_tokens >= int(limit_for_threshold * ESCALATION_THRESHOLD_RATIO)
        and (time.time() - escalation_start) < ESCALATION_MAX_TIME_SECONDS
    ):
        passes += 1
        pass_start = time.time()
        setattr(agent, "_pending_reduction_reason", f"escalation pass {passes}")
        logger.warning(
            "Prompt still near/over limit after reduction (est ~%s / limit %s). Escalating (pass %d).",
            after_tokens,
            limit_for_threshold,
            passes,
        )
        try:
            after_msgs, after_tokens = _attempt_reduce()
            pass_duration = time.time() - pass_start
            logger.debug("Escalation pass %d completed in %.2fs", passes, pass_duration)
        except Exception:
            logger.debug("Escalation reduction pass failed", exc_info=True)
            break

    # Check if we hit time limit
    total_escalation_time = time.time() - escalation_start
    if total_escalation_time >= ESCALATION_MAX_TIME_SECONDS and after_tokens >= int(
        limit_for_threshold * ESCALATION_THRESHOLD_RATIO
    ):
        logger.warning(
            "Escalation terminated after %.2fs (time budget exceeded). "
            "Final tokens: %s / limit %s",
            total_escalation_time,
            after_tokens,
            limit_for_threshold,
        )

    # Update escalation counter for next turn if still large
    if (
        after_tokens is not None
        and limit_for_threshold
        and after_tokens >= int(limit_for_threshold * ESCALATION_THRESHOLD_RATIO)
    ):
        setattr(agent, "_prompt_budget_escalations", escalation_count + 1)
    else:
        # Safe attribute deletion with proper exception handling
        if hasattr(agent, "_prompt_budget_escalations"):
            try:
                delattr(agent, "_prompt_budget_escalations")
            except AttributeError:
                pass  # Already deleted, safe to ignore
            except Exception as e:
                logger.debug("Failed to delete _prompt_budget_escalations: %s", e)
                setattr(agent, "_prompt_budget_escalations", 0)

    if after_msgs < before_msgs or (
        before_tokens is not None
        and after_tokens is not None
        and after_tokens < before_tokens
    ):
        logger.info(
            "Prompt budget reduction complete: messages %d->%d, est tokens %s->%s (passes=%d)",
            before_msgs,
            after_msgs,
            before_tokens if before_tokens is not None else "unknown",
            after_tokens if after_tokens is not None else "unknown",
            passes,
        )
    else:
        logger.info("Prompt budget reduction completed but no change detected")
        history = getattr(agent, "_context_reduction_events", [])
        if not history:
            logger.warning(
                "Prompt budget attempted reduction but conversation manager reported no changes. "
                "Current est tokens ~%s / limit %s. Manual trimming may be required.",
                after_tokens if after_tokens is not None else "unknown",
                limit_for_threshold,
            )


class PromptBudgetHook(HookProvider):
    """Hook provider that enforces prompt budget around model calls.

    Registers to production SDK events to ensure provider-agnostic behavior:
    - BeforeModelCallEvent: run budget check and enforce reductions if near/over threshold
    - AfterModelCallEvent: optional diagnostics (telemetry deltas)
    """

    def __init__(self, ensure_budget_callback: Callable[[Any], None]) -> None:
        self._callback = ensure_budget_callback

    def register_hooks(self, registry) -> None:  # type: ignore[no-untyped-def]
        logger.info(
            "HOOK REGISTRATION: Registering PromptBudgetHook callbacks for BeforeModelCallEvent and AfterModelCallEvent"
        )
        registry.add_callback(BeforeModelCallEvent, self._on_before_model_call)
        registry.add_callback(AfterModelCallEvent, self._on_after_model_call)
        logger.info(
            "HOOK REGISTRATION: PromptBudgetHook callbacks registered successfully"
        )

    def _on_before_model_call(self, event) -> None:  # type: ignore[no-untyped-def]
        """Add type safety for event attributes."""
        # Validate event
        if event is None:
            logger.warning("HOOK EVENT: Received None event in _on_before_model_call")
            return

        logger.info(
            "HOOK EVENT: BeforeModelCallEvent fired - event=%s, has_agent=%s",
            type(event).__name__,
            getattr(event, "agent", None) is not None,
        )
        if self._callback and getattr(event, "agent", None) is not None:
            agent = event.agent

            # CRITICAL: Strip reasoning content BEFORE conversation management
            # Prevents 7000+ reasoning blocks from accumulating (85% of token bloat)
            _strip_reasoning_content(agent)

            # Proactively apply sliding window management before threshold check
            # This enforces the configured window size (e.g., 100 messages)
            conversation_manager = getattr(agent, "conversation_manager", None)
            if conversation_manager is None:
                conversation_manager = _SHARED_CONVERSATION_MANAGER

            if conversation_manager is not None:
                try:
                    logger.info(
                        "Applying conversation management before model call (agent=%s)",
                        getattr(agent, "name", "unknown")
                    )
                    conversation_manager.apply_management(agent)
                except Exception as e:
                    logger.warning(
                        "Failed to apply conversation management (agent=%s, error=%s)",
                        getattr(agent, "name", "unknown"),
                        str(e),
                        exc_info=True
                    )

            self._callback(agent)
        else:
            logger.warning(
                "HOOK EVENT: BeforeModelCallEvent skipped - callback=%s, agent=%s",
                self._callback is not None,
                getattr(event, "agent", None),
            )

    def _on_after_model_call(self, event) -> None:  # type: ignore[no-untyped-def]
        """Add type safety for event attributes and cleanup temporary attributes."""
        # Validate event
        if event is None:
            logger.warning("HOOK EVENT: Received None event in _on_after_model_call")
            return

        logger.debug(
            "HOOK EVENT: AfterModelCallEvent fired - event=%s", type(event).__name__
        )

        # Cleanup temporary attributes after model call
        agent = getattr(event, "agent", None)
        if agent is not None:
            # Clean up pending reduction reason if it wasn't consumed
            if hasattr(agent, "_pending_reduction_reason"):
                try:
                    delattr(agent, "_pending_reduction_reason")
                except AttributeError:
                    pass  # Already cleaned up
                except Exception as e:
                    logger.debug("Failed to cleanup _pending_reduction_reason: %s", e)

        # Telemetry deltas are picked up by _ensure_prompt_within_budget; no-op here
        return


__all__ = [
    "MappingConversationManager",
    "LargeToolResultMapper",
    "PromptBudgetHook",
    "PROMPT_TOKEN_FALLBACK_LIMIT",
    "PROMPT_TELEMETRY_THRESHOLD",
    "register_conversation_manager",
    "_ensure_prompt_within_budget",
    "_estimate_prompt_tokens",
    "_strip_reasoning_content",
    "clear_shared_conversation_manager",
    "get_shared_conversation_manager",
]
