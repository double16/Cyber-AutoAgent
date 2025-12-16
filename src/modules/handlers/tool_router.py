#!/usr/bin/env python3
"""Hook that reroutes unknown tools to shell and externalizes large outputs.

SDK Contract Compliance:
- AfterToolCallEvent.result is the ONLY writable field
- Modifications MUST REPLACE event.result, not mutate nested dicts
- See: strands/hooks/events.py AfterToolCallEvent._can_write()
"""

import logging
import os
import re
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, TypedDict

from strands.hooks import BeforeToolCallEvent  # type: ignore
from strands.types.tools import ToolResultContent

from modules.handlers import sanitize_target_name

logger = logging.getLogger(__name__)


class ToolRouterHook:
    """BeforeToolCall hook that maps unknown tool names to shell and truncates large results.

    SDK Contract:
    - BeforeToolCallEvent: Can write to selected_tool, tool_use, cancel_tool
    - AfterToolCallEvent: Can ONLY write to result (must REPLACE, not mutate)
    """

    MAX_ARTIFACTS_PER_SESSION = 100
    ARTIFACT_CLEANUP_THRESHOLD = 150

    def __init__(
        self,
        shell_tool: Any,
        max_result_chars: int = 30000,
        artifacts_dir: Optional[str | Path] = None,
        artifact_threshold: Optional[int] = None,
    ) -> None:
        self._shell_tool = shell_tool
        self._max_result_chars = max_result_chars
        if isinstance(artifacts_dir, Path):
            self._artifact_dir = artifacts_dir
        elif isinstance(artifacts_dir, str) and artifacts_dir:
            self._artifact_dir = Path(artifacts_dir)
        else:
            self._artifact_dir = None
        self._artifact_threshold = artifact_threshold or 10000
        self._artifact_count = 0
        # Thread safety for artifact counting
        self._artifact_lock = threading.Lock()

    def register_hooks(self, registry) -> None:  # type: ignore[no-untyped-def]
        from strands.hooks import AfterToolCallEvent

        registry.add_callback(BeforeToolCallEvent, self._on_before_tool_async)
        registry.add_callback(AfterToolCallEvent, self._truncate_large_results_async)

    async def _on_before_tool_async(self, event) -> None:  # type: ignore[no-untyped-def]
        """Route unknown tools to shell executor."""
        if event is None:
            logger.warning("Received None event in _on_before_tool")
            return

        if getattr(event, "selected_tool", None) is not None:
            return

        tool_use = getattr(event, "tool_use", {}) or {}
        if not isinstance(tool_use, dict):
            logger.warning("Invalid tool_use type: %s", type(tool_use))
            return

        tool_name = str(tool_use.get("name", "")).strip()
        if not tool_name:
            return

        raw_input = tool_use.get("input", {})
        if isinstance(raw_input, dict):
            params: dict[str, Any] = raw_input
        else:
            params = {"options": str(raw_input)}
            if isinstance(raw_input, str) and raw_input.strip().startswith("{"):
                try:
                    import json as _json

                    maybe = _json.loads(raw_input)
                    if isinstance(maybe, dict):
                        params = maybe
                except Exception:
                    pass

        options = _s(params.get("options"))
        target = _first(
            params.get("target"),
            params.get("host"),
            params.get("url"),
            params.get("ip"),
        )

        known = {"options", "target", "host", "url", "ip"}
        extras: list[str] = []
        for key, value in params.items():
            if key in known:
                continue
            if isinstance(value, (str, int, float)):
                value_str = _s(value)
                if not value_str:
                    continue
                flag = ("-" if len(key) == 1 else "--") + key.replace("_", "-")
                extras.append(f"{flag} {value_str}")

        parts = [tool_name]
        if options:
            parts.append(options)
        if target:
            parts.append(target)
        if extras:
            parts.extend(extras)
        command = " ".join(p for p in parts if p)

        event.selected_tool = self._shell_tool  # type: ignore[attr-defined]
        tool_use["input"] = {"command": command}

    async def _truncate_large_results_async(self, event) -> None:
        """Truncate large tool results and externalize to artifacts.

        SDK Contract Compliance:
        - MUST REPLACE event.result with new dict, NOT mutate nested content
        - Creates new content list with modified blocks
        - Preserves all ToolResult schema fields (status, toolUseId, content)
        """
        if event is None:
            logger.warning("Received None event in _truncate_large_results")
            return

        tool_name = getattr(event, "tool_use", {}).get("name", "unknown")

        result = getattr(event, "result", None)
        if not result or not isinstance(result, dict):
            return

        # Validate ToolResult schema (graceful handling of malformed results)
        content = result.get("content")
        if not isinstance(content, list):
            logger.debug("ToolResult content is not a list (%s), skipping truncation", type(content))
            return

        # Track if any modifications were made
        modified = False
        new_content = []

        for block in content:
            if not isinstance(block, dict):
                # Preserve unknown blocks unchanged
                logger.warning("content block is not a dictionary: %s", type(block))
                new_content.append(block)
                continue

            summary_lines = []

            for file_type in ["document", "image"]:
                if file_type not in block:
                    continue
                document: TypedDict = block.get(file_type)
                ext = sanitize_target_name(document.get("format", "bin"))
                artifact_path = self._persist_artifact(tool_name, document.get("source", {}).get("bytes", b''), ext)
                try:
                    relative_path = os.path.relpath(artifact_path, os.getcwd())
                except Exception:
                    relative_path = str(artifact_path)
                summary_lines.extend([
                    f"[Tool output: {artifact_path.stat().st_size} bytes | File: {relative_path}]"
                ])
                logger.debug("saved tool output file to %s", artifact_path)

            for file_type in ["text", "json"]:
                if file_type not in block:
                    continue
                logger.debug("processing tool output type %s", file_type)
                text = block.get(file_type)
                if isinstance(text, bytes):
                    text = text.decode(encoding="utf-8", errors="ignore")
                elif not isinstance(text, str):
                    text = str(text)

                original_size = len(text)
                needs_externalization = original_size > self._artifact_threshold
                needs_truncation = original_size > self._max_result_chars

                # Skip if no action needed - preserve original block
                if not needs_externalization and not needs_truncation and not summary_lines:
                    # Assume only one type of result per block, original block will be appended later
                    continue

                artifact_path = None

                # Always externalize large outputs to preserve full evidence
                if needs_externalization:
                    artifact_path = self._persist_artifact(tool_name, text, "json" if file_type == "json" else "log")

                # Calculate actual truncation target
                # When externalizing, use smaller inline preview (artifact_threshold)
                # When just truncating, use max_result_chars
                if artifact_path is not None:
                    # Externalized: use smaller inline preview to save context
                    truncate_target = min(self._artifact_threshold, self._max_result_chars)
                else:
                    truncate_target = self._max_result_chars

                # Only log "Truncating" if we're actually reducing size
                actual_truncated_size = min(truncate_target, original_size)
                if actual_truncated_size < original_size:
                    logger.warning(
                        "Truncating large tool result: tool=%s, original_size=%d chars, truncated_to=%d",
                        tool_name,
                        original_size,
                        actual_truncated_size,
                    )
                elif artifact_path is not None:
                    # Just externalized, not truncated
                    logger.info(
                        "Externalized tool result to artifact: tool=%s, size=%d chars, artifact=%s",
                        tool_name,
                        original_size,
                        artifact_path,
                    )

                # Build new text content (DO NOT mutate original block)
                snippet = text[:truncate_target]
                if artifact_path is not None:
                    try:
                        relative_path = os.path.relpath(artifact_path, os.getcwd())
                    except Exception:
                        relative_path = str(artifact_path)
                    # Build concise summary with artifact reference
                    summary_lines.extend([
                        f"[Tool output: {original_size:,} chars | Inline: {len(snippet):,} chars | Full: {relative_path}]",
                        "",
                        snippet,
                        "",
                        f"[Complete output saved to: {relative_path}]"
                    ])
                else:
                    summary_lines.extend([f"[Truncated: {original_size:,} chars total]", "", snippet])

            if summary_lines:
                # Create NEW block with modified text (SDK compliant - no mutation)
                new_block = ToolResultContent()
                new_block["text"] = "\n".join(summary_lines)
                new_content.append(new_block)
                modified = True
            else:
                new_content.append(block)

        # SDK Contract: REPLACE event.result with new dict (not mutate)
        if modified:
            # Build new ToolResult preserving all schema fields
            new_result = {
                "content": new_content,
            }
            # Preserve required ToolResult fields
            if "status" in result:
                new_result["status"] = result["status"]
            if "toolUseId" in result:
                new_result["toolUseId"] = result["toolUseId"]
            # Preserve any additional fields
            for key in result:
                if key not in new_result:
                    new_result[key] = result[key]

            # REPLACE event.result (SDK compliant)
            event.result = new_result

    def _persist_artifact(self, tool_name: str, payload: str | bytes, extension: str = "log") -> Optional[Path]:
        """Validate artifact path operations."""
        # Validate inputs
        if not self._artifact_dir:
            return None
        if not isinstance(payload, str) and not isinstance(payload, bytes):
            logger.warning("Invalid payload type for artifact: %s", type(payload))
            return None
        if not payload:
            logger.debug("Empty payload, skipping artifact creation")
            return None

        try:
            # Race condition in directory creation - exist_ok=True handles concurrent creation
            # Multiple threads/processes may try to create the same directory simultaneously
            try:
                self._artifact_dir.mkdir(parents=True, exist_ok=True)
            except FileExistsError:
                # Directory was created by another thread/process between check and creation
                # This is safe to ignore since exist_ok=True should handle it, but we catch just in case
                pass

            safe_tool = re.sub(r"[^a-zA-Z0-9_.-]", "_", tool_name or "tool")
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = (
                f"{safe_tool[:40] or 'tool'}_{timestamp}_{uuid.uuid4().hex[:6]}.artifact.{extension}"
            )
            artifact_path = self._artifact_dir / filename

            # Prevent path traversal
            if not artifact_path.resolve().is_relative_to(self._artifact_dir.resolve()):
                logger.error("Path traversal attempt detected: %s", artifact_path)
                return None

            # Use atomic write with exclusive creation to prevent race conditions
            # If file already exists (UUID collision or concurrent write), we'll get FileExistsError
            def write_payload(path: Path):
                if isinstance(payload, str):
                    path.write_text(payload, encoding="utf-8", errors="ignore")
                else:
                    with open(path, "wb") as f:
                        f.write(payload)

            try:
                write_payload(artifact_path)
            except FileExistsError:
                # Extremely rare UUID collision or concurrent write - retry with new UUID
                filename = (
                    f"{safe_tool[:40] or 'tool'}_{timestamp}_{uuid.uuid4().hex[:8]}_retry.artifact.{extension}"
                )
                artifact_path = self._artifact_dir / filename
                write_payload(artifact_path)

            logger.debug("Persisted artifact: %s", artifact_path)

            # Track artifacts and clean up old ones to prevent disk exhaustion
            # Thread-safe artifact counting
            should_cleanup = False
            with self._artifact_lock:
                self._artifact_count += 1
                should_cleanup = self._artifact_count >= self.ARTIFACT_CLEANUP_THRESHOLD

            if should_cleanup:
                self._cleanup_old_artifacts()

            return artifact_path
        except Exception as exc:
            logger.warning("Failed to persist tool output artifact: %s", exc, exc_info=True)
            return None

    def _cleanup_old_artifacts(self) -> None:
        """Clean up old artifacts to prevent unbounded disk usage.

        Keeps only the most recent MAX_ARTIFACTS_PER_SESSION artifacts,
        removing older ones based on modification time.
        """
        if not self._artifact_dir or not self._artifact_dir.exists():
            return

        try:
            # Get all .log files in artifact directory
            artifacts = list(self._artifact_dir.glob("*.artifact.*"))
            if len(artifacts) <= self.MAX_ARTIFACTS_PER_SESSION:
                # No cleanup needed - thread-safe update
                with self._artifact_lock:
                    self._artifact_count = len(artifacts)
                return

            # Sort by modification time (oldest first)
            artifacts.sort(key=lambda p: p.stat().st_mtime)

            # Remove oldest artifacts, keep only MAX_ARTIFACTS_PER_SESSION
            to_remove = artifacts[:-self.MAX_ARTIFACTS_PER_SESSION]
            removed_count = 0
            for artifact in to_remove:
                try:
                    artifact.unlink()
                    removed_count += 1
                except Exception as e:
                    logger.debug("Failed to remove old artifact %s: %s", artifact, e)

            # Update count - thread-safe
            with self._artifact_lock:
                self._artifact_count = self.MAX_ARTIFACTS_PER_SESSION
            logger.info(
                "Cleaned up %d old artifacts, keeping %d most recent",
                removed_count,
                self.MAX_ARTIFACTS_PER_SESSION
            )
        except Exception as e:
            logger.warning("Failed to cleanup old artifacts: %s", e, exc_info=True)


def _s(value: Any) -> str:
    """Safe string conversion with proper error handling."""
    try:
        if value is None:
            return ""
        # Handle potential encoding issues
        result = str(value).strip()
        # Validate result is valid string
        if not isinstance(result, str):
            return ""
        return result
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        logger.debug("Unicode error in string conversion: %s", e)
        return ""
    except Exception as e:
        logger.debug("Failed to convert value to string: %s", e)
        return ""


def _first(*values: Any) -> str:
    for value in values:
        converted = _s(value)
        if converted:
            return converted
    return ""
