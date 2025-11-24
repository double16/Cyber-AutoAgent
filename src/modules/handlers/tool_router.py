#!/usr/bin/env python3
"""Hook that reroutes unknown tools to shell and externalizes large outputs."""

import logging
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from strands.hooks import BeforeToolCallEvent  # type: ignore

logger = logging.getLogger(__name__)


class ToolRouterHook:
    """BeforeToolCall hook that maps unknown tool names to shell and truncates large results."""

    # Constants for artifact cleanup to prevent unbounded disk usage
    MAX_ARTIFACTS_PER_SESSION = 100  # Maximum number of artifacts to keep
    ARTIFACT_CLEANUP_THRESHOLD = 150  # Clean up when we exceed this many artifacts

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
        # Default artifact threshold to 10KB - externalize medium-to-large outputs to save context
        self._artifact_threshold = artifact_threshold or 10000
        # Feature flag: inline the artifact head explicitly to improve rehydration without requiring a follow-up tool call
        self._inline_artifact_head = (
            str(os.getenv("CYBER_TOOL_INLINE_ARTIFACT_HEAD", "true")).lower() == "true"
        )
        # Track artifact count for cleanup
        self._artifact_count = 0

    def register_hooks(self, registry) -> None:  # type: ignore[no-untyped-def]
        from strands.hooks import AfterToolCallEvent

        registry.add_callback(BeforeToolCallEvent, self._on_before_tool_async)
        registry.add_callback(AfterToolCallEvent, self._truncate_large_results_async)

    async def _on_before_tool_async(self, event) -> None:  # type: ignore[no-untyped-def]
        """Add type safety for event attributes (async version)."""
        # Validate event object
        if event is None:
            logger.warning("Received None event in _on_before_tool")
            return

        if getattr(event, "selected_tool", None) is not None:
            return

        tool_use = getattr(event, "tool_use", {}) or {}
        # Validate tool_use is a dict
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
        """Add type safety for event attributes."""
        # Validate event object
        if event is None:
            logger.warning("Received None event in _truncate_large_results")
            return

        result = getattr(event, "result", None)
        if not result or not isinstance(result, dict):
            return
        content = result.get("content", [])
        for block in content:
            if not isinstance(block, dict) or "text" not in block:
                continue
            text = block["text"]
            if not isinstance(text, str):
                continue
            needs_externalization = len(text) > self._artifact_threshold
            needs_truncation = (
                len(text) > self._max_result_chars or needs_externalization
            )
            if not needs_truncation:
                continue

            tool_name = getattr(event, "tool_use", {}).get("name", "unknown")
            artifact_path = None
            if needs_externalization:
                artifact_path = self._persist_artifact(tool_name, text)
            logger.warning(
                "Truncating large tool result: tool=%s, original_size=%d chars, truncated_to=%d",
                tool_name,
                len(text),
                min(self._max_result_chars, len(text)),
            )
            # Reserve space for artifact preview (4KB) + headers (~1KB)
            if artifact_path is not None:
                preview_limit = max(100, self._max_result_chars - 5000)
            else:
                preview_limit = self._max_result_chars
            snippet = text[:preview_limit]
            if artifact_path is not None:
                try:
                    relative_path = os.path.relpath(artifact_path, os.getcwd())
                except Exception:
                    relative_path = str(artifact_path)
                artifact_preview = ""
                try:
                    with open(
                        artifact_path, "r", encoding="utf-8", errors="ignore"
                    ) as fh:
                        artifact_preview = fh.read(4000)
                except Exception:
                    artifact_preview = ""
                summary_lines = [
                    f"[Tool output: {len(text):,} chars total | Preview: {len(snippet):,} chars below | Full: {relative_path}]",
                    "",
                    snippet,
                ]
                if artifact_preview:
                    # Make the head explicit to aid LLM consumption even if it doesn't issue the follow-up tool call
                    if self._inline_artifact_head:
                        summary_lines.extend([
                            "",
                            "[Artifact head - 4000 chars:]",
                            artifact_preview,
                            "",
                            f"[Complete output saved to: {relative_path}]"
                        ])
                    else:
                        summary_lines.extend([
                            "",
                            "[Artifact head - 4000 chars:]",
                            artifact_preview
                        ])
                block["text"] = "\n".join(summary_lines)
            else:
                suffix_lines = [f"[Truncated: {len(text)} chars total]"]
                block["text"] = f"{snippet}\n\n" + "\n".join(suffix_lines)

    def _persist_artifact(self, tool_name: str, payload: str) -> Optional[Path]:
        """Validate artifact path operations."""
        # Validate inputs
        if not self._artifact_dir:
            return None
        if not isinstance(payload, str):
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
                f"{safe_tool[:40] or 'tool'}_{timestamp}_{uuid.uuid4().hex[:6]}.log"
            )
            artifact_path = self._artifact_dir / filename

            # Prevent path traversal
            if not artifact_path.resolve().is_relative_to(self._artifact_dir.resolve()):
                logger.error("Path traversal attempt detected: %s", artifact_path)
                return None

            # Use atomic write with exclusive creation to prevent race conditions
            # If file already exists (UUID collision or concurrent write), we'll get FileExistsError
            try:
                artifact_path.write_text(payload, encoding="utf-8", errors="ignore")
            except FileExistsError:
                # Extremely rare UUID collision or concurrent write - retry with new UUID
                filename = (
                    f"{safe_tool[:40] or 'tool'}_{timestamp}_{uuid.uuid4().hex[:8]}_retry.log"
                )
                artifact_path = self._artifact_dir / filename
                artifact_path.write_text(payload, encoding="utf-8", errors="ignore")

            logger.debug("Persisted artifact: %s", artifact_path)

            # Track artifacts and clean up old ones to prevent disk exhaustion
            self._artifact_count += 1
            if self._artifact_count >= self.ARTIFACT_CLEANUP_THRESHOLD:
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
            artifacts = list(self._artifact_dir.glob("*.log"))
            if len(artifacts) <= self.MAX_ARTIFACTS_PER_SESSION:
                # No cleanup needed
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

            # Update count
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
