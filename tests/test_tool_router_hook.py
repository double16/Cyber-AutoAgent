#!/usr/bin/env python3
"""Tests for ToolRouterHook.

This module tests:
1. BeforeToolCallEvent: Unknown tool routing to shell
2. AfterToolCallEvent: Large result truncation with SDK contract compliance
3. Thread safety: Artifact count atomicity
4. Schema validation: ToolResult structure validation
"""
import asyncio
import copy
import threading
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from modules.handlers.tool_router import ToolRouterHook


# ============================================================================
# Test Fixtures
# ============================================================================


class MockAfterToolCallEvent:
    """Mock that simulates SDK AfterToolCallEvent behavior.

    The real SDK AfterToolCallEvent:
    - Only allows writing to 'result' field via _can_write()
    - Nested mutations bypass __setattr__ but violate SDK contract
    - This mock tracks whether result was REPLACED vs MUTATED
    """

    def __init__(self, result: dict, tool_use: dict | None = None):
        self._result = result
        self._original_result_id = id(result)
        self._original_content_id = id(result.get("content", [])) if result else None
        self.tool_use = tool_use or {"name": "test_tool"}
        self._result_was_replaced = False
        self._content_was_mutated = False

    @property
    def result(self) -> dict:
        return self._result

    @result.setter
    def result(self, value: dict) -> None:
        """Track when result is properly REPLACED (SDK compliant)."""
        self._result = value
        self._result_was_replaced = True

    def check_mutation_pattern(self) -> dict[str, Any]:
        """Check whether SDK contract was followed.

        Returns dict with:
        - result_replaced: True if event.result was assigned new object
        - content_mutated: True if content blocks were mutated in-place
        - sdk_compliant: True if replacement pattern was used
        """
        current_content_id = id(self._result.get("content", [])) if self._result else None

        # Check if content list identity changed (new list created)
        content_identity_changed = current_content_id != self._original_content_id

        return {
            "result_replaced": self._result_was_replaced,
            "content_identity_changed": content_identity_changed,
            "sdk_compliant": self._result_was_replaced,
        }


def create_tool_result(text: str, tool_use_id: str = "test_id") -> dict:
    """Create a valid ToolResult structure."""
    return {
        "status": "success",
        "toolUseId": tool_use_id,
        "content": [{"text": text}],
    }


# ============================================================================
# Original Tests: BeforeToolCallEvent
# ============================================================================


def test_tool_router_maps_unknown_tool_to_shell():
    """Test that unknown tools are mapped to shell."""
    async def _test():
        # Prepare hook with a sentinel shell tool
        sentinel_shell = object()
        hook = ToolRouterHook(shell_tool=sentinel_shell)  # type: ignore[attr-defined]

        # Minimal event carrying an unknown tool name
        event = types.SimpleNamespace()
        event.selected_tool = None
        event.tool_use = {
            "name": "nmap",
            "input": {"options": "-sC -sV", "target": "http://example.com:8080"},
        }

        # Invoke async hook
        await hook._on_before_tool_async(event)  # type: ignore[attr-defined]

        # Verify that shell was selected and command composed
        assert event.selected_tool is sentinel_shell
        cmd = event.tool_use.get("input", {}).get("command", "")
        assert isinstance(cmd, str) and cmd.startswith("nmap")
        assert "-sC" in cmd and "-sV" in cmd and "http://example.com:8080" in cmd

    asyncio.run(_test())


def test_tool_router_keeps_registered_tools_unchanged():
    """Test that registered tools are not modified."""
    async def _test():
        sentinel_shell = object()
        hook = ToolRouterHook(shell_tool=sentinel_shell)  # type: ignore[attr-defined]

        event = types.SimpleNamespace()
        event.selected_tool = object()  # Simulate already-resolved tool
        event.tool_use = {"name": "shell", "input": {"command": "echo hi"}}

        await hook._on_before_tool_async(event)  # should no-op

        # selected_tool remains unchanged (not replaced with sentinel)
        assert event.selected_tool is not sentinel_shell
        # input remains as-is
        assert event.tool_use["input"]["command"] == "echo hi"

    asyncio.run(_test())


# ============================================================================
# NEW TESTS: AfterToolCallEvent SDK Contract Compliance
# ============================================================================


class TestAfterToolCallEventSDKContract:
    """Test that AfterToolCallEvent handling follows SDK contract.

    SDK Contract (from strands/hooks/events.py):
    - event.result is the ONLY writable field
    - Modifications should REPLACE event.result, not mutate nested dicts
    - _can_write() returns True only for 'result' field

    These tests validate the implementation follows this contract.
    """

    def test_truncation_replaces_result_not_mutates(self, tmp_path):
        """CRITICAL: Verify result is REPLACED, not mutated in-place.

        This is the core SDK contract test. The implementation MUST:
        1. Create a NEW ToolResult dict
        2. Assign it to event.result
        3. NOT mutate the original content blocks in-place

        Current bug (lines 186, 189): block["text"] = ... mutates in-place
        """
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=100,
                artifacts_dir=tmp_path,
                artifact_threshold=50,
            )

            # Create large content that triggers truncation
            large_text = "X" * 200
            original_result = create_tool_result(large_text)

            # Track the original content block
            original_content_block = original_result["content"][0]
            original_text_before = original_content_block["text"]

            event = MockAfterToolCallEvent(original_result)

            # Invoke the hook
            await hook._truncate_large_results_async(event)

            # Check SDK compliance
            mutation_check = event.check_mutation_pattern()

            # THE KEY ASSERTION: result must be REPLACED
            assert mutation_check["sdk_compliant"], (
                "SDK CONTRACT VIOLATION: event.result was not replaced.\n"
                "The hook mutated content blocks in-place instead of creating new result.\n"
                f"result_replaced={mutation_check['result_replaced']}\n"
                "Fix: Create new content list and assign new dict to event.result"
            )

        asyncio.run(_test())

    def test_original_result_unchanged_after_truncation(self, tmp_path):
        """Verify original result dict is not modified (immutability).

        SDK expects hooks to not modify the original objects.
        This catches in-place mutations that corrupt shared references.
        """
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=100,
                artifacts_dir=tmp_path,
                artifact_threshold=50,
            )

            # Create and deep copy original
            large_text = "X" * 200
            original_result = create_tool_result(large_text)
            original_snapshot = copy.deepcopy(original_result)

            event = MockAfterToolCallEvent(original_result)
            await hook._truncate_large_results_async(event)

            # Original should be unchanged IF we followed SDK contract
            # Note: This will FAIL with current implementation due to in-place mutation
            original_text_now = original_result["content"][0]["text"]
            original_text_was = original_snapshot["content"][0]["text"]

            # If result was properly REPLACED, original should be unchanged
            # If result was MUTATED in-place, original will be modified
            if not event.check_mutation_pattern()["sdk_compliant"]:
                pytest.skip("Skipping immutability check - SDK contract already violated")

            assert original_text_now == original_text_was, (
                "IMMUTABILITY VIOLATION: Original result was modified.\n"
                f"Original text length: {len(original_text_was)}\n"
                f"Current text length: {len(original_text_now)}\n"
                "The hook should create new objects, not modify originals."
            )

        asyncio.run(_test())

    def test_truncation_preserves_toolresult_schema(self, tmp_path):
        """Verify truncated result maintains valid ToolResult schema.

        ToolResult TypedDict requires:
        - status: str ("success" or "error")
        - toolUseId: str
        - content: list[ToolResultContent]
        """
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=100,
                artifacts_dir=tmp_path,
                artifact_threshold=50,
            )

            large_text = "X" * 200
            original_result = create_tool_result(large_text, tool_use_id="schema_test_123")
            event = MockAfterToolCallEvent(original_result)

            await hook._truncate_large_results_async(event)

            result = event.result

            # Validate schema
            assert "status" in result, "Missing 'status' field in ToolResult"
            assert "toolUseId" in result, "Missing 'toolUseId' field in ToolResult"
            assert "content" in result, "Missing 'content' field in ToolResult"

            assert isinstance(result["status"], str), "'status' must be string"
            assert isinstance(result["toolUseId"], str), "'toolUseId' must be string"
            assert isinstance(result["content"], list), "'content' must be list"

            # Verify original values preserved
            assert result["status"] == "success", "status should be preserved"
            assert result["toolUseId"] == "schema_test_123", "toolUseId should be preserved"

        asyncio.run(_test())

    def test_no_truncation_for_small_results(self):
        """Verify small results pass through unchanged."""
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=1000,
                artifact_threshold=500,
            )

            small_text = "Small output"
            original_result = create_tool_result(small_text)
            original_text = original_result["content"][0]["text"]

            event = MockAfterToolCallEvent(original_result)
            await hook._truncate_large_results_async(event)

            # Result should be unchanged
            assert len(event.result["content"]) == 1
            result_text = event.result["content"][0]["text"]
            assert result_text == original_text, (
                "Small results should pass through unchanged"
            )

        asyncio.run(_test())


# ============================================================================
# NEW TESTS: Thread Safety
# ============================================================================


class TestToolRouterThreadSafety:
    """Test thread safety of ToolRouterHook.

    The hook has shared state:
    - _artifact_count: Incremented on each artifact creation
    - Concurrent tool calls could cause race conditions
    """

    def test_artifact_count_thread_safety(self, tmp_path):
        """Verify artifact counting is thread-safe.

        Bug: self._artifact_count += 1 is not atomic.
        Multiple threads can read same value and increment to same result.
        """
        hook = ToolRouterHook(
            shell_tool=object(),
            max_result_chars=100,
            artifacts_dir=tmp_path,
            artifact_threshold=50,
        )

        errors = []
        results = []
        num_threads = 20
        barrier = threading.Barrier(num_threads)

        async def truncate_async(thread_id: int):
            try:
                large_text = f"Thread {thread_id}: " + "X" * 200
                result = create_tool_result(large_text, f"thread_{thread_id}")
                event = MockAfterToolCallEvent(result, {"name": f"tool_{thread_id}"})
                await hook._truncate_large_results_async(event)
                return hook._artifact_count
            except Exception as e:
                errors.append(e)
                return None

        def thread_worker(thread_id: int):
            barrier.wait()  # Synchronize all threads to start together
            count = asyncio.run(truncate_async(thread_id))
            results.append(count)

        threads = [
            threading.Thread(target=thread_worker, args=(i,))
            for i in range(num_threads)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"

        # Check artifact files created
        artifact_files = list(tmp_path.glob("*.log"))

        # With thread safety, we should have exactly num_threads artifacts
        assert len(artifact_files) == num_threads, (
            f"Expected {num_threads} artifacts, got {len(artifact_files)}.\n"
            "Artifacts should not be overwritten; each thread should produce exactly one artifact."
        )

    def test_concurrent_cleanup_safety(self, tmp_path):
        """Test that concurrent cleanup doesn't cause errors."""
        hook = ToolRouterHook(
            shell_tool=object(),
            max_result_chars=100,
            artifacts_dir=tmp_path,
            artifact_threshold=50,
        )

        # Pre-create many artifacts to trigger cleanup
        for i in range(160):
            (tmp_path / f"test_artifact_{i:03d}.log").write_text(f"content {i}")

        hook._artifact_count = 160
        errors = []

        def cleanup_worker():
            try:
                hook._cleanup_old_artifacts()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=cleanup_worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should not raise errors even with concurrent cleanup
        assert not errors, f"Cleanup errors: {errors}"


# ============================================================================
# NEW TESTS: Schema Validation
# ============================================================================


class TestToolResultSchemaValidation:
    """Test ToolResult schema validation before modification."""

    def test_handles_missing_status_field(self):
        """Verify graceful handling when status field is missing."""
        async def _test():
            hook = ToolRouterHook(shell_tool=object(), max_result_chars=100)

            # Malformed result missing 'status'
            malformed_result = {
                "toolUseId": "test",
                "content": [{"text": "X" * 200}],
            }

            event = types.SimpleNamespace(
                result=malformed_result,
                tool_use={"name": "test"},
            )

            # Should not raise, should handle gracefully
            try:
                await hook._truncate_large_results_async(event)
            except KeyError as e:
                pytest.fail(f"Should handle missing status gracefully: {e}")

        asyncio.run(_test())

    def test_handles_missing_tooluseid_field(self):
        """Verify graceful handling when toolUseId field is missing."""
        async def _test():
            hook = ToolRouterHook(shell_tool=object(), max_result_chars=100)

            # Malformed result missing 'toolUseId'
            malformed_result = {
                "status": "success",
                "content": [{"text": "X" * 200}],
            }

            event = types.SimpleNamespace(
                result=malformed_result,
                tool_use={"name": "test"},
            )

            try:
                await hook._truncate_large_results_async(event)
            except KeyError as e:
                pytest.fail(f"Should handle missing toolUseId gracefully: {e}")

        asyncio.run(_test())

    def test_handles_non_list_content(self):
        """Verify graceful handling when content is not a list."""
        async def _test():
            hook = ToolRouterHook(shell_tool=object(), max_result_chars=100)

            # Malformed result with string content
            malformed_result = {
                "status": "success",
                "toolUseId": "test",
                "content": "not a list",
            }

            event = types.SimpleNamespace(
                result=malformed_result,
                tool_use={"name": "test"},
            )

            try:
                await hook._truncate_large_results_async(event)
            except TypeError as e:
                pytest.fail(f"Should handle non-list content gracefully: {e}")

        asyncio.run(_test())

    def test_handles_none_result(self):
        """Verify graceful handling of None result."""
        async def _test():
            hook = ToolRouterHook(shell_tool=object(), max_result_chars=100)

            event = types.SimpleNamespace(
                result=None,
                tool_use={"name": "test"},
            )

            # Should return early without error
            await hook._truncate_large_results_async(event)

        asyncio.run(_test())


# ============================================================================
# NEW TESTS: Artifact Externalization
# ============================================================================


class TestArtifactExternalization:
    """Test artifact externalization functionality."""

    def test_externalization_creates_artifact_file(self, tmp_path):
        """Verify large outputs are saved to artifact files."""
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=100,
                artifacts_dir=tmp_path,
                artifact_threshold=50,
            )

            large_text = "X" * 200
            result = create_tool_result(large_text)
            event = MockAfterToolCallEvent(result, {"name": "test_tool"})

            await hook._truncate_large_results_async(event)

            # Check artifact was created
            artifacts = list(tmp_path.glob("*.log"))
            assert len(artifacts) == 1, f"Expected 1 artifact, got {len(artifacts)}"

            # Verify artifact contains full content
            artifact_content = artifacts[0].read_text()
            assert artifact_content == large_text, "Artifact should contain full output"

        asyncio.run(_test())

    def test_externalization_includes_artifact_reference(self, tmp_path):
        """Verify truncated result includes reference to artifact."""
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=100,
                artifacts_dir=tmp_path,
                artifact_threshold=50,
            )

            large_text = "X" * 200
            result = create_tool_result(large_text)
            event = MockAfterToolCallEvent(result, {"name": "test_tool"})

            await hook._truncate_large_results_async(event)

            result_text = event.result["content"][0]["text"]

            # Should contain artifact reference
            assert "artifacts/" in result_text or ".log" in result_text, (
                "Truncated result should reference artifact file"
            )
            assert "chars" in result_text.lower(), (
                "Should indicate character count"
            )

        asyncio.run(_test())

    def test_image_creates_artifact_file(self, tmp_path):
        """Verify large outputs are saved to artifact files."""
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=10000,
                artifacts_dir=tmp_path,
                artifact_threshold=10000,
            )

            image_data = b'\x47\x49\x46\x38\x39\x61'
            result = {
                "status": "success",
                "toolUseId": "test_id",
                "content": [{"image": {
                    "format": "gif",
                    "source": {"bytes": image_data}
                }}],
            }
            event = MockAfterToolCallEvent(result, {"name": "test_tool"})

            await hook._truncate_large_results_async(event)

            # Check artifact was created
            artifacts = list(tmp_path.glob("*.artifact.gif"))
            assert len(artifacts) == 1, f"Expected 1 artifact, got {len(artifacts)}"

            # Verify artifact contains full content
            artifact_content = artifacts[0].read_bytes()
            assert artifact_content == image_data, "Artifact should contain full output"

        asyncio.run(_test())

    def test_document_and_image_creates_artifact_files(self, tmp_path):
        """Verify large outputs are saved to artifact files."""
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=10000,
                artifacts_dir=tmp_path,
                artifact_threshold=10000,
            )

            image_data = b'\x47\x49\x46\x38\x39\x61'
            pdf_data = b'PDF'
            result = {
                "status": "success",
                "toolUseId": "test_id",
                "content": [{"image": {
                    "format": "gif",
                    "source": {"bytes": image_data}
                }},
                    {"document": {
                        "format": "pdf",
                        "source": {"bytes": pdf_data}
                    }}],
            }
            event = MockAfterToolCallEvent(result, {"name": "test_tool"})

            await hook._truncate_large_results_async(event)

            # Check artifact was created
            image_artifacts = list(tmp_path.glob("*.artifact.gif"))
            assert len(image_artifacts) == 1, f"Expected 1 image artifact, got {len(image_artifacts)}"

            # Verify artifact contains full content
            artifact_content = image_artifacts[0].read_bytes()
            assert artifact_content == image_data, "Image artifact should contain full output"

            # Check artifact was created
            pdf_artifacts = list(tmp_path.glob("*.artifact.pdf"))
            assert len(pdf_artifacts) == 1, f"Expected 1 document artifact, got {len(pdf_artifacts)}"

            # Verify artifact contains full content
            artifact_content = pdf_artifacts[0].read_bytes()
            assert artifact_content == pdf_data, "Document artifact should contain full output"

        asyncio.run(_test())


# ============================================================================
# Integration Test: Full Pipeline
# ============================================================================


class TestToolRouterIntegration:
    """Integration tests for complete tool routing pipeline."""

    def test_full_pipeline_with_large_output(self, tmp_path):
        """Test complete pipeline: route tool -> execute -> truncate result."""
        async def _test():
            sentinel_shell = MagicMock()
            hook = ToolRouterHook(
                shell_tool=sentinel_shell,
                max_result_chars=500,
                artifacts_dir=tmp_path,
                artifact_threshold=200,
            )

            # 1. Before: Route unknown tool
            before_event = types.SimpleNamespace(
                selected_tool=None,
                tool_use={"name": "nmap", "input": {"target": "example.com"}},
            )
            await hook._on_before_tool_async(before_event)
            assert before_event.selected_tool is sentinel_shell

            # 2. After: Truncate large result
            large_output = "Nmap scan results:\n" + "PORT   STATE SERVICE\n" * 100
            after_result = create_tool_result(large_output)
            after_event = MockAfterToolCallEvent(after_result, {"name": "shell"})

            await hook._truncate_large_results_async(after_event)

            # Verify truncation occurred
            result_text = after_event.result["content"][0]["text"]
            assert len(result_text) < len(large_output), "Result should be truncated"

            # Verify artifact created
            artifacts = list(tmp_path.glob("*.log"))
            assert len(artifacts) == 1, "Artifact should be created"

        asyncio.run(_test())


    def test_image_does_not_crash_when_artifacts_disabled(self):
        """Verify image blocks don't crash when artifacts_dir is None.

        This covers the prior bug where _persist_artifact() returned None and the code
        tried to call .stat() / relpath() on it.
        """
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=10000,
                artifacts_dir=None,
                artifact_threshold=10000,
            )

            image_data = b"\x47\x49\x46\x38\x39\x61"
            result = {
                "status": "success",
                "toolUseId": "test_id",
                "content": [
                    {
                        "image": {
                            "format": "gif",
                            "source": {"bytes": image_data},
                        }
                    }
                ],
            }
            event = MockAfterToolCallEvent(result, {"name": "test_tool"})

            # Should not raise
            await hook._truncate_large_results_async(event)

            # Should replace the binary payload with a text summary noting disabled persistence
            assert isinstance(event.result.get("content"), list)
            assert event.result["content"], "Expected non-empty content"
            text = event.result["content"][0].get("text", "")
            assert "Artifact persistence disabled" in text

        asyncio.run(_test())

    def test_document_does_not_crash_when_artifacts_disabled(self):
        """Verify document blocks don't crash when artifacts_dir is None."""
        async def _test():
            hook = ToolRouterHook(
                shell_tool=object(),
                max_result_chars=10000,
                artifacts_dir=None,
                artifact_threshold=10000,
            )

            pdf_data = b"%PDF-1.4\n%..."
            result = {
                "status": "success",
                "toolUseId": "test_id",
                "content": [
                    {
                        "document": {
                            "format": "pdf",
                            "source": {"bytes": pdf_data},
                        }
                    }
                ],
            }
            event = MockAfterToolCallEvent(result, {"name": "test_tool"})

            # Should not raise
            await hook._truncate_large_results_async(event)

            assert isinstance(event.result.get("content"), list)
            assert event.result["content"], "Expected non-empty content"
            text = event.result["content"][0].get("text", "")
            assert "Artifact persistence disabled" in text

        asyncio.run(_test())