from typing import Any

from strands.types.exceptions import ContextWindowOverflowException

from modules.handlers.conversation_budget import (
    MappingConversationManager,
    LargeToolResultMapper,
)


class _AgentStub:
    def __init__(self, messages: list[dict[str, Any]]) -> None:
        self.messages = messages
        self.system_prompt = "stub"
        self.tool_registry = None


def _make_message(text: str) -> dict[str, Any]:
    return {"role": "assistant", "content": [{"type": "text", "text": text}]}


def test_pruning_conversation_manager_sliding_trims_messages():
    """Test that conversation manager prunes to the configured target when window exceeded.

    NOTE: The manager targets 90% of window_size, but will not prune below the
    preservation minimum (preserve_first + preserve_last + 1).
    """
    manager = MappingConversationManager(
        window_size=3, summary_ratio=0.5, preserve_recent_messages=1
    )
    agent = _AgentStub([_make_message(str(i)) for i in range(5)])

    manager.apply_management(agent)

    assert len(agent.messages) == 2

    # Always preserve the first message
    assert agent.messages[0]["content"][0]["text"] == "0"

    # The last message should be retained (either via preserve_last or the +1 minimum)
    assert agent.messages[-1]["content"][0]["text"] == "4"


def test_pruning_conversation_manager_falls_back_to_summary(monkeypatch):
    """Test summarization fallback when sliding window overflows.

    NOTE: SDK contract requires raising ContextWindowOverflowException when
    reduction is impossible (all messages in preservation zone).
    Use larger window to allow actual summarization to occur.
    """
    import pytest

    manager = MappingConversationManager(
        window_size=10, summary_ratio=0.5, preserve_recent_messages=2
    )
    # More messages to give room for summarization
    agent = _AgentStub([_make_message(f"msg{i}") for i in range(5)])

    # Force sliding reduction to raise overflow so summarization path executes
    def _raise_overflow(*_args, **_kwargs):
        raise ContextWindowOverflowException("forced")

    monkeypatch.setattr(manager._sliding, "reduce_context", _raise_overflow)

    summary_message = _make_message("summary")

    def _fake_generate_summary(messages, _agent):
        # Should summarize messages not in preservation zone
        return summary_message

    monkeypatch.setattr(manager, "_generate_summary", _fake_generate_summary)

    manager.reduce_context(agent)

    # After summarization: summary + preserved messages
    assert agent.messages[0] is summary_message or "summary" in str(agent.messages[0])


def test_reduce_context_raises_when_exhausted(monkeypatch):
    """Test that reduce_context raises ContextWindowOverflowException when exhausted.

    SDK Contract: When reduction is truly impossible (all messages preserved),
    the manager MUST raise ContextWindowOverflowException to signal exhaustion.

    This test monkeypatches the sliding window to do nothing (simulating a scenario
    where no reduction is possible), then verifies our exhaustion logic raises.
    """
    import pytest

    manager = MappingConversationManager(
        window_size=10,
        summary_ratio=0.5,
        preserve_recent_messages=1,
        preserve_first_messages=1,
    )
    # Only 2 messages with preserve_first=1 + preserve_last=1 = ALL preserved
    agent = _AgentStub([_make_message("old"), _make_message("recent")])

    # Mock sliding window to do nothing (no raise, no change)
    # This simulates the scenario where sliding can't reduce further
    def _noop_reduce(*args, **kwargs):
        pass

    monkeypatch.setattr(manager._sliding, "reduce_context", _noop_reduce)

    # This should raise because:
    # 1. Sliding does nothing (mocked)
    # 2. No change detected (before_msgs == after_msgs)
    # 3. Messages <= preserve_first + preserve_last + 1 (exhaustion condition)
    with pytest.raises(ContextWindowOverflowException) as exc_info:
        manager.reduce_context(agent)

    assert "exhausted" in str(exc_info.value).lower()


def test_tool_result_compressor_truncates_large_content():
    mapper = LargeToolResultMapper(max_tool_chars=100, truncate_at=10)
    message = {
        "role": "assistant",
        "content": [
            {
                "toolResult": {
                    "status": "success",
                    "toolUseId": "abc",
                    "content": [
                        {"text": "x" * 120},
                    ],
                }
            }
        ],
    }
    result = mapper(message, 1, [message])
    assert result is not None
    tool_content = result["content"][0]["toolResult"]["content"]
    assert "compressed" in tool_content[0]["text"]
    assert "[truncated" in tool_content[1]["text"]


def test_tool_result_compressor_summarizes_json():
    mapper = LargeToolResultMapper(max_tool_chars=50, truncate_at=10)
    message = {
        "role": "assistant",
        "content": [
            {
                "toolResult": {
                    "status": "success",
                    "toolUseId": "json",
                    "content": [
                        {"json": {"a": "x" * 50, "b": "y" * 60, "c": "z" * 70}},
                    ],
                }
            }
        ],
    }
    result = mapper(message, 1, [message])
    assert result is not None

    # New format includes a human-readable text indicator and a structured JSON indicator.
    tool_content = result["content"][0]["toolResult"]["content"]

    text_blocks = [b["text"] for b in tool_content if isinstance(b, dict) and "text" in b]
    json_blocks = [b["json"] for b in tool_content if isinstance(b, dict) and "json" in b]

    assert any("Compressed:" in t for t in text_blocks), "Expected compression text indicator"
    assert any("keys" in t for t in text_blocks), "Expected key count in text indicator"

    assert json_blocks, "Expected structured JSON compression indicator"
    json_block = json_blocks[0]
    assert json_block.get("_compressed") is True
    assert "_n_original_keys" in json_block
    assert json_block.get("_type") == "json"


def test_reduce_context_records_event(monkeypatch):
    manager = MappingConversationManager(
        window_size=2, summary_ratio=0.5, preserve_recent_messages=1
    )
    agent = _AgentStub(
        [_make_message("one"), _make_message("two"), _make_message("three")]
    )
    setattr(agent, "_pending_reduction_reason", "telemetry tokens 900")

    manager.reduce_context(agent)

    history = getattr(agent, "_context_reduction_events", [])
    assert history, "Expected reduction history to be recorded"
    event = history[-1]
    assert event["reason"] == "telemetry tokens 900"
    assert event["removed_messages"] > 0
