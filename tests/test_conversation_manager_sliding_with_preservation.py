import logging
from dataclasses import dataclass
import pytest

from strands.agent.conversation_manager import SlidingWindowConversationManager
from strands.types.exceptions import ContextWindowOverflowException
from modules.handlers.conversation_budget import SlidingWindowConversationManagerWithPreservation

logger = logging.getLogger(__name__)


@dataclass
class DummyAgent:
    messages: list


def _make_fake_super_reduce(window_size: int):
    """
    Patch target for SlidingWindowConversationManager.reduce_context.

    Mimics a basic sliding window:
      - keeps the last `window_size` messages
      - sets self.removed_message_count to number removed
    """

    def _fake_reduce_context(self, agent, e=None, **kwargs):
        original_len = len(agent.messages)
        if original_len > window_size:
            agent.messages = agent.messages[-window_size:]
        removed = original_len - len(agent.messages)
        self.removed_message_count = removed

    return _fake_reduce_context


def _fake_super_reduce_noop(self, agent, e=None, **kwargs):
    """
    Does not reduce at all. Used to force the overflow path when preservation
    makes the list >= original length.
    """
    self.removed_message_count = 0


def test_reduce_context_preserves_first_messages_and_does_not_overflow(monkeypatch, caplog):
    """
    Happy path: super reduces enough that after re-inserting preserved messages,
    the resulting length is still < before_reduce_count.
    """
    # super reduces to last 4 (10 -> 4), then we re-add 2 preserved => 6 (< 10)
    monkeypatch.setattr(
        SlidingWindowConversationManager,
        "reduce_context",
        _make_fake_super_reduce(window_size=4),
    )

    original = [f"m{i}" for i in range(10)]
    agent = DummyAgent(messages=original.copy())

    mgr = SlidingWindowConversationManagerWithPreservation(
        window_size=4,
        preserve_first_messages=2,
    )

    caplog.set_level(logging.INFO)

    mgr.reduce_context(agent)

    assert agent.messages[:2] == original[:2]
    assert agent.messages[2:] == original[-4:]

    # Base removed 6 (10 -> 4). We re-added 2 preserved messages, so net removed should be 4.
    assert mgr.removed_message_count == 4

    assert "Preserved 2 messages" in caplog.text


def test_reduce_context_raises_when_unable_to_trim(monkeypatch):
    """
    If super doesn't trim anything, preservation can make the length stay the same
    (or grow). The updated method raises ContextWindowOverflowException when
    after_reduce_count >= before_reduce_count.
    """
    monkeypatch.setattr(
        SlidingWindowConversationManager,
        "reduce_context",
        _fake_super_reduce_noop,
    )

    original = [f"m{i}" for i in range(10)]
    agent = DummyAgent(messages=original.copy())

    mgr = SlidingWindowConversationManagerWithPreservation(
        window_size=999,  # irrelevant due to noop super
        preserve_first_messages=2,
    )

    with pytest.raises(ContextWindowOverflowException, match="Unable to trim conversation context!"):
        mgr.reduce_context(agent)

    # In this scenario, we never trimmed, so agent.messages is unchanged.
    assert agent.messages == original


def test_reduce_context_no_preservation_delegates_to_super(monkeypatch):
    monkeypatch.setattr(
        SlidingWindowConversationManager,
        "reduce_context",
        _make_fake_super_reduce(window_size=4),
    )

    original = [f"m{i}" for i in range(10)]
    agent = DummyAgent(messages=original.copy())

    mgr = SlidingWindowConversationManagerWithPreservation(
        window_size=4,
        preserve_first_messages=0,
    )

    mgr.reduce_context(agent)

    assert agent.messages == original[-4:]
    assert mgr.removed_message_count == 6
