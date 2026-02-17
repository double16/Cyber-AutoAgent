#!/usr/bin/env python3
"""
Unit tests for AgentRepairHook MaxTokensReachedException handling.

Covers:
- after_model_call_check sets retry + state flag on MaxTokensReachedException
- resets retry counter when current_step advances
- stops retrying after 2 retries
- before_model_call_inject consumes state flag and injects reduced assistant text + system continue instructions
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import modules.handlers.agent_repair_hook as arh
from modules.handlers.agent_repair_hook import AgentRepairHook
from strands.types.exceptions import MaxTokensReachedException
from strands.types.content import Message
from strands.hooks.events import AfterModelCallEvent

# -------------------------
# Minimal fakes / helpers
# -------------------------

@dataclass
class FakeCallbackHandler:
    current_step: int = 0
    max_steps: int = 10
    reasoning_buffer: List[str] = None

    def __post_init__(self) -> None:
        if self.reasoning_buffer is None:
            self.reasoning_buffer = []

    def _emit_accumulated_reasoning(self, force: bool = False) -> None:
        # Called in a try/except, but we keep it harmless.
        return


class FakeAgent:
    def __init__(self, messages: Optional[List[Dict[str, Any]]] = None, callback_handler: Any = None):
        self.messages = messages if messages is not None else []
        self.callback_handler = callback_handler


class FakeAfterModelCallEvent:
    def __init__(
            self,
            agent: FakeAgent,
            exception: Optional[Exception] = None,
            stop_response: Optional[Any] = None,
            state: Optional[Dict[str, Any]] = None,
    ):
        self.agent = agent
        self.exception = exception
        self.stop_response = stop_response
        self.retry = False
        self.state = state if state is not None else {}


class FakeBeforeModelCallEvent:
    def __init__(self, agent: FakeAgent, state: Optional[Dict[str, Any]] = None):
        self.agent = agent
        self.state = state if state is not None else {}


class FakeStopResponse:
    def __init__(self, assistant_text: str):
        # Mimic: event.stop_response.message.get("content", [])
        self.message = {"content": [{"text": assistant_text}]}


class _ReducedText:
    def __init__(self, text: str):
        self._text = text

    def to_text(self) -> str:
        return self._text


# -------------------------
# Tests
# -------------------------

def test_after_model_call_maxtokens_no_message(monkeypatch):
    hook = AgentRepairHook()
    cb = FakeCallbackHandler(current_step=1)
    agent = FakeAgent(messages=[], callback_handler=cb)

    event_state: Dict[str, Any] = {}
    ev = FakeAfterModelCallEvent(
        agent=agent,
        exception=MaxTokensReachedException("max tokens"),
        stop_response=None,
        state=event_state,
    )

    hook.after_model_call_check(ev)

    assert ev.retry is False
    assert arh._REASONING_LOOP_RETRY_STATE_KEY not in event_state


def test_after_model_call_sets_retry_and_state_for_maxtokens_exception(monkeypatch):
    hook = AgentRepairHook()
    cb = FakeCallbackHandler(current_step=1, reasoning_buffer=["Repeated reasoning. Repeated reasoning."])
    agent = FakeAgent(messages=[], callback_handler=cb)

    event_state: Dict[str, Any] = {}
    ev = FakeAfterModelCallEvent(
        agent=agent,
        exception=MaxTokensReachedException("max tokens"),
        stop_response=None,
        state=event_state,
    )

    hook.after_model_call_check(ev)

    assert getattr(agent, "_max_tokens_retry_count", None) == 1
    assert ev.retry is True
    assert arh._REASONING_LOOP_RETRY_STATE_KEY in event_state


def test_after_model_call_sets_retry_and_state_for_maxtokens_stop_reason(monkeypatch):
    hook = AgentRepairHook()
    cb = FakeCallbackHandler(current_step=1, reasoning_buffer=["Repeated reasoning. Repeated reasoning."])
    agent = FakeAgent(messages=[], callback_handler=cb)

    event_state: Dict[str, Any] = {}
    ev = FakeAfterModelCallEvent(
        agent=agent,
        exception=None,
        stop_response=AfterModelCallEvent.ModelStopResponse(stop_reason="max_tokens", message=Message(content=[], role="assistant")),
        state=event_state,
    )

    hook.after_model_call_check(ev)

    assert getattr(agent, "_max_tokens_retry_count", None) == 1
    assert ev.retry is True
    assert arh._REASONING_LOOP_RETRY_STATE_KEY in event_state


def test_after_model_call_resets_retry_count_when_step_advances(monkeypatch):
    hook = AgentRepairHook()

    cb = FakeCallbackHandler(current_step=5)
    agent = FakeAgent(messages=[], callback_handler=cb)

    setattr(agent, "_max_tokens_retry_count", 2)  # simulate prior retries

    event_state: Dict[str, Any] = {}
    ev = FakeAfterModelCallEvent(
        agent=agent,
        exception=None,
        stop_response=AfterModelCallEvent.ModelStopResponse(stop_reason="end_turn", message=Message(content=[], role="assistant")),
        state=event_state,
    )

    hook.after_model_call_check(ev)

    assert getattr(agent, "_max_tokens_retry_count", None) == 0
    assert ev.retry is False
    assert arh._REASONING_LOOP_RETRY_STATE_KEY not in event_state


def test_after_model_call_does_not_retry_after_two_retries(monkeypatch):
    hook = AgentRepairHook()

    cb = FakeCallbackHandler(current_step=7)
    agent = FakeAgent(messages=[], callback_handler=cb)

    setattr(agent, "_max_tokens_retry_count", 2)  # at limit

    event_state: Dict[str, Any] = {}
    ev = FakeAfterModelCallEvent(
        agent=agent,
        exception=MaxTokensReachedException("max tokens"),
        stop_response=None,
        state=event_state,
    )

    hook.after_model_call_check(ev)

    assert ev.retry is False
    assert arh._REASONING_LOOP_RETRY_STATE_KEY not in event_state


def test_before_model_call_inject_replaces_last_assistant_with_reduced_text_and_adds_continue_system(monkeypatch):
    hook = AgentRepairHook()

    # Patch text reduction helpers to be deterministic and cheap.
    monkeypatch.setattr(arh, "collapse_first_repeated_sequence", lambda s: s)
    monkeypatch.setattr(arh, "reduce_lines_lossy", lambda *_args, **_kwargs: _ReducedText("REDUCED"))
    monkeypatch.setattr(arh, "get_reflection_snapshot", lambda **_kwargs: "REFLECTION_SNAPSHOT")

    cb = FakeCallbackHandler(current_step=2, max_steps=10)

    # Provide a last assistant message so truncated_message path is used (avoids the callback_handler early-return bug).
    agent = FakeAgent(
        messages=[
            {"role": "user", "content": [{"type": "text", "text": "hi"}]},
            {"role": "assistant", "content": [{"type": "text", "text": "lots of repetitive reasoning..."}]},
        ],
        callback_handler=cb,
    )

    state = {arh._REASONING_LOOP_RETRY_STATE_KEY: ("REDUCED", True)}
    ev = FakeBeforeModelCallEvent(agent=agent, state=state)

    hook.before_model_call_inject(ev)

    # Flag should be consumed.
    assert arh._REASONING_LOOP_RETRY_STATE_KEY not in state

    # Last message should have been replaced with reduced assistant notes.
    assert agent.messages[-2]["role"] == "assistant"
    assert agent.messages[-2]["content"][0]["text"] == "REDUCED"

    # A system message with continue instructions should be appended.
    assert agent.messages[-1]["role"] == "system"
    sys_text = agent.messages[-1]["content"][0]["text"]
    assert "<continue_instructions>" in sys_text
    assert "REFLECTION_SNAPSHOT" in sys_text


def test_before_model_call_inject_appends_reduced_if_last_not_assistant(monkeypatch):
    hook = AgentRepairHook()

    monkeypatch.setattr(arh, "collapse_first_repeated_sequence", lambda s: s)
    monkeypatch.setattr(arh, "reduce_lines_lossy", lambda *_args, **_kwargs: _ReducedText("REDUCED"))
    monkeypatch.setattr(arh, "get_reflection_snapshot", lambda **_kwargs: "REFLECTION_SNAPSHOT")

    cb = FakeCallbackHandler(current_step=3, max_steps=10)

    agent = FakeAgent(
        messages=[
            {"role": "user", "content": [{"type": "text", "text": "hi"}]},
            # last is NOT assistant, so we should append reduced assistant message
            {"role": "user", "content": [{"type": "text", "text": "go on"}]},
            # but we still need a prior assistant to source truncated_message from; place it earlier
            {"role": "assistant", "content": [{"type": "text", "text": "some reasoning to reduce"}]},
            {"role": "user", "content": [{"type": "text", "text": "continue"}]},
        ],
        callback_handler=cb,
    )

    state = {arh._REASONING_LOOP_RETRY_STATE_KEY: ("REDUCED", False)}
    ev = FakeBeforeModelCallEvent(agent=agent, state=state)

    hook.before_model_call_inject(ev)

    # Reduced assistant message appended just before the system continue message
    assert agent.messages[-2]["role"] == "assistant"
    assert agent.messages[-2]["content"][0]["text"] == "REDUCED"
    assert agent.messages[-1]["role"] == "system"
