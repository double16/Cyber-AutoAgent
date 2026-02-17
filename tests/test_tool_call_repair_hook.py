from __future__ import annotations

import types
import pytest

import modules.handlers.agent_repair_hook as tcrh


class FakeCallbackHandler:
    def __init__(self):
        self.current_step = 0


class FakeAgent:
    def __init__(self, messages=None):
        self.messages = messages if messages is not None else []
        self.callback_handler = FakeCallbackHandler()


class FakeAfterModelCallEvent:
    def __init__(self, assistant_text: str | None, state: dict | None = None):
        self.retry = False
        self.invocation_state = state if state is not None else {}

        # Build stop_response.message["content"] in the shape the hook expects
        content_blocks = []
        if assistant_text is not None:
            content_blocks.append({"text": assistant_text})

        self.stop_response = types.SimpleNamespace(
            stop_reason=None,
            message={"content": content_blocks}
        )

        self.exception = None

        self.agent = FakeAgent(messages=content_blocks)


class FakeBeforeModelCallEvent:
    def __init__(self, agent: FakeAgent, state: dict | None = None):
        self.agent = agent
        self.invocation_state = state if state is not None else {}


@pytest.mark.parametrize(
    "xmlish",
    [
        "<parameter=cmd>id</parameter></function>"
        "<function=shell><parameter=cmd>id</parameter></function>"
    ]
)
def test_after_model_call_sets_retry_and_flag_on_xmlish_tool_markup(xmlish):
    hook = tcrh.AgentRepairHook()

    state = {}

    event = FakeAfterModelCallEvent(assistant_text=xmlish, state=state)

    hook.after_model_call_check(event)

    assert event.retry is True
    assert state.get(tcrh._TOOL_CALLS_RETRY_STATE_KEY) is True


def test_after_model_call_does_not_retry_twice_if_flag_already_set():
    hook = tcrh.AgentRepairHook()

    xmlish = "<parameter=cmd>whoami</parameter></function>"
    state = {tcrh._TOOL_CALLS_RETRY_STATE_KEY: True}

    event = FakeAfterModelCallEvent(assistant_text=xmlish, state=state)

    hook.after_model_call_check(event)

    assert event.retry is False  # no infinite loop


def test_after_model_call_no_retry_when_no_xmlish_markup():
    hook = tcrh.AgentRepairHook()

    state = {}
    event = FakeAfterModelCallEvent(assistant_text="normal assistant output", state=state)

    hook.after_model_call_check(event)

    assert event.retry is False
    assert tcrh._TOOL_CALLS_RETRY_STATE_KEY not in state


def test_after_model_call_graceful_when_no_stop_response_or_content():
    hook = tcrh.AgentRepairHook()

    # stop_response is None
    event = types.SimpleNamespace(stop_response=None, retry=False, invocation_state={})
    hook.after_model_call_check(event)  # should not raise
    assert event.retry is False

    # stop_response exists but no content blocks
    event2 = types.SimpleNamespace(
        stop_response=types.SimpleNamespace(message={"content": []}),
        retry=False,
        invocation_state={},
    )
    hook.after_model_call_check(event2)  # should not raise
    assert event2.retry is False


def test_before_model_call_injects_system_message_on_retry_flag_and_clears_flag():
    hook = tcrh.AgentRepairHook()

    agent = FakeAgent(messages=[{"role": "user", "content": [{"type": "text", "text": "hi"}]}])
    state = {tcrh._TOOL_CALLS_RETRY_STATE_KEY: True}
    event = FakeBeforeModelCallEvent(agent=agent, state=state)

    hook.before_model_call_inject(event)

    # flag cleared so it only applies to the retry
    assert tcrh._TOOL_CALLS_RETRY_STATE_KEY not in state

    # system message appended
    assert isinstance(agent.messages, list)
    assert agent.messages[-1]["role"] == "system"
    last_text = agent.messages[-1]["content"][0]["text"]
    assert "OpenAI-style tool calling" in last_text
    assert "<function=" in last_text  # the admonition mentions it


def test_before_model_call_does_nothing_if_flag_not_set():
    hook = tcrh.AgentRepairHook()

    agent = FakeAgent(messages=[])
    state = {}
    event = FakeBeforeModelCallEvent(agent=agent, state=state)

    hook.before_model_call_inject(event)

    assert agent.messages == []


def test_state_bag_prefers_event_dict_attributes_then_falls_back_to_agent_hook_state():
    hook = tcrh.AgentRepairHook()

    # Prefer invocation_state when it's a dict
    e1 = types.SimpleNamespace(invocation_state={"x": 1})
    bag1 = hook._state_bag(e1)
    assert bag1 is e1.invocation_state

    # Fall back to agent._hook_state when no dict attrs exist
    agent = FakeAgent(messages=[])
    e2 = types.SimpleNamespace(agent=agent)  # no invocation_state/state/context/metadata
    bag2 = hook._state_bag(e2)
    assert isinstance(bag2, dict)
    assert getattr(agent, "_hook_state") is bag2
