from __future__ import annotations

import types


import modules.handlers.tool_call_repair_hook as tcrh


class FakeAgent:
    def __init__(self, messages=None):
        self.messages = messages if messages is not None else []


class FakeAfterModelCallEvent:
    def __init__(self, assistant_text: str | None, state: dict | None = None):
        self.retry = False
        self.invocation_state = state if state is not None else {}

        # Build stop_response.message["content"] in the shape the hook expects
        content_blocks = []
        if assistant_text is not None:
            content_blocks.append({"text": assistant_text})

        self.stop_response = types.SimpleNamespace(
            message={"content": content_blocks}
        )


class FakeBeforeModelCallEvent:
    def __init__(self, agent: FakeAgent, state: dict | None = None):
        self.agent = agent
        self.invocation_state = state if state is not None else {}


def test_after_model_call_sets_retry_and_flag_on_xmlish_tool_markup():
    hook = tcrh.ToolCallRepairHook()

    # Must match: <parameter=[^>]+> ... </function>
    xmlish = "<parameter=cmd>id</parameter></function>"
    state = {}

    event = FakeAfterModelCallEvent(assistant_text=xmlish, state=state)

    hook.after_model_call_check(event)

    assert event.retry is True
    assert state.get(tcrh._STATE_KEY) is True


def test_after_model_call_does_not_retry_twice_if_flag_already_set():
    hook = tcrh.ToolCallRepairHook()

    xmlish = "<parameter=cmd>whoami</parameter></function>"
    state = {tcrh._STATE_KEY: True}

    event = FakeAfterModelCallEvent(assistant_text=xmlish, state=state)

    hook.after_model_call_check(event)

    assert event.retry is False  # no infinite loop


def test_after_model_call_no_retry_when_no_xmlish_markup():
    hook = tcrh.ToolCallRepairHook()

    state = {}
    event = FakeAfterModelCallEvent(assistant_text="normal assistant output", state=state)

    hook.after_model_call_check(event)

    assert event.retry is False
    assert tcrh._STATE_KEY not in state


def test_after_model_call_graceful_when_no_stop_response_or_content():
    hook = tcrh.ToolCallRepairHook()

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
    hook = tcrh.ToolCallRepairHook()

    agent = FakeAgent(messages=[{"role": "user", "content": [{"type": "text", "text": "hi"}]}])
    state = {tcrh._STATE_KEY: True}
    event = FakeBeforeModelCallEvent(agent=agent, state=state)

    hook.before_model_call_inject(event)

    # flag cleared so it only applies to the retry
    assert tcrh._STATE_KEY not in state

    # system message appended
    assert isinstance(agent.messages, list)
    assert agent.messages[-1]["role"] == "system"
    last_text = agent.messages[-1]["content"][0]["text"]
    assert "OpenAI-style tool calling" in last_text
    assert "<function=" in last_text  # the admonition mentions it


def test_before_model_call_does_nothing_if_flag_not_set():
    hook = tcrh.ToolCallRepairHook()

    agent = FakeAgent(messages=[])
    state = {}
    event = FakeBeforeModelCallEvent(agent=agent, state=state)

    hook.before_model_call_inject(event)

    assert agent.messages == []


def test_before_model_call_skips_if_messages_is_not_a_list():
    hook = tcrh.ToolCallRepairHook()

    agent = FakeAgent(messages=None)
    agent.messages = "not-a-list"  # force non-list
    state = {tcrh._STATE_KEY: True}
    event = FakeBeforeModelCallEvent(agent=agent, state=state)

    hook.before_model_call_inject(event)

    # It should return without error; note flag is cleared only after it decides to inject,
    # and your code clears it before checking messages. So validate that behavior:
    assert tcrh._STATE_KEY not in state


def test_state_bag_prefers_event_dict_attributes_then_falls_back_to_agent_hook_state():
    hook = tcrh.ToolCallRepairHook()

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
