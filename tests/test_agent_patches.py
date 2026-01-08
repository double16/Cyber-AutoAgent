# test_tool_use_id_class_patch.py
from __future__ import annotations

import pytest

from strands.hooks.events import AfterToolCallEvent
from modules.agents.patches import patch_model_class_tool_use_id, unpatch_model_class_tool_use_id, ToolUseIdHook


def _list_id_factory(ids: list[str]):
    it = iter(ids)

    def factory() -> str:
        try:
            return next(it)
        except StopIteration as e:
            raise AssertionError("id_factory called more times than expected") from e

    return factory


# ----------------------------
# Fake models (event sources)
# ----------------------------

class FakeModelBasicBad:
    """
    toolUseId == name (bad) and delta repeats it.
    """
    async def stream(self):
        yield {
            "contentBlockStart": {
                "start": {"toolUse": {"name": "mytool", "toolUseId": "mytool", "input": {"x": 1}}}
            }
        }
        yield {
            "contentBlockDelta": {
                "delta": {"toolUse": {"name": "mytool", "toolUseId": "mytool", "input": {"x": 2}}}
            }
        }
        yield {"current_tool_use": {"name": "mytool", "toolUseId": "mytool", "input": {"x": 3}}}


class FakeModelHallucinatedName:
    """
    name starts with tooluse_ and toolUseId == name (bad) -> name rewritten to 'shell'
    """
    async def stream(self):
        yield {
            "contentBlockStart": {
                "start": {"toolUse": {"name": "tooluse_abcdef", "toolUseId": "tooluse_abcdef", "input": {"x": 1}}}
            }
        }


class FakeModelDeltaNoNameNoId:
    """
    Delta has neither name nor toolUseId -> should NOT be rewritten (guarded by (name or tuid)).
    """
    async def stream(self):
        yield {
            "contentBlockStart": {
                "start": {"toolUse": {"name": "mytool", "toolUseId": "mytool", "input": {"x": 1}}}
            }
        }
        yield {"contentBlockDelta": {"delta": {"toolUse": {"name": None, "toolUseId": None, "input": {"x": 2}}}}}


class FakeModelAlreadyGood:
    async def stream(self):
        yield {
            "contentBlockStart": {
                "start": {"toolUse": {"name": "mytool", "toolUseId": "tooluse_abc123", "input": {"x": 1}}}
            }
        }


class FakeModelMissingNameForcedBad:
    """
    Start event has missing/empty name but a toolUseId. We pass a custom is_bad_id to force the
    new 'if not name: tool_use["name"] = tuid' behavior.
    """
    async def stream(self):
        yield {
            "contentBlockStart": {
                "start": {"toolUse": {"name": "", "toolUseId": "mytool", "input": {"x": 1}}}
            }
        }
        yield {"current_tool_use": {"name": "", "toolUseId": "mytool", "input": {"x": 2}}}


# ----------------------------
# Fixtures to undo class patch
# ----------------------------

@pytest.fixture(autouse=True)
def _reset_class_patches():
    yield
    unpatch_model_class_tool_use_id(FakeModelBasicBad)
    unpatch_model_class_tool_use_id(FakeModelHallucinatedName)
    unpatch_model_class_tool_use_id(FakeModelDeltaNoNameNoId)
    unpatch_model_class_tool_use_id(FakeModelAlreadyGood)
    unpatch_model_class_tool_use_id(FakeModelMissingNameForcedBad)


# ----------------------------
# Tests
# ----------------------------

@pytest.mark.asyncio
async def test_rewrites_bad_tooluseid_and_keeps_consistent_for_delta_and_current_tool_use():
    patch_model_class_tool_use_id(FakeModelBasicBad, id_factory=_list_id_factory(["fixed-1"]))

    m = FakeModelBasicBad()
    out = [ev async for ev in m.stream()]

    start = out[0]["contentBlockStart"]["start"]["toolUse"]
    delta = out[1]["contentBlockDelta"]["delta"]["toolUse"]
    ctu = out[2]["current_tool_use"]

    assert start["toolUseId"] == "fixed-1"
    assert delta["toolUseId"] == "fixed-1"
    assert ctu["toolUseId"] == "fixed-1"
    assert start["name"] == "mytool"  # name preserved in normal case


@pytest.mark.asyncio
async def test_state_is_per_stream_call_new_id_each_time():
    patch_model_class_tool_use_id(FakeModelBasicBad, id_factory=_list_id_factory(["fixed-1", "fixed-2"]))

    m = FakeModelBasicBad()

    out1 = [ev async for ev in m.stream()]
    out2 = [ev async for ev in m.stream()]

    id1 = out1[0]["contentBlockStart"]["start"]["toolUse"]["toolUseId"]
    id2 = out2[0]["contentBlockStart"]["start"]["toolUse"]["toolUseId"]

    assert id1 == "fixed-1"
    assert id2 == "fixed-2"


@pytest.mark.asyncio
async def test_delta_with_no_name_and_no_id_is_not_rewritten():
    patch_model_class_tool_use_id(FakeModelDeltaNoNameNoId, id_factory=_list_id_factory(["fixed-1"]))

    m = FakeModelDeltaNoNameNoId()
    out = [ev async for ev in m.stream()]

    # Start got rewritten
    start = out[0]["contentBlockStart"]["start"]["toolUse"]
    assert start["toolUseId"] == "fixed-1"

    # Delta should remain untouched because (name or tuid) is False
    delta = out[1]["contentBlockDelta"]["delta"]["toolUse"]
    assert delta["name"] is None
    assert delta["toolUseId"] is None


@pytest.mark.asyncio
async def test_does_not_change_already_unique_tooluseid():
    patch_model_class_tool_use_id(FakeModelAlreadyGood, id_factory=_list_id_factory(["fixed-1"]))

    m = FakeModelAlreadyGood()
    out = [ev async for ev in m.stream()]

    tool_use = out[0]["contentBlockStart"]["start"]["toolUse"]
    assert tool_use["toolUseId"] == "tooluse_abc123"


@pytest.mark.asyncio
async def test_missing_name_is_filled_with_old_tooluseid_when_forced_bad():
    # Force the bad-id path when name is empty string, to cover:
    #   if not name: tool_use["name"] = tuid
    def force_bad_id(tool_use_id, tool_name) -> bool:
        return not tool_name  # treat missing/empty name as bad

    patch_model_class_tool_use_id(
        FakeModelMissingNameForcedBad,
        is_bad_id=force_bad_id,
        id_factory=_list_id_factory(["fixed-1", "fixed-2"]),
    )

    m = FakeModelMissingNameForcedBad()
    out = [ev async for ev in m.stream()]

    start = out[0]["contentBlockStart"]["start"]["toolUse"]
    ctu = out[1]["current_tool_use"]

    # Start: name should be populated from the pre-rewrite toolUseId ("mytool")
    assert start["name"] == "mytool"
    assert start["toolUseId"] == "fixed-1"

    # current_tool_use: name should be populated similarly, and toolUseId should reuse state ("fixed-1")
    assert ctu["name"] == "mytool"
    assert ctu["toolUseId"] == "fixed-1"


def test_patch_is_idempotent():
    patch_model_class_tool_use_id(FakeModelBasicBad, id_factory=_list_id_factory(["fixed-1"]))
    patch_model_class_tool_use_id(FakeModelBasicBad, id_factory=_list_id_factory(["fixed-2"]))  # no-op


@pytest.mark.asyncio
async def test_unpatch_restores_original_stream_behavior():
    patch_model_class_tool_use_id(FakeModelBasicBad, id_factory=_list_id_factory(["fixed-1"]))

    m = FakeModelBasicBad()
    patched_out = [ev async for ev in m.stream()]
    assert patched_out[0]["contentBlockStart"]["start"]["toolUse"]["toolUseId"] == "fixed-1"

    unpatch_model_class_tool_use_id(FakeModelBasicBad)

    m2 = FakeModelBasicBad()
    unpatched_out = [ev async for ev in m2.stream()]
    assert unpatched_out[0]["contentBlockStart"]["start"]["toolUse"]["toolUseId"] == "mytool"


def test_patch_raises_if_no_stream_method():
    class NoStream:
        pass

    with pytest.raises(TypeError):
        patch_model_class_tool_use_id(NoStream)


def test_tooluseid_hook_registers_after_tool_call_callback():
    hook = ToolUseIdHook()

    calls = []

    class RegistryStub:
        def add_callback(self, event_type, callback):
            calls.append((event_type, callback))

    registry = RegistryStub()
    hook.register_hooks(registry)

    assert len(calls) == 1
    event_type, callback = calls[0]

    assert event_type is AfterToolCallEvent
    # Bound method should be on this instance
    assert getattr(callback, "__self__", None) is hook
    assert getattr(callback, "__func__", None) is ToolUseIdHook.revert_tool_use_id


def test_tooluseid_hook_reverts_tooluseid_and_result_when_generated_id_present():
    hook = ToolUseIdHook()

    class Event:
        def __init__(self):
            self.tool_use = {"name": "mem0_memory", "toolUseId": "tooluse_deadbeef"}
            self.result = {"toolUseId": "tooluse_deadbeef", "ok": True}

    ev = Event()
    hook.revert_tool_use_id(ev)  # type: ignore[arg-type]

    # tool_use reverted
    assert ev.tool_use["toolUseId"] == "mem0_memory"
    assert ev.tool_use["_toolUseId"] == "tooluse_deadbeef"

    # result reverted
    assert ev.result["toolUseId"] == "mem0_memory"
    assert ev.result["_toolUseId"] == "tooluse_deadbeef"


@pytest.mark.parametrize(
    "tool_name,tool_use_id",
    [
        ("mem0_memory", "mem0_memory"),   # not generated
        ("mem0_memory", ""),              # empty id
        ("", "tooluse_deadbeef"),         # missing tool name => guard should prevent changes
        ("mem0_memory", "abc123"),        # doesn't start with tooluse_
    ],
)
def test_tooluseid_hook_noop_when_not_generated_or_missing_name(tool_name, tool_use_id):
    hook = ToolUseIdHook()

    class Event:
        def __init__(self):
            self.tool_use = {"name": tool_name, "toolUseId": tool_use_id}
            self.result = {"toolUseId": tool_use_id, "ok": True}

    ev = Event()
    before_tool_use = dict(ev.tool_use)
    before_result = dict(ev.result)

    hook.revert_tool_use_id(ev)  # type: ignore[arg-type]

    assert ev.tool_use == before_tool_use
    assert ev.result == before_result


def test_tooluseid_hook_ignores_non_dict_result():
    hook = ToolUseIdHook()

    class Event:
        def __init__(self):
            self.tool_use = {"name": "shell", "toolUseId": "tooluse_deadbeef"}
            self.result = "not a dict"

    ev = Event()
    hook.revert_tool_use_id(ev)  # type: ignore[arg-type]

    assert ev.tool_use["toolUseId"] == "shell"
    assert ev.tool_use["_toolUseId"] == "tooluse_deadbeef"
    assert ev.result == "not a dict"


def test_tooluseid_hook_handles_event_without_tool_use_attr():
    hook = ToolUseIdHook()

    class Event:
        def __init__(self):
            self.result = {"toolUseId": "tooluse_deadbeef"}

    ev = Event()
    before_result = dict(ev.result)

    hook.revert_tool_use_id(ev)  # type: ignore[arg-type]

    # With no tool_use (and thus no tool_name), hook should do nothing.
    assert ev.result == before_result
