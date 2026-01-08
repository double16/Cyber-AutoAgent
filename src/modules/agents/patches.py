"""
These are monkey patches to handle inconsistencies in some providers.

We require a unique ID per tool call. There `toolUseId` and `id` properties are candidates. `toolUseId` is used by
some providers for the tool name and strands ignores the `id` property. We modify the flow such that before a tool is
processed we detect this case and replace `toolUseId` with a unique value. Before sending the result back to the model,
we revert this or the model will do strange things like think the unique ID is a tool name that can be called. The
important parts of the flow are:

1. prompt sent to model
2. streaming response starts  <-- we need to patch the ID here by modifying the events
3. SDK event received by our handler
4. BeforeToolCallEvent hooks processed
5. AfterToolCallEvent hooks processed  <-- we need to revert here because hooks are allowed to change response content
6. SDK event received by our handler  <-- additional property _toolUseId is accepted here because it doesn't interfere with the model
7. Tool results sent to model

"""
from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Optional, Type
from uuid import uuid4
from strands.hooks.events import AfterToolCallEvent
from strands.hooks import HookProvider, HookRegistry


@dataclass
class _ToolUseIdStreamState:
    current_tool_use_id: Optional[str] = None


def patch_model_class_tool_use_id(
        model_cls: Type[Any],
        *,
        is_bad_id: Optional[Callable[[Optional[str], Optional[str]], bool]] = None,
        id_factory: Optional[Callable[[], str]] = None,
        attr_prefix: str = "_tooluseid_class_patch",
) -> Type[Any]:
    """
    Monkey-patch model_cls.stream at the *class* level so toolUseId is unique per invocation.

    Patches tool-use IDs in these event shapes (covers common Strands provider normalizations):
      - ev["contentBlockStart"]["start"]["toolUse"]   (Bedrock-ish)
      - ev["contentBlockDelta"]["delta"]["toolUse"]   (Bedrock-ish)
      - ev["current_tool_use"]                        (Strands callback convenience)

    Idempotent: safe to call multiple times.

    Returns:
      model_cls (patched)
    """
    enabled_attr = f"{attr_prefix}_enabled"
    orig_attr = f"{attr_prefix}_orig_stream"

    if getattr(model_cls, enabled_attr, False):
        return model_cls

    if not hasattr(model_cls, "stream"):
        raise TypeError(f"{model_cls.__name__} has no 'stream' method to patch")

    if is_bad_id is None:
        def is_bad_id(tool_use_id: Optional[str], tool_name: Optional[str]) -> bool:
            # Treat missing/empty OR "id == tool name" as bad (your reported symptom)
            if not tool_use_id:
                return True
            if tool_name and tool_use_id == tool_name:
                return True
            return False

    if id_factory is None:
        id_factory = lambda: f"tooluse_{uuid4().hex}"

    orig_stream = getattr(model_cls, "stream")
    setattr(model_cls, orig_attr, orig_stream)

    @functools.wraps(orig_stream)
    async def stream_patched(self: Any, *args: Any, **kwargs: Any) -> AsyncIterator[dict]:
        state = _ToolUseIdStreamState()

        async for ev in orig_stream(self, *args, **kwargs):
            # --- Pattern A: contentBlockStart -> toolUse ---
            cbs = ev.get("contentBlockStart")
            if isinstance(cbs, dict):
                start = cbs.get("start")
                if isinstance(start, dict):
                    tool_use = start.get("toolUse")
                    if isinstance(tool_use, dict):
                        name = tool_use.get("name")
                        tuid = tool_use.get("toolUseId")
                        if is_bad_id(tuid, name):
                            if not name:
                                tool_use["name"] = tuid
                            tuid = id_factory()
                            tool_use["_toolUseId"] = tool_use["toolUseId"] = tuid
                        state.current_tool_use_id = tuid

            # --- Pattern B: contentBlockDelta -> toolUse (keep consistent) ---
            cbd = ev.get("contentBlockDelta")
            if isinstance(cbd, dict):
                delta = cbd.get("delta")
                if isinstance(delta, dict):
                    dtu = delta.get("toolUse")
                    if isinstance(dtu, dict):
                        name = dtu.get("name")
                        tuid = dtu.get("toolUseId")
                        if (name or tuid) and is_bad_id(tuid, name) and state.current_tool_use_id:
                            dtu["_toolUseId"] = dtu["toolUseId"] = state.current_tool_use_id

            # --- Pattern C: Strands convenience field current_tool_use ---
            ctu = ev.get("current_tool_use")
            if isinstance(ctu, dict):
                name = ctu.get("name")
                tuid = ctu.get("toolUseId")
                if is_bad_id(tuid, name):
                    if not name:
                        ctu["name"] = tuid
                    tuid = state.current_tool_use_id or id_factory()
                    ctu["_toolUseId"] = ctu["toolUseId"] = tuid
                state.current_tool_use_id = tuid

            yield ev

    setattr(model_cls, "stream", stream_patched)
    setattr(model_cls, enabled_attr, True)
    return model_cls


def unpatch_model_class_tool_use_id(
        model_cls: Type[Any],
        *,
        attr_prefix: str = "_tooluseid_class_patch",
) -> Type[Any]:
    """Restore the original model_cls.stream if it was patched by patch_model_class_tool_use_id()."""
    enabled_attr = f"{attr_prefix}_enabled"
    orig_attr = f"{attr_prefix}_orig_stream"

    if getattr(model_cls, enabled_attr, False) and hasattr(model_cls, orig_attr):
        setattr(model_cls, "stream", getattr(model_cls, orig_attr))
        setattr(model_cls, enabled_attr, False)
    return model_cls


class ToolUseIdHook(HookProvider):
    def register_hooks(self, registry: "HookRegistry", **kwargs: Any) -> None:
        registry.add_callback(AfterToolCallEvent, self.revert_tool_use_id)

    def revert_tool_use_id(self, event: AfterToolCallEvent):
        tool_use = getattr(event, "tool_use", {})
        tool_name = tool_use.get("name", "")
        tool_use_id = tool_use.get("toolUseId", "")

        if tool_use_id.startswith("tooluse_") and tool_name:
            # reverse the patch that set a generated ID because some models use toolUseId as the tool name !?!
            tool_use["_toolUseId"] = tool_use_id
            tool_use["toolUseId"] = tool_name

            result = getattr(event, "result", None)
            if isinstance(result, dict) and "toolUseId" in result:
                result["_toolUseId"] = tool_use_id
                result["toolUseId"] = tool_name
