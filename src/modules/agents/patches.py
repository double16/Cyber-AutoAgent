"""
These are monkey patches to handle inconsistencies in some providers.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Optional, Type
from uuid import uuid4


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
                            elif name.startswith("tooluse_"):
                                # there is a bizarre hallucination where the command name is a tooluse_* ID that wasn't seen before
                                tool_use["name"] = "shell"
                            tuid = id_factory()
                            tool_use["toolUseId"] = tuid
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
                            dtu["toolUseId"] = state.current_tool_use_id

            # --- Pattern C: Strands convenience field current_tool_use ---
            ctu = ev.get("current_tool_use")
            if isinstance(ctu, dict):
                name = ctu.get("name")
                tuid = ctu.get("toolUseId")
                if is_bad_id(tuid, name):
                    if not name:
                        ctu["name"] = tuid
                    tuid = state.current_tool_use_id or id_factory()
                    ctu["toolUseId"] = tuid
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
