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
    where_set: Optional[str] = None

    def __call__(self, *, where: str, marker: str, id_factory: Optional[Callable[[str], str]]) -> str:
        assert where
        assert marker
        assert id_factory
        if self.where_set and self.where_set != where:
            if not self.current_tool_use_id:
                self.current_tool_use_id = id_factory(marker)
                self.where_set = where
        else:
            self.current_tool_use_id = id_factory(marker)
            self.where_set = where
        return self.current_tool_use_id


def patch_model_class_tool_use_id(
        model_cls: Type[Any],
        *,
        id_factory: Optional[Callable[[str], str]] = None,
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
        if "stubs" in model_cls.__qualname__.lower():
            # unit test mock
            return model_cls
        raise TypeError(f"{model_cls.__name__} has no 'stream' method to patch")

    # inline function supports unit tests
    # marker: X - no toolUseId given, N - no tool_name given, E - toolUseId == tool_name, 'U' - unknown
    if id_factory is None:
        id_factory = lambda marker: f"tooluse_{marker or 'U'}-{uuid4().hex}"

    orig_stream = getattr(model_cls, "stream")
    setattr(model_cls, orig_attr, orig_stream)

    @functools.wraps(orig_stream)
    async def stream_patched(self: Any, *args: Any, **kwargs: Any) -> AsyncIterator[dict]:
        state = _ToolUseIdStreamState()

        def _patch_tool_use_id(event: dict[str, Any], where: str) -> None:
            name = event.get("name")
            tuid = event.get("toolUseId")
            if not name and not tuid:
                return
            if not tuid:
                marker = 'X'
            elif not name:
                marker = 'N'
            elif tuid == name:
                marker = 'E'
            else:
                return
            if not name:
                # in this case, toolUseId is the tool name, but no tool_name was given
                event["name"] = tuid
            tuid = state(where=where, marker=marker, id_factory=id_factory)
            event["_toolUseId"] = event["toolUseId"] = tuid

        async for ev in orig_stream(self, *args, **kwargs):
            # contentBlockStart and current_tool_use may come in any order, but we assume for a given provider the order is consistent

            # --- Pattern A: contentBlockStart -> toolUse ---
            cbs = ev.get("contentBlockStart")
            if isinstance(cbs, dict):
                start = cbs.get("start")
                if isinstance(start, dict):
                    tool_use = start.get("toolUse")
                    if isinstance(tool_use, dict):
                        _patch_tool_use_id(tool_use, "contentBlockStart")

            # --- Pattern B: contentBlockDelta -> toolUse (keep consistent) ---
            # Assumption: contentBlockDelta do not overlap with concurrent tool uses
            cbd = ev.get("contentBlockDelta")
            if isinstance(cbd, dict):
                delta = cbd.get("delta")
                if isinstance(delta, dict):
                    dtu = delta.get("toolUse")
                    if isinstance(dtu, dict):
                        name = dtu.get("name")
                        tuid = dtu.get("toolUseId")
                        if (name or tuid) and state.current_tool_use_id:
                            dtu["_toolUseId"] = dtu["toolUseId"] = state.current_tool_use_id

            # --- Pattern C: Strands convenience field current_tool_use ---
            ctu = ev.get("current_tool_use")
            if isinstance(ctu, dict):
                _patch_tool_use_id(ctu, "current_tool_use")

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

        tool_use_id_type = tool_use_id[:10]
        if tool_use_id_type in ["tooluse_N-", "tooluse_X-", "tooluse_E-", "tooluse_U-"] and tool_name:
            # reverse the patch that set a generated ID because some models use toolUseId as the tool name or no tool name at all !?!

            reverted_tool_name = tool_name
            if tool_use_id_type == "tooluse_E-":
                reverted_tool_use_id = tool_name
            elif tool_use_id_type == "tooluse_N-":
                reverted_tool_use_id = tool_name
                reverted_tool_name = ''
            else:
                reverted_tool_use_id = ''

            tool_use["_toolUseId"] = tool_use_id
            tool_use["toolUseId"] = reverted_tool_use_id
            tool_use["name"] = reverted_tool_name

            result = getattr(event, "result", None)
            if isinstance(result, dict) and "toolUseId" in result:
                # there is no tool_name in "result"
                result["_toolUseId"] = tool_use_id
                result["toolUseId"] = reverted_tool_use_id


_OLLAMA_MODEL_TOKEN_USAGE_PATCH_ATTR = "_caa_ollama_usage_patch_v1"


def patch_ollama_model_token_usage(
        *,
        module_name: str = "strands.models.ollama",
        cls_name: str = "OllamaModel",
        validate: bool = True,
) -> None:
    """
    Monkey-patch OllamaModel.format_chunk to correct usage token mapping.

    Correct mapping for Ollama:
      - prompt_eval_count -> inputTokens (prompt)
      - eval_count        -> outputTokens (completion)

    Notes:
        - Idempotent: repeated calls do not stack patches.
    """
    mod = __import__(module_name, fromlist=[cls_name])
    OllamaModel: Type[Any] = getattr(mod, cls_name)

    if not hasattr(OllamaModel, "format_chunk"):
        raise RuntimeError(f"{module_name}.{cls_name} has no format_chunk method")

    # If already patched, do nothing (idempotent).
    existing = getattr(OllamaModel, _OLLAMA_MODEL_TOKEN_USAGE_PATCH_ATTR, None)
    if isinstance(existing, dict) and existing.get("is_patched") is True:
        return

    original_format_chunk = OllamaModel.format_chunk

    def patched_format_chunk(self: Any, event: dict[str, Any]) -> Any:
        out = original_format_chunk(self, event)

        # Only touch metadata chunks that contain usage dict.
        try:
            if isinstance(out, dict) and "metadata" in out:
                md = out.get("metadata") or {}
                usage = md.get("usage")

                if isinstance(usage, dict):
                    data = event.get("data")

                    # Ollama python client event has these fields on the event object.
                    prompt_eval_count = getattr(data, "prompt_eval_count", None)
                    eval_count = getattr(data, "eval_count", None)

                    # Only rewrite when we can confidently read both values.
                    if prompt_eval_count is not None and eval_count is not None:
                        usage["inputTokens"] = int(prompt_eval_count)
                        usage["outputTokens"] = int(eval_count)
                        usage["totalTokens"] = int(prompt_eval_count) + int(eval_count)
        except Exception:
            # Never break streaming due to patch logic.
            return out

        return out

    # Apply patch and record original for safe restoration.
    OllamaModel.format_chunk = patched_format_chunk  # type: ignore[method-assign]
    setattr(
        OllamaModel,
        _OLLAMA_MODEL_TOKEN_USAGE_PATCH_ATTR,
        {
            "is_patched": True,
            "original": original_format_chunk,
        },
    )

    if validate and OllamaModel.format_chunk is original_format_chunk:
        raise RuntimeError("Patch did not apply (method reference unchanged)")
