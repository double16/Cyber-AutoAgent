#!/usr/bin/env python3
from __future__ import annotations

import re
from typing import Any

from strands.hooks import HookProvider, HookRegistry
from strands.hooks.events import BeforeModelCallEvent, AfterModelCallEvent

from modules.config.system.logger import get_logger

logger = get_logger("Handlers.ToolCallRepair")

_XML_TOOLCALL_RE = re.compile(r"<parameter=[^>]+>.*?</function>", re.DOTALL)

_STATE_KEY = "force_openai_toolcalls_retry"

class ToolCallRepairHook(HookProvider):
    """
    If a model prints XML-ish tool calls in content (common with qwen3-coder drift),
    retry once with an extra instruction to emit OpenAI-style tool_calls only.

    This is Strands-native: it doesn't patch Agent or OllamaModel.
    """

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(AfterModelCallEvent, self.after_model_call_check)
        registry.add_callback(BeforeModelCallEvent, self.before_model_call_inject)
        logger.debug("ToolCallRepairHook registered")

    def after_model_call_check(self, event: AfterModelCallEvent) -> None:
        """
        Runs after the model returns and before tools are processed.
        If we detect XML-ish tool call markup, request a retry.
        """
        try:
            # Try to obtain assistant text in the most common ways.
            # Adjust these accessors if your event exposes different fields.
            if event is None or event.stop_response is None:
                return
            for block in event.stop_response.message.get("content", []):
                if "text" in block:
                    assistant_text = block.get("text")
                else:
                    continue
                if not assistant_text:
                    continue

                if _XML_TOOLCALL_RE.search(assistant_text):
                    # Mark for one retry and ask Strands to redo the model call
                    state = self._state_bag(event)
                    if state.get(_STATE_KEY):
                        # already retried once; don't loop forever
                        return

                    state[_STATE_KEY] = True
                    event.retry = True
                    logger.warning("Detected XML-ish tool call markup; forcing model retry with corrective instruction")
                    return
        except Exception as e:
            logger.debug("after_model_call_check error: %s", e)

    def before_model_call_inject(self, event: BeforeModelCallEvent) -> None:
        """
        Runs right before the model call.
        If the previous response triggered a retry, inject a short corrective instruction.
        """
        try:
            state = self._state_bag(event)
            if not state.get(_STATE_KEY):
                return

            # Clear flag so it applies only to the retry
            state.pop(_STATE_KEY, None)

            # Modify messages in-place (common Strands behavior)
            messages = getattr(event.agent, "messages", None)
            if not isinstance(messages, list):
                return

            messages.append({
                "role": "system",
                "content": [{"type": "text", "text":(
                    "IMPORTANT: Tool calls must be emitted using OpenAI-style tool calling only "
                    "(tool_calls with JSON arguments). Do NOT output tool calls in XML/HTML/text "
                    "such as <function=...> or <parameter=...>. If you need a tool, emit a proper tool call."
                )}]
            })
            logger.warning("Injected tool-call format correction into retry model call")
        except Exception as e:
            logger.debug("before_model_call_inject error: %s", e)

    def _state_bag(self, event: Any) -> dict:
        """
        Access a per-invocation mutable bag.
        Different Strands versions expose this differently.
        """
        for attr in ("invocation_state", "state", "context", "metadata"):
            bag = getattr(event, attr, None)
            if isinstance(bag, dict):
                return bag
        # Fallback: store on the agent instance (works when events don't carry state)
        agent = getattr(event, "agent", None)
        if agent is not None:
            bag = getattr(agent, "_hook_state", None)
            if not isinstance(bag, dict):
                bag = {}
                setattr(agent, "_hook_state", bag)
            return bag
        return {}
