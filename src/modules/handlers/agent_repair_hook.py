from __future__ import annotations

import re
from typing import Any

from strands.hooks import HookProvider, HookRegistry
from strands.hooks.events import BeforeModelCallEvent, AfterModelCallEvent
from strands.types.exceptions import MaxTokensReachedException

from modules.config.system.logger import get_logger
from modules.prompts.factory import get_reflection_snapshot
from modules.utils.text_reducer import reduce_lines_lossy, collapse_first_repeated_sequence

logger = get_logger("Handlers.AgentRepairHook")

_XML_TOOLCALL_RE = re.compile(r"<(?:function|parameter)=[^>]+>.*?</function>", re.DOTALL)

_TOOL_CALLS_RETRY_STATE_KEY = "force_openai_toolcalls_retry"
_REASONING_LOOP_RETRY_STATE_KEY = "reasoning_loop_retry"


class AgentRepairHook(HookProvider):
    """
    Case one:
    If a model prints XML-ish tool calls in content (common with qwen3-coder drift),
    retry once with an extra instruction to emit OpenAI-style tool_calls only.

    Case two:
    Reasoning loop exceeds max tokens.
    """

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(AfterModelCallEvent, self.after_model_call_check)
        registry.add_callback(BeforeModelCallEvent, self.before_model_call_inject)
        logger.debug("AgentRepairHook registered")

    def after_model_call_check(self, event: AfterModelCallEvent) -> None:
        """
        Runs after the model returns and before tools are processed.
        - If we detect XML-ish tool call markup, request a retry.
        - If we detect reasoning loop exceeds max tokens, request a retry.
        """
        if event is None:
            return

        try:
            agent = event.agent
            callback_handler = getattr(agent, "callback_handler", None)

            max_tokens_reached = False
            if event.stop_response is not None and event.stop_response.stop_reason == "max_tokens":
                max_tokens_reached = True
            elif event.exception is not None:
                error_str = str(event.exception).lower()
                if isinstance(event.exception,
                              MaxTokensReachedException) or "maxtokensreached" in error_str or "max_tokens" in error_str:
                    max_tokens_reached = True
            if agent is not None and max_tokens_reached:
                logger.info("Model input token limit reached, checking if this is a reasoning loop")
                max_tokens_retry_count = getattr(agent, "_max_tokens_retry_count", 0)
                if max_tokens_retry_count >= 2:
                    logger.error("Too many attempts to continue from reasoning loop (%d)", max_tokens_retry_count)
                else:
                    # this _could_ be a reasoning loop, we need to check if reducing the text makes a noticeable difference

                    # sometimes the max_tokens response includes the response, otherwise we'll look for reasoning text
                    truncated_message = ""
                    replace_last_message = False
                    if event.stop_response is not None and \
                            event.stop_response.stop_reason == "max_tokens" and \
                            event.stop_response.message is not None and \
                            len(event.stop_response.message.get("content", [])) > 0:
                        truncated_message = "".join(
                            [block.get("text", "") for block in event.stop_response.message.get("content", [])]
                        ).strip()
                        truncated_message_prefix = truncated_message[:1000]
                        replace_last_message = truncated_message and len(agent.messages) > 0 and any(
                            [block.get("text", "").startswith(truncated_message_prefix) for block in
                             agent.messages[-1].get("content", [])])
                    if not truncated_message and len(agent.messages) > 0 and \
                            agent.messages[-1].get("role","") == "assistant":
                        truncated_message = "".join(
                            [block.get("text", "") for block in agent.messages[-1].get("content", [])]
                        ).strip()
                        replace_last_message = bool(truncated_message)
                    if not truncated_message and callback_handler is not None:
                        truncated_message = "".join(callback_handler.reasoning_buffer).strip()
                        truncated_message_prefix = truncated_message[:1000]
                        replace_last_message = truncated_message and len(agent.messages) > 0 and any(
                            [block.get("text", "").startswith(truncated_message_prefix) for block in
                             agent.messages[-1].get("content", [])])
                    if truncated_message:
                        reduced_text = reduce_lines_lossy(
                            collapse_first_repeated_sequence(truncated_message),
                            similarity_threshold=0.5, max_lines=40
                        ).to_text().strip()
                        setattr(agent, "_max_tokens_retry_count", max_tokens_retry_count + 1)
                        state = self._state_bag(event)
                        state[_REASONING_LOOP_RETRY_STATE_KEY] = (reduced_text, replace_last_message)
                        event.retry = True
                        logger.warning(
                            "Model input token limit reached in step %s, retrying with reduced text",
                            str(callback_handler.current_step) if callback_handler else "?"
                        )
                        return
                    else:
                        logger.warning("Reasoning text not found")

            if event.stop_response is None:
                return

            # successful model call, reset counter
            setattr(agent, "_max_tokens_retry_count", 0)

            # Try to obtain assistant text in the most common ways.
            # Adjust these accessors if your event exposes different fields.
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
                    if state.get(_TOOL_CALLS_RETRY_STATE_KEY):
                        # already retried once; don't loop forever
                        return

                    state[_TOOL_CALLS_RETRY_STATE_KEY] = True
                    event.retry = True
                    logger.warning(
                        "Detected XML-ish tool call markup in step %s; forcing model retry with corrective instruction",
                        str(callback_handler.current_step) if callback_handler else "?"
                    )
                    return
        except Exception as e:
            logger.debug("after_model_call_check error: %s", e)

    def before_model_call_inject(self, event: BeforeModelCallEvent) -> None:
        """
        Runs right before the model call.
        If the previous response triggered a retry, inject a short corrective instruction.
        """
        try:
            agent = event.agent
            messages = getattr(agent, "messages", None)
            if not isinstance(messages, list):
                return
            callback_handler = getattr(agent, "callback_handler", None)
            state = self._state_bag(event)

            if state.get(_TOOL_CALLS_RETRY_STATE_KEY):
                state.pop(_TOOL_CALLS_RETRY_STATE_KEY, None)

                messages.append({
                    "role": "system",
                    "content": [{"type": "text", "text": (
                        "IMPORTANT: Tool calls must be emitted using OpenAI-style tool calling only "
                        "(tool_calls with JSON arguments). Do NOT output tool calls in XML/HTML/text "
                        "such as <function=...> or <parameter=...>. If you need a tool, emit a proper tool call."
                    )}]
                })
                logger.warning("Injected tool-call format correction into retry model call")
                return

            if state.get(_REASONING_LOOP_RETRY_STATE_KEY):
                reduced_text, replace_last_message = state.pop(_REASONING_LOOP_RETRY_STATE_KEY, (None, None))

                if reduced_text:
                    reduced_message = {"role": "assistant", "content": [{"type": "text", "text": reduced_text}]}
                    if replace_last_message:
                        agent.messages[-1] = reduced_message
                    else:
                        agent.messages.append(reduced_message)
                if callback_handler:
                    reflection_snapshot = get_reflection_snapshot(
                        current_step=callback_handler.current_step,
                        max_steps=callback_handler.max_steps,
                        plan_current_phase=None,
                    )
                else:
                    reflection_snapshot = ""
                messages.append({
                    "role": "system",
                    "content": [{"type": "text", "text": (
                        f"""<continue_instructions>
You are continuing from a prior run that entered a repetitive reasoning loop.

## CONSTRAINTS
- Do NOT restate repeated points from the reduced notes.
- Output must be structured, actionable, and short.
- Avoid meta commentary about "looping" beyond what's required to recover.

{reflection_snapshot}
<continue_instructions>"""
                    )}]
                })
                try:
                    if callback_handler:
                        callback_handler._emit_accumulated_reasoning(force=True)
                except Exception:
                    pass
                logger.warning("Injected reduced text and prompt into retry model call")
                return

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
