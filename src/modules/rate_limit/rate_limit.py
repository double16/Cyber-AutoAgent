#!/usr/bin/env python3
"""
Patches Model subclasses to enforce rate limiting on the client side to prevent the provider rate limit from stopping
the operation.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
import time
import threading
import json

from typing import Any, Optional, Type, TypeVar, Callable

from modules.config.types import RateLimitConfig

T = TypeVar("T")

logger = logging.getLogger("RateLimit")


# ----------------------------
# Thread-safe token buckets
# ----------------------------

class _TokenBucket:
    """
    Thread-safe token bucket.
    - capacity: max tokens in bucket
    - refill_rate_per_sec: tokens added per second
    """

    def __init__(self, capacity: float, refill_rate_per_sec: float) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate_per_sec)
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
            self._last = now

    def consume_blocking(self, amount: float) -> None:
        amount = float(amount)
        if amount <= 0:
            return
        if amount > self.capacity:
            logger.warning("Requested amount %f exceeds capacity %f", amount, self.capacity)
            # limit amount or we will wait forever
            amount = self.capacity

        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens >= amount:
                    self._tokens -= amount
                    return

                # Need to wait for more tokens
                needed = amount - self._tokens
                logger.debug("Need to refill %f", needed)
                # Avoid division by zero
                wait_s = needed / self.refill_rate if self.refill_rate > 0 else 0.5

            # Sleep outside lock
            sleep_time = min(120.0, max(wait_s, 0.1))
            # TODO: use an EventEmitter object
            rate_limit_event = {
                "type": "rate_limit",
                "timestamp": datetime.now().isoformat(),
                "needed": needed,
                "wait_total": wait_s,
                "sleep_time": sleep_time,
                "message": f"Sleeping for {sleep_time:.1f} seconds",
            }
            print(f"__CYBER_EVENT__{json.dumps(rate_limit_event)}__CYBER_EVENT_END__")
            time.sleep(sleep_time)


class ThreadSafeRateLimiter:
    """
    A process-wide limiter that works even if the caller creates a fresh asyncio loop per call
    (because it's based on threading primitives + blocking sleeps).
    """

    def __init__(self, cfg: RateLimitConfig) -> None:
        self.cfg = cfg
        # capacity = rpm, refill rate = rpm / 60 tokens per second
        self._req_bucket = _TokenBucket(cfg.rpm, cfg.rpm / 60.0) if cfg.rpm else None
        self._tok_bucket = _TokenBucket(cfg.tpm, cfg.tpm / 60.0) if cfg.tpm else None
        self._sem = threading.BoundedSemaphore(cfg.max_concurrent) if cfg.max_concurrent else None

    def acquire_blocking(self, token_cost: int) -> Callable[[], None]:
        """
        Blocks until:
        - a concurrency slot is available
        - request budget allows 1 request
        - token budget allows token_cost
        Returns a release() callable.
        """
        if self._sem:
            self._sem.acquire()

        try:
            if self._req_bucket:
                self._req_bucket.consume_blocking(1.0)
            if self._tok_bucket and token_cost > 0:
                self._tok_bucket.consume_blocking(float(token_cost))
        except Exception:
            if self._sem:
                self._sem.release()
            raise

        def release() -> None:
            if self._sem:
                self._sem.release()

        return release


# ----------------------------
# Token estimation (cheap/rough)
# ----------------------------

def _json_to_compact_str(v: Any) -> str:
    # Compact + stable-ish (sort keys) so estimates don’t fluctuate as much.
    try:
        return json.dumps(v, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    except Exception:
        return str(v)


def _extract_text_from_content(content: Any) -> str:
    # Strings
    if isinstance(content, str):
        return content

    # Dict “blocks”
    if isinstance(content, dict):
        # Common text block
        if isinstance(content.get("text"), str):
            return content["text"]

        # Common JSON block patterns:
        # 1) {"json": {...}} or {"json": [...]}
        if "json" in content:
            return _json_to_compact_str(content["json"])

        # 2) {"type": "json", "value": {...}} or {"type":"json","content":...}
        if content.get("type") == "json":
            for k in ("value", "content", "data", "object"):
                if k in content:
                    return _json_to_compact_str(content[k])

        # Sometimes blocks are nested
        for k in ("content", "value", "data"):
            if k in content:
                return _extract_text_from_content(content[k])

        return ""

    # List of blocks
    if isinstance(content, list):
        return "".join(_extract_text_from_content(x) for x in content)

    # Fallback (numbers, bools, etc.)
    if content is None:
        return ""
    return str(content)


def estimate_tokens_rough(messages: Any, system_prompt: Any, system_prompt_content: Any,
                          assume_output_tokens: int) -> int:
    # Very rough heuristic: ~4 chars/token for English-ish text.
    text = ""
    if system_prompt:
        text += _extract_text_from_content(system_prompt)
    if system_prompt_content:
        text += _extract_text_from_content(system_prompt_content)
    if messages:
        text += _extract_text_from_content(messages)

    # clamp
    chars = len(text)
    approx_in = max(1 if chars else 0, chars // 4)
    return int(approx_in + max(0, assume_output_tokens))


def _lc_message_text(msg: Any) -> str:
    """
    Best-effort extraction for LangChain BaseMessage-like objects.
    Includes:
      - msg.content
      - msg.additional_kwargs (tool_calls/function_call/etc) as JSON
    """
    if msg is None:
        return ""

    # BaseMessage-like: content
    content = getattr(msg, "content", None)
    text = _extract_text_from_content(content) if content is not None else ""

    # BaseMessage-like: additional kwargs (tool calls, function call, etc)
    ak = getattr(msg, "additional_kwargs", None)
    if isinstance(ak, dict) and ak:
        # Avoid exploding size too much; still count common payloads
        # (keeps your JSON counting behavior).
        text += _json_to_compact_str(ak)

    return text


def _estimate_tokens_for_batch_messages(
        batch_messages: Any,
        *,
        assume_output_tokens: int = 0,
) -> int:
    """
    LangChain ChatModel.generate/agenerate signature typically uses:
      generate(messages: list[list[BaseMessage]], ...)
      agenerate(messages: list[list[BaseMessage]], ...)
    We estimate across the whole batch.
    """
    # Accept a single conversation list as a convenience.
    # If user passes list[BaseMessage], treat as one item batch.
    if isinstance(batch_messages, list) and batch_messages and not isinstance(batch_messages[0], list):
        batch = [batch_messages]
    else:
        batch = batch_messages or []

    text = ""
    if isinstance(batch, list):
        for conv in batch:
            if not isinstance(conv, list):
                continue
            for msg in conv:
                text += _lc_message_text(msg)

    # Same heuristic as your estimate_tokens_rough: chars//4 (+ clamp)
    chars = len(text)
    approx_in = max(1 if chars else 0, chars // 4)
    return int(approx_in + max(0, int(assume_output_tokens or 0)))


# ----------------------------
# Strands Class patching
# ----------------------------

_ORIG_STREAM_ATTR = "_rl_orig_stream"
_ORIG_STRUCT_ATTR = "_rl_orig_structured_output"


def patch_model_provider_class(model_cls: Type[Any], limiter: ThreadSafeRateLimiter) -> None:
    """
    Monkey-patches model_cls.stream and model_cls.structured_output (if present),
    preserving originals on the class.

    Patch the *concrete provider classes* you use (GeminiModel, BedrockModel, LiteLLMModel, OllamaModel, ...).
    """
    if not hasattr(model_cls, "stream"):
        logger.warning(f"Rate limit: {model_cls} has no stream() to patch")
        return

    if not hasattr(model_cls, _ORIG_STREAM_ATTR):
        logger.info("Rate limit: Applying Strands rate limit to %s: %s", model_cls.__name__, str(limiter.cfg))
        setattr(model_cls, _ORIG_STREAM_ATTR, model_cls.stream)

    orig_stream = getattr(model_cls, _ORIG_STREAM_ATTR)

    async def stream(
            self,
            messages,
            tool_specs=None,
            system_prompt: Optional[str] = None,
            *,
            tool_choice=None,
            system_prompt_content=None,
            **kwargs: Any,
    ):
        token_cost = estimate_tokens_rough(
            messages=messages,
            system_prompt=system_prompt,
            system_prompt_content=system_prompt_content,
            assume_output_tokens=limiter.cfg.assume_output_tokens,
        )

        release = await asyncio.to_thread(limiter.acquire_blocking, token_cost)
        try:
            async for event in orig_stream(
                    self,
                    messages,
                    tool_specs,
                    system_prompt,
                    tool_choice=tool_choice,
                    system_prompt_content=system_prompt_content,
                    **kwargs,
            ):
                yield event
        finally:
            release()

    model_cls.stream = stream  # type: ignore[assignment]

    # structured_output is optional on some providers, but common in Strands
    if hasattr(model_cls, "structured_output"):
        if not hasattr(model_cls, _ORIG_STRUCT_ATTR):
            setattr(model_cls, _ORIG_STRUCT_ATTR, model_cls.structured_output)

        orig_struct = getattr(model_cls, _ORIG_STRUCT_ATTR)

        async def structured_output(
                self,
                output_model: Type[T],
                prompt,
                system_prompt: Optional[str] = None,
                **kwargs: Any,
        ):
            token_cost = estimate_tokens_rough(
                messages=prompt,
                system_prompt=system_prompt,
                system_prompt_content=None,
                assume_output_tokens=limiter.cfg.assume_output_tokens,
            )

            release = await asyncio.to_thread(limiter.acquire_blocking, token_cost)
            try:
                async for event in orig_struct(self, output_model, prompt, system_prompt=system_prompt, **kwargs):
                    yield event
            finally:
                release()

        model_cls.structured_output = structured_output  # type: ignore[assignment]


def unpatch_model_provider_class(model_cls: Type[Any]) -> None:
    if hasattr(model_cls, _ORIG_STREAM_ATTR):
        model_cls.stream = getattr(model_cls, _ORIG_STREAM_ATTR)  # type: ignore[assignment]
        delattr(model_cls, _ORIG_STREAM_ATTR)

    if hasattr(model_cls, _ORIG_STRUCT_ATTR):
        model_cls.structured_output = getattr(model_cls, _ORIG_STRUCT_ATTR)  # type: ignore[assignment]
        delattr(model_cls, _ORIG_STRUCT_ATTR)


# ----------------------------
# Langchain Class patching
# ----------------------------

_ORIG_GENERATE_ATTR = "_rl_orig_generate"
_ORIG_AGENERATE_ATTR = "_rl_orig_agenerate"


def patch_langchain_chat_class_generate(model_cls: Type[Any], limiter: ThreadSafeRateLimiter) -> None:
    """
    Monkey-patch LangChain chat model classes (ChatLiteLLM, ChatOllama, ChatBedrock, etc.)
    at the CLASS level, rate-limiting generate/agenerate.
    """

    # ---- generate (sync) ----
    if hasattr(model_cls, "generate") and callable(getattr(model_cls, "generate")):
        if not hasattr(model_cls, _ORIG_GENERATE_ATTR):
            logger.info(
                "Rate limit: Applying LangChain generate rate limit to %s: %s",
                model_cls.__name__,
                str(limiter.cfg),
            )
            setattr(model_cls, _ORIG_GENERATE_ATTR, model_cls.generate)

        orig_generate = getattr(model_cls, _ORIG_GENERATE_ATTR)

        def generate(self, messages, *args: Any, **kwargs: Any) -> Any:
            token_cost = _estimate_tokens_for_batch_messages(
                messages,
                assume_output_tokens=limiter.cfg.assume_output_tokens,
            )
            release = limiter.acquire_blocking(token_cost)
            try:
                return orig_generate(self, messages, *args, **kwargs)
            finally:
                release()

        model_cls.generate = generate  # type: ignore[assignment]
    else:
        logger.warning("Rate limit: %s has no generate() to patch", model_cls)

    # ---- agenerate (async) ----
    if hasattr(model_cls, "agenerate") and callable(getattr(model_cls, "agenerate")):
        if not hasattr(model_cls, _ORIG_AGENERATE_ATTR):
            logger.info(
                "Rate limit: Applying LangChain agenerate rate limit to %s: %s",
                model_cls.__name__,
                str(limiter.cfg),
            )
            setattr(model_cls, _ORIG_AGENERATE_ATTR, model_cls.agenerate)

        orig_agenerate = getattr(model_cls, _ORIG_AGENERATE_ATTR)

        async def agenerate(self, messages, *args: Any, **kwargs: Any) -> Any:
            token_cost = _estimate_tokens_for_batch_messages(
                messages,
                assume_output_tokens=limiter.cfg.assume_output_tokens,
            )
            release = await asyncio.to_thread(limiter.acquire_blocking, token_cost)
            try:
                result = orig_agenerate(self, messages, *args, **kwargs)
                if asyncio.iscoroutine(result):
                    return await result
                return result
            finally:
                release()

        model_cls.agenerate = agenerate  # type: ignore[assignment]
    else:
        logger.warning("Rate limit: %s has no agenerate() to patch", model_cls)


def unpatch_langchain_chat_class_generate(model_cls: Type[Any]) -> None:
    if hasattr(model_cls, _ORIG_GENERATE_ATTR):
        model_cls.generate = getattr(model_cls, _ORIG_GENERATE_ATTR)  # type: ignore[assignment]
        delattr(model_cls, _ORIG_GENERATE_ATTR)

    if hasattr(model_cls, _ORIG_AGENERATE_ATTR):
        model_cls.agenerate = getattr(model_cls, _ORIG_AGENERATE_ATTR)  # type: ignore[assignment]
        delattr(model_cls, _ORIG_AGENERATE_ATTR)
