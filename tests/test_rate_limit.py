from __future__ import annotations

import pytest
from unittest.mock import Mock

import modules.agents.rate_limit as rl


@pytest.fixture
def inline_to_thread(monkeypatch):
    async def fake_to_thread(fn, *args, **kwargs):
        return fn(*args, **kwargs)

    monkeypatch.setattr(rl.asyncio, "to_thread", fake_to_thread)


# ----------------------------
# _TokenBucket
# ----------------------------

def test_tokenbucket_consume_without_wait(monkeypatch):
    slept = {"called": False}

    def fake_sleep(_):
        slept["called"] = True
        raise AssertionError("sleep should not be called")

    monkeypatch.setattr(rl.time, "sleep", fake_sleep)

    b = rl._TokenBucket(capacity=10.0, refill_rate_per_sec=1.0)
    b.consume_blocking(3.0)

    assert b._tokens == pytest.approx(7.0)
    assert slept["called"] is False


def test_tokenbucket_refill_increases_tokens_up_to_capacity(monkeypatch):
    t = {"now": 1000.0}

    def fake_monotonic():
        return t["now"]

    monkeypatch.setattr(rl.time, "monotonic", fake_monotonic)

    b = rl._TokenBucket(capacity=10.0, refill_rate_per_sec=2.0)  # 2 tokens/sec
    b.consume_blocking(10.0)
    assert b._tokens == pytest.approx(0.0)

    # +3s => +6 tokens
    t["now"] += 3.0
    with b._lock:
        b._refill_locked()
    assert b._tokens == pytest.approx(6.0)

    # Big jump clamps at capacity
    t["now"] += 100.0
    with b._lock:
        b._refill_locked()
    assert b._tokens == pytest.approx(10.0)


def test_tokenbucket_amount_greater_than_capacity_clamps_and_warns(monkeypatch):
    b = rl._TokenBucket(capacity=2.0, refill_rate_per_sec=1.0)
    log = Mock()
    monkeypatch.setattr(rl, "logger", log)

    b.consume_blocking(10.0)

    assert log.warning.called
    # It clamps to capacity and consumes the whole bucket
    assert b._tokens == pytest.approx(0.0)


def test_tokenbucket_zero_or_negative_is_noop():
    b = rl._TokenBucket(capacity=5.0, refill_rate_per_sec=1.0)
    b.consume_blocking(0)
    b.consume_blocking(-1)
    assert b._tokens == pytest.approx(5.0)


# ----------------------------
# Token estimation
# ----------------------------

def test_json_to_compact_str_compacts_and_sorts_keys():
    assert rl._json_to_compact_str({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_extract_text_from_text_block():
    assert rl._extract_text_from_content({"text": "hello"}) == "hello"


def test_extract_text_from_json_key_block():
    assert rl._extract_text_from_content({"json": {"b": 1, "a": 2}}) == '{"a":2,"b":1}'


def test_extract_text_from_type_json_variants():
    assert rl._extract_text_from_content({"type": "json", "value": {"x": 1}}) == '{"x":1}'
    assert rl._extract_text_from_content({"type": "json", "content": [1, 2]}) == "[1,2]"


def test_extract_text_from_nested_content():
    assert rl._extract_text_from_content({"content": {"text": "nested"}}) == "nested"


def test_estimate_tokens_rough_includes_text_json_and_assume_output():
    messages = [
        {
            "role": "user",
            "content": [
                {"text": "abcd"},          # 4 chars -> 1 token under chars//4 heuristic
                {"json": {"k": "vvvv"}},   # counts JSON too
            ],
        }
    ]
    system_prompt = "zzzz"  # +1 token
    system_prompt_content = [{"text": "yyyy"}]  # +1 token

    est = rl.estimate_tokens_rough(
        messages=messages,
        system_prompt=system_prompt,
        system_prompt_content=system_prompt_content,
        assume_output_tokens=10,
    )

    assert est >= 10
    assert est > 0


# ----------------------------
# ThreadSafeRateLimiter
# ----------------------------

def test_limiter_init_builds_buckets_and_uses_rpm_per_second_refill():
    cfg = rl.RateLimitConfig(rpm=30.0, tpm=600.0, max_concurrent=None)
    limiter = rl.ThreadSafeRateLimiter(cfg)

    assert limiter._req_bucket is not None
    assert limiter._tok_bucket is not None

    assert limiter._req_bucket.capacity == pytest.approx(30.0)
    assert limiter._req_bucket.refill_rate == pytest.approx(30.0 / 60.0)

    assert limiter._tok_bucket.capacity == pytest.approx(600.0)
    assert limiter._tok_bucket.refill_rate == pytest.approx(600.0 / 60.0)


def test_acquire_blocking_calls_buckets_and_returns_release():
    cfg = rl.RateLimitConfig(rpm=10.0, tpm=100.0, max_concurrent=1)
    limiter = rl.ThreadSafeRateLimiter(cfg)

    limiter._req_bucket = Mock()
    limiter._tok_bucket = Mock()
    limiter._sem = Mock()

    release = limiter.acquire_blocking(token_cost=55)

    limiter._sem.acquire.assert_called_once()
    limiter._req_bucket.consume_blocking.assert_called_once_with(1.0)
    limiter._tok_bucket.consume_blocking.assert_called_once_with(55.0)

    release()
    limiter._sem.release.assert_called_once()


def test_acquire_blocking_releases_semaphore_on_exception():
    cfg = rl.RateLimitConfig(rpm=10.0, tpm=None, max_concurrent=1)
    limiter = rl.ThreadSafeRateLimiter(cfg)

    limiter._req_bucket = Mock()
    limiter._req_bucket.consume_blocking.side_effect = RuntimeError("boom")
    limiter._sem = Mock()

    with pytest.raises(RuntimeError):
        limiter.acquire_blocking(token_cost=0)

    limiter._sem.acquire.assert_called_once()
    limiter._sem.release.assert_called_once()


# ----------------------------
# patch_model_provider_class / unpatch_model_provider_class
# ----------------------------

@pytest.mark.asyncio
async def test_patch_and_unpatch_stream(monkeypatch, inline_to_thread):
    log = Mock()
    monkeypatch.setattr(rl, "logger", log)

    events = [{"e": 1}, {"e": 2}]

    class DummyModel:
        async def stream(
                self,
                messages,
                tool_specs=None,
                system_prompt=None,
                *,
                tool_choice=None,
                system_prompt_content=None,
                **kwargs,
        ):
            for e in events:
                yield e

    limiter = Mock(spec=rl.ThreadSafeRateLimiter)
    limiter.cfg = rl.RateLimitConfig(rpm=10.0, tpm=None, max_concurrent=None, assume_output_tokens=0)

    released = {"count": 0}

    def release():
        released["count"] += 1

    limiter.acquire_blocking.return_value = release

    try:
        rl.patch_model_provider_class(DummyModel, limiter)
        assert hasattr(DummyModel, rl._ORIG_STREAM_ATTR)

        m = DummyModel()
        got = []
        async for e in m.stream(messages=[{"role": "user", "content": [{"text": "hello"}]}]):
            got.append(e)

        assert got == events
        assert limiter.acquire_blocking.call_count == 1
        assert released["count"] == 1

        orig = getattr(DummyModel, rl._ORIG_STREAM_ATTR)
        rl.unpatch_model_provider_class(DummyModel)
        assert not hasattr(DummyModel, rl._ORIG_STREAM_ATTR)
        assert DummyModel.stream is orig
    finally:
        rl.unpatch_model_provider_class(DummyModel)


@pytest.mark.asyncio
async def test_patch_structured_output(monkeypatch, inline_to_thread):
    log = Mock()
    monkeypatch.setattr(rl, "logger", log)

    class DummyModel:
        async def stream(self, *args, **kwargs):
            yield {"stream": True}

        async def structured_output(self, output_model, prompt, system_prompt=None, **kwargs):
            yield {"ok": True}

    limiter = Mock(spec=rl.ThreadSafeRateLimiter)
    limiter.cfg = rl.RateLimitConfig(rpm=10.0, tpm=None, max_concurrent=None, assume_output_tokens=0)

    released = {"count": 0}

    def release():
        released["count"] += 1

    limiter.acquire_blocking.return_value = release

    try:
        rl.patch_model_provider_class(DummyModel, limiter)
        assert hasattr(DummyModel, rl._ORIG_STRUCT_ATTR)

        m = DummyModel()
        got = []
        async for e in m.structured_output(dict, prompt=[{"role": "user", "content": [{"json": {"a": 1}}]}]):
            got.append(e)

        assert got == [{"ok": True}]
        assert limiter.acquire_blocking.call_count >= 1
        assert released["count"] == 1
    finally:
        rl.unpatch_model_provider_class(DummyModel)


def test_patch_model_provider_class_no_stream_is_noop(monkeypatch):
    log = Mock()
    monkeypatch.setattr(rl, "logger", log)

    class NoStream:
        pass

    limiter = Mock(spec=rl.ThreadSafeRateLimiter)
    limiter.cfg = rl.RateLimitConfig(rpm=10.0)

    rl.patch_model_provider_class(NoStream, limiter)
    assert not hasattr(NoStream, rl._ORIG_STREAM_ATTR)
    assert log.warning.called
