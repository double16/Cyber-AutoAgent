import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from modules.tools import initialize_browser, browser_get_cookies
from modules.tools.browser import BrowserService, browser_evaluate_js, close_browser, _BROWSER, get_browser


def _stop_browser_loop(browser: BrowserService, timeout: float = 2.0) -> None:
    """Stop the BrowserService loop thread cleanly."""
    loop = getattr(browser, "_loop", None)
    thread = getattr(browser, "_loop_thread", None)

    if loop is not None:
        loop.call_soon_threadsafe(loop.stop)
    if thread is not None:
        thread.join(timeout=timeout)


async def _tool_like_call(browser: BrowserService, delay_s: float) -> int:
    """
    A 'tool-like' operation: user loop/thread -> run_in_browser_loop -> awaits a browser-loop coroutine.
    """
    async def _impl() -> int:
        # Make the op take time so other callers pile up concurrently.
        await asyncio.sleep(delay_s)
        return 1

    return await browser.run_in_browser_loop(_impl)


def _run_in_thread(barrier: threading.Barrier, browser: BrowserService, delay_s: float) -> int:
    """
    Simulate a Strands tool execution thread: each thread has its own event loop via asyncio.run().
    """
    barrier.wait()
    return asyncio.run(_tool_like_call(browser, delay_s))


def _run_evaluate_js_thread(barrier: threading.Barrier) -> int:
    """
    Simulate a Strands tool execution thread: each thread has its own event loop via asyncio.run().
    """
    barrier.wait()
    return int(asyncio.run(browser_evaluate_js("1")))


def _run_get_cookies_thread(barrier: threading.Barrier) -> int:
    """
    Simulate a Strands tool execution thread: each thread has its own event loop via asyncio.run().
    """
    barrier.wait()
    return 1 if bool(asyncio.run(browser_get_cookies())) else 0


@pytest.mark.parametrize("concurrency", [1, 2, 5, 10, 20])
@pytest.mark.parametrize("rounds", [1, 3])
def test_browser_run_in_browser_loop_is_single_flight(concurrency: int, rounds: int, tmp_path) -> None:
    browser = BrowserService(
        provider="ollama",
        model="llama3.2:3b",
        artifacts_dir=str(tmp_path),
        extra_http_headers=None,
    )
    try:
        delay_s = 0.05

        for _ in range(rounds):
            barrier = threading.Barrier(concurrency)

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [
                    pool.submit(_run_in_thread, barrier, browser, delay_s)
                    for _ in range(concurrency)
                ]
                results = [f.result(timeout=10) for f in futures]

            # all calls should have completed successfully
            assert sum(results) == concurrency

        # single-flight invariants (your instrumentation counters)
        assert browser._active_ops == 0
        assert browser._active_ops_peak == 1, f"peak={browser._active_ops_peak}"
        assert browser._active_ops_violations == 0, f"violations={browser._active_ops_violations}"

    finally:
        _stop_browser_loop(browser)


@pytest.mark.browser
@pytest.mark.asyncio
@pytest.mark.parametrize("concurrency", [1, 2, 5, 10, 20])
@pytest.mark.parametrize("rounds", [1, 3])
async def test_browser_run_in_browser_loop_is_single_flight_evaluate_js(concurrency: int, rounds: int, tmp_path) -> None:
    try:
        initialize_browser(provider="ollama", model="llama3.2:3b")

        for _ in range(rounds):
            barrier = threading.Barrier(concurrency)

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = [
                    pool.submit(_run_evaluate_js_thread, barrier) if idx % 2 == 0 else pool.submit(_run_get_cookies_thread, barrier)
                    for idx in range(concurrency)
                ]
                results = [f.result(timeout=10) for f in futures]

            # all calls should have completed successfully
            assert sum(results) == concurrency

        # single-flight invariants (your instrumentation counters)
        async with get_browser() as browser:
            assert browser is not None
            assert browser._active_ops == 0
            assert browser._active_ops_peak == 1, f"peak={browser._active_ops_peak}"
            assert browser._active_ops_violations == 0, f"violations={browser._active_ops_violations}"

    finally:
        close_browser()


def test_browser_run_in_browser_loop_is_reentrant(tmp_path) -> None:
    """Ensure a coroutine already running on the browser loop can call run_in_browser_loop() again.

    This verifies the re-entrancy fast-path (running is self._loop) and prevents deadlocks.
    """
    browser = BrowserService(
        provider="ollama",
        model="llama3.2:3b",
        artifacts_dir=str(tmp_path),
        extra_http_headers=None,
    )
    try:
        async def _nested_call() -> int:
            async def _inner() -> int:
                await asyncio.sleep(0.01)
                return 42

            # This call will execute while already on the browser loop.
            return await browser.run_in_browser_loop(_inner)

        async def _outer() -> int:
            # Execute _nested_call *on* the browser loop.
            return await browser.run_in_browser_loop(_nested_call)

        result = asyncio.run(_outer())
        assert result == 42

        # Ensure we didn't record any concurrency violations.
        assert browser._active_ops == 0
        assert browser._active_ops_peak == 1, f"peak={browser._active_ops_peak}"
        assert browser._active_ops_violations == 0, f"violations={browser._active_ops_violations}"
    finally:
        _stop_browser_loop(browser)


@pytest.mark.parametrize("executors", [2, 4])
@pytest.mark.parametrize("workers_per_executor", [1, 3])
@pytest.mark.parametrize("rounds", [1, 2])
def test_browser_single_flight_across_multiple_threadpool_executors(
        executors: int,
        workers_per_executor: int,
        rounds: int,
        tmp_path,
) -> None:
    """Mimic Strands ConcurrentToolExecutor behavior by using multiple thread pools.

    Each ThreadPoolExecutor represents a separate pool that may run tools concurrently.
    The browser must remain single-flight across all pools.
    """
    browser = BrowserService(
        provider="ollama",
        model="llama3.2:3b",
        artifacts_dir=str(tmp_path),
        extra_http_headers=None,
    )
    try:
        total_workers = executors * workers_per_executor
        delay_s = 0.05

        for _ in range(rounds):
            barrier = threading.Barrier(total_workers)

            pools: list[ThreadPoolExecutor] = [
                ThreadPoolExecutor(max_workers=workers_per_executor)
                for _ in range(executors)
            ]
            try:
                futures = []
                for pool in pools:
                    for _i in range(workers_per_executor):
                        futures.append(pool.submit(_run_in_thread, barrier, browser, delay_s))

                results = [f.result(timeout=15) for f in futures]
                assert sum(results) == total_workers
            finally:
                for pool in pools:
                    pool.shutdown(wait=True, cancel_futures=True)

        # Invariants: still single-flight across all pools
        assert browser._active_ops == 0
        assert browser._active_ops_peak == 1, f"peak={browser._active_ops_peak}"
        assert browser._active_ops_violations == 0, f"violations={browser._active_ops_violations}"
    finally:
        _stop_browser_loop(browser)

@pytest.mark.browser
@pytest.mark.asyncio
@pytest.mark.parametrize("executors", [2, 4])
@pytest.mark.parametrize("workers_per_executor", [1, 3])
@pytest.mark.parametrize("rounds", [1, 2])
async def test_browser_single_flight_across_multiple_threadpool_executors_evaluate_js(
        executors: int,
        workers_per_executor: int,
        rounds: int,
        tmp_path,
) -> None:
    """Mimic Strands ConcurrentToolExecutor behavior by using multiple thread pools.

    Each ThreadPoolExecutor represents a separate pool that may run tools concurrently.
    The browser must remain single-flight across all pools.
    """
    try:
        initialize_browser(provider="ollama", model="llama3.2:3b")

        total_workers = executors * workers_per_executor

        for _ in range(rounds):
            barrier = threading.Barrier(total_workers)

            pools: list[ThreadPoolExecutor] = [
                ThreadPoolExecutor(max_workers=workers_per_executor)
                for _ in range(executors)
            ]
            try:
                futures = []
                for pool in pools:
                    for _i in range(workers_per_executor):
                        if _i % 2 == 0:
                            futures.append(pool.submit(_run_evaluate_js_thread, barrier))
                        else:
                            futures.append(pool.submit(_run_get_cookies_thread, barrier))

                results = [f.result(timeout=15) for f in futures]
                assert sum(results) == total_workers
            finally:
                for pool in pools:
                    pool.shutdown(wait=True, cancel_futures=True)

        # Invariants: still single-flight across all pools
        async with get_browser() as browser:
            assert browser._active_ops == 0
            assert browser._active_ops_peak == 1, f"peak={browser._active_ops_peak}"
            assert browser._active_ops_violations == 0, f"violations={browser._active_ops_violations}"
    finally:
        close_browser()
