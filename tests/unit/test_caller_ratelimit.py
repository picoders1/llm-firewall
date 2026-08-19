"""The per-caller ceiling, tested on an injected clock.

A rate limiter tested with `sleep` is tested slowly and flakily, and the
behaviour that matters — what happens exactly at the window boundary — is the
part wall-clock testing approximates worst. The clock is a parameter so the
boundary can be asserted rather than sampled.
"""

from __future__ import annotations

import pytest

from app.auth.ratelimit import WINDOW_SECONDS, CallerLimiter, LimitKind

pytestmark = pytest.mark.unit


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _limiter(*, per_minute: int = 0, max_concurrent: int = 0) -> tuple[CallerLimiter, FakeClock]:
    clock = FakeClock()
    return CallerLimiter(per_minute=per_minute, max_concurrent=max_concurrent, clock=clock), clock


async def test_a_limiter_with_no_limits_admits_everything():
    limiter, _ = _limiter()
    assert limiter.enabled is False
    for _ in range(100):
        assert await limiter.acquire("app") is None


async def test_the_allowance_is_spent_and_then_refused():
    limiter, _ = _limiter(per_minute=3)
    for _ in range(3):
        assert await limiter.acquire("app") is None
    rejection = await limiter.acquire("app")
    assert rejection is not None
    assert rejection.kind is LimitKind.RATE


async def test_the_window_slides_rather_than_resetting():
    """A fixed calendar window lets a caller send the full allowance at the end of
    one window and again at the start of the next — twice the limit across two
    seconds, which is exactly when a runaway retry loop does its damage."""
    limiter, clock = _limiter(per_minute=2)
    await limiter.acquire("app")
    clock.advance(59.0)
    await limiter.acquire("app")

    # The first hit is still inside the trailing window.
    assert await limiter.acquire("app") is not None

    # One second later it has expired, and exactly one slot frees up.
    clock.advance(1.1)
    assert await limiter.acquire("app") is None
    assert await limiter.acquire("app") is not None


async def test_retry_after_is_never_zero():
    """Advising a client to retry in 0 seconds when the oldest hit expires in 0.4
    invites an immediate second 429 and a hot loop."""
    limiter, clock = _limiter(per_minute=1)
    await limiter.acquire("app")
    clock.advance(WINDOW_SECONDS - 0.4)
    rejection = await limiter.acquire("app")
    assert rejection is not None
    assert rejection.retry_after_seconds >= 1


async def test_callers_have_independent_allowances():
    """One noisy application must not throttle another. Identity is the point of
    having identity."""
    limiter, _ = _limiter(per_minute=1)
    assert await limiter.acquire("app-a") is None
    assert await limiter.acquire("app-a") is not None
    assert await limiter.acquire("app-b") is None


async def test_concurrency_is_released_when_a_request_finishes():
    limiter, _ = _limiter(max_concurrent=2)
    assert await limiter.acquire("app") is None
    assert await limiter.acquire("app") is None
    rejection = await limiter.acquire("app")
    assert rejection is not None
    assert rejection.kind is LimitKind.CONCURRENCY

    await limiter.release("app")
    assert await limiter.acquire("app") is None


async def test_a_concurrency_rejection_does_not_spend_the_rate_allowance():
    """Otherwise a caller at its concurrency ceiling would silently burn through
    its per-minute budget while every request was being refused — two limits
    compounding into one much stricter than either."""
    limiter, _ = _limiter(per_minute=10, max_concurrent=1)
    assert await limiter.acquire("app") is None
    for _ in range(5):
        rejection = await limiter.acquire("app")
        assert rejection is not None and rejection.kind is LimitKind.CONCURRENCY

    await limiter.release("app")
    # 9 of the 10 remain: only the first, admitted request was counted.
    for _ in range(9):
        assert await limiter.acquire("app") is None
        await limiter.release("app")
    assert await limiter.acquire("app") is not None


async def test_releasing_more_than_acquired_does_not_go_negative():
    """A double release would otherwise create free capacity out of nothing."""
    limiter, _ = _limiter(max_concurrent=1)
    await limiter.acquire("app")
    await limiter.release("app")
    await limiter.release("app")
    assert limiter.snapshot() == {}
    assert await limiter.acquire("app") is None
    assert await limiter.acquire("app") is not None


async def test_memory_is_bounded_by_the_configured_callers():
    """Buckets are keyed by caller id, and caller ids come from configuration
    rather than from the wire — so there is no request a client can send that
    grows this map."""
    limiter, _ = _limiter(per_minute=5, max_concurrent=5)
    for _ in range(50):
        await limiter.acquire("app")
        await limiter.release("app")
    assert set(limiter.snapshot()) <= {"app"}
