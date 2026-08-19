"""Per-caller rate and concurrency limits, in this process only.

Authentication answers *who*; it does not answer *how much*. A caller whose
credential leaked, or whose retry loop went wrong, is authenticated all the way
to the upstream bill — so identity without a ceiling is only half the control
(ADR-024 §16).

## Deliberately in-process

No Redis, no shared store. The honest consequence, recorded rather than hidden:
**with N replicas the effective limit is N times the configured value.** For the
deployment this project actually has — a single container, or a small replica
set behind an ingress — an approximate ceiling that needs no new infrastructure
is worth more than an exact one that needs a datastore to run at all. A
deployment that needs an exact global limit should set it at the ingress, which
already sees every request.

## Why a sliding window rather than a fixed one

A fixed calendar window lets a caller send the full allowance in the last second
of one window and again in the first second of the next — twice the limit across
a two-second span, which is exactly when a runaway retry loop does its damage.
This keeps request timestamps and counts over a trailing 60 seconds, at the cost
of remembering at most `limit` timestamps per caller.

Memory is bounded by construction: callers come from configuration, not from the
wire, so the number of buckets is the number of configured callers.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

WINDOW_SECONDS = 60.0


class LimitKind(StrEnum):
    RATE = "rate"
    CONCURRENCY = "concurrency"


@dataclass(frozen=True, slots=True)
class LimitRejection:
    kind: LimitKind
    retry_after_seconds: int


class CallerLimiter:
    """Sliding-window rate limit plus a concurrency ceiling, per caller.

    `clock` is injectable because a rate limiter tested with `sleep` is a rate
    limiter tested slowly and flakily. The window boundary is the interesting
    behaviour and it should be asserted exactly, not approximated by wall-clock.
    """

    def __init__(
        self,
        *,
        per_minute: int,
        max_concurrent: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._per_minute = per_minute
        self._max_concurrent = max_concurrent
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._in_flight: dict[str, int] = {}
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return self._per_minute > 0 or self._max_concurrent > 0

    async def acquire(self, caller_id: str) -> LimitRejection | None:
        """Reserve a slot, or say why not. Returns `None` when admitted."""
        if not self.enabled:
            return None
        now = self._clock()
        async with self._lock:
            if self._per_minute > 0:
                hits = self._hits.setdefault(caller_id, deque())
                cutoff = now - WINDOW_SECONDS
                while hits and hits[0] <= cutoff:
                    hits.popleft()
                if len(hits) >= self._per_minute:
                    # Round up: advising a client to retry in 0 seconds when the
                    # oldest hit expires in 0.4 invites an immediate second 429.
                    wait = hits[0] + WINDOW_SECONDS - now
                    return LimitRejection(LimitKind.RATE, max(1, int(wait) + 1))

            if self._max_concurrent > 0:
                in_flight = self._in_flight.get(caller_id, 0)
                if in_flight >= self._max_concurrent:
                    return LimitRejection(LimitKind.CONCURRENCY, 1)
                self._in_flight[caller_id] = in_flight + 1

            # Recorded only once BOTH checks pass, so a request rejected for
            # concurrency does not also consume its caller's rate allowance.
            if self._per_minute > 0:
                self._hits[caller_id].append(now)
        return None

    async def release(self, caller_id: str) -> None:
        if self._max_concurrent <= 0:
            return
        async with self._lock:
            remaining = self._in_flight.get(caller_id, 0) - 1
            if remaining > 0:
                self._in_flight[caller_id] = remaining
            else:
                self._in_flight.pop(caller_id, None)

    def snapshot(self) -> dict[str, int]:
        """In-flight counts, for tests and diagnostics. Never served to a client."""
        return dict(self._in_flight)


__all__ = ["WINDOW_SECONDS", "CallerLimiter", "LimitKind", "LimitRejection"]
