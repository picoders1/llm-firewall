"""What `firewall_upstream_errors_total` counts, and what it must not (R-107).

Phase 20 found the counter empty after an induced upstream failure. The gateway
had behaved correctly — 502, failed safe, audited — but the metric the
`FirewallUpstreamErrorsHigh` alert depends on never came into existence, so the
alert could not fire for the condition it names.

The cause was the guard, not the recording: the error was only counted inside a
branch that required `upstream_latency_ms`, and a latency only exists when the
call **succeeded**. `HttpUpstreamClient.chat_completions` raises on a timeout, an
unreachable host, an upstream error status or a malformed body, so on every real
upstream failure the latency is `None` and the branch was skipped.

The same guard had the mirror-image fault: a request whose upstream call
succeeded and whose status was then set to 5xx by something *after* the upstream
— an output-side detector failure — was counted as an upstream error.

`upstream_called` with **no** latency is the precise signature of "the call was
attempted and did not complete", and that is what this now counts.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.observability.metrics import Metrics, record_trace

pytestmark = pytest.mark.unit


@dataclass
class FakeTrace:
    """Only the attributes `record_trace` reads."""

    status_code: int
    upstream_called: bool
    upstream_latency_ms: float | None
    model: str | None = "mock-model"
    decision: object | None = None
    gateway_latency_ms: float = 1.0
    input_chars: int = 10
    caller_id: str | None = None
    detector_outcomes: tuple = ()
    events: tuple = ()


def upstream_errors(metrics: Metrics) -> float:
    total = 0.0
    for family in metrics.registry.collect():
        if family.name == "firewall_upstream_errors":
            total += sum(s.value for s in family.samples if s.name.endswith("_total"))
    return total


def test_a_successful_request_records_no_upstream_error():
    m = Metrics()
    record_trace(
        m,
        FakeTrace(status_code=200, upstream_called=True, upstream_latency_ms=12.5),
        route="/v1/chat/completions",
    )
    assert upstream_errors(m) == 0


def test_an_upstream_failure_is_counted_exactly_once():
    """The R-107 case. `upstream_called` with no latency is a call that raised."""
    m = Metrics()
    record_trace(
        m,
        FakeTrace(status_code=502, upstream_called=True, upstream_latency_ms=None),
        route="/v1/chat/completions",
    )
    assert upstream_errors(m) == 1


def test_repeated_upstream_failures_count_once_each():
    m = Metrics()
    for _ in range(5):
        record_trace(
            m,
            FakeTrace(status_code=502, upstream_called=True, upstream_latency_ms=None),
            route="/v1/chat/completions",
        )
    assert upstream_errors(m) == 5


def test_a_block_that_never_reached_the_upstream_is_not_an_upstream_error():
    """A 403 decided before the upstream. `upstream_called` is False, so the
    absent latency must not be read as a failed call."""
    m = Metrics()
    record_trace(
        m,
        FakeTrace(status_code=403, upstream_called=False, upstream_latency_ms=None),
        route="/v1/chat/completions",
    )
    assert upstream_errors(m) == 0


def test_a_detector_failure_after_a_successful_upstream_is_not_an_upstream_error():
    """The mirror-image fault the old guard had. The model answered; a detector
    failed afterwards and set 503. Counting that as an upstream error would point
    an operator at the wrong system — and `FirewallUpstreamErrorsHigh` says in so
    many words that the firewall is fine and the model endpoint is not."""
    m = Metrics()
    record_trace(
        m,
        FakeTrace(status_code=503, upstream_called=True, upstream_latency_ms=9.0),
        route="/v1/chat/completions",
    )
    assert upstream_errors(m) == 0


def test_the_latency_histogram_still_observes_completed_calls():
    """The fix must not cost the existing latency metric."""
    m = Metrics()
    record_trace(
        m,
        FakeTrace(status_code=200, upstream_called=True, upstream_latency_ms=12.5),
        route="/v1/chat/completions",
    )
    counts = {
        s.labels.get("outcome"): s.value
        for family in m.registry.collect()
        if family.name == "firewall_upstream_latency_seconds"
        for s in family.samples
        if s.name.endswith("_count")
    }
    assert counts.get("ok") == 1
