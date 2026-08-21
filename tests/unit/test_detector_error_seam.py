"""The Run 3 detector-error seam, pinned so it cannot rot (ADR-035, phase 0c).

Alerts #5 `FirewallDetectorErrorRateHigh` and #6 `FirewallDetectorErrorsPresent`
need a real `firewall_detector_errors_total` sample. The seam originally
registered for that — a backtracking regex exceeding `timeout_ms` — was
**disproven in phase 1**: `asyncio.wait_for` cannot preempt a `BaseDetector` whose
`detect()` never awaits, and does not even *report* the overrun, so eight marker
requests were recorded as eight successful 1.2 s detector runs (R-108).

This is the replacement, and the reason it is a committed test rather than a
one-off check is that the phase-1 failure was caused by trusting an unverified
mechanism. The seam is verified here on every run:

    custom_patterns[].confidence is read as `float(...)` with NO bound
      -> a match constructs DetectionResult(score=2.0)
      -> `score: float = Field(ge=0.0, le=1.0)` raises ValidationError in detect()
      -> GuardedDetector's `except Exception` records error_kind="ValidationError"

Deterministic by CONTENT, not by timing: no marker, no fault. That is the property
that distinguishes it from the seam it replaces, and it is asserted below rather
than asserted about.

**The seam depends on a defect.** `confidence` being unvalidated is R-110 — an
operator typing `confidence: 95` for `0.95` gets a policy that starts cleanly and
then 503s every matching request. Validating it is the right fix and it would
**close this seam**; ADR-035 registers that as the invalidating evidence. If these
tests start failing because `confidence` was bounded, that is the fix landing, not
a regression — the seam then needs a successor design, not a repair.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from app.config.policy import DetectorPolicy
from app.core.normalize import decode_embedded, normalize
from app.core.types import DetectionContext, Direction, Role
from app.detectors.guarded import GuardedDetector
from app.detectors.registry import create

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[2]
FAULT_POLICY = REPO / "config" / "policies" / "fault-injection.yaml"
DEFAULT_POLICY = REPO / "config" / "policies" / "default.yaml"

ERROR_MARKER_NAME = "FAULT_DETECTOR_ERROR"
LATENCY_MARKER_NAME = "FAULT_INJECTION_MARKER"
EXPECTED_ERROR_KIND = "ValidationError"

# The timeout the shipped policy gives `pii.regex`. Used as the guard budget so
# the test exercises the same numbers the deployment does.
PII_TIMEOUT_MS = 100


def ctx(text: str, direction: Direction = Direction.INPUT) -> DetectionContext:
    """The offset map is load-bearing.

    `DetectionContext.source_span` returns None when `normalized_offsets` is
    empty, so a hand-built context with no offsets yields no spans, no score and
    no fault — which looks exactly like the seam not working. Building the
    context the way the gateway does is what makes this test meaningful.
    """
    folded = normalize(text)
    return DetectionContext(
        request_id="test",
        direction=direction,
        role=Role.USER,
        raw_text=text,
        normalized_text=folded.text,
        normalized_offsets=folded.offsets,
        decoded_segments=decode_embedded(text),
    )


def _pii_options(path: Path) -> dict[str, Any]:
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    options: dict[str, Any] = policy["input"]["pii"]["options"]
    return options


def _marker(name: str) -> dict[str, Any]:
    for entry in _pii_options(FAULT_POLICY)["custom_patterns"]:
        if entry.get("name") == name:
            return dict(entry)
    raise AssertionError(f"{name} is not declared in {FAULT_POLICY.name}")


def _detector(options: dict[str, Any]) -> GuardedDetector:
    """Built through the SHIPPED registry and guard — no doubles anywhere."""
    policy = DetectorPolicy(
        detector="pii.regex", threshold=0.50, timeout_ms=PII_TIMEOUT_MS, options=options
    )
    return GuardedDetector(create("pii.regex", policy), timeout_ms=PII_TIMEOUT_MS)


@pytest.fixture
def error_marker() -> str:
    return str(_marker(ERROR_MARKER_NAME)["pattern"])


@pytest.fixture
def fault_detector() -> GuardedDetector:
    return _detector(_pii_options(FAULT_POLICY))


@pytest.fixture
def shipped_detector() -> GuardedDetector:
    return _detector(_pii_options(DEFAULT_POLICY))


# --- The seam itself ---------------------------------------------------------


def test_the_fault_policy_builds_without_a_startup_failure():
    """The out-of-range value must be accepted at BUILD time and rejected at
    MATCH time. If it failed at build, the process would refuse to start and the
    fault would be a startup failure — which is what disqualified every other
    candidate in ADR-035's phase 0c search."""
    _detector(_pii_options(FAULT_POLICY))


async def test_the_marker_produces_a_recorded_detector_error(fault_detector, error_marker):
    result = await fault_detector.detect(ctx(f"please summarise {error_marker} for me"))

    assert result.errored is True
    assert result.error_kind == EXPECTED_ERROR_KIND
    assert result.reasons == (f"detector_error:{EXPECTED_ERROR_KIND}",)
    # The guard reports a failure as a non-detection with a zero score: it records,
    # it never decides (ADR-007). Turning this into a block is the policy engine's
    # job, and `on_error: fail_closed` is what does it.
    assert result.detected is False
    assert result.score == 0.0


async def test_the_error_kind_is_exactly_the_label_the_alert_will_group_by(
    fault_detector, error_marker
):
    """`FirewallDetectorErrorsPresent` aggregates `by (detector, error_kind)`. If
    pydantic ever renames its exception, the label moves and the registered
    expected evidence in ADR-035 is wrong — this fails then, rather than the
    alert silently grouping by something nobody predicted."""
    result = await fault_detector.detect(ctx(error_marker))
    assert (fault_detector.name, result.error_kind) == ("pii.regex", EXPECTED_ERROR_KIND)


async def test_clean_traffic_under_the_fault_policy_does_not_error(fault_detector):
    result = await fault_detector.detect(ctx("What is the capital of France?"))
    assert result.errored is False
    assert result.error_kind is None


@pytest.mark.parametrize("repeats", (25,))
async def test_the_seam_is_deterministic_not_a_race(fault_detector, error_marker, repeats):
    """The disproven seam depended on a scheduler race; this one depends on a
    literal string. All-or-nothing across repeats is the difference, so it is
    asserted rather than described."""
    faulted = 0
    clean = 0
    for i in range(repeats):
        faulted += bool((await fault_detector.detect(ctx(f"{error_marker} {i}"))).errored)
        clean += bool((await fault_detector.detect(ctx(f"ordinary request {i}"))).errored)
    assert (faulted, clean) == (repeats, 0)


# --- Negative controls, each pinning a different reason it could be wrong ----


async def test_the_marker_is_inert_under_the_shipped_policy(shipped_detector, error_marker):
    """The control that matters most. `default.yaml` declares `custom_patterns: []`,
    so the marker is ordinary text to a production deployment: no error, no
    detection, no redaction."""
    result = await shipped_detector.detect(ctx(f"please summarise {error_marker} for me"))
    assert result.errored is False
    assert result.detected is False


async def test_an_in_range_confidence_with_the_same_marker_does_not_fault(error_marker):
    """Isolates the cause. Same pattern, same text, same detector — only the
    confidence differs. If this errored, the fault would be coming from the marker
    string and the whole mechanism would be misattributed."""
    options = {
        "entities": ["EMAIL"],
        "custom_patterns": [
            {"name": ERROR_MARKER_NAME, "pattern": error_marker, "confidence": 0.9}
        ],
    }
    result = await _detector(options).detect(ctx(error_marker))
    assert result.errored is False
    assert result.detected is True
    assert result.score == pytest.approx(0.9)


async def test_the_two_markers_stay_separable(fault_detector, error_marker):
    """#16 uses the backtracking marker and #5/#6 use this one. If either produced
    the other's effect they would contaminate each other's measurements: a
    ValidationError from the latency marker would corrupt #5's numerator, and
    backtracking from the error marker would corrupt #16's p95."""
    latency_marker_payload = "x" * 24 + "z"

    latency = await fault_detector.detect(ctx(latency_marker_payload))
    assert latency.errored is False, "the latency marker must not raise ValidationError"

    error = await fault_detector.detect(ctx(error_marker))
    assert error.errored is True
    # A literal match costs microseconds. The latency marker costs ~10^5 times
    # more; a bound this loose still separates them by orders of magnitude.
    assert error.latency_ms < 50.0, error.latency_ms


def test_the_error_marker_is_a_literal_not_a_pattern(error_marker):
    """A metacharacter here would risk a second, accidental backtracking fault —
    reintroducing exactly the CPU-stall property (R-108) this seam was chosen to
    avoid."""
    assert not set(error_marker) & set(".^$*+?{}[]\\|()"), error_marker


def test_the_latency_marker_keeps_an_in_range_confidence():
    """It must stay a LATENCY fault. Giving it an out-of-range confidence would
    silently turn #16's driver into an error generator."""
    entry = _marker(LATENCY_MARKER_NAME)
    assert 0.0 <= float(entry.get("confidence", 0.85)) <= 1.0


def test_the_seam_still_depends_on_an_unbounded_confidence(error_marker):
    """The registered invalidating evidence, made executable.

    ADR-035 phase 0c records that validating `custom_patterns[].confidence`
    (R-110) is the correct fix and that it CLOSES this seam. This test states the
    dependency explicitly so that, when the fix lands, the failure names the
    reason instead of looking like a broken fixture.
    """
    entry = _marker(ERROR_MARKER_NAME)
    assert float(entry["confidence"]) > 1.0, (
        "the detector-error seam requires an out-of-range confidence; if this was "
        "deliberately bounded, R-110 has been fixed and the seam needs a successor "
        "design (ADR-035, phase 0c, 'what evidence would invalidate this seam')"
    )
