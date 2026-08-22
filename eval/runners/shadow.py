"""Drive corpus traffic through the RUNNING gateway and record what it decided.

Phase 20 (ADR-034). The distinction from every other runner in this directory is
that this one exercises the **deployment**: normalisation, the detector pipeline,
the policy engine, the audit write and the upstream call, over a socket, exactly
as a caller would. `scripts/evaluate_*.py` score detectors offline and cannot see
any of that.

It is deliberately not a *benchmark* — `eval/runners/benchmark.py` owns latency and
throughput measurement, and duplicating it was refused in Phase 15. What this gained
in Phase 2 of ADR-035 is a **sustained mode**: a paced, seeded, fault-mixing driver
for the alerts whose conditions must hold for ten or fifteen minutes.

That belongs here rather than in `benchmark.py` for a specific reason. `benchmark.py`
is the fixed-grid experiment whose output backs published performance claims; putting
load-generation and fault-injection code inside it would place new machinery in the
measurement path those claims depend on. This runner already drives the deployment.

**The one-shot behaviour is the default and is unchanged.** Supplying none of the
sustained flags reproduces Run 1 exactly, which is why the original `drive()` is left
alone rather than reimplemented on top of the async path.

**Hold-out corpora are not readable from here.** Phase 20 measures a deployment,
not a detector's generalisation, and spending a scoring budget on it would burn
irreplaceable evidence to answer a question it was not reserved for (ADR-034).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN = "holdout"

# Fault markers (ADR-035 §5, and phase 0c for `detector-error`). Each is a string
# spliced into the prompt; none of them is a mechanism of its own.
#
#   upstream-500     the mock's shipped trigger. NO second upstream fault
#                    mechanism is introduced — ADR-035 forbids one.
#   detector-error   phase 0c: matches a custom pattern whose confidence is out of
#                    range, so `DetectionResult` rejects the score and the detector
#                    raises. Drives #5 and #6. Costs microseconds.
#   detector-timeout 24 x's: ~0.8-1.2 s of backtracking. Recorded for completeness;
#                    it produces NO detector error (R-108) and is not used for #5/#6.
#   detector-slow    22 x's: ~0.2-0.3 s, under the budget. Drives #16.
#
# The last three only do anything when `config/policies/fault-injection.yaml` is
# mounted. Against a production policy they are ordinary text.
FAULT_MARKERS = {
    "upstream-500": "__return_500__",
    "detector-error": "FAULT-DETECTOR-ERROR-3f9a1c",
    "detector-timeout": "x" * 24 + "z",
    "detector-slow": "x" * 22 + "z",
}


@dataclass(slots=True)
class Outcome:
    sample_id: str
    label: str
    category: str
    status_code: int
    decision: str
    block_category: str | None
    latency_ms: float


@dataclass(slots=True)
class Report:
    corpus: str
    outcomes: list[Outcome] = field(default_factory=list)
    # Achieved, never requested. A run whose realised fault fraction misses its
    # target must show up as a discrepancy rather than be assumed away — the
    # denominators of #5 and #8 depend on this being measured.
    sent: int = 0
    faulted: int = 0
    auth_failed: int = 0
    # What the seeded schedule asked for. `faulted` is what was actually sent; the
    # two differing means a slot was dropped, and that is a finding, not a rounding.
    planned_faults: int = 0
    planned_auth_failures: int = 0
    seed: int = 0

    def counts(self) -> Counter[str]:
        return Counter(o.decision for o in self.outcomes)

    def status_counts(self) -> Counter[int]:
        return Counter(o.status_code for o in self.outcomes)

    def achieved_fault_fraction(self) -> float:
        return self.faulted / self.sent if self.sent else 0.0

    def by_category(self) -> dict[str, Counter[str]]:
        out: dict[str, Counter[str]] = {}
        for o in self.outcomes:
            out.setdefault(o.category, Counter())[o.decision] += 1
        return out


def load_cases(path: Path, limit: int | None) -> list[dict]:
    if FORBIDDEN in path.parts:
        raise SystemExit(f"refusing to read a budgeted hold-out corpus: {path}")
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return cases[:limit] if limit else cases


def drive(base_url: str, cases: list[dict], model: str, api_key: str | None) -> Report:
    report = Report(corpus="")
    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    with httpx.Client(timeout=30.0) as client:
        for case in cases:
            text = case.get("text") or case.get("prompt") or ""
            if not text:
                continue
            started = time.perf_counter()
            try:
                response = client.post(
                    f"{base_url}/v1/chat/completions",
                    json={"model": model, "messages": [{"role": "user", "content": text}]},
                    headers=headers,
                )
                status = response.status_code
                body = response.json() if response.content else {}
            except httpx.HTTPError as exc:
                status, body = 0, {"error": {"type": type(exc).__name__}}
            latency = (time.perf_counter() - started) * 1000

            # The gateway reports a refusal as an error payload; an allowed
            # request comes back as a completion. Redaction is invisible from
            # the client, which is the point of it, so it is read from the
            # audit trail rather than inferred here.
            error = (body or {}).get("error") or {}
            if status == 200:
                decision, block_category = "allow", None
            elif status == 403:
                decision = "block"
                block_category = error.get("category") or error.get("type")
            else:
                decision, block_category = f"http_{status}", error.get("type")

            report.outcomes.append(
                Outcome(
                    sample_id=str(case.get("sample_id", "")),
                    label=str(case.get("label", "")),
                    category=str(case.get("category", "unknown")),
                    status_code=status,
                    decision=decision,
                    block_category=block_category,
                    latency_ms=round(latency, 3),
                )
            )
    return report


def _classify(status: int, body: dict) -> tuple[str, str | None]:
    """The gateway reports a refusal as an error payload and an allow as a
    completion. Redaction is invisible from the client — which is the point of it —
    so it is read from the audit trail, never inferred here."""
    error = (body or {}).get("error") or {}
    if status == 200:
        return "allow", None
    if status == 403:
        return "block", error.get("category") or error.get("type")
    return f"http_{status}", error.get("type")


async def _one(
    client: httpx.AsyncClient,
    *,
    base_url: str,
    model: str,
    case: dict,
    text: str,
    headers: dict[str, str],
) -> Outcome:
    started = time.perf_counter()
    try:
        response = await client.post(
            f"{base_url}/v1/chat/completions",
            json={"model": model, "messages": [{"role": "user", "content": text}]},
            headers=headers,
        )
        status = response.status_code
        body = response.json() if response.content else {}
    except httpx.HTTPError as exc:
        status, body = 0, {"error": {"type": type(exc).__name__}}
    latency = (time.perf_counter() - started) * 1000
    decision, block_category = _classify(status, body)
    return Outcome(
        sample_id=str(case.get("sample_id", "")),
        label=str(case.get("label", "")),
        category=str(case.get("category", "unknown")),
        status_code=status,
        decision=decision,
        block_category=block_category,
        latency_ms=round(latency, 3),
    )


async def drive_sustained(
    base_url: str,
    cases: list[dict],
    model: str,
    api_key: str | None,
    *,
    duration_s: float,
    rate: float,
    concurrency: int,
    fault_fraction: float,
    fault_marker: str | None,
    auth_failure_rate: float,
    seed: int,
) -> Report:
    """Hold a condition at a known rate for a known duration.

    Rate control, not maximum throughput: the ratio alerts (#5, #8) divide by a
    request count, so the denominator has to be a number this driver chose rather
    than whatever the machine happened to manage.

    Fault selection is a **seeded** PRNG and the corpus order is fixed, so the same
    invocation reproduces the same pattern of faulted requests on any machine.
    """
    marker = FAULT_MARKERS[fault_marker] if fault_marker else None
    usable = [c for c in cases if (c.get("text") or c.get("prompt"))]
    if not usable:
        raise SystemExit("corpus contains no usable text field")

    report = Report(corpus="", seed=seed)
    base_headers = {"content-type": "application/json"}
    if api_key:
        base_headers["authorization"] = f"Bearer {api_key}"

    limiter = asyncio.Semaphore(concurrency)
    started_at = time.perf_counter()
    total_slots = max(1, int(duration_s * rate))
    lock = asyncio.Lock()

    # The schedule is drawn UP FRONT, not inside the coroutines.
    #
    # Drawing per-slot from a shared PRNG made determinism an accident of timing:
    # at 5 req/s with 4 ms responses the slots happen to run in order, so the seed
    # appeared to reproduce — but a slow fault (an 800 ms backtrack, a stalled
    # database) overlaps them, the draw order changes, and both the pattern and
    # the count drift. Precomputing makes the guarantee structural instead of
    # incidental, which matters because #5's denominator depends on it.
    # EXACT counts, not Bernoulli draws. A per-slot coin flip is unbiased in
    # expectation and badly behaved in a single run: seed 20260822 gave 24 faults
    # in 300 slots against a requested 15 (+2.4 sd, the top 6% of seeds), handing
    # #5 a denominator 60% off target for no reason. The seed still decides WHICH
    # slots fault; it no longer decides how many.
    rng = random.Random(seed)  # noqa: S311 - reproducibility, not cryptography
    fault_schedule = [False] * total_slots
    if marker is not None and fault_fraction > 0:
        k = max(1, round(fault_fraction * total_slots))
        for i in rng.sample(range(total_slots), min(k, total_slots)):
            fault_schedule[i] = True
    auth_schedule = [False] * total_slots
    if auth_failure_rate > 0:
        k = max(1, round(auth_failure_rate * total_slots))
        for i in rng.sample(range(total_slots), min(k, total_slots)):
            auth_schedule[i] = True
    report.planned_faults = sum(fault_schedule)
    report.planned_auth_failures = sum(auth_schedule)

    async def slot(index: int) -> None:
        # Absolute schedule, not sleep-per-request: a per-request sleep drifts by
        # the request duration and the achieved rate silently sags under load.
        due = started_at + index / rate
        delay = due - time.perf_counter()
        if delay > 0:
            await asyncio.sleep(delay)

        case = usable[index % len(usable)]
        text = str(case.get("text") or case.get("prompt") or "")
        headers = dict(base_headers)

        is_faulted = fault_schedule[index]
        is_auth_failure = auth_schedule[index]

        if is_faulted:
            text = f"{text} {marker}"
        if is_auth_failure:
            headers["authorization"] = f"Bearer invalid-{index:06d}"

        async with limiter:
            outcome = await _one(
                client, base_url=base_url, model=model, case=case, text=text, headers=headers
            )
        async with lock:
            report.outcomes.append(outcome)
            report.sent += 1
            report.faulted += int(is_faulted)
            report.auth_failed += int(is_auth_failure)

    limits = httpx.Limits(
        max_connections=max(concurrency * 2, 16),
        max_keepalive_connections=max(concurrency * 2, 16),
    )
    async with httpx.AsyncClient(timeout=30.0, limits=limits) as client:
        await asyncio.gather(*(slot(i) for i in range(total_slots)))
    return report


def _render_sustained(report: Report, elapsed_s: float) -> None:
    print(f"corpus        : {report.corpus}")
    print(f"seed          : {report.seed}")
    print(f"elapsed       : {elapsed_s:.1f} s")
    print(f"sent          : {report.sent}")
    print(f"achieved rate : {report.sent / elapsed_s:.3f} req/s")
    print(
        f"faulted       : {report.faulted} of {report.planned_faults} planned  "
        f"(achieved fraction {report.achieved_fault_fraction():.4f})"
    )
    print(f"auth failures : {report.auth_failed} of {report.planned_auth_failures} planned")
    print("status codes  :")
    for status, n in sorted(report.status_counts().items()):
        print(f"  {status:>4} {n:6}")
    lat = sorted(o.latency_ms for o in report.outcomes)
    if lat:
        print(
            f"latency ms    : p50={lat[len(lat) // 2]:.1f} "
            f"p95={lat[int(len(lat) * 0.95)]:.1f} p99={lat[min(int(len(lat) * 0.99), len(lat) - 1)]:.1f}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--base-url", default="http://localhost:8005")
    parser.add_argument("--model", default="mock-model")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--api-key", default=None)

    sustained = parser.add_argument_group(
        "sustained mode (ADR-035 §5)",
        "Omit all of these and the runner behaves exactly as it did in Run 1.",
    )
    sustained.add_argument(
        "--duration-s", type=float, default=None, help="hold for this long, cycling the corpus"
    )
    sustained.add_argument("--rate", type=float, default=5.0, help="target requests/second")
    sustained.add_argument("--concurrency", type=int, default=8, help="max in-flight requests")
    sustained.add_argument(
        "--fault-fraction", type=float, default=0.0, help="share of requests carrying the marker"
    )
    sustained.add_argument("--fault-marker", choices=sorted(FAULT_MARKERS), default=None)
    sustained.add_argument(
        "--auth-failure-rate",
        type=float,
        default=0.0,
        help="share of requests sent with a deliberately invalid bearer token",
    )
    sustained.add_argument(
        "--seed", type=int, default=20260822, help="seeds fault selection; recorded in the report"
    )
    args = parser.parse_args(argv)

    corpus_path = args.corpus.resolve()
    cases = load_cases(corpus_path, args.limit)

    if args.duration_s is not None:
        for name, value in (("--rate", args.rate), ("--concurrency", args.concurrency)):
            if value <= 0:
                parser.error(f"{name} must be positive")
        for name, value in (
            ("--fault-fraction", args.fault_fraction),
            ("--auth-failure-rate", args.auth_failure_rate),
        ):
            if not 0.0 <= value <= 1.0:
                parser.error(f"{name} must be within [0, 1]")
        if args.fault_fraction > 0 and args.fault_marker is None:
            parser.error("--fault-fraction needs --fault-marker")
        started = time.perf_counter()
        report = asyncio.run(
            drive_sustained(
                args.base_url,
                cases,
                args.model,
                args.api_key,
                duration_s=args.duration_s,
                rate=args.rate,
                concurrency=args.concurrency,
                fault_fraction=args.fault_fraction,
                fault_marker=args.fault_marker,
                auth_failure_rate=args.auth_failure_rate,
                seed=args.seed,
            )
        )
        report.corpus = str(corpus_path.relative_to(REPO_ROOT))
        _render_sustained(report, time.perf_counter() - started)
        return 0

    report = drive(args.base_url, cases, args.model, args.api_key)
    report.corpus = str(corpus_path.relative_to(REPO_ROOT))

    counts = report.counts()
    total = len(report.outcomes)
    print(f"corpus   : {report.corpus}")
    print(f"requests : {total}")
    for decision, n in counts.most_common():
        print(f"  {decision:14} {n:5}  {n / total:7.4f}")
    print("\nby category:")
    for category, c in sorted(report.by_category().items()):
        n = sum(c.values())
        blocked = c.get("block", 0)
        print(f"  {category:16} n={n:5}  block={blocked:5} ({blocked / n:6.4f})  {dict(c)}")
    lat = sorted(o.latency_ms for o in report.outcomes)
    if lat:
        print(
            f"\nlatency ms: p50={lat[len(lat) // 2]:.1f} "
            f"p95={lat[int(len(lat) * 0.95)]:.1f} p99={lat[int(len(lat) * 0.99)]:.1f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
