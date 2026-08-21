"""Drive corpus traffic through the RUNNING gateway and record what it decided.

Phase 20 (ADR-034). The distinction from every other runner in this directory is
that this one exercises the **deployment**: normalisation, the detector pipeline,
the policy engine, the audit write and the upstream call, over a socket, exactly
as a caller would. `scripts/evaluate_*.py` score detectors offline and cannot see
any of that.

It is deliberately not a load generator — `eval/runners/benchmark.py` already
does latency and throughput, and duplicating it was refused in Phase 15.

**Hold-out corpora are not readable from here.** Phase 20 measures a deployment,
not a detector's generalisation, and spending a scoring budget on it would burn
irreplaceable evidence to answer a question it was not reserved for (ADR-034).
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN = "holdout"


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

    def counts(self) -> Counter[str]:
        return Counter(o.decision for o in self.outcomes)

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--base-url", default="http://localhost:8005")
    parser.add_argument("--model", default="mock-model")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args(argv)

    corpus_path = args.corpus.resolve()
    cases = load_cases(corpus_path, args.limit)
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
