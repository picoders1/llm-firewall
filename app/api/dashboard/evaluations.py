"""Read-only view over committed evaluation artefacts.

**No evaluation table is created.** `docs/11-data-model.md` reserves one, and
`app/database/models.py` says plainly why it does not exist: "a table nobody
writes is schema nobody can justify". Evaluation results are produced by the
offline harness and committed under `eval/results/`, so that directory *is* the
source of truth. Copying it into PostgreSQL would create a second copy that can
disagree with the first, and the dashboard would then have to pick one.

Only runs with a **valid final artefact** are reported as finalised (§15): a
`result.json` carrying both `metadata.finished_at` and a classification block. A
directory without one is counted and reported as skipped, never silently dropped —
an evaluation that vanished from the list is indistinguishable from one that never
ran.

`superseded` is derived, not guessed: when several complete runs share a detector,
dataset and split, the newest is current and the older ones are superseded. That
is the only relation the artefacts actually support.

Nothing here reads `predictions.csv`. Per-sample rows are not dashboard data, and
not reading them is cheaper than filtering them.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from app.api.dashboard.schemas import EvaluationDetail, EvaluationSummary

REPO_ROOT = Path(__file__).resolve().parents[3]
RESULTS_ROOT = REPO_ROOT / "eval" / "results"
# A directory listing is not an unbounded query, but it is not free either.
MAX_RUNS = 500


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _load(path: Path) -> dict[str, Any] | None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


# Machine metadata is required to interpret a latency figure (docs/13), so it is
# exposed — but only the parts that do that job. The exact kernel and platform
# strings identify the host without helping anyone read a percentile, so they are
# dropped rather than forwarded (§13: no infrastructure detail).
_MACHINE_FIELDS = ("cpu_model", "cpu_count_logical", "memory_total_gb", "gpu", "python", "torch")


def _safe_machine(machine: dict[str, Any]) -> dict[str, Any]:
    safe = {key: machine[key] for key in _MACHINE_FIELDS if key in machine}
    system = machine.get("os")
    if isinstance(system, str) and system:
        # "Linux 7.0.0-28-generic" -> "Linux"
        safe["os"] = system.split()[0]
    return safe


def _summarise(run_dir: Path, payload: dict[str, Any]) -> EvaluationSummary | None:
    metadata = payload.get("metadata") or {}
    metrics = payload.get("metrics") or {}
    classification = metrics.get("classification") or {}
    if not metadata.get("finished_at") or not classification:
        return None
    dataset = metadata.get("dataset") or {}
    config = metadata.get("detector_config") or {}
    return EvaluationSummary(
        run_id=str(metadata.get("run_id") or run_dir.name),
        status="complete",
        detector=metadata.get("detector"),
        dataset=dataset.get("name"),
        dataset_version=dataset.get("split"),
        dataset_sha256=dataset.get("checksum"),
        model_version=config.get("implementation"),
        threshold=metrics.get("threshold"),
        precision=classification.get("precision"),
        recall=classification.get("recall"),
        f1=classification.get("f1"),
        fpr=classification.get("fpr"),
        fnr=classification.get("fnr"),
        sample_count=classification.get("n") or dataset.get("sample_count"),
        created_at=_parse_time(metadata.get("finished_at")),
    )


def _discover() -> tuple[list[tuple[Path, dict[str, Any], EvaluationSummary]], int]:
    found: list[tuple[Path, dict[str, Any], EvaluationSummary]] = []
    skipped = 0
    if not RESULTS_ROOT.is_dir():
        return found, skipped
    for run_dir in sorted(RESULTS_ROOT.iterdir())[:MAX_RUNS]:
        if not run_dir.is_dir():
            continue
        payload = _load(run_dir / "result.json")
        summary = _summarise(run_dir, payload) if payload else None
        if summary is None:
            skipped += 1
            continue
        found.append((run_dir, payload or {}, summary))
    return found, skipped


def _mark_superseded(items: list[EvaluationSummary]) -> list[EvaluationSummary]:
    """Newest complete run per (detector, dataset, split) stays current."""
    newest: dict[tuple[str | None, str | None, str | None], datetime] = {}
    for item in items:
        key = (item.detector, item.dataset, item.dataset_version)
        stamp = item.created_at
        if stamp is not None and (key not in newest or stamp > newest[key]):
            newest[key] = stamp
    out: list[EvaluationSummary] = []
    for item in items:
        key = (item.detector, item.dataset, item.dataset_version)
        superseded = item.created_at is not None and key in newest and item.created_at < newest[key]
        out.append(item.model_copy(update={"status": "superseded"}) if superseded else item)
    return out


def list_evaluations() -> tuple[list[EvaluationSummary], int]:
    discovered, skipped = _discover()
    items = _mark_superseded([summary for _, _, summary in discovered])
    items.sort(key=lambda i: i.created_at or datetime.min.replace(tzinfo=None), reverse=True)
    return items, skipped


def get_evaluation(run_id: str) -> EvaluationDetail | None:
    discovered, _ = _discover()
    marked = {s.run_id: s for s in _mark_superseded([s for _, _, s in discovered])}
    for run_dir, payload, summary in discovered:
        if summary.run_id != run_id:
            continue
        metadata = payload.get("metadata") or {}
        metrics = payload.get("metrics") or {}
        classification = metrics.get("classification") or {}
        intervals = {
            key: value
            for key, value in classification.items()
            if key.endswith("_ci95") and isinstance(value, list)
        }
        per_category = metrics.get("per_category") or metrics.get("by_category") or {}
        machine = _safe_machine(metadata.get("machine") or {})
        return EvaluationDetail(
            **marked[run_id].model_dump(),
            latency=metrics.get("latency") if isinstance(metrics.get("latency"), dict) else None,
            category_metrics=per_category if isinstance(per_category, dict) else {},
            confidence_intervals=intervals,
            benchmark_metadata={
                "machine": machine,
                "git": metadata.get("git"),
                "seed": metadata.get("seed"),
                "config_hash": metadata.get("config_hash"),
                "lockfile_hash": metadata.get("lockfile_hash"),
                "warnings": payload.get("warnings") or [],
                "disclaimer": payload.get("disclaimer"),
            },
            # Repository-relative, so no filesystem layout is disclosed.
            artefact_path=str(run_dir.relative_to(REPO_ROOT)),
        )
    return None
