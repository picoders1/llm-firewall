"""Controlled gateway performance benchmark (docs/15).

Answers one question honestly: **how much latency does the firewall add, and
where does it go?** Not "how fast is it" — that depends on a machine, a payload
and an upstream, and a number without those is a number about nothing.

## What makes the measurement valid

**The mock upstream** (ADR-009). A real provider's latency varies by seconds and
by token count — one to three orders of magnitude larger than the effect being
measured — so benchmarking overhead through a real model measures the model.

**Server-measured overhead, not a subtraction of distributions.** The gateway
already reports `x-firewall-gateway-ms` and `x-firewall-upstream-ms` per
response, so every request yields a *paired* observation of its own overhead and
its own upstream cost. §12 forbids subtracting two unrelated percentiles, and
this is why that is not necessary here: p99 overhead is the 99th percentile of
per-request overheads, not `p99(total) - p99(upstream)`.

**Interleaving.** Conditions rotate within each cell rather than running to
completion one after another, so thermal drift and background load land on all
conditions rather than on whichever ran last.

**Identical payloads.** Every condition sends bytes from the same deterministic
generator (`workloads.py`), because a size difference between conditions would
be indistinguishable from an overhead difference.

## What it deliberately does not do

No retries — a retry would hide a failure and inflate a percentile. No adaptive
load — the concurrency is what was asked for. No warm-up samples in the output.
And no claim beyond the conditions recorded in the manifest.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from eval.metrics.latency import latency_stats
from eval.runners import workloads

REPO = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO / "eval" / "results" / "performance"

# Conditions from docs/15's registered design, plus E for the deployment path
# that did not exist when that document was written (ADR-026, ADR-028).
CONDITION_HELP = {
    "A": "client -> mock upstream (gateway bypassed): the floor",
    "B": "client -> gateway with detectors disabled -> mock: proxy cost alone",
    "C": "client -> gateway with detectors enabled -> mock: the headline",
    "E": "client -> HTTPS edge -> gateway -> mock: full deployment path",
    "F": "client -> gateway with detectors enabled, audit OFF -> mock: C minus the database write",
}


@dataclass(slots=True)
class Sample:
    """One measured request. Written raw so every statistic can be recomputed."""

    condition: str
    workload: str
    size: str
    concurrency: int
    repeat: int
    latency_ms: float
    status: int
    ok: bool
    response_bytes: int
    # Server-measured, from response headers. `None` for condition A (no
    # gateway) and for any response the gateway did not annotate.
    gateway_ms: float | None = None
    upstream_ms: float | None = None
    error: str | None = None


@dataclass(slots=True)
class Cell:
    """One (condition, workload, size, concurrency, repeat) combination."""

    condition: str
    workload: str
    size: str
    concurrency: int
    repeat: int
    iterations: int
    warmup: int
    samples: list[Sample] = field(default_factory=list)


# --- Environment ---------------------------------------------------------------


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(  # noqa: S603 - fixed argv
            cmd, capture_output=True, text=True, timeout=20, check=False
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def machine_metadata() -> dict[str, Any]:
    """Everything needed to know whether two runs are comparable (§4).

    Recorded rather than assumed: docs/15 is explicit that results from
    different machines are not to be compared as if they were one run, and the
    only way to enforce that is to make the machine part of the artefact.
    """
    cpu = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass

    mem_kb = 0
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal"):
                mem_kb = int(line.split()[1])
                break
    except OSError:
        pass

    return {
        "os": platform.platform(),
        "cpu": cpu,
        "logical_cores": os.cpu_count(),
        "ram_gb": round(mem_kb / 1024 / 1024, 1) if mem_kb else None,
        "gpu": _run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"])
        or "none",
        "python": platform.python_version(),
        "docker": _run(["docker", "--version"]),
        "docker_compose": _run(["docker", "compose", "version", "--short"]),
        "git_commit": _run(["git", "-C", str(REPO), "rev-parse", "HEAD"]),
        "git_dirty": bool(_run(["git", "-C", str(REPO), "status", "--porcelain"])),
    }


async def gateway_metadata(base_url: str) -> dict[str, Any]:
    """Policy version and detector configuration, read from the instance itself.

    Asked of the running gateway rather than of the repository: the benchmark
    must record what was actually measured, and a checkout can differ from what
    is deployed.
    """
    out: dict[str, Any] = {}
    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=10.0, verify=False) as client:  # noqa: S501 - self-signed dev cert; this reads metadata, not traffic
            ready = await client.get("/ready")
            out["ready_status"] = ready.json().get("status")
            for check in ready.json().get("checks", []):
                if check["name"] == "policy_loaded":
                    out["policy_version"] = check.get("detail")
                if check["name"] == "detectors_warmed":
                    out["detectors"] = check.get("detail")
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        out["error"] = type(exc).__name__
    return out


# --- Execution ------------------------------------------------------------------


async def _one(
    client: httpx.AsyncClient, path: str, body: dict[str, Any], headers: dict[str, str]
) -> tuple[float, httpx.Response | None, str | None]:
    started = time.perf_counter()
    try:
        response = await client.post(path, json=body, headers=headers)
    except Exception as exc:
        return (time.perf_counter() - started) * 1000.0, None, type(exc).__name__
    return (time.perf_counter() - started) * 1000.0, response, None


async def _drive(
    client: httpx.AsyncClient,
    path: str,
    body: dict[str, Any],
    headers: dict[str, str],
    cell: Cell,
    *,
    count: int,
    collect: list[Sample] | None,
) -> None:
    """Issue `count` requests at the cell's concurrency.

    `collect=None` is the warm-up: those requests are issued and their timings
    are never constructed at all, which is stronger than recording and filtering
    them later — there is no path by which a warm-up sample can reach the output.

    A semaphore rather than batched `gather`: batching produces a sawtooth where
    every worker waits for the slowest of its batch, which shows up as tail
    latency the server never caused.
    """
    limiter = asyncio.Semaphore(cell.concurrency)
    expected = workloads.EXPECTED_STATUS[cell.workload]

    async def one() -> None:
        async with limiter:
            latency, response, error = await _one(client, path, body, headers)
            if collect is None:
                return
            if response is None:
                collect.append(
                    Sample(
                        condition=cell.condition,
                        workload=cell.workload,
                        size=cell.size,
                        concurrency=cell.concurrency,
                        repeat=cell.repeat,
                        latency_ms=latency,
                        status=0,
                        ok=False,
                        response_bytes=0,
                        error=error,
                    )
                )
                return
            gateway = response.headers.get("x-firewall-gateway-ms")
            upstream = response.headers.get("x-firewall-upstream-ms")
            collect.append(
                Sample(
                    condition=cell.condition,
                    workload=cell.workload,
                    size=cell.size,
                    concurrency=cell.concurrency,
                    repeat=cell.repeat,
                    latency_ms=latency,
                    status=response.status_code,
                    # "ok" means the gateway did what the workload expects. A
                    # blocked injection is a success, not a benchmark error (§17).
                    ok=response.status_code in expected,
                    response_bytes=len(response.content),
                    gateway_ms=float(gateway) if gateway else None,
                    upstream_ms=float(upstream) if upstream else None,
                )
            )

    await asyncio.gather(*(one() for _ in range(count)))


async def run_cell(cell: Cell, endpoint: str, path: str, headers: dict[str, str]) -> Cell:
    body = workloads.build(cell.workload, cell.size)
    limits = httpx.Limits(
        max_connections=max(cell.concurrency * 2, 16),
        max_keepalive_connections=max(cell.concurrency * 2, 16),
    )
    async with httpx.AsyncClient(
        base_url=endpoint,
        timeout=60.0,
        limits=limits,
        verify=False,  # noqa: S501 - the local edge serves a self-signed development certificate
    ) as client:
        # Warm-up: JIT, connection pool, page cache, detector state. Discarded by
        # passing `collect=None` — they never enter the sample set at all, which
        # is stronger than filtering them out later.
        await _drive(client, path, body, headers, cell, count=cell.warmup, collect=None)
        await _drive(client, path, body, headers, cell, count=cell.iterations, collect=cell.samples)
    return cell


# --- Reporting -------------------------------------------------------------------


def summarise(samples: list[Sample]) -> dict[str, Any]:
    """Client latency, server overhead and upstream cost, each as its own
    distribution over the SAME requests."""
    ok = [s for s in samples if s.ok]
    out: dict[str, Any] = {
        "n": len(samples),
        "n_ok": len(ok),
        "error_rate": round(1 - len(ok) / len(samples), 5) if samples else None,
        "statuses": {},
        "client_latency_ms": latency_stats([s.latency_ms for s in ok]).as_dict() if ok else None,
    }
    for sample in samples:
        key = str(sample.status) if sample.status else (sample.error or "transport_error")
        out["statuses"][key] = out["statuses"].get(key, 0) + 1

    gateway = [s.gateway_ms for s in ok if s.gateway_ms is not None]
    upstream = [s.upstream_ms for s in ok if s.upstream_ms is not None]
    if gateway:
        out["gateway_overhead_ms"] = latency_stats(gateway).as_dict()
    if upstream:
        out["upstream_ms"] = latency_stats(upstream).as_dict()
    if ok:
        out["response_bytes_median"] = sorted(s.response_bytes for s in ok)[len(ok) // 2]
    return out


def cell_key(cell: Cell) -> str:
    return f"{cell.condition}|{cell.workload}|{cell.size}|c{cell.concurrency}|r{cell.repeat}"


__all__ = [
    "CONDITION_HELP",
    "Cell",
    "Sample",
    "cell_key",
    "gateway_metadata",
    "machine_metadata",
    "run_cell",
    "summarise",
]


# --- CLI ---------------------------------------------------------------------------


def _plan(args: argparse.Namespace) -> list[Cell]:
    """Every cell to run, ordered so conditions INTERLEAVE.

    docs/15 requires interleaving rather than running each condition to
    completion: on a laptop, thermal drift over a long run would otherwise be
    indistinguishable from a difference between conditions, and it would always
    favour whichever ran first.
    """
    cells: list[Cell] = []
    for repeat in range(1, args.repeats + 1):
        for size in args.payload:
            for concurrency in args.concurrency:
                for condition in args.conditions:
                    workload = {"short": "W1", "medium": "W2", "long": "W3"}[size]
                    cells.append(
                        Cell(
                            condition=condition,
                            workload=workload,
                            size=size,
                            concurrency=concurrency,
                            repeat=repeat,
                            iterations=args.iterations,
                            warmup=args.warmup,
                        )
                    )
    return cells


def _endpoint(condition: str, args: argparse.Namespace) -> tuple[str, str, dict[str, str]]:
    """Where a condition sends its traffic, and with what credential."""
    headers = {"content-type": "application/json"}
    if condition == "A":
        return args.mock_url, "/v1/chat/completions", headers
    if condition == "B":
        return args.passthrough_url, "/v1/chat/completions", headers
    if condition == "C":
        return args.gateway_url, "/v1/chat/completions", headers
    if condition == "F":
        return args.noaudit_url, "/v1/chat/completions", headers
    if condition == "E":
        if args.caller_key:
            headers["authorization"] = f"Bearer {args.caller_key}"
        return args.edge_url, "/v1/chat/completions", headers
    raise ValueError(f"unknown condition {condition!r}")


async def _main(args: argparse.Namespace) -> int:
    run_id = f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}__{args.label}"
    out_dir = Path(args.out) / run_id
    if out_dir.exists():
        print(f"refusing to overwrite {out_dir}")
        return 1
    out_dir.mkdir(parents=True)

    cells = _plan(args)
    print(f"run {run_id}: {len(cells)} cells, {sum(c.iterations for c in cells)} measured requests")

    started = datetime.now(UTC)
    for index, cell in enumerate(cells, start=1):
        endpoint, path, headers = _endpoint(cell.condition, args)
        print(f"  [{index}/{len(cells)}] {cell_key(cell)} -> {endpoint}", flush=True)
        await run_cell(cell, endpoint, path, headers)
    finished = datetime.now(UTC)

    manifest = {
        "run_id": run_id,
        "label": args.label,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_s": round((finished - started).total_seconds(), 1),
        "protocol": "docs/15-performance-benchmarking.md",
        "conditions": {c: CONDITION_HELP[c] for c in args.conditions},
        "concurrency": args.concurrency,
        "payload_sizes": args.payload,
        "iterations_per_cell": args.iterations,
        "warmup_per_cell": args.warmup,
        "warmup_included_in_samples": False,
        "repeats": args.repeats,
        "upstream_latency_ms": args.upstream_latency_ms,
        "clock": "time.perf_counter (monotonic)",
        "connection_reuse": True,
        "retries": "none",
        "endpoints": {
            "mock": args.mock_url,
            "passthrough": args.passthrough_url,
            "gateway": args.gateway_url,
            "noaudit": args.noaudit_url,
            "edge": args.edge_url,
        },
        "workloads": {k: workloads.DESCRIPTIONS[k] for k in ("W1", "W2", "W3")},
        "payload_bytes": {
            size: workloads.payload_bytes(
                workloads.build({"short": "W1", "medium": "W2", "long": "W3"}[size], size)
            )
            for size in args.payload
        },
        "machine": machine_metadata(),
        "gateway": await gateway_metadata(args.gateway_url),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    with (out_dir / "raw_results.jsonl").open("w", encoding="utf-8") as handle:
        for cell in cells:
            for sample in cell.samples:
                handle.write(json.dumps(asdict(sample)) + "\n")

    summary = {cell_key(cell): summarise(cell.samples) for cell in cells}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"\nwrote {out_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--label", required=True, help="short slug for the run directory")
    parser.add_argument("--conditions", default="A,B,C", help=",".join(CONDITION_HELP))
    parser.add_argument("--concurrency", default="1,4,16")
    parser.add_argument("--payload", default="short,medium,long")
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument(
        "--upstream-latency-ms",
        type=int,
        default=0,
        help="recorded in the manifest; set MOCK_LATENCY_MS on the mock to match",
    )
    parser.add_argument("--mock-url", default="http://localhost:8081")
    parser.add_argument("--passthrough-url", default="http://localhost:8100")
    parser.add_argument("--gateway-url", default="http://localhost:8000")
    parser.add_argument("--noaudit-url", default="http://localhost:8101")
    parser.add_argument("--edge-url", default="https://localhost:8443")
    parser.add_argument("--caller-key", default=os.environ.get("BENCH_CALLER_KEY", ""))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)

    args.conditions = [c.strip().upper() for c in args.conditions.split(",") if c.strip()]
    args.concurrency = [int(c) for c in args.concurrency.split(",") if c.strip()]
    args.payload = [p.strip() for p in args.payload.split(",") if p.strip()]
    return asyncio.run(_main(args))


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main())
