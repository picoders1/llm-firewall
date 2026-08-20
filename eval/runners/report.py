"""Turn benchmark runs into the artefacts a reader can check (docs/15, §26).

Derives everything from the committed `raw_results.jsonl`, never from a
remembered number, so every statistic in the report can be recomputed by anyone
who has the run directory.

## The two overhead definitions, and why both are reported

docs/15 defines `gateway_overhead = total_client_latency − upstream_latency`.
The gateway also reports its own in-handler span as `x-firewall-gateway-ms`.
These are **not** the same quantity and the difference is itself a result:

* the in-handler span starts after ASGI, middleware and body read, and stops
  before the response is serialised and written;
* the client-side definition includes all of that, plus the extra network hop
  the gateway adds by existing.

Reporting only the smaller one would understate what a caller actually waits
for. Reporting only the larger one would attribute the harness's own loopback
cost to the gateway. Both are computed **per request** from paired samples —
§12 forbids subtracting two unrelated percentiles, and pairing is what makes
that unnecessary.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from eval.metrics.latency import latency_stats

REPO = Path(__file__).resolve().parents[2]


def load_samples(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "raw_results.jsonl"
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def paired_overhead(samples: list[dict[str, Any]]) -> list[float]:
    """docs/15's definition, computed per request.

    Only samples that carry a server-measured upstream time can be paired; a
    condition with no gateway (A) has none, and a blocked request never called
    the upstream so its client latency IS its overhead.
    """
    out: list[float] = []
    for sample in samples:
        if not sample["ok"]:
            continue
        upstream = sample.get("upstream_ms")
        if upstream is None:
            continue
        out.append(max(0.0, sample["latency_ms"] - upstream))
    return out


def group(samples: list[dict[str, Any]]) -> dict[tuple[str, str, int], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        grouped[(sample["condition"], sample["size"], sample["concurrency"])].append(sample)
    return grouped


def latency_table(run_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for (condition, size, concurrency), samples in sorted(group(load_samples(run_dir)).items()):
        ok = [s for s in samples if s["ok"]]
        if not ok:
            continue
        client = latency_stats([s["latency_ms"] for s in ok])
        row: dict[str, Any] = {
            "condition": condition,
            "payload": size,
            "concurrency": concurrency,
            "n": len(samples),
            "n_ok": len(ok),
            "client_p50_ms": round(client.p50_ms, 3),
            "client_p95_ms": round(client.p95_ms, 3),
            "client_p99_ms": round(client.p99_ms, 3),
            "client_mean_ms": round(client.mean_ms, 3),
            "client_stdev_ms": round(client.stdev_ms, 3),
            "throughput_per_s": round(client.throughput_per_s, 1),
            "percentiles_reliable": client.percentiles_reliable,
        }
        server = [s["gateway_ms"] for s in ok if s.get("gateway_ms") is not None]
        if server:
            stats = latency_stats(server)
            row |= {
                "server_overhead_p50_ms": round(stats.p50_ms, 3),
                "server_overhead_p95_ms": round(stats.p95_ms, 3),
                "server_overhead_p99_ms": round(stats.p99_ms, 3),
            }
        paired = paired_overhead(ok)
        if paired:
            stats = latency_stats(paired)
            row |= {
                "paired_overhead_p50_ms": round(stats.p50_ms, 3),
                "paired_overhead_p95_ms": round(stats.p95_ms, 3),
                "paired_overhead_p99_ms": round(stats.p99_ms, 3),
            }
        rows.append(row)
    return rows


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    if not rows:
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_dir")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    rows = latency_table(run_dir)
    write_csv(rows, run_dir / "latency_by_configuration.csv")

    throughput = [
        {
            "condition": r["condition"],
            "payload": r["payload"],
            "concurrency": r["concurrency"],
            "throughput_per_s": r["throughput_per_s"],
            "n": r["n"],
            "client_p50_ms": r["client_p50_ms"],
        }
        for r in rows
    ]
    write_csv(throughput, run_dir / "throughput_by_concurrency.csv")
    print(f"wrote {run_dir}/latency_by_configuration.csv and throughput_by_concurrency.csv")
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main())
