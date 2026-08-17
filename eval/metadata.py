"""Reproducibility metadata.

A report that cannot name the commit, the dataset checksum and the machine is not
evidence. The runner refuses to write a report without this block
(docs/13-evaluation-strategy.md, docs/15-performance-benchmarking.md).
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str]) -> str | None:
    executable = shutil.which(command[0])
    if executable is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603
            [executable, *command[1:]],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=REPO_ROOT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None if result.returncode == 0 else None


def git_state() -> dict[str, Any]:
    """Commit and cleanliness.

    `dirty` matters as much as the hash: a result produced from an uncommitted
    working tree cannot be reconstructed from the commit alone, and the report
    should say so rather than imply reproducibility it does not have.
    """
    commit = _run(["git", "rev-parse", "HEAD"])
    status = _run(["git", "status", "--porcelain"])
    return {
        "commit": commit,
        "dirty": bool(status) if status is not None else None,
        "branch": _run(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
    }


def gpu_info() -> dict[str, Any]:
    output = _run(
        ["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"]
    )
    if not output:
        return {"present": False}
    name, memory, driver = (part.strip() for part in output.split(",", 2))
    return {"present": True, "name": name, "memory": memory, "driver": driver}


def cpu_model() -> str | None:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def total_memory_gb() -> float | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / 1024 / 1024, 1)
    except (OSError, ValueError):
        pass
    return None


def lockfile_hash() -> str | None:
    """Fingerprint of the resolved dependency set."""
    lock = REPO_ROOT / "uv.lock"
    if not lock.is_file():
        return None
    return f"sha256:{hashlib.sha256(lock.read_bytes()).hexdigest()[:16]}"


def library_versions() -> dict[str, str]:
    from importlib import metadata

    versions: dict[str, str] = {}
    for package in ("pydantic", "torch", "transformers", "onnxruntime", "presidio-analyzer"):
        try:
            versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            continue
    return versions


def machine_metadata() -> dict[str, Any]:
    """Everything needed to interpret a latency number.

    The reference machine is laptop-class. Figures from it characterise
    **relative** cost; they are not production capacity, and the report says so.
    """
    return {
        "os": f"{platform.system()} {platform.release()}",
        "platform": platform.platform(),
        "cpu_model": cpu_model(),
        "cpu_count_logical": __import__("os").cpu_count(),
        "memory_total_gb": total_memory_gb(),
        "gpu": gpu_info(),
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "libraries": library_versions(),
        "machine_class": "laptop — relative overhead only, not production capacity",
    }


def config_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()[:16]}"


def run_metadata(
    *,
    run_id: str,
    detector: str,
    detector_config: dict[str, Any],
    dataset_name: str,
    dataset_checksum: str,
    split: str,
    sample_count: int,
    seed: int,
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "detector": detector,
        "detector_config": detector_config,
        "config_hash": config_hash(detector_config),
        "dataset": {
            "name": dataset_name,
            "checksum": dataset_checksum,
            "split": split,
            "sample_count": sample_count,
        },
        "seed": seed,
        "git": git_state(),
        "lockfile_hash": lockfile_hash(),
        "machine": machine_metadata(),
    }
