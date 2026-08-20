"""What may enter the build context, bound to what the code actually opens.

The image is the deployed artefact. Anything in it that nothing reads is either
bloat or disclosure, and the failure mode is silent: nobody inspects a layer that
builds successfully. These tests need no Docker — they compare the ignore file
against the one filename the application reads at runtime.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
EVALUATIONS = REPO_ROOT / "app" / "api" / "dashboard" / "evaluations.py"


def ignore_lines() -> list[str]:
    return [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def test_evaluation_artefacts_are_an_allow_list_not_an_exclude_list():
    """An exclude-list fails open on every artefact type invented after it was
    written. `predictions*`/`*.csv`/`*.svg` did exactly that when Phase 15 started
    writing `raw_results.jsonl` (ADR-032)."""
    lines = ignore_lines()
    assert "eval" in lines, "the eval tree must be excluded wholesale"
    reincludes = [line for line in lines if line.startswith("!eval")]
    assert reincludes == ["!eval/results/*/result.json"], reincludes


def test_the_allow_list_matches_the_only_filename_the_dashboard_opens():
    """Bound in both directions: if the dashboard learns to read a second file,
    this fails until the ignore file is updated to ship it."""
    source = EVALUATIONS.read_text(encoding="utf-8")
    opened = set(re.findall(r'run_dir / "([^"]+)"', source))
    assert opened == {"result.json"}, opened


@pytest.mark.parametrize(
    "path",
    (
        ".env",
        "deploy/certs",
        "deploy/secrets",
        "*.pem",
        "*.key",
        ".git",
        "tests",
        "artifacts",
        "eval/datasets",
    ),
)
def test_material_that_must_never_reach_a_layer_is_excluded(path: str):
    """Certificates and keys are the sharpest of these: baked into a layer they
    survive every `docker rmi` of the running container and are readable by
    anyone who can pull the image (ADR-026)."""
    lines = ignore_lines()
    # Excluded outright, or covered by an excluded ancestor: `eval` alone keeps
    # `eval/datasets` out, and requiring a redundant second line would be
    # asserting the spelling rather than the property.
    ancestors = {path}
    parts = path.split("/")
    ancestors |= {"/".join(parts[:n]) for n in range(1, len(parts))}
    assert ancestors & set(lines), f"{path} is not excluded by any line in .dockerignore"
