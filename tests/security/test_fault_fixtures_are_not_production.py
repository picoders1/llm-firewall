"""The Run 3 fault fixtures, kept out of production by tests rather than by care.

ADR-035 registers a fault-injection policy whose entire purpose is to stall a
detector — a catastrophic-backtracking regex handed to `pii.regex` through the
`custom_patterns` seam. That is a legitimate validation fixture and an illegitimate
production policy, and the difference between the two is enforced here.

The failure this guards against is not exotic. `deploy/docker/Dockerfile` copies
`config/` wholesale, so the fixture would have shipped inside the production image
the moment it existed, leaving production one `FIREWALL_POLICY_FILE` away from
loading it. It is excluded from the build context instead, and the overlay
bind-mounts it at runtime — so the fixture is opt-in at the *mount*, which nothing
in a production manifest can supply, rather than at a setting, which anything can.

Three independent locks, asserted independently below:

  1. the file exists in no image layer;
  2. `compose.fault.yaml` is referenced by no production manifest and no CI job;
  3. no policy a production manifest can reach declares a non-empty
     `custom_patterns`.

Static by design, like `test_deployment_topology.py`: it runs in the fast suite
with no containers, so a manifest edit that quietly makes the fixture reachable
fails in seconds instead of in whatever review notices it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]

FAULT_COMPOSE = REPO / "compose.fault.yaml"
FAULT_POLICY = REPO / "config" / "policies" / "fault-injection.yaml"
DEFAULT_POLICY = REPO / "config" / "policies" / "default.yaml"
DOCKERIGNORE = REPO / ".dockerignore"

# Manifests and automation that must never pull in the fault overlay. The CI
# workflow is included because a job that composed it would run the fixture on
# every push, which is the same exposure as a production manifest with a slower
# blast radius.
PRODUCTION_MANIFESTS = (
    REPO / "compose.prod.yaml",
    REPO / "compose.prod-selftest.yaml",
    REPO / ".github" / "workflows" / "ci.yml",
)

# The development audit store. The fault stack must never mount it: `down -v`
# removes the volumes of the project it runs against, and an operator's trail is
# not something a validation fixture may delete.
DEVELOPMENT_VOLUME = "postgres-data"
FAULT_VOLUME = "firewall-fault-pgdata"

# The two fault markers (ADR-035 §3 and phase 0c). They drive different alerts by
# different mechanisms and must stay separable: (a) costs CPU and produces no
# error, (b) costs microseconds and produces a ValidationError.
LATENCY_MARKER = "FAULT_INJECTION_MARKER"
ERROR_MARKER = "FAULT_DETECTOR_ERROR"
ERROR_PATTERN = "FAULT-DETECTOR-ERROR-3f9a1c"

# `DetectionResult.score` is `Field(ge=0.0, le=1.0)`, and
# `RegexPiiDetector._resolve_rules` reads `confidence` with no bound. Anything
# outside this range turns every match into a fail-closed 503 (R-110).
CONFIDENCE_RANGE = (0.0, 1.0)


class _TagTolerantLoader(yaml.SafeLoader):
    """`SafeLoader` that survives Compose's `!override` and `!reset` tags.

    Those tags are Compose merge directives, not data. `safe_load` raises on an
    unknown tag, which would make this whole file unrunnable against the very
    manifest it exists to check.
    """


def _keep_value(loader: yaml.Loader, _suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return loader.construct_scalar(node)  # type: ignore[arg-type]


_TagTolerantLoader.add_multi_constructor("!", _keep_value)


def _load(path: Path) -> Any:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_TagTolerantLoader)  # noqa: S506


def _ignore_lines() -> list[str]:
    return [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _custom_patterns(policy: dict) -> list[tuple[str, Any]]:
    """Every `custom_patterns` entry anywhere in a policy, with its path."""
    found: list[tuple[str, Any]] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "custom_patterns" and value:
                    found.append((f"{path}.{key}", value))
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")

    walk(policy, "")
    return found


def _policy_files_reachable_from(path: Path) -> set[str]:
    """`FIREWALL_POLICY_FILE` values a manifest sets, however they are spelled."""
    text = path.read_text(encoding="utf-8")
    values: set[str] = set()
    for line in text.splitlines():
        if "FIREWALL_POLICY_FILE" not in line:
            continue
        _, _, rhs = line.partition("FIREWALL_POLICY_FILE")
        value = rhs.lstrip(" :=").strip().strip("\"'")
        if value:
            values.add(value)
    return values


# --- Lock 1: the fixture exists in no image layer ----------------------------


def test_the_fault_policy_is_excluded_from_the_build_context():
    """`COPY config ./config` is unfiltered. Without this line the fixture ships
    in the production image, and "production never mounts it" degrades to
    "production never sets one environment variable" — a much weaker claim than
    ADR-035 §3 registers."""
    assert "config/policies/fault-injection.yaml" in _ignore_lines(), (
        "the fault policy is not excluded from the Docker build context; it would "
        "be baked into the production image by `COPY config ./config`"
    )


def test_the_default_policy_is_not_excluded_by_the_same_line():
    """The exclusion must be surgical. A broader pattern would take the real
    policy out of the image and the gateway would fail to start — a failure this
    test turns into a fast, obvious one."""
    assert "config/policies" not in _ignore_lines()
    assert "config" not in _ignore_lines()


# --- Lock 2: no production manifest and no CI job composes the overlay -------


@pytest.mark.parametrize("manifest", PRODUCTION_MANIFESTS, ids=lambda p: p.name)
def test_no_production_manifest_references_the_fault_overlay(manifest: Path):
    assert manifest.exists(), manifest
    assert "compose.fault.yaml" not in manifest.read_text(encoding="utf-8"), (
        f"{manifest.name} references the fault overlay"
    )


@pytest.mark.parametrize("manifest", PRODUCTION_MANIFESTS, ids=lambda p: p.name)
def test_no_production_manifest_references_the_fault_policy(manifest: Path):
    """Belt and braces: the overlay is the supported route, but a manifest could
    point `FIREWALL_POLICY_FILE` straight at the file without naming the overlay."""
    assert "fault-injection.yaml" not in manifest.read_text(encoding="utf-8"), (
        f"{manifest.name} references the fault policy directly"
    )


# --- Lock 3: nothing production can reach declares a custom pattern ----------


def test_the_default_policy_declares_no_custom_patterns():
    """The production policy ships `custom_patterns: []` and must stay that way.
    This is the seam Fixture B uses, and `app/detectors/pii/regex.py` compiles
    whatever it finds there with only `re.error` caught — a valid but pathological
    pattern is accepted and run (R-108)."""
    assert _custom_patterns(_load(DEFAULT_POLICY)) == []


@pytest.mark.parametrize(
    "policy",
    sorted(p for p in (REPO / "config" / "policies").glob("*.yaml") if p.name != FAULT_POLICY.name),
    ids=lambda p: p.name,
)
def test_no_shipped_policy_other_than_the_fixture_declares_custom_patterns(policy: Path):
    """Every policy that is *not* the fixture, including any added later. A new
    policy file with a custom pattern fails here until someone justifies it."""
    assert _custom_patterns(_load(policy)) == [], policy.name


def test_the_fixture_is_the_only_policy_any_manifest_reaches_with_a_custom_pattern():
    """Bound to the manifests rather than to the directory: a policy could live
    anywhere. Every `FIREWALL_POLICY_FILE` set by anything other than the fault
    overlay must resolve to a policy with no custom patterns."""
    offenders: list[str] = []
    manifests = [*sorted(REPO.glob("compose*.yaml")), REPO / ".github/workflows/ci.yml"]
    for manifest in manifests:
        if manifest.name == FAULT_COMPOSE.name:
            continue
        for value in _policy_files_reachable_from(manifest):
            candidate = REPO / value.lstrip("/").removeprefix("app/")
            if not candidate.is_file():
                continue
            if _custom_patterns(_load(candidate)):
                offenders.append(f"{manifest.name} -> {value}")
    assert offenders == [], offenders


# --- The fixture validates the SHIPPED policy, not a nearby one --------------


def test_the_fixture_differs_from_the_default_policy_only_by_the_custom_pattern():
    """Run 3 must exercise the policy that ships. If the fixture drifts — a
    threshold nudged, a detector toggled — every alert it validates is validated
    against something nobody deploys, and the run is worthless without saying so."""
    default = _load(DEFAULT_POLICY)
    fault = _load(FAULT_POLICY)

    injected = fault["input"]["pii"]["options"].pop("custom_patterns")
    assert injected == [
        # (a) latency, for #16. In-range confidence: a match would be an ordinary
        #     detection, and it never matches anyway.
        {"name": LATENCY_MARKER, "pattern": "(x+x+)+y"},
        # (b) detector error, for #5 and #6 (ADR-035 phase 0c). The out-of-range
        #     confidence IS the fault.
        {"name": ERROR_MARKER, "pattern": ERROR_PATTERN, "confidence": 2.0},
    ], injected

    # Put back the empty list the default carries, then require exact equality.
    fault["input"]["pii"]["options"]["custom_patterns"] = []
    assert fault == default, "the fault policy differs from default.yaml by more than the marker"


def test_the_fixture_keeps_the_production_detector_configuration():
    """Stated separately from the equality above so the failure message names the
    thing that matters: 0.85/block on both heuristics, transformer disabled and
    warn-only, no provenance overlay."""
    fault = _load(FAULT_POLICY)
    assert fault["input"]["prompt_injection"]["threshold"] == 0.85
    assert fault["input"]["prompt_injection"]["action"] == "block"
    assert fault["input"]["jailbreak"]["threshold"] == 0.85
    assert fault["input"]["jailbreak"]["action"] == "block"
    assert fault["input"]["prompt_injection_ml"]["enabled"] is False
    assert fault["input"]["prompt_injection_ml"]["action"] == "warn"
    assert "by_trust" not in yaml.dump(fault)


# --- Fixture C: the disposable database is genuinely disposable --------------


def test_the_fault_stack_is_a_separate_compose_project():
    """`down -v` removes the volumes of the project it is invoked against. Sharing
    the development project name would make the documented teardown delete the
    development audit store."""
    fault = _load(FAULT_COMPOSE)
    assert fault["name"] == "llm-firewall-fault"
    assert _load(REPO / "compose.yaml")["name"] == "llm-firewall"


def test_the_fault_database_uses_its_own_named_volume():
    fault = _load(FAULT_COMPOSE)
    mounts = fault["services"]["postgres"]["volumes"]
    assert mounts == [f"{FAULT_VOLUME}:/var/lib/postgresql/data"], mounts
    assert fault["volumes"][FAULT_VOLUME]["name"] == FAULT_VOLUME


def test_the_fault_stack_mounts_and_declares_no_development_volume():
    """Asserted against what Compose would MOUNT, not against the file's bytes.

    The first version of this test grepped the raw text and failed on the comment
    that explains why the development volume must not be used — proving only that
    a manifest can be correct while a test reads it wrongly.
    """
    fault = _load(FAULT_COMPOSE)
    for name, service in fault.get("services", {}).items():
        for mount in service.get("volumes", []) or []:
            source = str(mount).split(":", 1)[0]
            assert source != DEVELOPMENT_VOLUME, f"{name} mounts the development volume"
    assert DEVELOPMENT_VOLUME not in (fault.get("volumes") or {})


def test_the_fault_database_has_a_distinct_name():
    """`scripts/seed_backdated_audit.py` refuses to write to anything but
    `firewall_fault`. Host, port and role are identical to development, so the
    database name is the only thing that can carry that distinction."""
    fault = _load(FAULT_COMPOSE)
    assert fault["services"]["postgres"]["environment"]["POSTGRES_DB"] == "firewall_fault"
    url = fault["services"]["firewall-api"]["environment"]["FIREWALL_DATABASE_URL"]
    assert url.endswith("/firewall_fault"), url


def test_the_fault_policy_arrives_as_a_runtime_mount():
    """The mount is the opt-in. Since the file is in no image layer, this is the
    only way any container can see it."""
    fault = _load(FAULT_COMPOSE)
    mounts = fault["services"]["firewall-api"]["volumes"]
    assert any("fault-injection.yaml" in str(m) and str(m).endswith(":ro") for m in mounts), mounts


def test_the_fault_overlay_commits_no_caller_credential():
    """ADR-024: the gateway stores digests, never raw keys. A committed pair would
    put a usable credential in git to save one command."""
    text = FAULT_COMPOSE.read_text(encoding="utf-8")
    assert "FIREWALL_CALLER_API_KEYS: ${FAULT_CALLER_API_KEYS:-}" in text
    assert "FIREWALL_CALLER_AUTH_MODE: ${FAULT_CALLER_AUTH_MODE:-disabled}" in text


# --- Phase 0c: the detector-error seam must not be reachable from production ---


def _confidences(policy: dict) -> list[tuple[str, float]]:
    """Every `custom_patterns` confidence in a policy, with the pattern name."""
    out: list[tuple[str, float]] = []
    for path, entries in _custom_patterns(policy):
        for entry in entries:
            if isinstance(entry, dict) and "confidence" in entry:
                out.append((f"{path}:{entry.get('name')}", float(entry["confidence"])))
    return out


@pytest.mark.parametrize(
    "policy",
    sorted(p for p in (REPO / "config" / "policies").glob("*.yaml") if p.name != FAULT_POLICY.name),
    ids=lambda p: p.name,
)
def test_no_shipped_policy_declares_an_out_of_range_confidence(policy: Path):
    """The specific value the phase 0c seam depends on, checked directly.

    `custom_patterns` being empty already implies this, but the two facts are
    worth separating: a future policy could gain a legitimate custom pattern and
    still must never gain an out-of-range confidence, because that is not a
    detection setting — it is a switch that 503s every matching request (R-110).
    """
    low, high = CONFIDENCE_RANGE
    offenders = [(k, v) for k, v in _confidences(_load(policy)) if not low <= v <= high]
    assert offenders == [], offenders


def test_the_out_of_range_confidence_exists_only_in_the_fault_fixture():
    """Bound to the manifests, not to the directory: a policy could live anywhere.
    Nothing a production manifest can reach may carry the seam."""
    low, high = CONFIDENCE_RANGE
    offenders: list[str] = []
    manifests = [*sorted(REPO.glob("compose*.yaml")), REPO / ".github" / "workflows" / "ci.yml"]
    for manifest in manifests:
        if manifest.name == FAULT_COMPOSE.name:
            continue
        for value in _policy_files_reachable_from(manifest):
            candidate = REPO / value.lstrip("/").removeprefix("app/")
            if not candidate.is_file():
                continue
            bad = [k for k, v in _confidences(_load(candidate)) if not low <= v <= high]
            if bad:
                offenders.append(f"{manifest.name} -> {value}: {bad}")
    assert offenders == [], offenders


def test_the_fault_fixture_declares_exactly_the_two_registered_markers():
    """Two markers, two mechanisms, no third. A marker nobody registered is a
    fault nobody predicted."""
    patterns = _load(FAULT_POLICY)["input"]["pii"]["options"]["custom_patterns"]
    assert [entry["name"] for entry in patterns] == [LATENCY_MARKER, ERROR_MARKER]


def test_the_error_marker_is_a_literal():
    """A metacharacter would risk a second accidental backtracking fault, which is
    the CPU-stall property (R-108) this seam was chosen to avoid."""
    patterns = {
        e["name"]: e for e in _load(FAULT_POLICY)["input"]["pii"]["options"]["custom_patterns"]
    }
    assert not set(str(patterns[ERROR_MARKER]["pattern"])) & set(".^$*+?{}[]\\|()")


def test_the_two_markers_do_not_match_each_others_payloads():
    """Separability at the pattern level, so #16's driver cannot silently feed
    #5's numerator or vice versa."""
    import re

    patterns = {
        e["name"]: str(e["pattern"])
        for e in _load(FAULT_POLICY)["input"]["pii"]["options"]["custom_patterns"]
    }
    latency_payload = "x" * 24 + "z"
    assert re.search(patterns[ERROR_MARKER], latency_payload, re.IGNORECASE) is None
    assert re.search(patterns[LATENCY_MARKER], ERROR_PATTERN, re.IGNORECASE) is None


def test_only_the_error_marker_carries_the_out_of_range_confidence():
    """The latency marker must stay a latency fault. An out-of-range confidence
    there would quietly turn #16's driver into an error generator."""
    low, high = CONFIDENCE_RANGE
    bad = [k for k, v in _confidences(_load(FAULT_POLICY)) if not low <= v <= high]
    assert [k.rsplit(":", 1)[-1] for k in bad] == [ERROR_MARKER], bad
    assert all(k.endswith(f"input.pii.options.custom_patterns:{ERROR_MARKER}") for k in bad), bad


def test_the_fault_overlay_introduces_no_second_upstream_fault_mechanism():
    """ADR-035: the mock's existing content triggers stay the only upstream fault
    path. A second mechanism would need its own review and its own guard."""
    text = FAULT_COMPOSE.read_text(encoding="utf-8")
    assert "MOCK_LATENCY_MS" not in text
    assert "MOCK_SLOW_S" not in text
