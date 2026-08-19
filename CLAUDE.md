# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
uv sync --all-groups                          # install (uv + PEP 621; Poetry is broken here)
uv run pytest -m "unit or api or security"    # fast suite, no containers
uv run pytest -m evaluation                   # dataset/experiment guards (no GPU, no model loads)
uv run pytest -m integration                  # needs PostgreSQL + mock upstream via compose
uv run pytest tests/unit/test_policy_engine.py::test_name   # single test
uv run ruff check . && uv run ruff format --check .
uv run mypy app                               # strict, app/ only
uv lock --check                               # CI fails if the lock is stale
```

Containers and DB:

```bash
docker compose up -d --build                  # gateway :8000, mock upstream :8081, postgres
uv run alembic upgrade head
curl localhost:8081/__stats                   # mock upstream call counter — proves a BLOCK never forwarded
```

PostgreSQL is published on host port **5434** (5432/5433 are occupied on the reference machine).
`.env.example` defaults work with no credentials and no network egress.

## Architecture

Request path: middleware → `api/v1/chat.py` → `core/normalize.py` → `detectors/pipeline.py`
(concurrent, each wrapped in `GuardedDetector`) → `policy/engine.py` → `gateway/upstream.py` →
output inspection → audit.

Six constraints do most of the work. **All six are enforced by tests, not convention** — the
first four by `tests/unit/test_layer_boundaries.py`, which parses the AST so a violation is
caught even if the module is never imported, and the last two by
`tests/security/test_operator_auth.py` and `tests/security/test_caller_auth.py`, which attack
the boundaries rather than describing them.

- **Detectors detect; the policy engine decides.** `app/detectors/` cannot import `app/policy`,
  and `Action` is not importable inside detectors. This makes the whole security decision surface
  a pure function `(results, config, direction, provenance) -> PolicyDecision`, exhaustively
  testable as a truth table with no models loaded.
- **Fail closed, loudly.** A detector that raises or times out blocks by default with a distinct
  `503 detector_failure`. Per-detector override exists; a fail-open detector is named in a startup
  warning.
- **Normalisation preserves offsets.** `core/normalize.py` carries raw text, normalised text and an
  offset map, so redaction spans computed on normalised text map back to the raw body (ADR-010).
- **Provenance may only tighten.** `core/provenance.py` derives trust from role; a trust claim is
  never read from the wire (`trust_inline_claims=False`). `config/policy.py` rejects any `by_trust`
  overlay that loosens a decision, at load time.
- **Operator identity is derived, never received.** `app/middleware/auth.py` assigns an access
  class by path — and unknown paths default to **operator-only**, so a new route is protected
  before anyone classifies it. No identity header is read until the socket's peer falls inside
  `FIREWALL_TRUSTED_PROXIES`; `X-Forwarded-For` is never consulted, because it is
  client-supplied. Production refuses to start with an unauthenticated console, with a
  `0.0.0.0/0` trusted range, or with no trusted range at all (ADR-023). The console remains
  read-only: non-`GET` on the operator surface is refused at the boundary, so a mutating
  endpoint cannot inherit read-only authentication without an edit there.
  `/v1/**` is outside this boundary and covered by the separate one below.

- **Callers are a second, separate boundary.** `app/middleware/caller_auth.py` guards `/v1/**`
  with a service API key on `Authorization: Bearer`, compared against SHA-256 digests in
  `FIREWALL_CALLER_API_KEYS` — **the raw key is never stored on the gateway**, and the
  comparison loop does not short-circuit on the first match. It runs in middleware so a
  refusal costs no detector inference (~95 ms) and never reaches the upstream; every negative
  test asserts `upstream.call_count == 0`, because a 401 alone would not prove it. Operator and
  caller principals are **different types** so one cannot be substituted for the other. A
  client header can never become the upstream credential: `HttpUpstreamClient` binds
  `authorization` at construction and `chat_completions(self, payload)` has nowhere to put a
  header — a test asserts that signature (ADR-024).

The operator boundary is off outside production (`console_auth_mode` derives to `disabled`),
so `docker compose up` and the whole test suite behave exactly as before; tests that need it
use the `enforcing_client` fixture, and `compose.console-auth.yaml` adds an nginx proxy for
manual work. The caller boundary derives the same way; tests that need it use `caller_client`,
and `scripts/generate_caller_key.py` mints a credential for manual work.

Configuration is two deliberately separate systems (ADR-011): **settings** from `FIREWALL_*` env
vars (secrets, `SecretStr`), and **policy** from `config/policies/default.yaml` (thresholds,
actions, failure modes). Policy YAML structurally rejects any key matching `*_key`, `*secret*`,
`*token*`, `*password*`, so a credential cannot be committed that way. Invalid policy prevents
startup and is never silently repaired.

## Evaluation and experiment discipline

This is the unusual part of the repo and the easiest thing to break. `eval/` and `scripts/` hold a
pre-registration regime, not a scratch area.

- **No fabricated metrics, ever.** Every number in documentation must come from a committed report
  carrying its dataset checksum and machine metadata. `docs/22-evidence-and-claims.md` lists each
  claim alongside the artefact required before it may be made, plus claims that are explicitly
  refused. If a figure cannot be traced to an artefact, do not write it.
- **ADRs are pre-registered protocols.** `docs/adr/ADR-014` onward fix hypotheses, success criteria
  (with denominators, CI method and *direction*), and failure modes *before* execution. Criteria are
  never retuned after seeing results, and a registered failure mode must not later be presented as a
  discovery.
- **Frozen corpora are versioned, never edited.** `eval/datasets/holdout/**` and
  `eval/datasets/finetune/**` have hashes pinned in selection locks and tests. Editing one destroys
  the record of a completed experiment. Extend by creating a new version that reproduces the split
  rule byte-for-byte — `int(sha256(normalised_key(text).encode()).hexdigest()[:8], 16) % 100`, dev
  if `< 20`. Both the `[:8]` slice and the boundary matter: using the full digest, or 21, silently
  moves samples between splits and leaks a prior experiment's training data into the new dev split.
- **Hold-outs have a scoring budget.** Each corpus records how many times it has been scored;
  additional scorings must be declared in an ADR in advance. Selection and threshold calibration use
  **dev only**, enforced at the library boundary: `eval/schema.py:require_tunable` raises on a
  frozen split, and every `eval/metrics/calibration.py` entry point calls it.
- **Model weights never enter the app tree.** Checkpoints live in `artifacts/` (gitignored), as do
  `eval/datasets/raw/` (third-party data is downloaded, never committed —
  `eval/datasets/registry.yaml` records licence, provenance and contamination risk).
- **Production is frozen unless an ADR says otherwise**: registry is exactly
  `injection.heuristic`, `jailbreak.heuristic`, `pii.regex`, `output.stub`; heuristic threshold
  `0.85`; provenance overlays off; blocking disabled. Fine-tuned models are warn-only and not
  integrated.

Statistical conventions: Wilson intervals (`eval/metrics/classification.py`) for single rates, exact
McNemar (`scripts/evaluate_provenance.py:mcnemar_exact`) for paired same-corpus comparisons. Reuse
these rather than reimplementing.

A recurring bug worth knowing: computing "smallest k satisfying a bound" by iterating **downward**
returns `n` instead of the first qualifying value. It has appeared three times. Iterate upward and
return the first hit.

## Documentation

`docs/` is the source of truth; code contradicting it is a bug in one of the two. Start at
`docs/README.md`. `docs/19-implementation-roadmap.md` and the ADRs carry current state.

**The status banners in `README.md` and `docs/README.md` are stale** — they read "Phase 0 /
no evaluation has been run", but ADR-014 through ADR-020 record executed experiments with real
measured results. Trust `docs/19-implementation-roadmap.md` and the ADRs over those banners.

`docs/21-open-decisions.md` (OD-*) tracks what is genuinely unsettled, and `docs/20-risk-register.md`
(R-*) tracks failure modes with evidence. An item leaves either list only with the artefact that
resolved it.

## Conventions

- Negative results are first-class. A failed experiment honestly reported is the expected output;
  do not force a positive finding or optimise a report.
- When a test's expectation changes because the world changed, say so explicitly in the test
  docstring rather than silently editing the assertion.
- Tests must not be vacuous — assert that the input actually reaches the branch under test
  (a "borderline" sample scoring 0.0000 proves nothing about a threshold).
- Git: this repo commits manually. Stage changes and hand over the command; do not run
  `git commit` or `git push`.
