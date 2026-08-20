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

Nine constraints do most of the work. **All nine are enforced by tests, not convention** —
the first four by `tests/unit/test_layer_boundaries.py`, which parses the AST so a violation
is caught even if the module is never imported, and the last five by
`tests/security/test_operator_auth.py`, `test_caller_auth.py`, `test_edge_abuse_protection.py`,
`test_secure_transport.py` and `test_readiness_contract.py`, which attack the boundaries
rather than describing them.

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

- **Volume is the edge's problem; identity is the application's.** `deploy/docker/edge/`
  (wired by `compose.edge.yaml`) is a reference nginx front end doing `limit_req`,
  `limit_conn`, body size and read timeouts — it can refuse a connection for the price of a
  `RST`, which the application cannot. In-process there is only a safety net:
  `app/middleware/admission.py` bounds in-flight requests (**503**, outermost of all
  middleware, `/health` and `/ready` exempt) and `app/auth/admission.py` throttles repeated
  authentication failures per client address (**429**, before the credential comparison).
  **Both are off by default**, and every shipped limit value is a development default rather
  than a measured one (R-67). Per-client state is capped at 16,384 entries and expiring,
  because a map keyed by something an attacker chooses is a memory leak with a security
  justification (ADR-025). `tests/integration/test_edge_proxy.py` drives real nginx in CI.

- **The application verifies its transport; it never terminates it.** TLS ends at the edge
  (`compose.tls.yaml`, certificates mounted from `deploy/certs/`, generated by
  `scripts/generate_dev_cert.sh` and **never committed**). `FIREWALL_HTTPS_ENFORCED` refuses
  operator and gateway requests with **426** unless a *trusted* proxy asserts
  `X-Forwarded-Proto: https` — absence is treated as insecure, not assumed secure. Production
  refuses to start without it. `/health`, `/ready` and `/metrics` are exempt so a
  misconfigured deployment stays diagnosable and internal scraping keeps working. The edge
  exits rather than starting if its certificate and key are missing, mismatched or expired
  (ADR-026).

- **`/ready` is a security contract, and its checks are classified.** `app/api/readiness.py`
  reports `configuration`, `security_boundary`, `detectors` and `database` checks, each
  `required` or `advisory` — **only `required` failures return 503**. The classification is
  the substance: an unreachable audit store is *advisory* when `require_audit=false`, because
  ADR-012 says the security decision is unaffected and failing readiness would turn an audit
  outage into a traffic outage. Most security-boundary checks re-assert startup invariants
  and cannot fail in a correctly built process; `tests/security/test_readiness_contract.py`
  walks one list twice so startup validation and readiness cannot drift (ADR-027).

The operator boundary is off outside production (`console_auth_mode` derives to `disabled`),
so `docker compose up` and the whole test suite behave exactly as before; tests that need it
use the `enforcing_client` fixture, and `compose.console-auth.yaml` adds an nginx proxy for
manual work. The caller boundary derives the same way; tests that need it use `caller_client`,
and `scripts/generate_caller_key.py` mints a credential for manual work. The edge is opt-in
too: `docker compose -f compose.yaml -f compose.edge.yaml up -d --build` (host port **8089**;
8080 is taken on the reference machine). Add `-f compose.tls.yaml` for HTTPS on **:8443**
after running `./scripts/generate_dev_cert.sh`.

**Alerts are evaluated, not described.** `deploy/alerts/firewall.rules.yaml` holds 16 rules
in two severities — `critical` means wake someone, `warning` means a ticket, and there is no
third level. Each has an entry in `docs/runbook.md`, and `tests/unit/test_alert_rules.py`
fails if a rule has no entry, an entry has no rule, or a rule names a metric the registry
does not export. `promtool test rules` runs 24 cases in CI, and the ones that assert
**silence** are the point: a zero-valued retention timestamp must not read as 56 years of
staleness, one transient audit failure must not page, `sync` mode has no queue to saturate.
Thresholds not derived from an invariant carry `calibration: unvalidated` in both the rule
and the runbook (R-88). Half the policy is the list of things deliberately **not** alerted —
notably `firewall_audit_rows_deleted_total`, because a counter ticks whether or not
deletion is keeping up. Configuration is exported as metrics
(`firewall_audit_retention_period_seconds`, `firewall_audit_queue_capacity`,
`firewall_retention_enabled`) so a rule can never hardcode a threshold the app owns.
Phase 17 found `/metrics` had been unscrapeable by Prometheus the whole time — the
content type said OpenMetrics, the body was text format (R-87, ADR-031).

**Retention deletes by age, and by nothing else.** `app/database/retention.py` enforces
ADR-012's periods — 30 days of `request_traces` (and `detector_results` with them, by
`ON DELETE CASCADE`), 180 days of `security_events` — four phases after they were
decided and never implemented. **The only predicate is `created_at`**: there is no
filter by decision, category, detector or caller, because a purge that can be aimed
at particular rows is a mechanism for erasing the evidence of a block.
`tests/security/test_retention_safety.py` compiles the statements and asserts on the
SQL. Deletion is **batched** because `Database` sets a 5-second command timeout — one
unbounded `DELETE` against a backlog times out, rolls back, and deletes nothing while
appearing enabled — and the cutoff comes from PostgreSQL's clock, not the process's.
**Off by default** (deletion is irreversible; an upgrade must not start removing an
operator's trail), on in `compose.prod.yaml`, and a startup warning names the
consequence while it is off. `scripts/purge_audit.py` is dry-run unless given
`--execute`. The metric that matters is `firewall_audit_oldest_row_age_seconds`, not
the delete counter: a counter can tick while the backlog grows (ADR-030).

**The audit write is off the request path, and drops rather than blocks.**
`FIREWALL_AUDIT_WRITE_MODE=queue_drop` (set in `compose.prod.yaml`; the code default is
still `sync`) puts a bounded `asyncio.Queue` in front of PostgreSQL, saving ~9 ms p50. When
it fills, records are **dropped and counted** in `firewall_audit_events_dropped_total` —
blocking was implemented, measured against a stalled database, and removed because it hung
the request path until every client timed out. A graceful stop drains and loses nothing; a
`SIGKILL` loses what is queued (49/300 measured). `require_audit=true` forces `sync` and the
combination is refused at startup (ADR-029, amending ADR-012).

**Deployment is an artefact, not a description.** `compose.yaml` is development — it publishes
the gateway on :8000 and PostgreSQL on :5434 for convenience. `compose.prod.yaml` is the
reference production topology and is *standalone*, because an overlay cannot un-publish a
port: only the edge publishes, the audit store sits on an `internal: true` network the edge
cannot even resolve, the four `SecretStr` settings arrive as mounted files at
`/run/secrets/FIREWALL_*`, and `/ready` is the health gate so a container that lost its
security configuration never has traffic routed to it. `tests/security/test_deployment_topology.py`
asserts all of that from the manifests; `tests/integration/test_prod_topology.py` probes a
running stack (ADR-028). Kubernetes is deferred — no measured sizing and no cluster to
validate against (OD-41).

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
- **Production is frozen unless an ADR says otherwise.** The registry holds five detectors —
  `injection.heuristic`, `jailbreak.heuristic`, `pii.regex`, `injection.transformer`,
  `output.stub` — of which the **enabled** set is the first three plus `pii.regex` on output.
  `injection.transformer` is disabled and warn-only (ADR-021); `output.stub` is disabled.
  Heuristic threshold `0.85`; provenance overlays absent; ML blocking refused on evidence. Fine-tuned models are warn-only and not
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

The status banners in `README.md`, `docs/README.md` and `docs/00-project-overview.md` were
stale for eighteen phases and were **corrected in Phase 18**; `docs/release-readiness.md` is
now the capability-by-capability answer to "is this ready", and it grades against evidence
rather than against documentation. `docs/19-implementation-roadmap.md` and the ADRs remain
authoritative for the phase record.

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
