# Data Model

PostgreSQL holds two unrelated things that happen to share a database: the **audit trail**
of production traffic, and the **results of evaluation runs**. They are separate table
groups with separate retention rules and are never joined.

> **Implementation status.** Three tables exist today — `request_traces`,
> `detector_results`, `security_events` — created by migration `0001_audit_schema`, applied,
> rolled back and re-applied against PostgreSQL 16. `policy_decisions` and the evaluation
> tables below are **specified but not created**: nothing writes them yet, and a table
> nobody writes is schema nobody can justify. Two documented differences from the
> specification below, both narrowing: `request_traces` additionally records
> `upstream_called`, `normalization_latency_ms`, `policy_latency_ms` and
> `inspected_messages`; and `security_events.content_preview` was **not created at all**,
> because its absence is a stronger guarantee than a gated column.

Schema is created and evolved exclusively through Alembic migrations. Nothing is created
by `Base.metadata.create_all()` outside of unit-test fixtures — a schema that only exists
because the app booted is a schema nobody can review or roll back.

## Design rule: raw prompts have nowhere to go

There is deliberately **no column anywhere that can hold a full prompt or completion**.
This is enforced structurally rather than by discipline: the audit tables store hashes,
lengths, categories and scores. A future change that wants prompt text has to add a column,
which is a visible migration and a reviewable decision. See
[ADR-012](adr/ADR-012-persistence-and-retention.md) and
[10-security-model.md](10-security-model.md).

---

## Audit tables

### `request_traces`
One row per request that reaches the gateway, including rejected ones.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigserial` PK | |
| `request_id` | `text` UNIQUE NOT NULL | correlation ID, matches logs and traces |
| `created_at` | `timestamptz` NOT NULL | server clock, default `now()` |
| `model` | `text` | as requested by the client |
| `upstream_host` | `text` | host only, never the full URL with query |
| `status_code` | `smallint` NOT NULL | |
| `decision` | `text` NOT NULL | `allow` / `warn` / `redact` / `block` |
| `block_category` | `text` NULL | set only when `decision = 'block'` |
| `gateway_latency_ms` | `numeric(10,3)` | **excludes** upstream time |
| `upstream_latency_ms` | `numeric(10,3)` NULL | null when not forwarded |
| `detector_latency_ms` | `numeric(10,3)` | wall-clock of the detection stage |
| `input_tokens` / `output_tokens` | `integer` NULL | only when the upstream reports them |
| `input_chars` / `output_chars` | `integer` | always available, useful when tokens are not |
| `truncated` | `boolean` | inspection hit `max_inspect_chars` |
| `client_id` | `text` NULL | tenant/API-key **identifier**, never the key itself |

Indexes: `(created_at DESC)`, `UNIQUE(request_id)`, `(decision, created_at DESC)`,
`(model, created_at DESC)`.

### `detector_results`
One row per detector per request. This is the table that makes threshold tuning possible:
it records scores for detectors that did *not* fire, so an operator can ask "what would
have happened at threshold 0.7" without re-running traffic.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigserial` PK | |
| `trace_id` | `bigint` FK → `request_traces.id` ON DELETE CASCADE | |
| `detector` | `text` NOT NULL | |
| `direction` | `text` NOT NULL | `input` / `output` |
| `category` | `text` NOT NULL | |
| `detected` | `boolean` NOT NULL | |
| `score` | `numeric(5,4)` NOT NULL | |
| `threshold` | `numeric(5,4)` NOT NULL | the threshold in force **at decision time** |
| `latency_ms` | `numeric(10,3)` | |
| `errored` | `boolean` NOT NULL DEFAULT false | |
| `error_kind` | `text` NULL | `timeout`, exception class name |
| `reasons` | `jsonb` | rule names only — never matched text |

Indexes: `(trace_id)`, `(detector, created_at DESC)`, partial index on `(errored) WHERE errored`.

Recording the threshold on the row matters: policy changes over time, and a historical
decision must be interpretable against the policy that actually produced it.

### `policy_decisions`
One row per policy evaluation (input and output are separate evaluations of the same
request), recording the *reasoning*, not just the outcome.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigserial` PK | |
| `trace_id` | `bigint` FK CASCADE | |
| `direction` | `text` NOT NULL | |
| `action` | `text` NOT NULL | |
| `category` | `text` NULL | |
| `triggering_detector` | `text` NULL | |
| `policy_version` | `text` NOT NULL | hash of the effective policy |
| `reasons` | `jsonb` | |

`policy_version` is the SHA-256 of the **effective policy** — the canonical serialisation of
the validated `PolicyConfig`, not the raw file bytes. Two semantically identical policies
therefore share a version, and a comment or reformat does not manufacture a spurious one;
the version changes if and only if behaviour changes. Without it, "why was this blocked in
March" is unanswerable after any config change.

*(Implementation note: the original plan hashed the file bytes. Changed during Phase 0 —
see `PolicyConfig.version_hash` and `tests/unit/test_policy_version.py`.)*

### `security_events`
The append-only security record. Deliberately denormalised: an auditor reads one table, and
it survives independently of the trace tables' retention.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigserial` PK | |
| `request_id` | `text` NOT NULL | |
| `created_at` | `timestamptz` NOT NULL | |
| `event_type` | `text` NOT NULL | `block`, `redact`, `warn`, `detector_failure`, `upstream_failure` |
| `direction` | `text` NOT NULL | |
| `category` | `text` NOT NULL | |
| `detector` | `text` NULL | |
| `score` | `numeric(5,4)` NULL | |
| `content_hash` | `text` NULL | truncated SHA-256 of inspected text |
| `content_length` | `integer` NULL | |
| `client_id` | `text` NULL | |
| `model` | `text` NULL | |
| `severity` | `smallint` NOT NULL | |
| `details` | `jsonb` | rule names, span *offsets and labels* — never span contents |

Indexes: `(created_at DESC)`, `(category, created_at DESC)`, `(content_hash)`,
`(request_id)`.

The `content_hash` index is the operationally interesting one: it turns "is someone probing
us with the same payload repeatedly" into a `GROUP BY` instead of a forensic exercise, and
it does so without storing a single prompt.

---

## Evaluation tables

Populated only by the harness, never by production traffic.

### `evaluation_runs`

| Column | Type | Notes |
|---|---|---|
| `id` | `bigserial` PK | |
| `run_id` | `text` UNIQUE NOT NULL | also the report filename stem |
| `started_at` / `finished_at` | `timestamptz` | |
| `dataset_name` / `dataset_version` / `dataset_split` | `text` | |
| `dataset_checksum` | `text` | SHA-256 of the resolved case list — the reproducibility anchor |
| `detector_config` | `jsonb` | the exact detector + threshold set under test |
| `policy_version` | `text` | |
| `git_commit` | `text` | |
| `machine_metadata` | `jsonb` | CPU model, core count, RAM, GPU, OS, Python version |
| `metrics` | `jsonb` | precision, recall, F1, FPR, FNR, latency percentiles |
| `sample_count` | `integer` | reported next to every metric, always |

### `evaluation_cases`
One row per case per run — the raw material for error analysis. Without per-case results,
"recall improved" cannot be turned into "here are the twelve prompts that still get
through", which is the only version of that sentence worth anything.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigserial` PK | |
| `run_id` | `text` FK → `evaluation_runs.run_id` | |
| `sample_id` | `text` NOT NULL | stable across runs |
| `category` | `text` NOT NULL | `benign`, `direct_prompt_injection`, … |
| `expected_label` | `boolean` NOT NULL | positive = attack |
| `predicted_label` | `boolean` NOT NULL | |
| `score` | `numeric(5,4)` | |
| `latency_ms` | `numeric(10,3)` | |
| `outcome` | `text` | `tp` / `fp` / `tn` / `fn` — generated, indexed |

Index on `(run_id, outcome)` so "show me every false negative in run X" is one query.

Evaluation datasets are **public benchmark data only** and never contain production
traffic; the separation is a licensing and privacy requirement, not just tidiness.

---

## Retention

| Data | Default | Rationale |
|---|---|---|
| `request_traces`, `detector_results`, `policy_decisions` | 30 days | Operational tuning window |
| `security_events` | 180 days | Incident investigation typically starts long after the event |
| `content_preview` | never in production | Refused by `Settings.effective_content_logging()` |
| Evaluation tables | indefinite | Small, and reproducibility depends on history |

Enforcement is a scheduled `DELETE` in Phase 5, not a manual process. Retention is
configuration, and the configured values are printed at startup so a deployment cannot
quietly retain more than intended.

## Access and durability notes

* The application connects as a role with `SELECT/INSERT/UPDATE` on audit tables and **no
  `DROP`**; migrations run as a separate role. Least privilege is cheap here and prevents
  an application-level SQL flaw from destroying the audit trail.
* Audit writes are behind a repository interface. Phase 0 writes synchronously; Phase 5
  moves them to a bounded in-process queue with a background writer so database latency
  leaves the request path. The interface does not change, only its implementation — this
  is why the repository boundary exists in Phase 0 despite being trivially thin there.
