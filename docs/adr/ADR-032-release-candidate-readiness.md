# ADR-032: Release-Candidate Readiness

**Status:** Accepted
**Date:** 2026-08-20
**Phase:** 18
**Produces:** [docs/release-readiness.md](../release-readiness.md)

## Context

Eighteen phases of implementation, each with its own ADR and its own tests. What
had never happened is the thing every one of those phases assumed someone else
would do: **check the whole system against itself, sceptically, at once.**

This project has a specific, repeated failure pattern worth naming before the
audit's results, because it is what the audit was designed to find. Five times now
a capability has been fully documented and only partially enforced — operator
authentication (Phase 9), TLS (Phase 12), deployment topology (Phase 14), the audit
queue (OD-42), retention (Phase 16). Each time the design document was right, the
prose was confident, and no artefact made it true.

Phase 17 found a sixth variant and a worse one: a capability that was documented,
**tested**, and broken. `/metrics` had two passing tests asserting the wrong
content type while no Prometheus on earth could scrape it.

So the audit rule for this phase was: **documentation never earns a PASS.**

## Decision

Ship a release candidate, with 46 capabilities graded against evidence in
[release-readiness.md](../release-readiness.md):

| | Count |
|---|---|
| PASS | 26 |
| PARTIAL | 13 |
| DEFERRED | 6 |
| SUPERSEDED | 1 |
| **BLOCKED** | **0** |

PASS requires implementation, automated tests, integration or live evidence, and
documentation that matches. PARTIAL means all of that plus a limitation a
deployment has to know about — it is not a euphemism for incomplete, and thirteen
of them are the honest core of this release.

### What was deferred rather than built

The brief for this phase forbade adding features, and the roadmap contains items
that a less disciplined release would have implemented for completeness:

* **Grafana dashboards as code — SUPERSEDED.** The console already answers "what is
  happening" from the audit trail and Phase 17's rules answer "should someone act".
  A third view of the same data, in a tool this deployment does not run, would be
  maintained by nobody.
* **OTLP/Langfuse exporter — DEFERRED.** Nothing has asked for distributed traces,
  and a security gateway should not ship telemetry to a third party by default
  (ADR-008).
* **Presidio — DEFERRED.** The regex baseline covers structured identifiers. Adding
  spaCy and two Presidio packages to a runtime image is a real cost and no evidence
  justifies it yet.
* **Kubernetes — DEFERRED.** No measured sizing, no cluster to validate against
  (OD-41). Manifests nobody can run are fictional infrastructure.
* **Streaming — DEFERRED.** `stream: true` returns `400`. Refusing is honest;
  passing a token stream through uninspected would not be.
* **Least-privilege database role — DEFERRED, and it is a regression.** ADR-012
  specified `SELECT/INSERT/UPDATE` and no `DROP`. It was never implemented in any
  manifest, and Phase 16's retention job now genuinely needs `DELETE` (R-82, OD-43).

Each is recorded with the evidence that deferred it, which is the difference
between a deferral and an omission.

## Findings

### One code defect, found by inspecting a build rather than reading a file

**The production image shipped 17 MB of per-sample benchmark data.** The
`.dockerignore` excluded `predictions*`, `*.csv` and `*.svg`, and its comment
claimed the image carried "~200K of `result.json`". Phase 15's benchmark harness
then began writing `raw_results.jsonl` — a filename none of those patterns match —
and four phases of per-request rows shipped in the runtime image while the comment
kept asserting otherwise.

The fix is not a fourth pattern. **An exclude-list fails open on every artefact type
invented after it is written.** It was replaced by an allow-list of the single
filename `app/api/dashboard/evaluations.py` actually opens, and
`tests/security/test_image_build_context.py` binds the two: if the dashboard learns
to read a second file, the test fails until the ignore file is updated to ship it.

Image: 238 MB → 217 MB. `/app/eval`: 21 MB → 264 KB. The dashboard lists the same
14 evaluations before and after.

No content risk — the rows are synthetic benchmark timings — but the same drift on
an artefact containing real payloads would have been a disclosure, and nothing in
the repository would have noticed.

### Documentation that had drifted

Corrected, all current-state only. Historical evaluation reports were **not**
touched, and none of the frozen artefacts were edited:

* `docs/00-project-overview.md` — the banner still read *"Phase 0 — planning
  complete, implementation not started. No evaluation has been run."* through
  eighteen phases and eight recorded experiments.
* The same document listed *"does not authenticate callers, terminate TLS, or
  rate-limit"* as a limitation. Two of those three have been false since Phase 10
  and Phase 12; the third is true in a more precise way now worth stating.
* `README.md` — seven phase rows reading "Not started" for work that ships,
  including one asserting "alerts and runbook not started" a phase after they
  landed.
* `docs/09-threat-model.md` — a heading reading "designed, not implemented" above a
  body that already said "the mechanism is implemented as of Phase A+B", and a B4
  row asserting a least-privilege role split that was never built.
* `CLAUDE.md` — described the detector registry as four entries; it has five since
  ADR-021 registered the transformer.

### What the audit verified rather than assumed

* **Canary sweep on a live stack.** A request carrying a marker string, an email
  address, a card number and a bearer token, driven through the real gateway.
  Zero occurrences in logs, in `/metrics`, in all eight Security Operations API
  routes, and in the audit tables — where `details` holds `{"EMAIL": 1, "PHONE": 1,
  "CREDIT_CARD": 1}` and no value.
* **Image contents.** `uid=10001(app)`, no compilers, no `.git`, no tests, no model
  weights, no private keys, `/app` not writable.
* **Production topology from the rendered manifest.** Only the edge publishes ports;
  the audit store sits on an `internal: true` network.
* **Repository sweep** for absolute home paths, DSNs, `sk-` keys and bearer tokens
  in tracked files: nothing but deliberately fake test fixtures.

### Scanners: what ran and what did not

Stated explicitly because the brief required it and because "we scan for that" is
the easiest unearned claim in security work:

| Tool | Status |
|---|---|
| `pip-audit --skip-editable` | **Executed.** No known vulnerabilities found |
| `ruff`, `mypy`, `pytest`, `uv lock --check`, `docker compose config` | **Executed.** All green; 1676 passing, 42 skipped |
| `promtool check rules` / `test rules` | **Executed.** 16 rules, 24 cases |
| **Trivy** | **CI-only. NOT executed.** Not installed locally, and CI has not run on a remote — so no image vulnerability scan result has ever been observed by anyone |
| **gitleaks** | **CI-only. NOT executed.** A manual `git grep` for credential shapes was run instead and found nothing, which is weaker and is not a substitute |

`torch` cannot be audited by `pip-audit` in its `+cu124` build, which is not on
PyPI. It is not a dependency of the application — it enters only through optional
extras used by the offline research harness.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **Tag a 1.0 release** | Nothing here has served production traffic. Every operational number is a development default and every runbook entry is written from the design. "Release candidate" is the accurate word and this project does not use inaccurate ones |
| **Mark PARTIAL capabilities as PASS with a footnote** | The footnote is the finding. Thirteen PARTIALs with named limitations are more useful to a reader than 39 PASSes and a paragraph of caveats nobody reads |
| **Build the deferred roadmap items for completeness** | Explicitly forbidden by this phase, and right: Grafana, OTLP, Presidio and Kubernetes would each add a maintained surface to satisfy a document rather than a need |
| **Add a fourth exclusion pattern to `.dockerignore`** | Fixes this instance and leaves the mechanism that produced it. The allow-list fails closed |
| **Install Trivy locally to close the gap** | Tempting and wrong here: a scan run once on a laptop, unrecorded and unrepeatable, would produce a claim with no artefact behind it. The honest statement is that CI holds it and CI has not run |
| **Rewrite historical reports to match current state** | Forbidden, and it would destroy the record of completed experiments. Evidence is immutable; only current-state documentation was corrected |

## Consequences

### Positive

* One document answers "is this ready", per capability, with the evidence.
* Two classes of silent drift are now test-bound: build-context contents against
  what the code reads, and (from Phase 17) alert rules against the runbook and the
  metric registry.
* The production image is 21 MB smaller and carries nothing the runtime opens.
* Every deferral has a reason attached, so the next person does not rediscover the
  question.

### Negative / accepted costs

* **The readiness matrix is a snapshot.** Nothing keeps it current, and it will be
  wrong the first time a capability changes without someone editing it. It is
  dated and phase-stamped rather than presented as continuously true.
* **Two scanners have never been observed to run.** CI defines them; CI has not
  executed on a remote. That is a real gap in a release audit and is recorded as
  such rather than glossed.
* **`PARTIAL` carries a lot of weight.** Thirteen capabilities ship with named
  limitations, and a reader who skims the status column will overestimate
  readiness. The limitation column is not optional reading.
* The audit is one person's sceptical pass. It found two real defects, which
  suggests a second pass by someone else would find more.

### Revisit when

Production traffic exists — every `calibration: unvalidated` threshold, every rate
limit and the capacity figures should be replaced with measured values, and the
matrix re-run. Also when CI first executes on a remote, at which point the Trivy
and gitleaks rows can be updated from "never observed" to a result.

## Verification

* `uv lock --check`, `ruff check`, `ruff format --check` (323 files),
  `mypy app services` (74 files), `pytest -q` (**1676 passed, 42 skipped**),
  `pip-audit --skip-editable` (no known vulnerabilities),
  `docker compose config` and `docker compose -f compose.prod.yaml config`.
* `tests/security/test_image_build_context.py` (11) — the allow-list bound to the
  code that reads it.
* `tests/integration/test_container.py` — asserts no non-summary evaluation
  artefact is present in the built image.
* Live canary sweep across logs, metrics, eight API routes and the audit tables.
* Production policy re-verified unchanged: registry of five with
  `injection.heuristic` 0.85/block, `jailbreak.heuristic` 0.85/block, `pii.regex`
  redact, `injection.transformer` **disabled**, `output.stub` **disabled**, no
  `by_trust` overlays, `config/policies/default.yaml` byte-identical to HEAD.
