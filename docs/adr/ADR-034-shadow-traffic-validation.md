# ADR-034: Controlled-Traffic Validation of the RC1 Baseline (Phase 20)

**Status:** Executed in part — runs 1 and 2 complete; measurements 3–5 partially executed with the unexecutable remainder named
**Date:** 2026-08-21
**Phase:** 20
**Validates:** `v1.0.0-rc1` at `76d6fadc60492c32a628ff673297317cef4383ec`

## Context

RC1 is closed: remote CI run `32501090591`, 11/11 green, both Trivy scans and
gitleaks observed remotely, evidence artefact captured against one image digest.
[release-readiness.md](../release-readiness.md) grades 46 capabilities —
26 PASS, 13 PARTIAL, 6 DEFERRED, 0 BLOCKED.

**The repository contains no Phase 20 plan.** The roadmap has a single paragraph
("put it in front of real traffic, even shadow traffic") and nothing that fixes
what would be measured or what would count as a finding. This ADR is that plan,
written before execution because every measurement protocol in this project since
ADR-014 has been pre-registered, and because a validation phase whose criteria are
chosen after seeing the numbers validates nothing.

## The honest framing, first

**This is not shadow traffic in the usual sense.** Shadow traffic means mirroring
real production requests alongside the live path. This project has no production
deployment and no request stream to mirror. What Phase 20 can do is drive
**synthetic controlled traffic** from corpora, through the real stack, and measure
what the shipped configuration does.

That distinction is load-bearing and must survive into every claim:

* It **can** establish how the deployed heuristics behave on representative text,
  what the block rate looks like, whether the alert rules fire on real conditions,
  whether the runbook's steps work, and whether the development-default limits are
  in the right order of magnitude.
* It **cannot** establish a production false-positive rate, a capacity figure, or a
  calibrated threshold. Those need traffic nobody here has, and
  [docs/22](../22-evidence-and-claims.md) already refuses those claims.

Phase 20 therefore *narrows* R-67 and R-88 rather than closing them.

## Traffic sources, and the budget that constrains them

| Source | Cases | Status | Use |
|---|---|---|---|
| `eval/datasets/finetune/dev/` | 808 (153 attack, 138 benign, 517 hard negative) | **Tunable** — reusable by design | Primary decision-behaviour traffic |
| `eval/datasets/raw/dolly-benign`, `oasst1-benign` | 8,000 | Public, never used in fine-tuning | Benign volume and FPR indication |
| `eval/datasets/raw/lakera-gandalf` | 999 | Public, human-authored extraction attempts | Attack volume |
| `eval/datasets/raw/deepset-prompt-injections` | 662 | Public | Attack/benign mix |
| `eval/datasets/raw/jackhhao-jailbreak` | 1,286 | Public | Jailbreak traffic |
| **`eval/datasets/holdout/**`** | — | **BUDGETED** | **NOT USED. Not scored, not read.** |

The hold-out exclusion is absolute. Phase 20 measures a *deployment*, not a
detector's generalisation, and spending a hold-out scoring on it would burn
irreplaceable evidence to answer a question it was not reserved for.

The public corpora carry the contamination caveat from ADR-020 (they were used for
base-model selection and are plausibly in pretraining). That does not matter here:
the detectors under test are **regex and keyword heuristics**, which have no
training set at all.

## What will be measured

### 1. Decision behaviour

Per corpus and per category: total, `allow`, `block`, `redact`, `warn`; per-detector
activation rate; and the two indicators that matter most —

* **hard-negative block rate** — text that quotes an attack without being one. This
  is the closest available proxy for operator-visible false positives.
* **attack pass rate** — the residual the README already refuses to call
  "prevention".

### 2. Request-path behaviour

Latency (p50/p95/p99), throughput, error rate, upstream call count on blocked
requests (must be zero), audit rows written vs requests served.

Reuses `eval/runners/benchmark.py` from Phase 15. **No second harness.**

### 3. Capacity and limits

Exercise `FIREWALL_MAX_CONCURRENT_REQUESTS`, the caller rate limit and the edge's
`limit_req`/`limit_conn` at their shipped development defaults, and record where
each begins refusing. **Measure; do not retune.** A default found to be wrong is a
recorded finding, not an edit.

### 4. Alert validation

Drive the conditions each rule describes and observe Prometheus transition
`pending` → `firing`. Phase 17 already observed two (`FirewallHTTPSEnforcementDisabled`,
`FirewallRetentionDisabled`); the promtool suite covers all 16 synthetically. What
is unproven is that a **real** condition produces the series the rule expects.

### 5. Runbook dry run

`docs/runbook.md` is PARTIAL for one reason: no entry has ever been followed. Walk
the evidence-gathering commands of a representative subset against a live stack and
record, per entry: exercised / worked / missing / unverified.

### 6. Security regression

The Phase 18 canary sweep and the boundary suites re-run unchanged. Phase 20 must
not weaken fail-closed behaviour, either boundary, TLS, admission, PII handling, or
the production policy.

## Success criteria, fixed now

Phase 20 **succeeds as a validation exercise** if it produces the measurements
above with their denominators, whatever the values are. It is not an experiment
with a hypothesis to confirm.

Two conditions would be **findings against RC1**, and both are release-relevant:

| Condition | Classification if observed |
|---|---|
| A blocked request reaches the upstream, or an audit row is missing for a served request | **Release blocker** |
| Any boundary (caller auth, operator auth, HTTPS, admission) fails open under load | **Release blocker** |
| Hard-negative block rate materially above the 0.0092 benign FPR already measured offline | **Measurement/calibration item** (R-88) |
| A development-default limit refusing traffic far below or above a sane operating point | **Measurement/calibration item** (R-67) |
| An alert rule that does not fire on the real condition it describes | **Post-RC hardening** |
| A runbook step that does not work as written | **Documentation/runbook gap** |

## Pre-registered failure modes

* **The synthetic corpus flatters the heuristics.** Dev-split attacks share
  phrasing with what the heuristics were written against. A high block rate here is
  therefore *not* evidence of detection quality, and must not be reported as one.
* **Loopback capacity is not deployment capacity.** Phase 15 already found the
  harness saturating before the gateway above concurrency 4 (R-79). The same
  ceiling applies and any throughput number inherits it.
* **A green alert test proves the rule, not the threshold.** Firing on a condition
  built to fire it says nothing about whether the threshold is right for real
  traffic (R-88).
* **The runbook dry run is a rehearsal, not an incident.** Commands working on a
  healthy stack does not establish that they work at 3am on a broken one.

## What Phase 20 explicitly may not do

Change a threshold, enable the transformer, enable provenance overlays, alter the
policy, retune a limit on the strength of one synthetic run, modify the RC tag, or
touch the Dockerfile to silence the `EDGE_TLS_KEY` linter warning already
classified as a false positive.

## Deliverables

* `eval/runners/shadow.py` — drives corpus cases through the **running gateway**
  (not the detectors offline) and records the decision, category and latency per
  case. The one new artefact; everything else reuses what exists.
* `eval/results/shadow/<run-id>/` — report with corpus checksums and machine
  metadata, matching the existing evaluation-artefact contract.
* Updates to `docs/20-risk-register.md` and `docs/22-evidence-and-claims.md` for
  whatever is actually measured.

## Execution status

| # | Measurement | Status |
|---|---|---|
| 1 | Decision behaviour | **Produced** — run 1, 1,808 requests |
| 2 | Request-path behaviour | **Produced** — latency in run 1; accepted/refused/upstream/audit in run 2 |
| 3 | Capacity and limits | **Partially produced** — edge `limit_req` and the in-process ceiling measured exactly; `limit_conn` and the caller rate limit not reachable in this stack |
| 4 | Alert validation | **Partially produced** — 3 of 16 observed on real conditions, **1 demonstrated defective (R-104)**, 12 not exercised with dependencies named |
| 5 | Runbook dry run | **Partially produced** — 3 entries walked, 1 command found broken as written (R-105) |
| 6 | Security regression | **Produced** — no invariant failed in either run |

**Phase 20 is therefore not complete.** Twelve alerts and the majority of runbook
entries remain unexercised, and each is recorded with the specific dependency that
prevents it rather than assumed acceptable.

## Verification

The protocol is satisfied when each numbered measurement above exists as a
committed artefact with its denominator, or is recorded as not produced with the
reason. Nothing in RC1 changes as a result of running it.
