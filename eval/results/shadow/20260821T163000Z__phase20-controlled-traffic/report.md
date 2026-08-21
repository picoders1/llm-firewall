# Phase 20 — Controlled-Traffic Validation, Run 1

Protocol: [ADR-034](../../../docs/adr/ADR-034-shadow-traffic-validation.md).
Baseline under test: **`v1.0.0-rc1`** at `76d6fadc60492c32a628ff673297317cef4383ec`.

**Synthetic controlled traffic driven through the running stack — not mirrored
production traffic.** No production deployment exists. Every figure below describes
what the shipped heuristics do to corpus text over a real socket, and none of it is
a production false-positive rate.

| | |
|---|---|
| Date | 2026-08-21 |
| Gateway | `http://localhost:8005` → container :8000, compose + edge + observability |
| Policy | injection.heuristic 0.85/block · jailbreak.heuristic 0.85/block · pii.regex redact · transformer **disabled** · overlays **0** |
| Audit mode | `sync` (code default) |
| Corpora | `finetune/dev` sha256:07a1e685aed81cdc… · `raw/dolly-benign` sha256:6a0b3089194768f1… |
| Hold-outs | **not read** — the harness refuses them by path |

## Decision behaviour — dev split, 808 requests

| Category | n | blocked | rate | 95% CI (Wilson) |
|---|---|---|---|---|
| attack | 153 | 72 | **0.4706** | [0.3932, 0.5494] |
| benign | 138 | 0 | **0.0000** | [0.0000, 0.0271] |
| hard_negative | 517 | 163 | **0.3153** | [0.2767, 0.3566] |

Totals: 573 allow / 235 block.

## Independent benign traffic — 1,000 unused public samples

| Corpus | n | blocked | rate | 95% CI |
|---|---|---|---|---|
| `raw/dolly-benign` | 1000 | 1 | **0.0010** | [0.0002, 0.0056] |

## The finding

**Ordinary benign traffic is clean; security-adjacent text is not.**

0.0010 on independent benign against **0.3153 on hard negatives** — text that
quotes or references an attack without being one. Roughly one in three legitimate
incident-response, abuse-report or security-documentation messages would be
refused by the shipped configuration.

This is the first time that rate has been measured **through the deployment**
rather than against a detector offline. It is a *calibration* finding, not a
defect: the heuristics do what they were written to do, and docs/22 has always
refused to call them prompt-injection detection.

Block attribution: `jailbreak` 262, `prompt_injection` 208 (over both dev runs).
The jailbreak heuristic is the larger contributor.

## Security invariants — held

| Invariant | Result |
|---|---|
| Blocked requests never reach the model | **235 blocks, upstream calls == allows exactly (573)** |
| Every served request has an audit row | **1616 traces for 1616 requests** |
| PII detector on both directions | ran on every request (0 activations; corpus carries no PII) |
| Production policy unchanged | verified against the committed tree |

## Latency (client-observed, loopback, sync audit)

dev split: p50 10.9 ms · p95 12.8 ms · p99 13.6 ms
public benign: p50 11.2 ms · p95 13.2 ms · p99 18.1 ms

Consistent with Phase 15's decomposition (audit write dominant under `sync`).
Loopback figures inherit R-79: the harness saturates before the gateway.

## Not yet executed from ADR-034

Capacity/limit exercise (§3), alert validation against real conditions (§4),
runbook dry run (§5). Recorded as outstanding rather than reported as done.
