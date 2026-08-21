# ADR-033: Release Scanning, Base-Image Patching, and Scanner Allow-Lists

**Status:** Accepted
**Date:** 2026-08-21
**Phase:** 19
**Produces:** [docs/release-ci-evidence.md](../release-ci-evidence.md), [docs/release-checklist.md](../release-checklist.md)

## Context

[ADR-032](ADR-032-release-candidate-readiness.md) graded 46 capabilities and left
exactly two rows saying the same thing: **Trivy and gitleaks are defined in CI, CI
has never run on a remote, and therefore no scan result has ever been observed by
anyone.** Phase 19 set out to close that.

It could not close it the intended way — the repository is private, the GitHub CLI
is not installed on the reference machine, and this project commits and pushes by
hand. So the scanners were run locally instead, which turned out to matter more
than observing a remote run would have, because **both of them fail.**

That is the finding. The gate everyone assumed was green had never been executed,
and when executed it was red twice.

## Decision

### 1. Investigate every scanner finding; allow-list per finding, never per path

gitleaks reported **7 findings** across the git history. All seven were classified
individually before anything was written to a configuration file:

| Classification | Count | |
|---|---|---|
| False positive | 4 | `tokenizer_revision` — a 40-hex commit SHA pinning the upstream tokenizer, which is exactly the reproducibility metadata docs/13 requires |
| Synthetic fixture | 2 | The suite's caller key, and a token-shaped canary in a privacy test |
| Documentation example | 1 | The `development-only` htpasswd credential from an opt-in local overlay |
| **Real credential** | **0** | |

`.gitleaks.toml` extends the default rule set and **disables no rule**. Each
allow-list entry is scoped to a *regex on the matched value*, and only
additionally to a path where that narrows it further. The tempting version —
`paths = ['tests/']` — would also mean a real key committed to a test fixture never
trips the scanner again.

**The allow-list is negative-controlled**, and this is the part that makes it
trustworthy rather than convenient. Two randomly generated credentials were
planted and the scan re-run:

* a `ghp_` token in an ordinary file — **caught**;
* a random 44-character key in `tests/conftest.py`, *the file carrying a
  path-scoped allow-list* — **caught**.

The three allowed strings stayed un-flagged in the same run. An allow-list that
cannot be shown to still detect is indistinguishable from a disabled scanner.

### 2. Patch base packages in the image layer, accepting the tension with the digest pin

Trivy reported **36 HIGH** in the application image: four CVEs
(`CVE-2026-53612/13/14/15`) across nine binaries from one source package,
`util-linux 2.41-5`, fixed in `2.41.5-0+deb13u1`. And **21 HIGH** in the edge.

The documented remedy in [18-ci-cd-strategy.md](../18-ci-cd-strategy.md) is
*"usually the base image; refresh the pinned digest"*. **It was tried and it does
not work here**: the current `python:3.12-slim-trixie` carries the same `2.41-5`.
The fix exists in Debian and has not reached the upstream image.

So the runtime layer now runs `apt-get upgrade` (and `apk upgrade` on the edge).
This is in genuine tension with the Dockerfile's own reasoning for pinning by
digest — *"a build that worked yesterday can silently become a different base image
today"* — and the tension is resolved in favour of patching, deliberately:

* The pin still fixes **which base the build starts from**, so the change remains
  reviewable and bisectable.
* The upgrade applies **the security updates published since that base was built**,
  which is the difference between shipping a fix and waiting for someone else to.
* Reproducibility does not disappear, it moves: CI now records the built image's
  identity next to the commit, and that identifier is what a release is traced by.
  A byte-identical rebuild months later was never achievable anyway once `apt-get
  update` was in the file.

Verified rather than assumed: all nine packages report `2.41.5-0+deb13u1`, and both
images now scan **0 HIGH/CRITICAL** under the unchanged policy.

The CVEs concern SUID `mount`/`umount`, and those binaries **are** present in the
image — checked, not argued. In the shipped topology `no-new-privileges: true` and
`cap_drop: ALL` neutralise SUID escalation and remove the `CAP_SYS_ADMIN` that
`mount` needs. That is why this was not an emergency; it is not why it would have
been acceptable to ship.

### 3. Scan the edge image, under the same policy

The edge had **never been scanned by anything**. CI scanned the application image
only, and the edge is the container on the public internet — the one terminating
TLS, with `nghttp2-libs` among its findings, serving the HTTP/2 it terminates.
There is no argument for holding the ingress to a looser standard than the service
behind it.

### 4. Record what was scanned, and retain it

A scan result that cannot name its subject is evidence of nothing. The `build` job
now writes `image-identity.txt` — commit, workflow run, Dockerfile, image ID and
digest — and uploads it with both Trivy reports as a 90-day artefact, with
`if: always()` so the report survives the run where the gate failed, which is the
run whose report someone will actually want.

### 5. Run the frontend tests in CI, and fix the invocation that hid them

`node --test tests/frontend/` — the invocation documented in the test file — has
not worked since Node 22 changed directory resolution: it loads the directory as a
module and exits 1 before running anything, which reads exactly like a failing
suite. **CI had no frontend job at all**, so 13 passing tests over the console's
formatters and `safeHref` had never run in the pipeline. Both are fixed.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **`.trivyignore` the util-linux CVEs as non-exploitable** | The mitigations are real (`no-new-privileges`, dropped capabilities) and the fix was one archive away. Accepting a fixable HIGH in a security product's own image because a container flag makes it hard to exploit is the argument every unpatched image is shipped on |
| **Blanket-allow `tests/` in gitleaks** | One line instead of four, and it would permanently blind the scanner to the most likely place for a credential to be committed by accident |
| **Delete `tokenizer_revision` from the artefacts to silence the false positive** | Editing four committed evaluation artefacts to please a regex, destroying the provenance of completed experiments. The scanner is wrong; the artefacts are right |
| **Pin the edge to a digest instead of `apk upgrade`** | Worth doing and orthogonal: a digest pin fixes *which* Alpine, not *whether it is patched*. The mutable-tag inconsistency with the application image is recorded as R-97 rather than fixed here, because changing both the pin and the patching in one step would leave neither attributable |
| **Wait for the upstream base image to rebuild** | The correct answer if it were imminent. It is not knowable when, and "we are waiting for Docker Hub" is not a release note |
| **Run CI locally with `act` and call it the remote result** | It would produce a green tick and no evidence. The brief asks for the environment that will actually execute the controls, and a local imitation is precisely what it excludes |

## Consequences

### Positive

* Both scanners have now produced a real, classified result — the first in the
  project's history.
* Both images ship with zero known fixable HIGH/CRITICAL vulnerabilities.
* The internet-facing container is scanned at all, and by the same policy.
* Scan evidence outlives the job log.
* The console's tests run in CI.

### Negative / accepted costs

* **The remote run is still unobserved.** This ADR does not close ADR-032's gap; it
  narrows it and makes the next run meaningful. The Trivy and gitleaks rows stay at
  "executed locally; remote unobserved" until a run is read.
* **`apt-get upgrade` makes two builds from the same pin non-identical.** Accepted
  above, and it is a real loss for anyone who wanted byte-reproducible images.
* **The allow-list will need maintenance.** Every entry is a standing assertion that
  a specific string is not a secret, and nothing re-checks that assertion when the
  file it points at changes.
* **Base-image CVEs will recur.** This fixes today's; nothing subscribes to
  tomorrow's, and the next unpatched HIGH will surface only when CI next runs.

### Revisit when

The upstream Python and nginx images ship the fixed packages — the `upgrade` lines
become redundant and can be removed with a comment saying why they existed. Also
when a remote run is finally observed, at which point this document's local results
become the fallback rather than the record.

## Verification

* gitleaks `v8.30.1`, 24 commits / 38.01 MB: **7 findings → 0**, negative-controlled
  with two planted credentials, both caught.
* Trivy `0.58.2` (DB 2026-08-21): application **36 HIGH → 0**, edge **21 HIGH → 0**,
  policy unchanged.
* Package versions verified in the built image: nine packages at
  `2.41.5-0+deb13u1`.
* Image assertions re-run after rebuild: `uid=10001`, no compiler, no `.git`, no
  `artifacts/`, `/app/eval` = 14 files, 0 non-summary.
* `uv lock --check`, `ruff`, `ruff format`, `mypy app services`, **`pytest -q`
  (1676 passed, 42 skipped)**, `pip-audit`, `node --test` (13 passed),
  `promtool test rules` (SUCCESS), both compose configs.
* Security regression gate: injection `403` with upstream +0; benign `200` with
  upstream +1; `/metrics` scrapeable; `/ready` ready; 104 boundary tests and 115
  retention/alert tests pass; production policy unchanged.
