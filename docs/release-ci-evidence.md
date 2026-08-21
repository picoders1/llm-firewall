# Release CI Evidence

Where the scanner and pipeline results for a release candidate are recorded, and
what each one is worth.

**Rule for this document: a result is recorded with the environment that produced
it.** A local scan is evidence about a locally built image. A remote CI run is
evidence about the artefact the pipeline builds. They are not interchangeable, and
this file never lets one stand in for the other.

---

## Run 1 — Phase 19, local scanner execution

**Status: superseded by Run 3. Retained as the record of how the gap was closed.**

| | |
|---|---|
| Date | 2026-08-21 |
| Repository | `picoders1/llm-firewall` (private) |
| Branch | `main` |
| Commit at time of scanning | `4c9b04d` + then-uncommitted Phase 19 changes |
| Environment | Reference development machine, not GitHub Actions |
| Remote workflow run ID | **pending** |
| Remote conclusion | **pending** |

## Run 3 — the release-candidate run: **SUCCESS**

**Status: GREEN. This is the run the release candidate rests on.**

| | |
|---|---|
| Workflow | `CI` |
| Run ID | **32501090591** |
| Commit | **`76d6fadc60492c32a628ff673297317cef4383ec`** — *"point the CI readiness probe at the port compose actually publishes"* |
| Event / branch | `push` → `main`; `HEAD == origin/main`, worktree clean |
| Started | 2026-08-21T16:05:19Z |
| Conclusion | **`success`** — observed via `gh api …/actions/runs/32501090591` |

### Job matrix — 11/11 success

| Job | Result |
|---|---|
| lockfile is current | success |
| lint and format | success |
| type check | success |
| unit, api and security tests | success |
| frontend tests | success |
| alert rules | success |
| dependency and secret scanning | success |
| container build and smoke test | success |
| TLS integration | success |
| production topology | success |
| integration tests | success |

### Scanner evidence — observed remotely, downloaded

`release-evidence-76d6fadc60492c32a628ff673297317cef4383ec` (1695 B, expires 2026-11-19):

```
commit:     76d6fadc60492c32a628ff673297317cef4383ec
workflow:   32501090591 attempt 1
dockerfile: deploy/docker/Dockerfile
image_id:   sha256:43abf734497bb63c44e0ba5d7abe2dbd7c8cfe0f350cae9974ff8d144c200d69
digest:     sha256:8786082d75ae19ed089ff307c997b043ee24924669b61df58b6ebaecb87205ac
```

| Scanner | Target | Result |
|---|---|---|
| Trivy | `llm-firewall:ci (debian 13.6)` | **0 vulnerabilities** |
| Trivy | `llm-firewall-edge:ci (alpine 3.21.3)` | **0 vulnerabilities** |
| gitleaks | full history | **0 findings** (`gitleaks-results.sarif`, job success) |

Policy unchanged throughout: `HIGH,CRITICAL`, `--ignore-unfixed`, `exit-code 1`, both
images. No `continue-on-error`, no skippable job.

**The gap opened in Phase 18 is closed.** Both scanners have now produced an
observed remote result tied to one exact commit and one image digest — which is
what Run 1 and Run 2 could not do.

### The Dockerfile annotation, classified rather than ignored

The run carries `SecretsUsedInArgOrEnv: ENV "EDGE_TLS_KEY"`.

**Classification: B — false positive on the variable name. Not release-blocking.**

`EDGE_TLS_KEY=/etc/nginx/tls/privkey.pem` is a **path**, not key material.
BuildKit's linter matches the identifier (`*KEY`), never the value. Verified
against the built image rather than argued:

* `/etc/nginx/tls/` **does not exist** in the image — it is a runtime mount only.
* The only `.pem` files present are the distribution CA trust store.
* CI's own **"Prove no key reached the image"** step passed in this run.

That is the guarantee ADR-026 §4 makes, and it holds. Recorded as a follow-up
hardening item — renaming to `EDGE_TLS_KEY_PATH` would silence the linter and
say what the variable means — **not** as a release blocker, and the Dockerfile is
not changed on the strength of a name-pattern match.

---

## Run 2 — Phase 19B, remote observation attempt

**Status: RUN TRIGGERED, RESULT NOT OBSERVED.**

| | |
|---|---|
| Date | 2026-08-21 |
| Commit | `f4bce17ea2fdb4651b9cf690b1d6dca45f66beb2` — *"record the first scan results ever observed (ADR-033)"* |
| Pushed to | `origin/main` — confirmed, `local main == origin/main`, 0 ahead / 0 behind |
| Contains the Phase 19 fixes | Confirmed: `.gitleaks.toml`, both patched Dockerfiles, the frontend job, edge scanning and artefact retention are all present in `origin/main` |
| Workflow | `CI` (`.github/workflows/ci.yml`), triggers on `push: branches: [main]` |
| Remote workflow run ID | **NOT OBSERVED** |
| Remote conclusion | **NOT OBSERVED** |

### Why it could not be observed

The push happened, so the pipeline was triggered. Reading its result requires
authenticated access to a **private** repository, and this environment has none:

| Mechanism | State |
|---|---|
| `gh` CLI | not installed |
| `GH_TOKEN` / `GITHUB_TOKEN` | not set |
| `~/.config/gh/hosts.yml` | absent |
| `~/.netrc`, `~/.git-credentials` | absent |
| git credential helper | not configured |
| Unauthenticated GitHub API | `404` on `/repos` and `/actions/runs` — private |

The remote is reached over SSH (`git@github.com:...`), which authenticates git
operations and carries no Actions API access. **No fabricated or inferred result is
recorded here**, and the scanner rows in
[release-readiness.md](release-readiness.md) and
[22-evidence-and-claims.md](22-evidence-and-claims.md) therefore remain at
"executed locally; remote unobserved".

### What is known about the commit that will be scanned

The working tree was clean and identical to `f4bce17` when every check below ran,
so these results describe exactly the code the remote pipeline will build:

| Control | Result |
|---|---|
| `uv lock --check` | PASS |
| `uv run ruff check .` | PASS |
| `uv run ruff format --check .` | PASS |
| `uv run mypy app services` | PASS — 74 files |
| `uv run pytest -q` | **1676 passed, 42 skipped** |
| `uv run pip-audit --skip-editable` | No known vulnerabilities |
| `node --test tests/frontend/*.test.mjs` | 13 passed |
| `promtool check rules` / `test rules` | 16 rules, SUCCESS |
| Trivy 0.58.2 — application image | **Total: 0 (HIGH 0, CRITICAL 0)**, exit 0 |
| Trivy 0.58.2 — edge image | **Total: 0 (HIGH 0, CRITICAL 0)**, exit 0 |
| Production policy | heuristic 0.85/block, transformer disabled/warn, overlays 0 — unchanged |

That is a strong prior for the remote run and **it is not the evidence this phase
requires**. The pipeline builds its own images on a different base snapshot, and
"it passed here" has been wrong before in this project — `/metrics` passed two
local tests while no Prometheus could scrape it (R-87).

### Why the remote result is still pending

The commit `4c9b04d` was already pushed to `origin/main`, so the pipeline has run
at least once. **That run's outcome has not been observed**, for two reasons that
are worth stating rather than working around:

1. The repository is private and the GitHub CLI is not installed on this machine,
   so the run cannot be read from here.
2. Whatever it concluded, it did not satisfy this phase's requirements: at that
   commit the workflow ran no frontend tests, recorded no image identity, retained
   no artefacts, never scanned the edge image, **and would have failed the
   `security` job on seven gitleaks findings and the `build` job on thirty-six
   Trivy findings** — both of which this phase found and fixed locally.

A new run against the Phase 19 commit is therefore required regardless. See
[How to complete this record](#how-to-complete-this-record).

### Scanner results — executed locally

#### gitleaks

| | |
|---|---|
| Version | `v8.30.1` (`ghcr.io/gitleaks/gitleaks`) |
| Scope | Full git history — 24 commits, ~38.01 MB |
| Configuration | `.gitleaks.toml` (extends the default rule set; **no rule disabled**) |
| Result **before** the allow-list | **7 findings**, exit 1 |
| Result **after** the allow-list | **0 findings**, exit 0 |
| Real credentials found | **None** |

All seven were investigated individually before anything was allow-listed:

| Rule | Location | Classification |
|---|---|---|
| `curl-auth-user` | `docs/22-evidence-and-claims.md` | **Documentation example** — the htpasswd credential from `compose.console-auth.yaml`, an opt-in local overlay. Named `development-only`; `compose.prod.yaml` is standalone and cannot inherit it |
| `generic-api-key` | `tests/conftest.py` | **Synthetic fixture** — the caller key the suite presents to `/v1`. High-entropy on purpose; ADR-024 mints keys with `secrets.token_urlsafe(32)` and a memorable fixture would break the assumption that an unsalted SHA-256 is adequate |
| `generic-api-key` | `tests/security/test_provenance_privacy.py` | **Synthetic canary** — a token-shaped string whose only purpose is to assert it never reaches a log, an audit row or a response |
| `generic-api-key` ×4 | 4 committed evaluation artefacts | **False positive** — `tokenizer_revision` pins the upstream tokenizer to a 40-hex commit SHA. It is the reproducibility metadata docs/13 requires; removing it would destroy the provenance of four completed experiments |

**Negative control.** An allow-list that quietly disables detection is worse than
no scanner. Two randomly generated credentials were planted and re-scanned:

| Probe | Location | Result |
|---|---|---|
| `ghp_` personal access token | an ordinary file | **caught** (`github-pat`) |
| random 44-char key | `tests/conftest.py` — *a file with a path-scoped allow-list* | **caught** (`generic-api-key`) |

The second is the one that matters: the allow-list is scoped to the `fw-test-`
prefix, not to the file, so a real key committed to that fixture still trips the
scanner. The three allowed strings remained un-flagged in the same run.

#### Trivy

| | |
|---|---|
| Version | `0.58.2` |
| Vulnerability DB | v2, updated 2026-08-21 01:31 UTC |
| Policy | `--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1` — unchanged, as documented in [18-ci-cd-strategy.md](18-ci-cd-strategy.md) |

**Application image** — `deploy/docker/Dockerfile`, base pinned
`python@sha256:229a2c5b…`

| | Findings | Exit |
|---|---|---|
| Before remediation | **36 HIGH** | 1 — the build gate fails |
| After remediation | **0** | 0 |

All 36 were four CVEs (`CVE-2026-53612/13/14/15`) across nine binary packages from
one source package, `util-linux` `2.41-5`, fixed in `2.41.5-0+deb13u1`.

* **Classification: base-image issue, fixable, exploitable in principle.** The SUID
  `mount` and `umount` binaries the CVEs concern *are* present in the image
  (verified, not assumed). In the shipped topology `no-new-privileges:true` and
  `cap_drop: ALL` neutralise SUID escalation and remove the `CAP_SYS_ADMIN` mount
  requires — but that is defence in depth, not a reason to ship the package.
* **Remediation attempted first, per the documented runbook** ("usually the base
  image; refresh the pinned digest"): the current `python:3.12-slim-trixie` tag
  carries the *same* `2.41-5`. **Refreshing the pin would not have fixed it**, so
  the runbook entry is incomplete and now says so.
* **Remediation applied:** `apt-get upgrade` in the runtime layer. Verified: all
  nine packages now report `2.41.5-0+deb13u1`.

**Edge image** — `deploy/docker/Dockerfile.edge`, base `nginx:1.27-alpine`

| | Findings | Exit |
|---|---|---|
| Before remediation | **21 HIGH** | 1 |
| After remediation | **0** | 0 |

`musl`, `zlib`, `libxml2` (6), `libexpat` (4), `libpng` (6), `c-ares` and
`nghttp2-libs` — the last serving the HTTP/2 this edge terminates. All fixable in
the Alpine archive.

**This image had never been scanned by anything.** CI scanned only the application
image, and the edge is the container on the public internet. It is now built and
scanned in the same job under the same policy.

#### Image identity at time of scanning

| | |
|---|---|
| Application | `sha256:7c6bd30a83166477cf8daa36eda10793a1ada4513793280f381a0ec2e9a25013` (224 MB) |
| Edge | `sha256:b983fe6440a01a1cc3be22badf1f44ddb1d20e9a68303eb58c60e4f5d47522a6` |

Local build identities. They are recorded because a scan result that cannot name
what it scanned is evidence of nothing — and they are **not** the CI-built
artefact, which is why the pipeline now records its own.

### Everything else, executed locally

| Control | Command | Result |
|---|---|---|
| Lockfile | `uv lock --check` | OK |
| Lint | `uv run ruff check .` | OK |
| Format | `uv run ruff format --check .` | 325 files formatted |
| Types | `uv run mypy app services` | 74 files, no issues |
| Tests | `uv run pytest -q` | **1676 passed, 42 skipped** |
| Dependencies | `uv run pip-audit --skip-editable` | No known vulnerabilities |
| Frontend | `node --test tests/frontend/*.test.mjs` | **13 passed** |
| Alert rules | `promtool check rules` / `test rules` | 16 rules, 24 cases, SUCCESS |
| Compose | `docker compose config`, `-f compose.prod.yaml config` | Both valid |

### Security regression gate

| Check | Expected | Observed |
|---|---|---|
| Injection | 403, upstream not called | **403, +0** |
| Benign | 200, upstream called once | **200, +1** |
| `/metrics` | scrapeable text exposition | **200, `text/plain; version=1.0.0`** |
| `/ready` | ready | **ready** |
| Caller / operator / transport boundaries | pass | **104 tests pass** |
| Retention and alert rules | unchanged | **115 tests pass** |
| Production policy | heuristic 0.85/block, transformer disabled, overlays 0 | **unchanged** |

---

## How to complete this record

The remote result is the evidence this phase exists to capture, and it needs a push
of the Phase 19 commit. Once it has run:

```bash
# with the GitHub CLI available and authenticated
gh run list --branch main --limit 5
gh run view <run-id>                       # job matrix and conclusions
gh run view <run-id> --log | grep -A30 Trivy
gh run download <run-id> -n release-evidence-<sha>   # image identity + both Trivy reports
```

Then fill in the run ID, the conclusion and the job matrix above, and only then
update the Trivy and gitleaks rows in
[release-readiness.md](release-readiness.md) and
[22-evidence-and-claims.md](22-evidence-and-claims.md). **Until that happens those
rows say "executed locally; remote unobserved", which is what is true.**

## Retention

The `build` job uploads `image-identity.txt`, `trivy-image-report.txt` and
`trivy-edge-report.txt` as `release-evidence-<sha>`, retained 90 days, with
`if: always()` so the report survives the run where the gate failed — which is the
run whose report someone will actually want.
