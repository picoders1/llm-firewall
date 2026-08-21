# Release Checklist

The gate between a release candidate and a tag. Every line is either checked with
a command or is not checked at all — there is no "looks fine" state.

**Nothing here may be ticked from documentation.** The Phase 18 audit exists
because this project has repeatedly found capabilities that were fully documented
and only partly enforced; the Phase 19 audit exists because `/metrics` was
documented, tested, and unscrapeable.

---

## 1. Working tree and provenance

- [x] Working tree clean apart from the intended release changes — `git status --porcelain`
- [x] Branch is `main` and tracks `origin/main`
- [x] Release commit created and pushed — `f4bce17`, `local main == origin/main`
- [x] Release commit SHA recorded in [release-ci-evidence.md](release-ci-evidence.md)

## 2. Local validation

- [x] `uv lock --check`
- [x] `uv run ruff check .`
- [x] `uv run ruff format --check .`
- [x] `uv run mypy app services`
- [x] `uv run pytest -q` — 1676 passed, 42 skipped
- [x] `uv run pip-audit --skip-editable` — no known vulnerabilities
- [x] `node --test tests/frontend/*.test.mjs` — 13 passed
- [x] `promtool check rules` and `promtool test rules` — 16 rules, 24 cases
- [x] `docker compose config` and `docker compose -f compose.prod.yaml config`

## 3. Security regression gate

- [x] Injection → `403`, and `upstream_called` did not increment
- [x] Benign → `200`, upstream called exactly once
- [x] Caller boundary: valid key → `200`, invalid → `401`, refused before inference
- [x] Operator boundary: unauthenticated console → `401` when enforcing
- [x] HTTPS: plaintext refused with `426` when enforced; TLS handshake succeeds
- [x] `/metrics` returns a scrapeable exposition **and a real Prometheus scrapes it**
- [x] `/ready` reports `ready` with its per-check breakdown
- [x] Retention behaviour unchanged
- [x] Alert rules validate and their unit tests pass

## 4. Production policy frozen

- [x] `injection.heuristic` — enabled, threshold `0.85`, action `block`
- [x] `jailbreak.heuristic` — enabled, threshold `0.85`, action `block`
- [x] `pii.regex` — enabled, action `redact`, both directions
- [x] `injection.transformer` — **disabled**, warn-only
- [x] `output.stub` — **disabled**
- [x] `by_trust` provenance overlays — **absent**
- [x] `config/policies/default.yaml` unchanged against `HEAD`

## 5. Images

- [x] Runs as a non-root user (`uid=10001`)
- [x] No compiler, no `.env`, no `tests/`, no `.git`, no `artifacts/`
- [x] No model weights and no private keys
- [x] `/app/eval` contains only `result.json` summaries — asserted against the built
      image, not against `.dockerignore` (R-92)
- [x] Only the intended port exposed
- [x] Application image scanned: **0 HIGH/CRITICAL**
- [x] Edge image scanned: **0 HIGH/CRITICAL**

## 6. Deployment topology

- [x] Only the edge publishes ports
- [x] Audit store on an `internal: true` network
- [x] Secrets arrive as file mounts; none baked into a layer
- [x] `/ready` is the health gate

## 7. Scanners

- [x] gitleaks executed — **locally**, v8.30.1, full history, 0 findings after a
      per-finding allow-list, negative-controlled
- [x] Trivy executed — **locally**, 0.58.2, both images, 0 HIGH/CRITICAL
- [ ] **gitleaks result observed from a remote CI run** — blocked: no GitHub credential in this environment
- [ ] **Trivy result observed from a remote CI run** — blocked: same
- [ ] CI evidence artefact `release-evidence-f4bce17` downloaded and attached

The push of `f4bce17` triggered the pipeline. Its result has **not been read**: the
repository is private, `gh` is not installed, and no token, `~/.netrc`,
`~/.git-credentials` or credential helper is configured. The remote is reached over
SSH, which authenticates git and grants no Actions API access. Nothing is inferred
from the local results (see [release-ci-evidence.md](release-ci-evidence.md), Run 2).

## 8. Documentation

- [x] [release-readiness.md](release-readiness.md) reflects the current code
- [x] [release-ci-evidence.md](release-ci-evidence.md) records what ran and where
- [x] [20-risk-register.md](20-risk-register.md) updated
- [x] [22-evidence-and-claims.md](22-evidence-and-claims.md) updated
- [x] No stale current-state claim contradicts the code

## 9. Tag

- [ ] **`v1.0.0-rc1` — NOT YET.**

Blocked on section 7, and on nothing else. Every other line in this checklist is
green against the exact commit that is on `origin/main`.

The tag may be created only when a remote CI run is green, the Trivy result is
recorded and the gitleaks result is recorded. All three are outstanding for one
reason, and it is not a code reason: **the pipeline's result cannot be read from
this environment.** The single remediation is access — `gh auth login`, or a
fine-grained token with `Actions: read` — not a change to the software.
