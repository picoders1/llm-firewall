# Release Checklist

The gate between a release candidate and a tag. Every line is either checked with
a command or is not checked at all — there is no "looks fine" state.

> **Commit identity note.** The SHAs below are the ones GitHub recorded, which predate the
> 2026-08-22 `filter-branch` rewrite. They are intentionally *not* rewritten — the remote
> executed against them. Their current reachable equivalents are in
> [git-history-rewrite.md](git-history-rewrite.md); every tree is identical.

**Nothing here may be ticked from documentation.** The Phase 18 audit exists
because this project has repeatedly found capabilities that were fully documented
and only partly enforced; the Phase 19 audit exists because `/metrics` was
documented, tested, and unscrapeable.

---

## 1. Working tree and provenance

- [x] Working tree clean apart from the intended release changes — `git status --porcelain`
- [x] Branch is `main` and tracks `origin/main`
- [x] Release commit created and pushed — **`76d6fad`**, `HEAD == origin/main`, worktree clean
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

## 7. Scanners — **verified by remote CI**

Run **32501090591**, commit `76d6fad`, conclusion `success`, 11/11 jobs.

- [x] gitleaks executed **remotely** — job `dependency and secret scanning` success,
      `gitleaks-results.sarif` downloaded, **0 findings**
- [x] Trivy executed **remotely** on the application image — `llm-firewall:ci
      (debian 13.6)`, **0 vulnerabilities**, policy `HIGH,CRITICAL` /
      `ignore-unfixed` / `exit-code 1`
- [x] Trivy executed **remotely** on the edge image — `llm-firewall-edge:ci
      (alpine 3.21.3)`, **0 vulnerabilities**, same policy
- [x] CI evidence artefact downloaded — `release-evidence-76d6fadc60492c32a628ff673297317cef4383ec`,
      digest `sha256:8786082d75ae…`
- [x] Integration tests green remotely
- [x] TLS integration green remotely
- [x] Production topology green remotely
- [x] Frontend tests green remotely
- [x] Container build and smoke test green remotely
- [x] Dockerfile `SecretsUsedInArgOrEnv` annotation classified — false positive on
      the variable **name**; the value is a path, `/etc/nginx/tls/` is absent from
      the image, and "Prove no key reached the image" passed. Follow-up hardening,
      not a blocker

## 8. Documentation

- [x] [release-readiness.md](release-readiness.md) reflects the current code
- [x] [release-ci-evidence.md](release-ci-evidence.md) records what ran and where
- [x] [20-risk-register.md](20-risk-register.md) updated
- [x] [22-evidence-and-claims.md](22-evidence-and-claims.md) updated
- [x] No stale current-state claim contradicts the code

## 9. Tag

- [x] **`v1.0.0-rc1` permitted.** Section 7 is satisfied by remote run 32501090591:
      conclusion `success`, 11/11 jobs, both Trivy scans and gitleaks observed
      remotely, evidence artefact downloaded, and the production policy verified
      unchanged against the committed tree.

The tag points at **`76d6fadc60492c32a628ff673297317cef4383ec`** and nothing else. It is a release *candidate*:
nothing here has served production traffic, most operational numbers are
development defaults (R-67, R-88), and enforcement is heuristic by design
(ADR-016). Those are stated in [release-readiness.md](release-readiness.md), not
hidden behind a green pipeline.
