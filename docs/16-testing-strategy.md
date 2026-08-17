# Testing Strategy

Tests are segmented by **what they need to run**, not by what they cover. That is what keeps
the fast loop fast and makes CI parallelisable.

```bash
uv run pytest -m "unit or api"    # seconds, no containers — the inner loop
uv run pytest -m security         # security-critical, no containers
uv run pytest -m integration      # needs postgres + mock upstream
uv run pytest -m evaluation       # harness
```

| Suite | Needs | Speed | Purpose |
|---|---|---|---|
| `tests/unit/` | nothing | ms | Pure logic: policy engine, normalisation, detectors, config |
| `tests/api/` | ASGI transport | ms | HTTP contract, status codes, envelopes; upstream stubbed with `respx` |
| `tests/security/` | ASGI transport | ms | **Security-critical behaviour.** Non-negotiable in CI |
| `tests/integration/` | Postgres + mock upstream containers | seconds | Real DB, real HTTP, real container |
| `tests/evaluation/` | nothing | seconds | Harness correctness: splits, metrics, reports |

## The two tests that matter most

**`tests/unit/test_policy_engine.py` — the truth table.** Every combination of detector ×
score-vs-threshold × configured action × error state × `on_error`, parametrised rather than
hand-enumerated. This is the entire security decision surface, tested in milliseconds with no
models, no HTTP and no database. It is the direct payoff of the purity constraint in
[ADR-003](adr/ADR-003-policy-engine-design.md), and if it is ever slow or awkward, the
engine has grown a dependency it should not have.

**`tests/security/test_log_leakage.py` — the canary.** Drive a request containing a unique
canary string through the app with logs captured, and assert the canary appears in **no** log
record at default configuration. Repeated for spans and for audit rows. This is the test that
protects the property the whole product depends on
([logging.md](10-security-model.md)), and it catches the leak a code reviewer would wave
through as debugging.

## Security suite contents

| Test | Verifies |
|---|---|
| `test_block.py` | Injection above threshold → 403, not forwarded upstream |
| `test_block_response.py` | Block response leaks no score, rule or matched text (T-13) |
| `test_redaction.py` | Spans replaced in request and response; surrounding text intact; correct offsets after normalisation |
| `test_fail_closed.py` | Detector exception and timeout → 503 `detector_failure` |
| `test_fail_open.py` | `fail_open` failure does not block, is recorded as errored |
| `test_log_leakage.py` | Canary absent from all logs |
| `test_secret_leakage.py` | API key and DB URL absent from logs, spans, errors, audit |
| `test_log_injection.py` | Malicious `X-Request-ID` cannot forge log records |
| `test_body_limit.py` | Oversized body → 413, rejected before full read; chunked bodies too |
| `test_evasion.py` | Zero-width, confusable, fullwidth and base64 variants produce the same verdict as the plain form |
| `test_upstream_leak.py` | Upstream error bodies are never reflected to the client |

## Conventions

* **`asyncio_mode = auto`** — no `@pytest.mark.asyncio` noise.
* **In-process ASGI transport** (`httpx.ASGITransport`) for api/security tests. No real
  sockets, no port conflicts, milliseconds per test.
* **`respx`** stubs the upstream in unit/api tests; the **containerised mock** serves
  integration tests. Both exist deliberately — the stub cannot validate serialisation,
  pooling or real timing, and the container is too slow for the inner loop
  ([ADR-009](adr/ADR-009-mock-upstream.md)).
* **SQLite (`aiosqlite`) for unit-level database tests, real Postgres for integration.**
  SQLite does not have Postgres semantics, so anything schema- or index-dependent must be
  integration-tested.
* **Fixtures build real objects.** A test that mocks the policy engine to test the policy
  engine tests nothing.
* **No network access in any default-CI test.** A test that needs the internet is opt-in and
  credential-gated.
* **Deterministic.** No `random` without a seed, no wall-clock assertions, no `sleep` where an
  event will do.

## What must have a test

Non-negotiable, enforced at review:

* Every branch of the policy engine.
* Every `on_error` path.
* Every action (allow / warn / redact / block), both directions.
* Every documented limit (body size, inspect chars, detector timeout).
* Every claim in `docs/requirements.md` — each FR/NFR names its test, and the name must
  resolve to a real test.
* Every evasion class the normaliser claims to handle.

## Coverage

Coverage is measured on `app/` and reported, with a floor in CI. It is a **smoke detector,
not a goal**: 100% coverage of the policy engine with weak assertions is worse than 80% with
the truth table. Reviews look at whether the security-critical paths are tested, not at the
percentage.

## Test data

* PII fixtures are **synthetic**: `example.com` emails, reserved-range phone numbers, standard
  Luhn-valid test card numbers, documentation-range IPs. Real PII never enters this
  repository.
* Attack strings in fixtures are live payloads. They are never sent to a real upstream from a
  test.
* The evaluation smoke set is separate from unit fixtures — a detector must not be tuned on
  the data it is evaluated against
  ([ADR-006](adr/ADR-006-evaluation-methodology.md)).
