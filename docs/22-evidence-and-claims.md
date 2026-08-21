# 22 — Evidence Ledger: Claims and Their Proof

Every claim this project may ever make — in the README, in a CV, in an interview — is listed
here with the artefact that must exist first, how that artefact is produced, and where it
lives.

**The rule:** if the artefact does not exist, the claim is not made. Not softened, not
hedged — not made.

Status: **Pending** (no artefact yet) · **Produced** (artefact committed, claim permitted).

Every **detection-quality and performance** row is Pending, because no evaluation and no
benchmark has been run. Several **engineering** rows moved to Produced with the vertical
slice — those are claims about how the system is built, verifiable by running the suite, and
they are the only claims currently permitted.

---

## Detection quality

| Claim | Evidence required | How produced | Status |
|---|---|---|---|
| Injection detection recall | Per-category recall, `n`, split, threshold, Wilson interval | `python -m eval run --split test --frozen` | **Produced** — internal only |
| FPR on benign traffic | FPR over a benign corpus with stated size and source | Same run (9,065 benign samples) | **Produced** — internal only |
| **FPR on independent benign traffic** | FPR over an authored, never-published corpus with a Wilson interval | `python -m scripts.validate_holdout` (457 benign, 170 hard negatives) | **Produced** — the strongest FPR evidence the project has |
| **Hard-negative FPR** | FPR restricted to legitimate text resembling an attack | Same run | **Produced** |
| **No threshold makes the classifier deployable** | Frozen dev-selected sweep evaluated on the hold-out | `python -m scripts.threshold_analysis` | **Produced** — `eval/results/20260817T102936Z__threshold-deployability/decision.md` |
| **Fine-tuning reduces the enterprise FPR problem** | Hold-out FPR before/after, scored once behind a pre-hold-out lock | `python -m scripts.finetune_strategy_a --holdout` | **Produced** — `eval/results/finetune/20260817T122701Z__strategy-a/report.md` |
| **Attack recall is retained after fine-tuning** | Per-category recall with denominators, same 60 in-scope attacks | Same run | **Produced** — 0.8833 → 0.8833; the 7 misses differ by one sample |
| Fine-tuning makes the classifier block-ready | All six ADR-015 criteria met simultaneously | Same run | **NOT produced — the claim is refused.** Four criteria unmet; two of them unachievable at their denominators |
| The fine-tuned model is faster | Like-for-like latency on one device | — | **NOT produced.** The two measurements are CPU vs GPU and are not comparable |
| **The FPR improvement generalises to independent data** | Same metrics on a second, independently authored hold-out sharing no text and using different attack vocabulary | `python -m scripts.evaluate_holdout_v3` | **Produced** — `eval/results/20260817T125002Z__holdout-v3-validation/report.md` |
| **quoted_attack and incident_response FPR meet their bounds** | Wilson interval clearing the bound at an adequate denominator | Same run | **Produced** — 0.0429 [0.0147, 0.1186] n=70; 0.0000 [0.0000, 0.0337] n=110 |
| Blocking readiness | All six ADR-015 criteria met simultaneously | Same run | **NOT produced — the claim is refused.** Both recall criteria fail on the model's merits |
| **Indirect-injection detection is inadequate** | Per-delivery-shape recall with adequate n, benign controls in the same containers | `python -m scripts.evaluate_indirect_v1` | **Produced** — 0.1423 (n=520); no shape reliably detected; `eval/results/20260817T130736Z__indirect-delivery-shape/report.md` |
| **The detector classifies the user's turn, not retrieved content** | Recall split by user framing on identical payloads | Same run | **Produced** — 0.0938 (n=480) planted vs 0.7250 (n=40) user-requested |
| **It fires on system-like markup regardless of content** | Benign controls sharing the attack container | Same run | **Produced** — `system_marker` recall 0.5667 with FPR 0.2000 (5/25 inert samples) |
| The firewall protects RAG applications | Indirect-injection recall meeting a stated bound | — | **NOT produced — the claim is refused and must not be made.** FNR 0.8577 |
| **The firewall can carry and act on content provenance** | Provenance model, gateway assignment and monotone policy overlay, with tests | `pytest -m "unit or security"` | **Produced** — [ADR-017](adr/ADR-017-provenance-aware-detection-context.md) Phases A+B+C; 892 tests pass |
| The firewall uses provenance in production | A calibrated overlay enabled in the shipped policy | — | **NOT produced.** The capability ships **off**; no threshold is calibrated (OD-3) |
| **A layer-2 classifier is integrated and can be enabled** | A registered detector, warn-only, disabled by default, with the model outside the app tree | `pytest tests/unit/test_transformer_detector.py` | **Produced** — [ADR-021](adr/ADR-021-layer2-transformer-integration.md) |
| **The gateway exposes real operational metrics** | Prometheus exposition of the documented catalogue, driven by real traffic | `curl localhost:8000/metrics` | **Produced** — Phase 5; counters move only when requests happen |
| **The console renders only backend data** | No hard-coded metric in the frontend source | `pytest tests/security/test_dashboard_frontend_safety.py` | **Produced** — asserted per file, including the classic placeholder values |
| **A missing percentile is never shown as zero** | Null-handling in the formatters | `node --test tests/frontend/*.test.mjs` | **Produced** — `formatDuration(null)` is "No observations" |
| **A small FPR survives its own dashboard** | Rounding that preserves 0.0092 | Same | **Produced** — renders 0.92%, not 1% |
| The dashboard has been visually reviewed on a real display | A human or a browser screenshot | — | **NOT produced.** Layout is verified structurally (routes, states, contract, CSS tokens); rendered pixels were not inspected |
| **The console refuses an unauthenticated client** | An enforcing app answering 401 to a request with no operator identity | `pytest tests/security/test_operator_auth.py tests/api/test_auth_boundary.py` | **Produced** — Phase 9, 48 cases ([ADR-023](adr/ADR-023-operator-authentication.md)) |
| **A spoofed identity header from an untrusted client is refused** | The same headers succeeding from the trusted peer and failing from an untrusted one | Same | **Produced** — including `X-Forwarded-For: 127.0.0.1` alongside the forgery, which changes nothing |
| **A refusal discloses nothing about the boundary** | A 401 body scanned for header names, CIDRs, roles and the shared secret | Same | **Produced** — and the denial log's `reason` is a closed enum, never the attacker's header value |
| **Production cannot start with an unauthenticated console** | A `ConfigurationError` at startup | Same | **Produced** — also for `proxy` mode with no trusted range, and for `0.0.0.0/0` |
| **The reference reverse proxy strips a client's own identity header** | nginx started, a request carrying `X-Auth-Request-User: root` driven through it, the injected value observed | `docker compose -f compose.yaml -f compose.console-auth.yaml up -d --build`, then `curl -u operator:development-only -H 'X-Auth-Request-User: root' localhost:8088/api/v1/session` | **Produced manually** — the response reports `subject: operator`, not `root`. **Not in CI**: no automated test starts nginx, so this is a one-time observation, not a regression guard (R-61). The configuration *is* asserted by test — the header list matches the three the application reads, and the probe locations carry no auth |
| A third-party identity proxy has been integrated | oauth2-proxy / Cloudflare Access / an ingress, end to end | — | **NOT produced.** The header contract is the one those products emit, and the header names are configurable, but no integration with any of them has been run |
| **An unauthenticated `/v1` request never reaches the model** | A counting upstream observed at zero across every refusal path | `pytest tests/security/test_caller_auth.py` | **Produced** — Phase 10, 43 cases. Asserted on `upstream.call_count`, not on the status code: a `401` alone would not prove the gateway had not authenticated on the way back ([ADR-024](adr/ADR-024-llm-caller-authentication.md)) |
| **A client's credential never becomes the gateway's** | The provider's request inspected for every header the client sent | `pytest tests/security/test_upstream_credential_isolation.py` | **Produced** — 14 cases. The property is structural: `chat_completions(self, payload)` has nowhere to put a header, and the signature itself is asserted so a refactor that adds one fails before it can leak |
| **A refusal cannot be used to enumerate configured callers** | Byte-identical bodies for missing and wrong credentials | Same | **Produced** — identical apart from the correlation id; the distinction goes to a metric label instead |
| **Failed authentication writes no audit row** | 20 refused requests, an empty audit sink | Same | **Produced** — a client that can create a row per request can fill an operator's disk |
| **A per-caller rate limit refuses with 429 and `Retry-After`** | A limiter driven past its allowance | `pytest tests/api/test_caller_boundary.py tests/unit/test_caller_ratelimit.py` | **Produced** — window boundary asserted on an injected clock, not sampled with `sleep` |
| The rate limit is a global ceiling | A shared counter across replicas | — | **NOT produced — refused.** It is **per process**: N replicas allow N times the configured value (R-63). An exact global limit belongs at the ingress |
| The gateway enforces a cost or token budget | Token accounting against a configured allowance | — | **NOT produced.** The ceiling counts requests. A caller sending very large prompts outspends one sending many small prompts inside the same limit (R-64, OD-37) |
| A caller-authentication proxy has been executed | An ingress asserting `X-Firewall-Caller`, driven end to end | — | **NOT produced.** `api_key` mode is exercised in containers; `proxy` mode is unit- and API-tested only, and CI starts no ingress (§28) |
| **Moving the audit write off the request path removes ~9 ms p50** | The same gateway measured in both modes, same payload and upstream | `FIREWALL_AUDIT_WRITE_MODE=queue_drop` then the Phase 15 harness | **Produced** — 22.19 ms → 13.34 ms p50 for a 265-byte request at concurrency 1 ([ADR-029](adr/ADR-029-audit-write-architecture.md)) |
| **A blocking queue turns a stalled database into a gateway outage** | The mode implemented and driven against a paused PostgreSQL | `docker pause` with `FIREWALL_AUDIT_QUEUE_SIZE=10` | **Produced** — 120 requests became 120 read timeouts, where drop-on-full served all 120 and counted 109 dropped records. The mode was removed on this evidence (R-81) |
| **A graceful shutdown loses no audit records** | Rows counted across `docker compose stop` | Same | **Produced** — 300/300 written with the bounded drain |
| **An ungraceful stop loses what is queued** | Rows counted across `SIGKILL` | Same | **Produced** — 49/300 with the queue, 300/300 synchronously. The cost is stated rather than discovered later (R-80) |
| **The queue loses nothing on a healthy database** | 500 requests, rows counted, drop counter read | Same | **Produced** — 500/500 written, 0 dropped, in both modes |
| The queue is sized for any deployment | Traffic to derive a queue depth and an alert threshold from | — | **NOT produced.** 1000 is a default, not a sizing. `firewall_audit_queue_depth` has no threshold because no deployment traffic exists to set one from |
| The hard-kill window is closed | A write-ahead log and a replay path | — | **NOT produced.** `sync` is the answer for deployments that cannot tolerate the window; a WAL is recorded as an alternative, not built (ADR-029 alternative E) |
| **Measured gateway overhead under a controlled mock upstream** | A benchmark with machine metadata, raw per-request timings and a stated protocol | `MOCK_LATENCY_MS=0 docker compose -f compose.yaml -f compose.bench.yaml up -d --build && uv run python -m eval.runners.benchmark --label x --conditions A,B,F,C` | **Produced** — `eval/results/performance/`. In-handler span **p50 2.27 ms / p95 3.16 ms** for a 265-byte request at concurrency 1 on a 12th-gen i7 laptop; **32.0 ms p50** for 16 KB |
| **The cost decomposes: detection, normalisation, policy** | Per-stage timings from the audit trail at concurrency 1 | Same run, `stage-breakdown-c1` | **Produced** — detectors 0.99/3.23/19.44 ms, normalisation 0.29/1.60/11.66 ms, policy **0.09 ms regardless of size**. Policy evaluation is a pure function and measures like one |
| **The synchronous audit write costs 10.5 ms p50** | Direct measurement after correcting the instrumentation ordering | `docker compose logs firewall-api \| grep request_decided` | **Produced** — 10.517 ms p50 / 14.377 ms p95, against 1.745 ms p50 for the rest of the gateway span. It had been reported as `0.000` for every request (R-77, R-78) |
| **Gateway overhead is independent of upstream latency** | The same measurement at three upstream delays | `upstream-{0,50,200}ms` runs | **Produced** — overhead 6.02 / 6.89 / 6.78 ms p50 while upstream moved 5 → 207 ms. This is what makes the mock a valid instrument (ADR-009) |
| **The TLS edge adds ~1.2 ms p50** | The same gateway process measured with and without the edge hop | `edge-vs-direct` run | **Produced** — 1.20 / 1.36 ms at concurrency 1; within noise at concurrency 4 |
| **The configured edge rate limit is enforced** | 40 requests at ~43 r/s against a 5 r/s + burst 10 configuration | Phase 15 protection experiment | **Produced** — 15 accepted, 25 refused with 429 |
| **The in-flight ceiling admits exactly its configured number** | 32 concurrent slow requests against a ceiling of 8 | Same | **Produced** — 8 admitted, 24 refused 503, and the slots returned afterwards |
| Any of these figures is a production capacity number | Production-representative hardware, traffic and provider | — | **NOT produced — refused.** Every figure is one laptop, a mock upstream and a stated payload. "Gateway supports X req/s" is not a claim this project can make (§21) |
| The shipped rate and resource limits are sized | A sizing exercise against measured traffic | — | **NOT produced.** Phase 15 characterised *cost*; it did not size *limits*. Every value in `compose.prod.yaml` and `compose.edge.yaml` remains a development default (R-67) |
| Throughput figures above concurrency 4 characterise the gateway | A harness that does not saturate first | — | **NOT produced.** Condition A degrades from 4 ms to 206 ms p50 between concurrency 1 and 64 on this machine, so client-observed figures there measure the harness (R-79) |
| A stability threshold for run-to-run variation | Repeated runs across sessions and thermal states | — | **NOT produced.** Two back-to-back runs agreed within ±4 % p50 at concurrency 1 and 11 % at concurrency 4. Reported, not turned into a bound |
| **The gateway and the audit store are unreachable from the host** | The production stack running, ports probed from outside it | `docker compose -f compose.prod.yaml -f compose.prod-selftest.yaml --env-file prod.selftest.env up -d --build && uv run pytest tests/integration/test_prod_topology.py -q` | **Produced** — `:8000`, `:5434` and `:8081` closed while `:8443` serves; `docker inspect` shows no port bindings on either. Every artefact in the repo used to contradict this obligation |
| **The edge cannot reach the audit store at all** | A name-resolution attempt from the edge container | `docker compose ... exec edge nslookup postgres` | **Produced** — SERVFAIL. The `internal` network split is enforced by the network driver, not by a firewall rule |
| **The production topology matches the documented obligations** | The manifests parsed and asserted, obligation by obligation | `uv run pytest tests/security/test_deployment_topology.py -q` | **Produced** — 43 cases: only the edge publishes, credentials are mounted not exported, every service drops all capabilities, `/ready` is the health gate, migrations are a separate profile |
| **The security pipeline is unchanged by the deployment shape** | An injection driven through the production path | `uv run pytest tests/integration/test_prod_topology.py -q` | **Produced** — 403 `security_block`, `upstream_called = false`, audit row in the private database carrying the caller id |
| Resource and rate limits in the production manifests are sized | A controlled benchmark | — | **NOT produced.** Every value inherits from the development stack. `docs/17` has said "Sizing: unknown. Pending Phase 4 benchmarks" since Phase 0 and that is still true (R-67) |
| The reference deployment supports rolling updates | A drain-and-replace mechanism | — | **NOT produced.** Plain Compose restarts a container; it cannot drain one, so a single-node deployment has a brief outage on restart (R-74, OD-41) |
| Kubernetes manifests exist and are valid | `kubectl apply --dry-run` or a cluster | — | **NOT produced — deliberately.** No `kubectl`, `kind`, `minikube` or `k3d` on this machine, so manifests could not be validated even client-side. Deferred with a recorded trigger rather than shipped unvalidated (OD-41) |
| Secret files are readable only by the container | File ownership matching the container uid | — | **PARTIALLY produced.** `init_prod_secrets.sh` chowns to uid 10001 where it has the privilege; unprivileged it falls back to 0444 inside a 0700 directory and says so. On this machine it fell back (R-75) |
| **An audit-store outage does not take the instance out of rotation** | A running app with an unreachable database, readiness still 200 | `uv run pytest tests/security/test_readiness_contract.py -q` | **Produced** — and the inverse: `require_audit=true` makes the same outage a 503. The previous behaviour failed readiness unconditionally, contradicting ADR-012 |
| **Schema skew is visible in readiness** | A database rolled back one revision, both revisions named in the response | `docker compose exec firewall-api alembic downgrade -1 && curl -s localhost:8000/ready` | **Produced manually and in tests** — observed live: `schema at 3c1d90b4e2a7, code expects 6b2f4c8d1a09`, advisory with best-effort audit and 503 with `require_audit=true` |
| **Every configuration refused at startup is also reported unready** | One shared list, walked twice — once against `create_app`, once against an independently assembled state | `uv run pytest tests/security/test_readiness_contract.py -q` | **Produced** — 5 configurations. This is what stops the startup checks and the readiness checks drifting apart |
| **`/ready` describes the boundary without revealing it** | A fully configured instance, body scanned for CIDRs, caller ids, modes, roles, paths and credentials | Same | **Produced** — it is a public probe, so the payload is deliberately vaguer than the operator API |
| **An advisory failure never changes the status code** | A `/8` trusted range flagged while the instance stays ready | `uv run pytest tests/unit/test_readiness.py -q` | **Produced** — 23 cases covering the classification |
| Readiness can detect a security boundary that was mis-built | An independent measurement of the running boundary | — | **NOT produced — and not possible.** Most boundary checks re-assert invariants the process refuses to start without, so they cannot fail in a correctly built process. Their value is a machine-readable contract and a regression net, stated plainly rather than dressed up as detection (R-71) |
| Readiness reflects whether traffic is actually flowing | Live request telemetry | — | **NOT produced — refused.** Readiness validates configuration. "No authenticated request recently" would make a quiet Sunday look like an outage |
| The schema check tolerates an expand/contract rollout | A compatibility range rather than exact equality | — | **NOT produced.** Exact equality, which is correct while migrations run before the rollout and wrong the first time a release spans two revisions (R-72, OD-40) |
| **An anonymous flood is refused by the edge, not the application** | A real nginx driven over a real socket until it returns 429 | `docker compose -f compose.yaml -f compose.edge.yaml up -d --build && uv run pytest -m integration -q` | **Produced, and running in CI** — 10 cases in `tests/integration/test_edge_proxy.py`. This is the class of claim Phase 9 recorded as unproduced for the console proxy |
| **The edge answers 429, not nginx's default 503** | The status of a rate-limited request through the proxy | Same | **Produced** — asserted explicitly, because the default would tell a client the server is broken rather than that it should slow down |
| **A 400 KB body is refused by the proxy** | A 413 with no application involvement | Same | **Produced** |
| **The security console is not reachable on the gateway edge** | 404 for `/dashboard`, `/api/`, `/metrics` | Same | **Produced** — so a deployment cannot publish the console on the gateway's address by accident |
| **A valid caller credential still gets a normal completion through the edge** | A 200 with a well-formed `chat.completion` | Same, with a per-run credential minted by `scripts/generate_caller_key.py` | **Produced in CI** — the digest goes to the gateway and the raw key to the test, never to the repository |
| **Limiter state stays bounded under a distributed flood** | 50,000 distinct client identities against a capped map | `pytest tests/unit/test_admission.py` | **Produced** — 19 cases. Expiry alone would bound nothing, so the cap and the eviction order are both asserted |
| **A concurrency slot is returned after a handler raises** | Repeated failures followed by a success | `pytest tests/security/test_edge_abuse_protection.py` | **Produced** — a leaked slot converges on refusing everything while the process still reports itself healthy |
| **`/health` and `/ready` answer while the ceiling refuses everything else** | Probes during saturation | Same | **Produced** — an orchestrator that cannot reach `/ready` turns a load spike into an outage |
| Any shipped rate limit is a recommended production value | Measured traffic and a sizing exercise | — | **NOT produced — refused.** Every value is a development default chosen to be observable by hand (R-67). ADR-025 gives an example production *column*, not a recommendation |
| Rate limiting is enforced globally across replicas | A shared counter | — | **NOT produced.** Per edge instance and per process (R-63, OD-38) |
| The authentication-failure throttle is safe to enable everywhere | Evidence that callers have distinct addresses | — | **NOT produced.** It throttles by address, so a caller sharing an egress gateway with an attacker is refused for the window (R-65). Off by default, and the reference overlay leaves it off because it tripped this project's own integration suite |
| **The edge serves HTTPS and refuses TLS 1.0/1.1** | Real handshakes, not a config file | `./scripts/generate_dev_cert.sh && docker compose -f compose.yaml -f compose.edge.yaml -f compose.tls.yaml up -d --build && uv run pytest tests/integration/test_tls_edge.py -q` | **Produced, in a dedicated CI job** — 19 cases. TLS 1.0 and 1.1 handshakes fail **and** 1.2 and 1.3 succeed, so the rejection is not satisfied by a server that refuses everything |
| **The served certificate matches its hostname and its key** | A verified handshake plus a byte comparison against the file on disk | Same | **Produced** — hostname checking stays on; the development CA is trusted explicitly rather than verification disabled |
| **Unusable TLS material stops the container** | Real containers started with broken pairs | `uv run pytest tests/integration/test_tls_failure_modes.py -q` | **Produced** — 6 cases: missing certificate, missing key, corrupt certificate, mismatched key, unknown mode, **and a valid pair that starts**. The mismatched-key case is the one that would otherwise survive startup and fail at first handshake |
| **A client cannot claim its plaintext hop was HTTPS** | The forged header refused, the same header from the trusted peer honoured | `uv run pytest tests/security/test_secure_transport.py -q` | **Produced** — 26 cases, including a forged `X-Forwarded-For` alongside |
| **HTTP redirects with 308, preserving the method** | The status and `Location` of a POST | `pytest tests/integration/test_tls_edge.py` | **Produced** — and the plain listener proxies no gateway path at all, so a redirect cannot become a plaintext bypass |
| **HSTS is sent over HTTPS and not over HTTP** | Both listeners inspected | Same | **Produced** — exactly one header, sourced from the component that observed the TLS connection |
| **HTTP/2 is negotiated, and HTTP/1.1 still works** | ALPN offered explicitly | Same | **Produced** — claimed only because it is measured |
| **No private key is in the repository or in the image** | `find` over the built image; gitignore and dockerignore coverage | The TLS CI job step *Prove no key reached the image* | **Produced** — the only PEMs in the edge image are the OS root CA bundle |
| TLS overhead is a production figure | A realistic workload, a real model, and a controlled benchmark | — | **NOT produced.** Measured HTTP-vs-HTTPS through the same edge on one machine against a mock upstream, keep-alive, n=300: p50 12.30 ms vs 12.04 ms, p95 16.88 ms vs 14.69 ms. **The difference is within run-to-run noise**; the supportable claim is no measurable regression at this workload, not a number |
| The edge-to-firewall hop is encrypted | mTLS or TLS on the internal hop | — | **NOT produced — deliberate.** Plaintext on an isolated network carrying only those two participants (R-68, OD-39) |
| Certificate expiry is monitored | An expiry metric or an alerting rule | — | **NOT produced.** The edge checks expiry at start-up only; a certificate that lapses while running keeps being served (R-69). The application holds no certificate and exposes no expiry metric |
| A production certificate authority is integrated | An ACME client or a CA integration | — | **NOT produced — out of scope by design.** The repository defines the interface (two paths and a mount) and pins itself to no issuer |
| A repository secret scan was run for this phase | `gitleaks` output | — | **NOT produced.** `gitleaks` is not installed on this machine; it runs in the pre-commit hook and the CI security job. Coverage was checked instead by asserting the gitignore and dockerignore patterns and by searching the built image |
| The operator console proxy is rate-limited | `limit_req` / `limit_conn` in its configuration | — | **NOT produced.** Phase 11 targeted the gateway edge; the console proxy gained nothing (R-66) |
| **Dashboard endpoints answer from real audit data** | Live aggregation over PostgreSQL, no fixture rows | `curl 'localhost:8000/api/v1/overview?hours=24'` | **Produced** — 184 traces / 65 events observed live |
| Dashboard API latency is a production figure | A realistic dataset and a controlled benchmark | — | **NOT produced.** Under 7 ms p99 measured on ~184 rows; that is a slow-query smoke test, not a performance claim |
| The dashboard shows detection quality on live traffic | Labelled production traffic | — | **NOT produced — refused.** Live traffic has no ground truth; quality figures come only from `eval/` |
| The observability API is safe to expose publicly | An authentication mechanism | — | **NOT produced.** Unauthenticated by design behind an assumed internal boundary (OD-35) |
| **Layer-2 CPU latency** | Same methodology as prior runs, on the reference machine | ADR-021 | **Produced** — p50 95.38 ms, p99 163.95 ms, 10.4/s single-threaded; ~8x the CUDA figures |
| The ML detector blocks anything | `action: block` in the shipped policy | — | **NOT produced — refused.** `action: warn`, asserted by test; blocking needs OD-18 |
| The ML detector runs in production today | An enabled policy block plus weights on disk | — | **NOT produced.** It ships disabled; enabling is a reviewable operator edit |
| Gateway overhead of layer 2 | End-to-end measurement against the mock upstream | — | **NOT produced.** ADR-021's figures are detector-only on one machine |
| **Provenance-aware detection improves indirect-injection recall** | Paired same-corpus comparison, text held constant, provenance varied, McNemar test | `python -m scripts.evaluate_provenance` | **Produced** — 0.1423 → 0.5365 (n=520, p ≈ 0); `eval/results/provenance/20260817T141551Z__provenance-secondary/report.md` |
| **It improves precision at the same time** | Benign-control FPR under both arms | Same run | **Produced** — 0.0167 → 0.0000, precision 1.0000 |
| **The effect depends on provenance, not on shorter inputs** | Ablations with provenance removed and inverted, same spans | Same run | **Produced** — 0.0000 and 0.0981 against 0.5365 |
| Provenance makes the detector blocking-ready | Indirect recall ≥ 0.80 per ADR-015 | — | **NOT produced — the claim is refused.** 0.5365; 46% still pass |
| The measured 0.5365 is what a deployment would obtain | The untrusted boundary declared by a real integration, not an oracle | — | **NOT produced.** The split used an oracle over the authoring pools; 0.5365 is a **ceiling for a perfectly cooperating integration** (OD-30) |
| **Coverage exists for the three undetected mechanisms** | A frozen training corpus and a disjoint hold-out, with contamination gates | `python -m scripts.datasets.build_mechanism_coverage --check` | **Produced** — `finetune-v2` (4,922) and `mechanisms-v1` (358); [ADR-019](adr/ADR-019-mechanism-coverage-fine-tuning.md) |
| **The three unseen mechanisms are learnable from text** | Per-mechanism recall on a disjoint hold-out, scored once | `python -m scripts.finetune_mechanisms --holdout` | **Produced** — 0.0000 → 0.7333 / 0.7333 / 0.9667; `eval/results/finetune/mechanisms/20260817T164552Z__adr019-strategy-a/report.md` |
| **The corpus did not teach it to block legitimate traffic** | Two benign-control families incl. document-carried | Same run | **Produced** — 0 FP on 178 controls, 0/90 document-carried, precision 1.0000 |
| **Extending the corpus caused catastrophic forgetting** | Rescored baseline on a prior hold-out under pre-registered bounds | Same run | **Produced** — extraction recall 0.8446 → 0.7534 (−0.0912) |
| The ADR-019 model is an improvement overall | All ADR-019 criteria met simultaneously | — | **NOT produced — the claim is refused.** Two regression criteria failed; the run is a FAILURE |
| **The ADR-019 regression is not a threshold artefact** | Recall and FPR moved in opposite directions, so the model is dominated at every operating point | Published aggregates in `holdout_metrics.json` | **Produced** — argument is threshold-free; requires no re-scoring |
| **Extraction's absolute training count never changed** | Per-sub-category counts in both frozen corpora | `eval/results/finetune/ADR-020-protocol/baseline_manifest.json` | **Produced** — 288 samples in v1 and v2; only its share of attack mass moved, 38.92% → 24.20% |
| The cause of the ADR-019 regression is known | An ablation separating composition, adaptation budget, capacity and seed variance | — | **NOT produced — the claim is refused.** Seven candidate causes; one eliminated, six live ([ADR-020](adr/ADR-020-retention-preserving-training.md)) |
| A retention-preserving successor works | ADR-020's retention, mechanism, benign and performance criteria met together | — | **NOT produced — the claim is refused.** ADR-020 executed and FAILED: extraction 0.7669 vs a 0.7946 floor |
| **Replay does not fix the ADR-019 regression** | A controlled arm varying composition alone at fixed step count, scored once on the frozen hold-out | `python -m scripts.evaluate_retention --report` | **Produced** — recovered 15% of the loss while collapsing two of three mechanisms |
| **Reduced adaptation does not fix it either** | A controlled arm varying epochs alone at an identical sampler | Same event | **Produced** — recovered 41%, collapsed the mechanisms further |
| **A single classifier cannot hold both capabilities at this model size** | Two independent interventions both trading one capability for the other | Same event | **Produced** — the basis for R-55 and OD-34 |
| Relative dilution caused the ADR-019 regression | Restoring the diluted proportion recovering the loss | — | **NOT produced — the claim is refused.** It was the leading hypothesis and recovered less than a sixth |
| A larger base model would hold both capabilities | An experiment varying model size | — | **NOT produced.** Nothing tested it; changing the base reopens ADR-014 |
| **Seed variance has been measured, once** | Three seeds per family scored on a common disjoint corpus | `python -m scripts.validate_proxy --report` | **Produced** — families fully disjoint; permutation p = 0.0500, the floor at 3v3 |
| **The ADR-019 regression is not explained by seed noise** | Between-condition gap exceeding within-condition spread across seeds | Same run | **Produced** — gap 0.0594 vs spread 0.0230 |
| Seed variance is now fully characterised | More than three runs per condition | — | **NOT produced — the claim is refused.** n=3 bounds run-level variance no more tightly than p = 0.0500 |
| **A disjoint public corpus can rank two fine-tunes of the same base** | Reproduction of a known effect on that corpus, by paired test | Same run | **Produced** — Strategy A > ADR-019, McNemar p < 1e-6 |
| **Dev-selected thresholds are arbitrary when dev separates perfectly** | Thresholds chosen under identical methodology across checkpoints | `eval/results/finetune/ADR-020-steps-0-1/metrics.json` | **Produced** — span 0.0694–0.9955 |
| Public-corpus scores are capability | An uncontaminated corpus | — | **NOT produced — the claim is refused.** Used in ADR-014 and plausibly in the base model's pretraining; admissible only to rank fine-tunes of the same base |

| Provenance adds negligible overhead | Baseline vs provenance-aware path, same workload, machine metadata | — | **NOT produced.** No numeric overhead may be quoted before implementation |
| **Dev FPR understates hold-out FPR by 5–24x** | Same run, six operating points | Same | **Produced** |
| Jailbreak detection recall | Reported separately from injection | Same run | **Produced** — internal only |
| The ML classifier beats the baseline by X | Both detectors, same split, same machine | `python -m eval compare` | **Produced** — internal only |
| System-prompt-extraction recall | Per-category recall with a real denominator | Same run (45 authored extraction attacks) | **Produced** |
| PII detection recall | **Per-entity** recall, never a single average | — | **Blocked: only 6 PII samples exist (OD-17)** |
| Indirect injection detection | Its own category row | — | **Blocked: only 5 samples exist (OD-17)** |

**"Internal only" is a real distinction, not hedging.** These results are measured and
committed, and they are not yet publishable as project metrics: the public corpora are
probably contaminated into both classifiers' training data, the uncontaminated hold-out has
32 benign samples, and no result has been reproduced on a second machine. They are good
enough to *decide with* ([ADR-014](adr/ADR-014-detector-selection.md)) and not good enough to
*advertise with*.

**Phrasing that is permitted once produced:** *"Recall 0.NN (95% CI a–b, n=N) on the held-out
test split of `<dataset>`, at threshold T, with FPR 0.NN on N benign samples — report:
`eval/reports/detect-<id>.md`."*

**Phrasing that is never permitted:** "94% accurate", "blocks prompt injection",
"state-of-the-art detection".

**Permitted for the fine-tuning result:** *"Standard supervised fine-tuning reduced
hard-negative false positives from 17.1% to 1.2% (n=170, Wilson 95% [0.3%, 4.2%]) on
an independently authored hold-out, with attack recall unchanged at 0.8833 (n=60).
Pre-registered blocking criteria were not met; the model remains in warn mode."*

**Never permitted:** "fine-tuning fixed the false-positive problem", "the model is now
production-ready for blocking", "93% improvement" without its denominator and interval,
or any latency comparison between the CPU and GPU measurements.

**Permitted for the v3 validation:** *"On a second, independently authored hold-out
(n=792) sharing no text with the first and using deliberately different attack
vocabulary, false positives on security-domain traffic met all four pre-registered
bounds — quoted_attack 4.3% (n=70, 95% CI [1.5%, 11.9%]), incident_response 0.0%
(n=110, [0.0%, 3.4%]). Attack recall did not meet its bound and the model remains in
warn mode."*

**Never permitted:** "validated for blocking", "the model generalises" without naming
which half (FPR generalised; recall failed), any indirect-injection recall figure from
either hold-out version, or an aggregate attack-recall comparison between v2 and v3 —
their attack mixes differ by construction.

**Permitted for the indirect-injection result:** *"On a dedicated 820-sample corpus
crossing twelve delivery shapes with eight attack mechanisms, the fine-tuned detector
recalled 14.2% of indirect injections (n=520, 95% CI [11.5%, 17.5%]). No delivery shape
was reliably detected and six recorded zero detections. The detector is not deployed in
blocking mode."*

**Never permitted:** any statement implying the firewall defends against indirect
injection or protects retrieval-augmented applications; quoting the aggregate 0.1423
without noting that six shapes are at zero; quoting `complicit_directive` recall
(0.7250) as an indirect-injection capability — it is a contrast condition measuring the
opposite thing.

**Permitted for ADR-017:** *"The architecture for provenance-aware detection is
designed and documented ([ADR-017](adr/ADR-017-provenance-aware-detection-context.md)),
including the trust model, normalisation compatibility, detector-compatibility
semantics and a migration plan. It is not implemented."*

**Permitted for the Phase D result:** *"On a paired comparison over 820 samples with
the model, weights and threshold held fixed, declaring which span was untrusted raised
indirect-injection recall from 14.2% to 53.7% (n=520, McNemar exact p < 0.001) while
benign-control false positives fell from 1.7% to 0.0%. The detector is not deployed in
blocking mode: 46% of indirect injections are still missed, and the measurement used
oracle segmentation, so it is a ceiling for a perfectly cooperating integration."*

**Permitted for ADR-019:** *"A pre-registered corpus extension took three previously
undetected attack mechanisms from 0% to 73%, 73% and 97% recall (n=60 each) with zero
false positives on 178 controls. The run was recorded as a FAILURE because
system-prompt-extraction recall regressed 9.1 points on a prior hold-out, outside the
bound fixed before training. The model is not deployed."*

**Never permitted for ADR-019:** quoting the mechanism recalls without the regression;
describing the run as a success; claiming the model is better than Strategy A; or
citing `safety_bypass` at 0.9667 without noting that 29 of 34 residual misses sit just
below a conservative frozen threshold, which is diagnostic and was excluded from the
decision.

**Permitted for ADR-020:** *"The regression was diagnosed from existing artefacts
without further training: it is a genuine loss of discrimination rather than a
threshold artefact, because recall fell while false positives rose. Seven candidate
causes were identified and one eliminated. A successor protocol is pre-registered and
has not been run."*

**Never permitted for ADR-020:** describing any cause as established — the ablation
that would separate them has not been run; quoting any number from the public proxy
corpora as capability; calling the layered detector a decision when it is an open
question (OD-34); or implying that ADR-019's regression is known to reproduce across
seeds, which is exactly what Step 1 exists to find out.

**Permitted for ADR-020 overall:** *"A pre-registered experiment tested whether the
mechanism coverage added in ADR-019 could be kept without losing system-prompt-extraction
recall. Two controlled arms — restoring the diluted training proportion, and halving the
adaptation budget — recovered 15% and 41% of the regression respectively, and both did so
by losing the mechanism coverage. The successor was not adopted; the original detector
remains the reference."*

**Never permitted for ADR-020:** calling it a partial success; quoting T3's better
extraction recall without noting that no T3 checkpoint was deployable and that its
mechanism recall collapsed to 0.05–0.12; presenting the improved false-positive rates as
an overall improvement; or claiming capacity is *proven* to be the cause — it is the
best-supported remaining explanation, not a measured one.

**Never permitted:** describing the firewall as provenance-aware, RAG-aware or
context-aware **in production** — the capability ships off; quoting 53.7% without both
the "46% still pass" and the oracle caveat; attributing the recall gain to the trust
*labels* (segmentation carries most of it, and arm A3 is the evidence); quoting
`complicit_directive` figures as indirect-injection performance; or presenting the
policy-ablation numbers as a detector result.

---

## Performance

| Claim | Evidence required | How produced | Stored at | Status |
|---|---|---|---|---|
| Gateway overhead of X ms p50 / Y ms p99 | Conditions A–D, warm-up, `n` ≥ 1000, machine metadata, concurrency level stated | `eval/runners/benchmark.py` | `eval/reports/bench-<run_id>.md` | Pending |
| Detection adds X ms | Condition C − B, per-detector histogram | Same | Same | Pending |
| Per-detector latency of X ms | Condition D | Same | Same | Pending |
| Sustained throughput of X req/s | Throughput **with error rate**, at a stated concurrency | Same | Same | Pending |
| Overhead is negligible relative to model latency | Both `MOCK_LATENCY_MS=0` and a realistic value | Same | Same | Pending |

Every performance claim must carry its conditions. *"XX ms overhead"* alone is not a claim,
it is a rumour — see [15-performance-benchmarking.md](15-performance-benchmarking.md) for the
definition of overhead and the required metadata block.

---

## Engineering

| Claim | Evidence required | How produced | Stored at | Status |
|---|---|---|---|---|
| OpenAI-compatible gateway | An unmodified OpenAI SDK client works end to end | `tests/integration/test_end_to_end.py` covers the request/response shape; the SDK test itself is Phase 1 | Test suite | **Partial** |
| Pluggable detector architecture | A detector added with one registry line and no changes elsewhere | Demonstrated: three stubs were replaced by real detectors with no caller changes | `tests/unit/test_layer_boundaries.py`, git history | **Produced** |
| Policy engine independent of detectors | Import-boundary test; truth table runs with no models loaded | `tests/unit/test_layer_boundaries.py`, `tests/unit/test_policy_engine.py` | Test suite | **Produced** |
| Fail-closed detector semantics | Timeout and exception both produce `503` + `detector_failure`, upstream not called | `tests/security/test_slice_invariants.py` | Test suite | **Produced** |
| Prompts never logged | Canary absent from every log record, driven through the full request path | `tests/security/test_log_leakage.py`, `test_slice_invariants.py` | Test suite | **Produced** |
| Evasion resistance | One test per evasion class, same verdict as the plain form | `tests/unit/test_normalize.py`, `tests/unit/test_baseline_detectors.py` | Test suite | **Produced** |
| Auditable security decisions | Blocked request persists trace + detector results + event with `policy_version`; verified in PostgreSQL | `tests/security/test_slice_invariants.py`, manual psql verification | Test suite | **Produced** |
| Runs with one command, no credentials | `docker compose up` → three healthy services, benign request returns a completion | `tests/integration/` | Test suite | **Produced** |
| CI enforces lint, types, tests, security scanning | Green pipeline with all jobs blocking | `.github/workflows/ci.yml` | CI history | Pending (not yet run on a remote) |
| **Audit retention is enforced, not described** | Rows past the period deleted and rows inside it kept, against real PostgreSQL, with the cascade verified | `tests/integration/test_retention.py` (9 tests), `tests/unit/test_retention_policy.py`, `tests/security/test_retention_safety.py` | Test suite | **Produced** ([ADR-030](adr/ADR-030-audit-retention.md)) |
| **The purge cannot be aimed at particular rows** | The compiled SQL contains no aimable column; one `DELETE`, one id source; no filter parameter on the sweeper or the CLI | `tests/security/test_retention_safety.py` | Test suite | **Produced** — asserted against generated SQL, not against prose |
| **No audit table can escape retention** | Every table in the schema is either swept by age or cascaded from one, asserted against the metadata | `tests/unit/test_retention_policy.py` | Test suite | **Produced** — a table added later fails the test rather than growing unnoticed |
| **Every documented alarm is an evaluated rule with instructions** | 16 rules, one runbook entry each, bound by test in both directions | `pytest tests/unit/test_alert_rules.py` | Test suite | **Produced** ([ADR-031](adr/ADR-031-alerting-and-incident-response.md)) |
| **The alert rules behave as intended, including when they must stay silent** | Rule evaluation by the real engine against synthetic series, firing and near-miss both asserted | `promtool test rules deploy/alerts/firewall.rules.test.yaml` | `deploy/alerts/` | **Produced** — 24 cases; the harness was negative-controlled so it demonstrably fails on a wrong expectation |
| **A real Prometheus can scrape this gateway** | A live server reporting the target `up` and the rules loaded | `docker compose -f compose.yaml -f compose.observability.yaml up -d` + `tests/integration/test_alerting.py` | Test suite | **Produced** — and it could not before Phase 17 (R-87) |
| **Every capability has been graded against evidence, not documentation** | A per-capability matrix naming implementation, tests, live evidence and docs, with PASS withheld where any is missing | `docs/release-readiness.md` | Repository | **Produced** — 46 capabilities: 26 PASS, 13 PARTIAL, 6 DEFERRED, 1 SUPERSEDED, 0 BLOCKED ([ADR-032](adr/ADR-032-release-candidate-readiness.md)) |
| **The deployed heuristics have been measured through the running gateway** | Decision behaviour per category over a real socket, with denominators and Wilson intervals | `eval/runners/shadow.py` against the RC1 stack | [eval/results/shadow/20260821T163000Z__phase20-controlled-traffic/report.md](eval/results/shadow/20260821T163000Z__phase20-controlled-traffic/report.md) | **Produced** — attack recall 0.4706 [0.3932, 0.5494]; benign FPR 0.0000 [0, 0.0271] dev and 0.0010 [0.0002, 0.0056] on 1,000 independent public samples; hard-negative block rate **0.3153** [0.2767, 0.3566] |
| **The shipped limits behave exactly as documented** | Offered load against configured ceilings, with accepted/refused counts and upstream calls | Phase 20 run 2 | [eval/results/shadow/20260821T171500Z__phase20-run2-limits-alerts-runbook/report.md](eval/results/shadow/20260821T171500Z__phase20-run2-limits-alerts-runbook/report.md) | **Produced** — edge `limit_req 5r/s burst=10`: 60 offered → 11 admitted / 49 refused, upstream = 11. In-process ceiling 64: 120 offered → **64 admitted / 56 refused**, counter 0→56, upstream = 64 |
| **Rejected and rate-limited requests never reach the model** | Upstream call count against admitted count under refusal conditions | Same run | [eval/results/shadow/20260821T171500Z__phase20-run2-limits-alerts-runbook/report.md](eval/results/shadow/20260821T171500Z__phase20-run2-limits-alerts-runbook/report.md) | **Produced** — upstream calls equalled admitted requests exactly in both experiments |
| **Three alert rules missed the first occurrence of their condition, and no longer do** | The defect demonstrated live, the fix demonstrated live on a virgin state, and promtool cases that fail against the old expressions | Phase 20 run 2 + post-RC hardening | [R-104](20-risk-register.md) | **Produced** — before: 56 rejections, `increase[5m] = 0`, no alert. After, on a fresh app with a renewed Prometheus volume so the series had never existed: `increase[5m] = 0` still, new clause 56, alert PENDING → FIRING. `firewall_audit_events_dropped_total` is unlabelled and was verified unaffected |
| **Upstream failures are now counted** | An induced upstream fault producing the metric the alert depends on | `__return_500__` through the real gateway | [R-107](20-risk-register.md) | **Produced** — 3 failures → `firewall_upstream_errors_total{kind="5xx"} 3.0`, exactly one each; previously the counter never came into existence |
| `FirewallUpstreamErrorsHigh` has been validated | The >10% for 10m condition exercised end to end | — | — | **NOT produced.** The numerator now exists and the expression is eligible; the sustained condition has not been run |
| The alert rules have been validated against real conditions | Every rule fired by the condition it describes | — | — | **NOT produced.** 3 of 16 observed firing/pending on real conditions, 1 demonstrated defective, **12 not exercised** — each with its missing dependency named |
| **One runbook procedure was corrected after execution** | The documented command failing, then working with the prerequisite | Phase 20 dry run | [R-105](20-risk-register.md) | **Produced** — `purge_audit.py` needs `FIREWALL_DATABASE_URL`; three runbook entries and docs/17 now say so, and the corrected procedure was dry-run |
| The runbook has been validated | Every entry walked against a real incident | — | — | **NOT produced.** Three entries dry-run on a healthy stack; one command found broken as written (R-105). A rehearsal is not an incident |
| The limits are correctly sized for production | The same measurements against real traffic | — | — | **NOT produced — the claim is refused.** Loopback only; R-67 remains open on sizing |
| **Blocked requests never reach the model, at scale** | Upstream call count against block count over a full corpus run | Same run | [eval/results/shadow/20260821T163000Z__phase20-controlled-traffic/report.md](eval/results/shadow/20260821T163000Z__phase20-controlled-traffic/report.md) | **Produced** — 235 blocks, upstream calls equal allows exactly (573); 1616 audit rows for 1616 requests |
| The measured hard-negative rate is a production false-positive rate | The same measurement on real traffic from a deployment | — | — | **NOT produced — the claim is refused.** The corpus is synthetic and security-adjacent by construction; no production deployment exists to mirror (ADR-034) |
| Phase 20 validated capacity, alerting and the runbook | Limits exercised under load, alerts fired by real conditions, runbook steps walked | — | — | **NOT produced.** ADR-034 registered six measurements; run 1 executed two (R-103) |
| **The runtime image carries no content and no research artefacts** | Image inspection plus a test binding the build context to what the code opens | `tests/security/test_image_build_context.py`, `tests/integration/test_container.py` | Test suite | **Produced** — `uid=10001`, no compilers, no weights, no keys; `/app/eval` 21 MB → 264 KB (R-92) |
| **No canary content reaches logs, metrics, the API or the audit trail** | A marker string, an email, a card number and a bearer token driven through a live gateway and searched for on every surface | Manual sweep, Phase 18 | Recorded in [ADR-032](adr/ADR-032-release-candidate-readiness.md) | **Produced** — zero occurrences across logs, `/metrics`, eight API routes and the audit tables |
| **The images have been scanned for vulnerabilities** | A Trivy report naming versions, policy and image identity, produced by the pipeline that will run them | Remote CI run 32501090591, `build` job | [release-ci-evidence.md](release-ci-evidence.md) | **Produced — verified by remote CI.** Application `debian 13.6` **0**, edge `alpine 3.21.3` **0**, tied to commit `76d6fad` and digest `sha256:8786082d75ae…` |
| **The repository has been scanned for secrets** | A gitleaks report over full history with every finding classified | Remote CI run 32501090591, `dependency and secret scanning` | [release-ci-evidence.md](release-ci-evidence.md) | **Produced — verified by remote CI.** 0 findings; `gitleaks-results.sarif` downloaded |
| **The gitleaks allow-list still detects real secrets** | Planted credentials caught in a re-scan, including inside an allow-listed file | Negative control, Phase 19 | [ADR-033](adr/ADR-033-release-scanning-and-base-image-patching.md) | **Produced** — a `ghp_` token and a random key in `tests/conftest.py` were both caught while the three allowed strings stayed silent |
| **CI has executed on a remote** | A GitHub Actions run ID with its job matrix | `gh run view 32501090591` | [release-ci-evidence.md](release-ci-evidence.md) | **Produced** — run 32501090591, conclusion `success`, **11/11 jobs**, commit `76d6fad` |
| This is a 1.0 release | A production track record | — | — | **NOT produced — the claim is refused.** `v1.0.0-rc1` at `76d6fad` is a release *candidate*: the pipeline is green and nothing here has served production traffic |
| The alert thresholds are correct | Thresholds derived from production traffic | — | — | **NOT produced — the claim is refused.** Every unmeasured threshold is labelled `calibration: unvalidated` in both the rule file and the runbook. They are starting points, not evidence (R-88) |
| The system has an availability or latency SLO | A target agreed with a consumer, and burn-rate alerts against it | — | — | **NOT produced.** No SLO exists. Phase 15 refused to publish one from laptop-class measurements, and alerting against an invented target would fabricate the number the alert depends on |
| Alerting has been exercised in a real incident | An incident record following a runbook entry to resolution | — | — | **NOT produced.** Every runbook entry is written from the code and the design, not from an incident anyone has had |
| The audit store grows at a known rate | A measured rate from representative production traffic | — | — | **NOT produced — the claim is refused.** The only figure that exists (55 MB over 2.4 days, 45,095 traces / 179,153 detector rows / 535 events, reference development machine, 2026-08-19) is development plus Phase 15 benchmark traffic on one laptop. It establishes that nothing deleted; it is **not** a growth rate and must not be used to size a disk |
| Retention keeps up at production volume | `firewall_audit_oldest_row_age_seconds` staying below the configured period under sustained real traffic | Metric exists; no such deployment | — | **NOT produced.** The mechanism is tested; its sufficiency at volume is not. The trigger for partitioning is written down instead (OD-43) |
| Deleting from the audit store reclaims disk immediately | `pg_total_relation_size` before and after a sweep | — | — | **NOT produced.** `DELETE` marks tuples dead; autovacuum reclaims the space for reuse and does not return it to the filesystem. `VACUUM FULL` would, and takes an `ACCESS EXCLUSIVE` lock on the audit tables — rejected in ADR-030 |

---

### Evaluation-methodology claims

| Claim | Evidence | Status |
|---|---|---|
| Thresholds are never tuned on the test split | `require_tunable` raises below the CLI; verified by test and by a refused command | **Produced** |
| Splits are deterministic and leak-free | Content-derived keys; integrity check reports 0 leaks and 0 duplicates on 11,009 samples | **Produced** |
| Dataset licences are verified, not assumed | Registry records the licence, gating and verification date read from the HF API; the loader refuses non-commercial sources | **Produced** |
| Metrics are correct | Verified against hand-computed matrices and against scikit-learn | **Produced** |
| Every result is reproducible | Reports refuse to write without commit, dataset checksum and machine metadata | **Produced** |
| Candidates are compared like-for-like | Identical data, splits, preprocessing and machine; unmeasurable candidates recorded as unmeasured, never estimated | **Produced** |

### Additional engineering claims produced by the vertical slice

| Claim | Evidence required | How produced | Status |
|---|---|---|---|
| A blocked prompt never reaches the model | Upstream **call counter** at zero for every blocked request — asserted in-process and across a real network boundary, not inferred from a 403 | `tests/security/test_slice_invariants.py`, `tests/integration/test_end_to_end.py` | **Produced** |
| PII is redacted before it leaves the gateway, in both directions | Forwarded payload and returned body both checked for the value | `tests/api/test_chat_completions.py`, `tests/integration/test_end_to_end.py` | **Produced** |
| The audit trail cannot hold prompt content | Schema asserted against a forbidden-substring list and a reviewed allowlist of free-text columns | `tests/security/test_audit_privacy.py` | **Produced** |
| Gateway overhead is measurable separately from model latency | Per-stage timings recorded per request and exposed as headers | `tests/integration/test_end_to_end.py`, `app/observability/timing.py` | **Produced** (the mechanism; **no figure is claimed**) |
| Detection quality of the baseline heuristics | — | — | **Not claimed. Unmeasured.** |

### Fine-tuning claims — none yet permitted

| Claim | Evidence required | Status |
|---|---|---|
| Fine-tuning reduces enterprise false positives | Hold-out evaluation at a dev-frozen checkpoint against the pre-registered criteria in ADR-015 | **Not claimed — no training performed** |
| The training corpus is uncontaminated | Build-time abort, pinned hold-out hash, 4 CI tests | **Produced** |
| The corpus is not near-duplicate slop | Jaccard ≥ 0.90 rate of 0.0000 against a 0.02 ceiling | **Produced** |
| The corpus forces context learning | Same 22 attack phrases on both label sides, asserted by test | **Produced** |

## Claims that will never be made

Regardless of what any artefact shows:

* "Prevents prompt injection" — no system does. The permitted form is a measured detection
  rate with its residual, on a named dataset.
* Any regulatory compliance status (GDPR, HIPAA, SOC 2, PCI-DSS, EU AI Act).
* "Production-ready" — until something is actually in production, and then it is a fact about
  a deployment, not a property of the repository.
* "Enterprise-grade", "military-grade", "state-of-the-art".
* Complete PII detection in any language.
* Any figure carried over from a model card or a third-party leaderboard as though it
  described this system.
* Performance extrapolated from the laptop-class reference machine to production capacity.
* Audit-store growth or disk sizing extrapolated from the development database. It holds
  benchmark traffic, not user traffic, and the two have no relationship.

---

## Interview defence map

For each likely question, where the answer is written down. If a row cannot be answered from
the repository, that is a gap in the repository, not in the preparation.

| Likely question | Answer lives in |
|---|---|
| Why FastAPI/Python and not Go? | [ADR-001](adr/ADR-001-technology-stack.md) — and the GIL cost is named, not hidden |
| Why not build on LiteLLM? | [ADR-001](adr/ADR-001-technology-stack.md) |
| How do detectors plug in? | [05](05-detector-architecture.md), [ADR-002](adr/ADR-002-detector-plugin-architecture.md) |
| Two detectors disagree — what happens? | [06](06-policy-engine.md), "Conflict resolution" |
| Why not weighted score fusion? | [06](06-policy-engine.md), [21](21-open-decisions.md) OD-4 |
| What happens when a detector times out? | [ADR-007](adr/ADR-007-detector-failure-semantics.md) — including the availability cost accepted |
| Isn't fail-closed dangerous? | [ADR-007](adr/ADR-007-detector-failure-semantics.md), PM-9 in [20](20-risk-register.md) |
| Why no streaming? | [07](07-openai-compatible-api.md), [03](03-request-response-flow.md) — three strategies and their real costs |
| How is overhead measured? | [15](15-performance-benchmarking.md) — definition, four conditions, required metadata |
| Why does a mock upstream exist? | [ADR-009](adr/ADR-009-mock-upstream.md) — it is what makes the benchmark valid |
| How do you avoid tuning on test? | [13](13-evaluation-strategy.md) — content-derived splits |
| What's your false-positive rate? | The FPR row above — reported with its denominator, or "not yet measured" |
| How do you stop the firewall leaking prompts? | [10](10-security-model.md) — sink-level redaction, schema constraint, canary test |
| What does this NOT protect against? | [09](09-threat-model.md) — the scope table, including multi-turn and adaptive evasion |
| Why Presidio and not a cloud DLP API? | [ADR-005](adr/ADR-005-pii-detection-strategy.md), [21](21-open-decisions.md) OD-11 |
| Why OTel instead of the Langfuse SDK? | [ADR-008](adr/ADR-008-observability-and-privacy.md) — and why Langfuse's headline features are unusable here |
| Why is there no prompt in the audit trail? | [ADR-012](adr/ADR-012-persistence-and-retention.md) — with the investigation cost accepted |
| What would you do differently at scale? | [ADR-001](adr/ADR-001-technology-stack.md) revisit triggers, [21](21-open-decisions.md) OD-10 |
| What's the weakest part? | [20](20-risk-register.md) — the pre-mortem is the answer, and it is written down |

The last row matters most. A candidate who has written their own pre-mortem can answer
"what's weak about this" with specifics instead of modesty.

---

## Maintenance

* A row moves to **Produced** only when the artefact is committed and its path is filled in.
* If an artefact is regenerated, the claim is re-checked against the new numbers — including
  downward.
* Any README or CV text making a claim not in this table is a defect.
