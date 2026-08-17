# ADR-011: Split Environment Settings from YAML Policy

**Status:** Accepted
**Date:** 2026-08-17
**Phase:** 0

## Context

This system has four kinds of configuration that people habitually put in one file:

1. **Secrets** — upstream API key, database password.
2. **Deployment settings** — bind address, pool sizes, log level, upstream URL.
3. **Security policy** — thresholds, actions, which detectors run, failure modes.
4. **Environment variation** — differences between development, testing and production.

They have genuinely different requirements. Secrets must never reach disk or git. Policy
should be declarative, diffable, reviewable, and changeable by a security engineer who is not
going to edit Python. Deployment settings belong to whoever operates the container. And a
policy change is a **security-relevant change** that should be visible in a pull request.

A single `config.yaml` collapses all four, which is how API keys end up committed.

## Decision

**Two systems, structurally separated, never mixed.**

### Settings — environment variables only

`pydantic-settings`, prefix `FIREWALL_`, `.env` support for local development. Covers
secrets and deployment values. Secrets are typed `SecretStr` so accidental interpolation
renders `**********`.

```
FIREWALL_ENVIRONMENT=production
FIREWALL_UPSTREAM_BASE_URL=https://api.example.com/v1
FIREWALL_UPSTREAM_API_KEY=sk-...
FIREWALL_DATABASE_URL=postgresql+asyncpg://...
FIREWALL_CONTENT_LOGGING=none
```

### Policy — YAML, secrets structurally forbidden

```yaml
version: 1
inspect_roles: [user, tool]
policies:
  prompt_injection:
    enabled: true
    threshold: 0.85
    action: block
    on_error: fail_closed
    timeout_ms: 250
```

Validated by a Pydantic schema at startup. A **validator rejects any key matching
`*_key`, `*secret*`, `*token*`, `*password*`** anywhere in the document — so putting a
credential in policy YAML is a startup failure, not a code-review catch.

The SHA-256 of the **effective policy** becomes `policy_version`, recorded on every persisted decision, so
a historical block can be interpreted against the policy that actually produced it.

### Environment overlays

`config/environments/{development,testing,production}.yaml` carry **non-secret** setting
overrides. Precedence, highest first:

```
environment variable  >  environment overlay YAML  >  built-in default
```

### Safety behaviours

* Unknown detector names, out-of-range thresholds, unknown actions, and `action: redact` on a
  detector that cannot produce spans all fail at **startup**. A policy error must never be a
  runtime surprise.
* `content_logging=full` is **downgraded to `hash` when `environment=production`**, in code.
* Every `fail_open` detector is named in a startup warning (ADR-007).
* Effective configuration is logged at startup with secrets masked — an operator should be
  able to see what is actually in force without guessing.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| **One YAML for everything** | The path by which secrets reach git. Also makes policy review noisy with deployment detail. |
| **Environment variables for everything** | Policy is nested and multi-detector; expressing it as `FIREWALL_POLICY_PROMPT_INJECTION_THRESHOLD` is unreadable, undiffable, and hostile to the security engineer who owns it. |
| **Policy in the database, edited via an admin UI** | Attractive for hot-reload and audit trails, and it makes the security policy mutable at runtime by whoever can reach the UI — a new and significant attack surface — while removing policy changes from code review. Revisit only with authentication, authorisation and change audit built for it. |
| **A policy DSL** | Rejected in ADR-003 for the same reason: expressiveness this system does not yet need, at the cost of a language to learn and debug. |
| **Hot-reload of the policy file** | Genuinely useful, and it introduces mid-request policy changes and a file-watching failure mode. Deferred to Phase 6 where it can be done with an atomic swap and a `policy_version` change recorded in the audit trail. |
| **`.env` files in production** | Fine for development; in production, secrets belong to the platform's secret manager, injected as environment variables. |

### Amendment (Phase 0 implementation)

`policy_version` is computed over the **canonical serialisation of the validated
`PolicyConfig`**, not over the raw file bytes as originally written. Hashing the bytes made
a comment or a reformat produce a new version, and made two semantically identical policies
hash differently — noise in exactly the field an auditor uses to correlate decisions. The
effective-policy hash changes if and only if behaviour changes.

Implementation: `PolicyConfig.version_hash`. Determinism, comment-insensitivity,
key-order-insensitivity and change-detection are covered by
`tests/unit/test_policy_version.py`.

## Consequences

### Positive
* Secrets cannot be committed via policy files — enforced by a validator, not a convention.
* Policy is a reviewable artefact: a threshold change shows up as a diff in a pull request,
  which is what makes it auditable.
* `policy_version` on every decision makes historical decisions interpretable.
* Misconfiguration fails at startup, when someone is watching, rather than at request time.
* Container-friendly: image plus environment variables, no config baked into layers.

### Negative / accepted costs
* Two places to look. A newcomer must learn which knob lives where; mitigated by
  `.env.example`, commented policy files, and the effective-configuration startup log.
* Policy changes require a restart until Phase 6.
* The secret-key validator is heuristic — it catches `openai_api_key`, not
  `my_special_value`. It is a safety net, not a guarantee, and `gitleaks` in CI backs it up.
* Environment overlays add a precedence rule people must remember.

### Revisit when
Per-tenant policy is needed (which pushes policy toward a datastore, with the authorisation
work that implies); or hot-reload lands in Phase 6.

## Verification

* `tests/unit/test_settings.py` — precedence order; production downgrades `full` content
  logging; secrets render masked when the settings object is logged or repr'd.
* `tests/unit/test_policy_config.py` — a policy YAML containing `api_key` fails to load;
  invalid thresholds, unknown detectors, unknown actions and span-less redaction all fail at
  startup.
* `tests/unit/test_policy_version.py` — `policy_version` matches the file hash and changes
  when the file changes.
* No `Settings` field is read from YAML, and no policy field is read from the environment —
  import/structure test.
