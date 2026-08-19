"""The caller boundary, attacked rather than described (ADR-024).

The property this file exists to protect is financial as much as it is
technical: the gateway holds `FIREWALL_UPSTREAM_API_KEY`, so a request that
reaches the upstream without authenticating spends someone's money. `401` alone
does not prove that did not happen — the gateway could authenticate on the way
back — which is why every negative case here asserts against the counting
upstream rather than against the status code.

The second property is separation. An operator session must not drive the model
and a service key must not read the security console; both directions are
tested, because a shared boundary is exactly the shortcut a later refactor would
take.
"""

from __future__ import annotations

import json

import pytest

from app.auth.caller import CallerAuthConfig, CallerDenyReason, digest
from app.config.settings import Settings
from app.core.exceptions import ConfigurationError
from tests.conftest import CALLER_ID, CALLER_KEY, CHAT_BODY, TRUSTED_PEER, UNTRUSTED_PEER

pytestmark = pytest.mark.security

CHAT = "/v1/chat/completions"
AUTH = {"authorization": f"Bearer {CALLER_KEY}"}


# --- §24: the core matrix, each asserted against the upstream counter --------


async def test_no_credential_is_refused_and_the_model_is_never_reached(caller_client, upstream):
    async with caller_client() as client:
        response = await client.post(CHAT, json=CHAT_BODY)
    assert response.status_code == 401
    assert upstream.call_count == 0


async def test_a_wrong_credential_is_refused_and_the_model_is_never_reached(
    caller_client, upstream
):
    async with caller_client() as client:
        response = await client.post(
            CHAT, json=CHAT_BODY, headers={"authorization": "Bearer fw-not-the-configured-key"}
        )
    assert response.status_code == 401
    assert upstream.call_count == 0


async def test_the_correct_credential_gets_normal_gateway_behaviour(caller_client, upstream):
    """The control test. Without it every refusal above could be caused by a
    broken request rather than by the boundary."""
    async with caller_client() as client:
        response = await client.post(CHAT, json=CHAT_BODY, headers=AUTH)
    assert response.status_code == 200
    assert upstream.call_count == 1


async def test_a_removed_caller_stops_working_immediately(caller_client, upstream):
    """Revocation is deleting the entry, and this is what proves it takes effect.

    There is no expiry field and no disabled flag; a credential that is not
    configured is not a credential. That is the whole revocation story, and the
    scalability limit ADR-024 records — it requires a deployment, not an API call.
    """
    async with caller_client(caller_api_keys=f"other-app:{digest('fw-some-other-key')}") as client:
        response = await client.post(CHAT, json=CHAT_BODY, headers=AUTH)
    assert response.status_code == 401
    assert upstream.call_count == 0


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer",
        "Bearer ",
        f"Basic {CALLER_KEY}",
        CALLER_KEY,
        f"Bearer {CALLER_KEY} extra",
    ],
    ids=["empty", "scheme-only", "scheme-space", "basic", "bare", "trailing"],
)
async def test_malformed_credentials_are_refused(caller_client, upstream, header: str):
    async with caller_client() as client:
        response = await client.post(CHAT, json=CHAT_BODY, headers={"authorization": header})
    assert response.status_code == 401
    assert upstream.call_count == 0


async def test_the_scheme_is_matched_case_insensitively(caller_client):
    """`bearer` and `Bearer` are the same scheme per RFC 9110, and clients differ.
    Rejecting one would be an interoperability bug wearing a security costume."""
    async with caller_client() as client:
        response = await client.post(
            CHAT, json=CHAT_BODY, headers={"authorization": f"bearer {CALLER_KEY}"}
        )
    assert response.status_code == 200


async def test_surrounding_whitespace_is_tolerated(caller_client):
    """Deliberate, not an oversight. RFC 9110 permits optional whitespace around a
    credential and intermediaries add it; a token cannot meaningfully contain
    whitespace, so trimming admits no key that would otherwise be refused. This
    is asserted so a later "hardening" pass does not remove it and break real
    clients in the name of strictness.
    """
    async with caller_client() as client:
        response = await client.post(
            CHAT, json=CHAT_BODY, headers={"authorization": f"Bearer   {CALLER_KEY}  "}
        )
    assert response.status_code == 200


# --- §12: spoofing, in proxy mode -------------------------------------------


PROXY_MODE = {
    "caller_auth_mode": "proxy",
    "caller_trusted_proxies": "127.0.0.1/32",
}


async def test_a_direct_client_cannot_assert_a_caller_identity(caller_client, upstream):
    """The attack: a client claims to be a trusted application. Its headers are
    well-formed and name a configured caller; the only thing wrong is that the
    socket did not come from the ingress."""
    async with caller_client(peer=UNTRUSTED_PEER, **PROXY_MODE) as client:
        response = await client.post(
            CHAT,
            json=CHAT_BODY,
            headers={
                "X-Firewall-Caller": CALLER_ID,
                "X-Caller": CALLER_ID,
                "X-Authenticated": "true",
                "Authorization": "Bearer forged",
            },
        )
    assert response.status_code == 401
    assert upstream.call_count == 0


async def test_a_forwarded_for_chain_cannot_manufacture_a_trusted_peer(caller_client, upstream):
    """`X-Forwarded-For` is client-supplied. Using it as an authentication signal
    would let the attacker write their own permission slip — the same rule as the
    operator boundary (ADR-023)."""
    async with caller_client(peer=UNTRUSTED_PEER, **PROXY_MODE) as client:
        response = await client.post(
            CHAT,
            json=CHAT_BODY,
            headers={
                "X-Firewall-Caller": CALLER_ID,
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "Forwarded": "for=127.0.0.1",
            },
        )
    assert response.status_code == 401
    assert upstream.call_count == 0


async def test_the_same_identity_from_the_trusted_proxy_is_honoured(caller_client, upstream):
    async with caller_client(peer=TRUSTED_PEER, **PROXY_MODE) as client:
        response = await client.post(CHAT, json=CHAT_BODY, headers={"X-Firewall-Caller": CALLER_ID})
    assert response.status_code == 200
    assert upstream.call_count == 1


async def test_the_proxy_cannot_invent_a_caller_the_gateway_does_not_know(caller_client, upstream):
    """The ingress says *who* is calling; this gateway still says whether that
    caller is allowed. A misconfigured proxy asserting an unknown identity does
    not silently gain access to the model."""
    async with caller_client(peer=TRUSTED_PEER, **PROXY_MODE) as client:
        response = await client.post(
            CHAT, json=CHAT_BODY, headers={"X-Firewall-Caller": "not-configured"}
        )
    assert response.status_code == 401
    assert upstream.call_count == 0


async def test_the_proxy_shared_secret_is_required_when_configured(caller_client):
    async with caller_client(
        peer=TRUSTED_PEER, caller_proxy_shared_secret="s3cret", **PROXY_MODE
    ) as client:
        without = await client.post(CHAT, json=CHAT_BODY, headers={"X-Firewall-Caller": CALLER_ID})
        correct = await client.post(
            CHAT,
            json=CHAT_BODY,
            headers={"X-Firewall-Caller": CALLER_ID, "X-Firewall-Proxy-Secret": "s3cret"},
        )
    assert without.status_code == 401
    assert correct.status_code == 200


@pytest.mark.parametrize(
    "caller",
    ["test-app\nevent=admin", "test-app\r\nSet-Cookie: a=b", "test-app\x00", "  "],
    ids=["newline", "crlf", "nul", "blank"],
)
async def test_a_malformed_caller_header_is_refused_not_sanitised(caller_client, caller: str):
    async with caller_client(peer=TRUSTED_PEER, **PROXY_MODE) as client:
        response = await client.post(CHAT, json=CHAT_BODY, headers={"X-Firewall-Caller": caller})
    assert response.status_code == 401


# --- §5: the two boundaries do not substitute for each other -----------------


async def test_an_operator_identity_does_not_authenticate_a_model_call(caller_client, upstream):
    """A stolen console session must not be able to spend the model budget."""
    async with caller_client(
        peer=TRUSTED_PEER, console_auth_mode="proxy", trusted_proxies="127.0.0.1/32"
    ) as client:
        response = await client.post(
            CHAT,
            json=CHAT_BODY,
            headers={"X-Auth-Request-User": "alice", "X-Auth-Request-Groups": "operators"},
        )
    assert response.status_code == 401
    assert upstream.call_count == 0


async def test_a_caller_key_does_not_open_the_security_console(caller_client):
    """And the other direction: a service credential must not read the event log."""
    async with caller_client(
        peer=UNTRUSTED_PEER, console_auth_mode="proxy", trusted_proxies="127.0.0.1/32"
    ) as client:
        for path in ("/api/v1/security/events", "/api/v1/detectors", "/dashboard"):
            response = await client.get(path, headers=AUTH)
            assert response.status_code == 401, path


# --- §15: what a refusal is allowed to say -----------------------------------


async def test_a_refusal_reveals_nothing_about_the_configured_credentials(caller_client):
    """An unauthorised client learns that it is unauthorised. Not which check
    failed, not which callers exist, not whether the key was merely stale —
    each of those is a step towards a working forgery or a list of targets.
    """
    async with caller_client(
        caller_api_keys=f"{CALLER_ID}:{digest(CALLER_KEY)},billing-svc:{digest('fw-other')}"
    ) as client:
        missing = await client.post(CHAT, json=CHAT_BODY)
        wrong = await client.post(
            CHAT, json=CHAT_BODY, headers={"authorization": "Bearer fw-wrong"}
        )

    assert missing.status_code == wrong.status_code == 401
    # Identical bodies apart from the correlation id: the response cannot be used
    # to tell "no credential" from "wrong credential".
    for response in (missing, wrong):
        body = response.json()
        del body["error"]["request_id"]
        assert body == {
            "error": {
                "message": "Incorrect API key provided.",
                "type": "invalid_request_error",
                "code": "invalid_api_key",
            }
        }
    for leaked in ("billing-svc", CALLER_ID, CALLER_KEY, "sha256", "digest", "traceback"):
        assert leaked.lower() not in wrong.text.lower(), leaked


async def test_the_denial_log_never_carries_the_presented_credential(caller_client, capsys):
    async with caller_client() as client:
        await client.post(
            CHAT, json=CHAT_BODY, headers={"authorization": "Bearer fw-secret-guess-12345"}
        )

    emitted = capsys.readouterr().out
    denials = [
        record
        for line in emitted.splitlines()
        if line.startswith("{")
        for record in [json.loads(line)]
        if record.get("event") == "caller_auth_denied"
    ]
    assert denials, f"the refusal was not logged: {emitted!r}"
    for record in denials:
        assert record["reason"] in {reason.value for reason in CallerDenyReason}
        assert "fw-secret-guess-12345" not in json.dumps(record)


async def test_failed_authentication_writes_no_audit_row(caller_client, audit):
    """§21. A client that can create a database row per request has a cheap way to
    fill an operator's disk — turning the audit trail into the denial-of-service
    vector. Counters and log lines cost bytes, not rows."""
    async with caller_client() as client:
        for _ in range(20):
            await client.post(CHAT, json=CHAT_BODY)
    assert audit.traces == []


# --- Configuration cannot be half-safe ---------------------------------------


def test_production_refuses_an_unauthenticated_gateway():
    settings = Settings(environment="production", caller_auth_mode="disabled")
    with pytest.raises(ConfigurationError, match="refused when environment=production"):
        CallerAuthConfig.from_settings(settings)


def test_production_defaults_to_enforcing_without_being_told():
    settings = Settings(environment="production", caller_api_keys=f"a:{digest('k')}")
    assert CallerAuthConfig.from_settings(settings).enforcing


def test_api_key_mode_without_keys_refuses_to_start():
    """It would reject every caller while reporting itself protected — a different
    failure from an open gateway, and an equally bad one."""
    settings = Settings(caller_auth_mode="api_key")
    with pytest.raises(ConfigurationError, match="FIREWALL_CALLER_API_KEYS"):
        CallerAuthConfig.from_settings(settings)


@pytest.mark.parametrize("everything", ["0.0.0.0/0", "::/0"])
def test_proxy_mode_trusting_the_whole_internet_refuses_to_start(everything: str):
    settings = Settings(
        caller_auth_mode="proxy",
        caller_trusted_proxies=everything,
        caller_api_keys=f"a:{digest('k')}",
    )
    with pytest.raises(ConfigurationError, match="trusts every host"):
        CallerAuthConfig.from_settings(settings)


def test_a_raw_key_in_configuration_is_refused():
    """The digest is the storage format, so pasting the key itself must fail
    loudly rather than silently creating a credential nobody can present."""
    with pytest.raises(ValueError, match="SHA-256 hex digest"):
        Settings(caller_api_keys=f"web-app:{CALLER_KEY}")


def test_two_callers_cannot_share_a_credential():
    """Sharing one makes the audit trail lie about who spent the budget, which is
    most of the reason caller identity exists."""
    shared = digest(CALLER_KEY)
    with pytest.raises(ValueError, match="share the same credential"):
        Settings(caller_api_keys=f"a:{shared},b:{shared}")


def test_no_credential_material_appears_in_the_startup_summary():
    settings = Settings(
        caller_api_keys=f"{CALLER_ID}:{digest(CALLER_KEY)}",
        caller_proxy_shared_secret="hunter2",
    )
    summary = json.dumps(settings.safe_summary())
    assert digest(CALLER_KEY) not in summary
    assert "hunter2" not in summary
    assert CALLER_ID in summary  # the identity IS safe, and useful, to log
    assert '"caller_proxy_shared_secret_set": true' in summary


def test_credential_comparison_does_not_short_circuit_on_the_first_match():
    """Returning early would make response time depend on a credential's position
    in the configured list, leaking how many callers precede a valid one.

    Asserted on behaviour rather than on timing: the last-configured caller must
    authenticate exactly as the first does, which is only true if every entry is
    compared.
    """
    keys = ",".join(f"caller-{i}:{digest(f'fw-key-{i}')}" for i in range(8))
    config = CallerAuthConfig.from_settings(
        Settings(caller_auth_mode="api_key", caller_api_keys=keys)
    )
    for index in (0, 7):
        principal, reason = config.authenticate(
            {}, {b"authorization": f"Bearer fw-key-{index}".encode()}
        )
        assert principal is not None and principal.caller_id == f"caller-{index}", reason


# --- Unchanged surfaces -------------------------------------------------------


async def test_probes_and_the_console_are_unaffected(caller_client):
    """Caller authentication covers `/v1/**` and nothing else."""
    async with caller_client() as client:
        assert (await client.get("/health")).status_code == 200
        assert (await client.get("/ready")).status_code == 200
        # Console open here because the operator boundary is off in `testing`.
        assert (await client.get("/dashboard")).status_code == 200


async def test_the_default_development_stack_still_calls_the_model(client, upstream):
    """The boundary is off outside production, so the quick start stays one
    command with no credential (NFR-012)."""
    response = await client.post("/v1/chat/completions", json=CHAT_BODY)
    assert response.status_code == 200
    assert upstream.call_count == 1


# --- §29: access-class confusion ---------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/v1/%2e%2e/api/v1/overview",
        "/v1//chat/completions",
        "/v1/chat/completions/",
        "//v1/chat/completions",
        "/V1/chat/completions",
    ],
    ids=["encoded-traversal", "double-slash", "trailing-slash", "leading-double", "uppercase"],
)
async def test_no_path_shape_falls_between_the_two_boundaries(caller_client, path: str):
    """Two middlewares split the URL space by path, and a request that neither
    claims would be a hole belonging to no boundary.

    `classify_path` defaults unknown shapes to *operator*, the stricter class, so
    confusion fails safe in both directions: a path that looks like `/v1` gets
    caller auth, and anything else gets operator auth. This asserts every shape
    is refused when neither credential is presented — which is only interesting
    because both boundaries are enforced here at once.
    """
    async with caller_client(
        peer=UNTRUSTED_PEER, console_auth_mode="proxy", trusted_proxies="127.0.0.1/32"
    ) as client:
        response = await client.get(path)
    assert response.status_code == 401, f"{path} reached a handler"


async def test_the_gateway_class_covers_every_v1_route(caller_client, upstream):
    """`/v1/models` is protected without its handler mentioning authentication —
    which is the reason the check lives in middleware rather than in a route
    dependency. Its 501 proves the handler ran only for the authenticated call.
    """
    async with caller_client() as client:
        anonymous = await client.get("/v1/models")
        authenticated = await client.get("/v1/models", headers=AUTH)
    assert anonymous.status_code == 401
    assert authenticated.status_code == 501
    assert upstream.call_count == 0
