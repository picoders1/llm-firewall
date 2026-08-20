"""The in-process safety net, behind the edge (ADR-025).

Two properties matter here and they pull in opposite directions. The limits have
to actually refuse traffic — and they have to refuse it *without* letting a
refusal become cheaper for the attacker than for the gateway. So most of these
tests check what a refusal costs: no upstream call, no detector run, no audit
row, no unbounded state.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from app.core.exceptions import UpstreamError
from app.middleware.admission import AT_CAPACITY_MESSAGE
from tests.conftest import CALLER_KEY, CHAT_BODY, TRUSTED_PEER, UNTRUSTED_PEER

pytestmark = pytest.mark.security

CHAT = "/v1/chat/completions"
AUTH = {"authorization": f"Bearer {CALLER_KEY}"}
WRONG = {"authorization": "Bearer fw-not-the-configured-key"}


# --- §7: authentication-failure flooding --------------------------------------


async def test_a_credential_guessing_flood_is_throttled(caller_client, upstream):
    """After the allowance the answer becomes 429, and — the point of the whole
    mechanism — it is produced *before* the credential comparison, so guessing
    costs a dictionary lookup rather than a SHA-256 and a scan of every digest."""
    async with caller_client(auth_failures_per_minute=3) as client:
        codes = [
            (await client.post(CHAT, json=CHAT_BODY, headers=WRONG)).status_code for _ in range(6)
        ]
    assert codes == [401, 401, 401, 429, 429, 429]
    assert upstream.call_count == 0


async def test_the_throttled_response_leaks_no_limiter_internals(caller_client):
    """It says *that* the client is limited, never how the limiter works.

    Concealing the throttle itself was considered and rejected: a client sending
    credentials it knows are wrong already knows why it is refused. What must not
    escape is the state — the count, the allowance, the window, the key.
    """
    async with caller_client(auth_failures_per_minute=1) as client:
        await client.post(CHAT, json=CHAT_BODY, headers=WRONG)
        throttled = await client.post(CHAT, json=CHAT_BODY, headers=WRONG)

    body = throttled.json()["error"]
    assert throttled.status_code == 429
    assert body["message"] == "Rate limit exceeded for this caller."
    assert int(throttled.headers["retry-after"]) >= 1
    assert set(body) == {"message", "type", "code", "request_id"}
    for leaked in ("127.0.0.1", "remaining", "window", "attempts", "x-real-ip"):
        assert leaked not in throttled.text.lower(), leaked


async def test_a_valid_credential_clears_an_accumulated_count(caller_client):
    async with caller_client(auth_failures_per_minute=3) as client:
        for _ in range(2):
            await client.post(CHAT, json=CHAT_BODY, headers=WRONG)
        assert (await client.post(CHAT, json=CHAT_BODY, headers=AUTH)).status_code == 200
        # The two earlier failures no longer count towards the allowance.
        codes = [
            (await client.post(CHAT, json=CHAT_BODY, headers=WRONG)).status_code for _ in range(3)
        ]
    assert codes == [401, 401, 401]


async def test_throttling_writes_no_audit_row(caller_client, audit):
    """§17. A client that can create a database row per refusal has a cheap way
    to fill an operator's disk — which would make the abuse protection into the
    abuse vector."""
    async with caller_client(auth_failures_per_minute=2) as client:
        for _ in range(30):
            await client.post(CHAT, json=CHAT_BODY, headers=WRONG)
    assert audit.traces == []


async def test_the_throttle_key_cannot_be_chosen_by_the_client(caller_client):
    """Evasion, not impersonation: if a client could pick its own key it would
    pick a new one every request and never reach the limit. The peer is
    untrusted here, so the headers are ignored and all six requests share one key.
    """
    async with caller_client(peer=UNTRUSTED_PEER, auth_failures_per_minute=2) as client:
        codes = []
        for index in range(5):
            response = await client.post(
                CHAT,
                json=CHAT_BODY,
                headers={
                    **WRONG,
                    "X-Real-IP": f"10.0.0.{index}",
                    "X-Forwarded-For": f"10.1.0.{index}",
                },
            )
            codes.append(response.status_code)
    assert codes == [401, 401, 429, 429, 429]


async def test_the_trusted_proxys_client_address_is_honoured(caller_client):
    """The control case: distinct clients behind the trusted edge are throttled
    independently, which is what makes the test above a statement about trust
    rather than about the header never being read."""
    async with caller_client(
        peer=TRUSTED_PEER,
        auth_failures_per_minute=1,
        trusted_proxies="127.0.0.1/32",
        console_auth_mode="disabled",
    ) as client:
        first = await client.post(CHAT, json=CHAT_BODY, headers={**WRONG, "X-Real-IP": "10.0.0.1"})
        again = await client.post(CHAT, json=CHAT_BODY, headers={**WRONG, "X-Real-IP": "10.0.0.1"})
        other = await client.post(CHAT, json=CHAT_BODY, headers={**WRONG, "X-Real-IP": "10.0.0.2"})
    assert (first.status_code, again.status_code, other.status_code) == (401, 429, 401)


async def test_the_throttle_is_off_by_default(caller_client, upstream):
    """Not enabled silently. A throttle keyed by address can catch a whole NAT'd
    office behind one key, so switching it on is a deployment decision."""
    async with caller_client() as client:
        codes = [
            (await client.post(CHAT, json=CHAT_BODY, headers=WRONG)).status_code for _ in range(8)
        ]
    assert set(codes) == {401}
    assert upstream.call_count == 0


# --- §10: global concurrency admission -----------------------------------------


async def test_the_process_refuses_beyond_its_in_flight_ceiling(caller_client, upstream):
    """One slow request occupies the only slot; the second is refused rather than
    queued. An unbounded queue in front of a bounded worker pool turns a burst
    into a memory problem instead of a rejection."""
    release = asyncio.Event()

    async def slow(payload):
        await release.wait()
        return await original(payload)

    async with caller_client(max_concurrent_requests=1) as client:
        original = upstream.chat_completions
        upstream.chat_completions = slow

        first = asyncio.create_task(client.post(CHAT, json=CHAT_BODY, headers=AUTH))
        await asyncio.sleep(0.05)
        second = await client.post(CHAT, json=CHAT_BODY, headers=AUTH)
        release.set()
        first_response = await first

    assert second.status_code == 503
    assert second.json()["error"]["message"] == AT_CAPACITY_MESSAGE
    assert second.headers["retry-after"] == "1"
    assert first_response.status_code == 200


async def test_a_slot_is_returned_even_when_the_handler_fails(caller_client, upstream):
    """Released in a `finally`. A leaked slot is permanent: the process converges
    on refusing everything while still reporting itself healthy, which is worse
    than having no ceiling at all."""
    async with caller_client(max_concurrent_requests=1) as client:
        upstream.fail_with = UpstreamError("the upstream model is unreachable")
        for _ in range(5):
            failed = await client.post(CHAT, json=CHAT_BODY, headers=AUTH)
            assert failed.status_code == 502
        upstream.fail_with = None
        assert (await client.post(CHAT, json=CHAT_BODY, headers=AUTH)).status_code == 200


async def test_probes_are_exempt_from_the_ceiling(caller_client, upstream):
    """An orchestrator that cannot reach `/ready` during a burst restarts or
    de-pools the instance, turning a load spike into an outage. The probe must
    report saturation, not be a casualty of it."""
    release = asyncio.Event()

    async def slow(payload):
        await release.wait()
        return await original(payload)

    async with caller_client(max_concurrent_requests=1) as client:
        original = upstream.chat_completions
        upstream.chat_completions = slow
        busy = asyncio.create_task(client.post(CHAT, json=CHAT_BODY, headers=AUTH))
        await asyncio.sleep(0.05)

        assert (await client.get("/health")).status_code == 200
        assert (await client.get("/ready")).status_code == 200
        # Everything else is refused while the slot is held.
        assert (await client.post(CHAT, json=CHAT_BODY, headers=AUTH)).status_code == 503

        release.set()
        await busy


async def test_admission_precedes_authentication(caller_client, upstream):
    """At capacity the answer is 503 for everyone, authenticated or not: the
    server has nothing to give either. Checking identity first would mean an
    anonymous flood still bought a credential comparison per request."""
    release = asyncio.Event()

    async def slow(payload):
        await release.wait()
        return await original(payload)

    async with caller_client(max_concurrent_requests=1, auth_failures_per_minute=1) as client:
        original = upstream.chat_completions
        upstream.chat_completions = slow
        busy = asyncio.create_task(client.post(CHAT, json=CHAT_BODY, headers=AUTH))
        await asyncio.sleep(0.05)

        anonymous = await client.post(CHAT, json=CHAT_BODY)
        release.set()
        await busy

    assert anonymous.status_code == 503
    assert upstream.call_count == 1


async def test_the_ceiling_is_off_by_default(caller_client):
    """Sizing it requires knowing the deployment's traffic and its CPU budget.
    A number invented here would be a guess that pages someone."""
    async with caller_client() as client:
        responses = await asyncio.gather(
            *(client.post(CHAT, json=CHAT_BODY, headers=AUTH) for _ in range(20))
        )
    assert {r.status_code for r in responses} == {200}


# --- §16: observability without cardinality hazards ---------------------------


async def test_the_metrics_never_carry_a_client_address(caller_client):
    async with caller_client(auth_failures_per_minute=1, max_concurrent_requests=64) as client:
        await client.post(CHAT, json=CHAT_BODY, headers=WRONG)
        await client.post(CHAT, json=CHAT_BODY, headers=WRONG)
        body = (await client.get("/metrics")).text

    assert "firewall_auth_failure_rate_limited_total 1.0" in body
    assert "firewall_active_requests" in body
    for forbidden in ("127.0.0.1", "10.0.0.", "X-Real-IP", CALLER_KEY):
        assert forbidden not in body, forbidden


async def test_the_throttle_log_never_carries_the_client_address(caller_client, capsys):
    """In a shared-egress deployment a client address is closer to personal data
    than to a useful operational signal, and it is unbounded either way."""
    async with caller_client(auth_failures_per_minute=1) as client:
        await client.post(CHAT, json=CHAT_BODY, headers=WRONG)
        await client.post(CHAT, json=CHAT_BODY, headers=WRONG)

    records = [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("{") and "caller_auth_throttled" in line
    ]
    assert records, "the throttle did not log at all"
    for record in records:
        serialised = json.dumps(record)
        assert "127.0.0.1" not in serialised
        assert "client" not in record
