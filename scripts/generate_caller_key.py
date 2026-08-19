#!/usr/bin/env python3
"""Mint a caller credential for `/v1/**` (ADR-024).

Prints two values with deliberately different destinations:

* the **raw key**, which goes to the calling application and nowhere else
* the **digest**, which goes in `FIREWALL_CALLER_API_KEYS` on the gateway

The gateway never sees the raw key at rest, so an environment dump, a
`docker inspect` or a misrouted log on the gateway side yields nothing a caller
could present.

This script *generates* rather than accepting a key someone chose, and that is
the security-relevant part. The gateway stores an unsalted SHA-256, which is
correct for a 256-bit random token and would be wrong for anything memorable —
there is no dictionary to run against `secrets.token_urlsafe(32)`. Letting an
operator supply "prod-key-2026" would quietly break that assumption while
producing a digest that looks identical.

    uv run python scripts/generate_caller_key.py web-app

Rotation is additive: configure both digests, move the caller to the new key,
then drop the old entry. Nothing here writes a file — the values are yours to
put in a secret manager, and a helper that "conveniently" appended to `.env`
would be a helper that commits credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import secrets
import sys

# Matches the gateway's own rule; a mismatch here would produce a credential the
# gateway then refuses at startup.
CALLER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
KEY_BYTES = 32


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "caller_id",
        help="identifier for the calling application, e.g. 'web-app' (lowercase, [a-z0-9._-])",
    )
    parser.add_argument(
        "--prefix",
        default="fw",
        help="human-readable key prefix, so a leaked token is recognisable in a log (default: fw)",
    )
    args = parser.parse_args(argv)

    if not CALLER_ID.match(args.caller_id):
        parser.error(
            f"{args.caller_id!r} is not a valid caller id: lowercase letters, digits, "
            "dot, dash or underscore, starting alphanumeric, 64 characters at most"
        )

    raw = f"{args.prefix}-{secrets.token_urlsafe(KEY_BYTES)}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    print(f"caller id     {args.caller_id}")
    print()
    print("--- give this to the calling application, once; it is not recoverable ---")
    print(f"  {raw}")
    print()
    print("--- put this on the gateway (secret manager / environment) ---")
    print(f"  FIREWALL_CALLER_API_KEYS={args.caller_id}:{digest}")
    print()
    print("Append further callers with commas. Never commit either value.")
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    sys.exit(main())
