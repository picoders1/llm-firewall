"""Request identity and content fingerprinting.

Content hashes let security events be correlated ("this exact payload was tried
47 times") without ever persisting the prompt itself. See
docs/10-security-model.md for the privacy trade-off, including the honest limit:
a hash proves sameness, not secrecy, so a low-entropy prompt can be confirmed by
an attacker who can guess and hash candidates.
"""

from __future__ import annotations

import hashlib
import uuid

_HASH_PREFIX_CHARS = 16
MAX_REQUEST_ID_CHARS = 128

# Explicit ASCII allowlist. `str.isalnum()` would be wrong here: it accepts
# Unicode digits and letters, which widens the surface beyond what the contract
# in docs/07-openai-compatible-api.md promises.
_ID_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_:.")


def new_request_id() -> str:
    return uuid.uuid4().hex


def content_hash(text: str) -> str:
    """Stable, truncated SHA-256 fingerprint of inspected content.

    Truncated to 64 bits: enough to correlate repeated attacks, short enough to
    stay readable in a log line, and not a record of the prompt.
    """
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:_HASH_PREFIX_CHARS]}"


def is_valid_request_id(value: str) -> bool:
    """Reject client-supplied correlation IDs that could poison the audit log.

    A client may propagate `X-Request-ID`, so it is untrusted input. Without this
    check a header containing a newline and a forged JSON object writes
    attacker-controlled records into the security log (FR-051).
    """
    return 0 < len(value) <= MAX_REQUEST_ID_CHARS and all(c in _ID_ALPHABET for c in value)
