"""Text normalisation — the first line of defence against detector evasion.

Attackers routinely defeat literal-text matching with invisible characters
(``ig<ZWSP>nore``), Unicode confusables (Cyrillic ``i`` for Latin ``i``),
fullwidth forms, or by hiding instructions inside base64. Normalising once, in
one place, means every detector inherits the same evasion resistance instead of
each re-implementing it.

Two properties matter for correctness downstream:

* Normalisation is **index-preserving**: :class:`Normalized` carries a map from
  each normalised character back to the offset in the original text, so a
  detector may match on normalised text and still emit redaction spans that are
  valid against the bytes the client actually sent. The invariant is
  ``len(text) == len(offsets)`` and it is asserted at construction.
* Normalisation is **lossy by design** and therefore never used as the text that
  is forwarded upstream. It exists only for inspection.

See docs/adr/ADR-010-normalization-strategy.md.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

from app.core.types import DecodedSegment, TextSpan

# Characters that render as nothing (or as pure formatting) but break naive
# substring matching. Written as explicit code points: a security-relevant table
# has to be reviewable, and literal invisible characters in source are not.
_INVISIBLE = frozenset(
    {
        "­",  # soft hyphen
        "᠎",  # Mongolian vowel separator
        "​",  # zero-width space
        "‌",  # zero-width non-joiner
        "‍",  # zero-width joiner
        "‎",  # left-to-right mark
        "‏",  # right-to-left mark
        " ",  # line separator
        " ",  # paragraph separator
        "‪",  # left-to-right embedding
        "‫",  # right-to-left embedding
        "‬",  # pop directional formatting
        "‭",  # left-to-right override
        "‮",  # right-to-left override
        "⁠",  # word joiner
        "⁡",  # function application
        "⁢",  # invisible times
        "⁣",  # invisible separator
        "⁤",  # invisible plus
        "⁦",  # left-to-right isolate
        "⁧",  # right-to-left isolate
        "⁨",  # first strong isolate
        "⁩",  # pop directional isolate
        "⁪",  # inhibit symmetric swapping
        "⁫",  # activate symmetric swapping
        "⁬",  # inhibit Arabic form shaping
        "⁭",  # activate Arabic form shaping
        "⁮",  # national digit shapes
        "⁯",  # nominal digit shapes
        "﻿",  # zero-width no-break space / BOM
        "￹",  # interlinear annotation anchor
        "￺",  # interlinear annotation separator
        "￻",  # interlinear annotation terminator
    }
)

# Confusables that survive NFKC because they are distinct letters, not
# compatibility variants. Deliberately small and auditable rather than a full
# UTS-39 table: every entry here is a mapping we can justify and test. Expanding
# it should be driven by evaluation evidence, since over-folding raises the
# false-positive rate on legitimate non-English text (ADR-010).
_CONFUSABLES = {
    # Cyrillic → Latin
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",
    "һ": "h",
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    # Greek → Latin
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    "ο": "o",
    "α": "a",
    "ι": "i",
    "ν": "v",
    "ρ": "p",
    # Punctuation variants used to break literal matching
    "‐": "-",
    "‑": "-",
    "‒": "-",
    "–": "-",
    "—": "-",
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
}

_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_MIN_PRINTABLE_RATIO = 0.85
_MIN_DECODED_CHARS = 4


@dataclass(frozen=True, slots=True)
class Normalized:
    """Normalised text plus the map back to the original offsets.

    Invariant: ``len(text) == len(offsets)``, and ``offsets`` is non-decreasing.
    """

    text: str
    # offsets[i] is the index in the source text that produced text[i].
    offsets: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.text) != len(self.offsets):
            raise ValueError(
                f"offset map desynchronised: {len(self.text)} chars, {len(self.offsets)} offsets"
            )

    def source_span(self, start: int, end: int, label: str = "match") -> TextSpan | None:
        """Translate a half-open span in normalised space back to the source text.

        Returns ``None`` for an empty or out-of-range span. The result may cover
        more source characters than the normalised match did, because dropped
        invisible characters and collapsed whitespace live inside the range —
        which is the behaviour redaction wants: the hidden characters an attacker
        inserted are removed along with the match.
        """
        if start < 0 or end > len(self.offsets) or start >= end:
            return None
        return TextSpan(start=self.offsets[start], end=self.offsets[end - 1] + 1, label=label)


def normalize(text: str) -> Normalized:
    """Fold a string to its inspection form, preserving source offsets.

    Applies, per character: invisible-character removal, confusable folding,
    NFKC compatibility folding, casefolding; then collapses whitespace runs to a
    single space and trims the ends.

    NFKC is applied per character rather than to the whole string so the offset
    map stays exact. This forgoes cross-character composition (e.g. a combining
    accent merging with the preceding letter), which does not affect the
    instruction-phrase matching detectors rely on.
    """
    chars: list[str] = []
    offsets: list[int] = []

    for index, char in enumerate(text):
        if char in _INVISIBLE:
            continue
        folded = unicodedata.normalize("NFKC", _CONFUSABLES.get(char, char)).casefold()
        for out_char in folded:
            chars.append(out_char)
            offsets.append(index)

    # Collapse whitespace runs, then trim the ends. Both operations drop
    # characters, so text and offsets must be filtered together — trimming the
    # string alone (e.g. with str.strip) desynchronises the map and silently
    # invalidates every span derived from it.
    collapsed: list[str] = []
    collapsed_offsets: list[int] = []
    in_space = False
    for char, offset in zip(chars, offsets, strict=True):
        is_space = char.isspace()
        if is_space and in_space:
            continue
        collapsed.append(" " if is_space else char)
        collapsed_offsets.append(offset)
        in_space = is_space

    start = 1 if collapsed and collapsed[0] == " " else 0
    stop = len(collapsed) - 1 if len(collapsed) > start and collapsed[-1] == " " else len(collapsed)

    return Normalized(
        text="".join(collapsed[start:stop]),
        offsets=tuple(collapsed_offsets[start:stop]),
    )


def decode_embedded(text: str, *, max_segments: int = 8) -> tuple[DecodedSegment, ...]:
    """Surface base64-encoded payloads hidden in `text`.

    A candidate is accepted only if it decodes cleanly to mostly-printable text;
    this keeps random identifiers, hashes and binary data out of the results.
    `max_segments` bounds the work an attacker can force with a long body.

    Only one level of decoding is performed. Nested encodings are deliberately
    not followed: it is unbounded attacker-controlled work, and nesting is itself
    a signal a detector can score (ADR-010).
    """
    segments: list[DecodedSegment] = []
    for match in _BASE64_CANDIDATE.finditer(text):
        if len(segments) >= max_segments:
            break
        candidate = match.group(0)
        if len(candidate) % 4:
            continue
        try:
            raw = base64.b64decode(candidate, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if len(decoded) < _MIN_DECODED_CHARS:
            continue
        printable = sum(1 for c in decoded if c.isprintable() or c.isspace())
        if printable / len(decoded) < _MIN_PRINTABLE_RATIO:
            continue
        segments.append(
            DecodedSegment(
                encoding="base64",
                span=TextSpan(start=match.start(), end=match.end(), label="base64"),
                decoded=decoded,
            )
        )
    return tuple(segments)
