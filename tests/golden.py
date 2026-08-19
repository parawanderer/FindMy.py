"""
Frozen structural transcripts of the formats this library writes.

**Why this exists.** Every other fixture here is built by the library's own writer at test
time and read back by its own reader, so the two can drift together and the suite stays
green -- and that is not hypothetical: the HMAC fixture in `test_pcs.py` built its digest
the same wrong way as the client, and could never have caught the bug it was written
around. Freezing the *output* is what makes that visible. A change to a writer moves a
digest here, and the diff is the question "did you mean to?".

**The digest is the assertion; the structure is for review.** A committed blob is
unreviewable -- anything can be hidden in it and nobody reads hex -- so a transcript shows
the shape in text: nesting, tags, lengths, field names. That makes a diff read `escrowedSPKI
grew 32 bytes` rather than forty lines of nothing. The transcript is *derived*, so it also
cannot be poisoned by hand: edit one and it stops matching what the builders produce.

**What it does not do.** It cannot tell you Apple changed something. Nothing offline can.
It tells a future contributor that what used to be produced is still produced, which is the
question somebody adding support for a new device actually needs answered.

Regenerate deliberately, and read the diff::

    UPDATE_GOLDEN=1 python -m pytest tests/test_golden.py
    git diff tests/golden/
"""

from __future__ import annotations

import hashlib
import itertools
import os
import plistlib
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence

GOLDEN_DIR = Path(__file__).parent / "golden"

UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"
"""Rewrite the transcripts instead of asserting against them."""

_DIGEST_CHARS = 16
"""Enough to pin a change, short enough to read in a diff."""


def digest(data: bytes) -> str:
    """Shorten a SHA-256 to something a person can compare by eye."""
    return hashlib.sha256(data).hexdigest()[:_DIGEST_CHARS]


def _indent(depth: int) -> str:
    return "  " * depth


# --- DER ---------------------------------------------------------------------------
#
# A deliberately separate reader from `findmy.cloudkit.der`, small enough to be obviously
# right: a transcript produced by the parser under test would agree with it by
# construction, which is the failure this file exists to catch.

_CLASS_NAMES = {0: "UNIVERSAL", 1: "APPLICATION", 2: "CONTEXT", 3: "PRIVATE"}
_UNIVERSAL_NAMES = {
    0x01: "BOOLEAN",
    0x02: "INTEGER",
    0x03: "BIT STRING",
    0x04: "OCTET STRING",
    0x05: "NULL",
    0x06: "OID",
    0x0C: "UTF8String",
    0x10: "SEQUENCE",
    0x11: "SET",
    0x13: "PrintableString",
    0x17: "UTCTime",
}


def _der_length(data: bytes, at: int) -> tuple[int, int]:
    """Read a length at `at`, returning it and the offset just past it."""
    first = data[at]
    if first < 0x80:
        return first, at + 1
    count = first & 0x7F
    return int.from_bytes(data[at + 1 : at + 1 + count], "big"), at + 1 + count


def _der_lines(data: bytes, depth: int) -> list[str]:
    lines: list[str] = []
    at = 0
    while at < len(data):
        tag = data[at]
        tag_class = tag >> 6
        constructed = bool(tag & 0x20)
        number = tag & 0x1F

        length, body_at = _der_length(data, at + 1)
        if body_at + length > len(data):
            # An element claiming more than remains. The caller turns this into a note
            # rather than a traceback -- it is what an ordinary non-key payload looks
            # like, and describing one should not be able to fail.
            msg = f"element claims {length} bytes, {len(data) - body_at} remain"
            raise ValueError(msg)
        body = data[body_at : body_at + length]

        if tag_class == 0:
            name = _UNIVERSAL_NAMES.get(number, f"tag {number}")
        else:
            name = f"[{_CLASS_NAMES[tag_class]} {number}]"

        lines.append(f"{_indent(depth)}{name} ({length})")
        if constructed:
            lines.extend(_der_lines(body, depth + 1))
        elif length:
            lines.append(f"{_indent(depth + 1)}sha256 {digest(body)}")

        at = body_at + length

    return lines


def der_transcript(data: bytes, depth: int = 1) -> list[str]:
    """Describe a DER structure as an indented tree, or say it is not one."""
    try:
        return _der_lines(data, depth)
    except (IndexError, KeyError, ValueError):
        return [f"{_indent(depth)}<not DER: {len(data)} bytes, sha256 {digest(data)}>"]


# --- property lists ----------------------------------------------------------------


def _value_lines(key: str, value: Any, depth: int) -> list[str]:  # noqa: ANN401, PLR0911
    prefix = f"{_indent(depth)}{key}"

    if isinstance(value, dict):
        lines = [f"{prefix}: dict ({len(value)})"]
        for name in sorted(value):
            lines.extend(_value_lines(name, value[name], depth + 1))
        return lines
    if isinstance(value, (bytes, bytearray)):
        # Never the value itself: some of these are key material, and a transcript is a
        # thing people paste into issues.
        return [f"{prefix}: bytes ({len(value)}) sha256 {digest(bytes(value))}"]
    if isinstance(value, bool):
        return [f"{prefix}: bool {value}"]
    if isinstance(value, (int, float)):
        return [f"{prefix}: number {value}"]
    if isinstance(value, str):
        return [f"{prefix}: str ({len(value)}) {value!r}"]
    if isinstance(value, datetime):
        return [f"{prefix}: date {value.isoformat()}"]
    if isinstance(value, list):
        lines = [f"{prefix}: list ({len(value)})"]
        for index, item in enumerate(value):
            lines.extend(_value_lines(f"[{index}]", item, depth + 1))
        return lines
    return [f"{prefix}: {type(value).__name__}"]


def plist_transcript(data: bytes, depth: int = 1) -> list[str]:
    """Describe a property list by key, type and length -- never by value for bytes."""
    parsed = plistlib.loads(data)
    if not isinstance(parsed, dict):
        return _value_lines("<root>", parsed, depth)
    return [line for name in sorted(parsed) for line in _value_lines(name, parsed[name], depth)]


# --- framing -----------------------------------------------------------------------


def keyvault_transcript(
    data: bytes,
    *,
    header_length: int,
    sections: int,
    depth: int = 1,
) -> list[str]:
    """
    Describe KeyVault framing: total length, header, offsets, sections.

    Also a separate reader, and for the same reason as the DER one. It reads the framing
    the way the format defines it rather than the way this library happens to write it.

    :param header_length: **Not inferable from the bytes.** The framing does not say how
        long its header is, and a reader that guesses -- by looking for the first zero
        word, say -- finds the PBKDF2 iteration count instead and describes nonsense.
        Every caller of the real parser passes this too.
    :param sections: Likewise. There are `sections + 1` offsets, the last being the end
        of the body, so a reader cannot tell where the offsets stop by looking either.
    """
    total = int.from_bytes(data[0:4], "big")
    lines = [f"{_indent(depth)}total {total} (actual {len(data)})"]

    header = data[4 : 4 + header_length]
    lines.append(f"{_indent(depth)}header ({len(header)}) sha256 {digest(header)}")

    offsets_at = 4 + header_length
    offsets = [
        int.from_bytes(data[at : at + 4], "big")
        for at in range(offsets_at, offsets_at + (sections + 1) * 4, 4)
    ]
    body_at = offsets_at + (sections + 1) * 4
    lines.append(f"{_indent(depth)}offsets {offsets}")

    for index, (start, end) in enumerate(itertools.pairwise(offsets)):
        section = data[body_at + start : body_at + end]
        declared = int.from_bytes(section[0:4], "big") if len(section) >= 4 else 0
        padding = len(section) - 4 - declared
        note = f", padded by {padding}" if padding > 0 else ""
        lines.append(
            f"{_indent(depth + 1)}section {index}: declares {declared}, "
            f"occupies {len(section)}{note}, sha256 {digest(section[4 : 4 + declared])}",
        )

    return lines


# --- protobuf ----------------------------------------------------------------------


_WIRE_NAMES = {0: "varint", 1: "i64", 2: "bytes", 5: "i32"}

_READABLE_LIMIT = 40
"""Above this, a length-delimited field is summarised rather than shown."""


def _varint(data: bytes, at: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[at]
        value |= (byte & 0x7F) << shift
        at += 1
        if not byte & 0x80:
            return value, at
        shift += 7


def protobuf_transcript(data: bytes, depth: int = 1) -> list[str]:
    """
    Describe a protobuf message by field number, wire type and length.

    No schema: the point is what went on the wire, and a description via the generated
    classes would agree with them by construction. Short printable fields are shown --
    a model id is what a person is checking -- and everything else is a digest, since
    half of these are keys.
    """
    lines: list[str] = []
    at = 0
    try:
        while at < len(data):
            key, at = _varint(data, at)
            field, wire = key >> 3, key & 0x07
            name = f"{_indent(depth)}field {field} ({_WIRE_NAMES.get(wire, wire)})"

            if wire == 0:
                value, at = _varint(data, at)
                lines.append(f"{name} = {value}")
            elif wire == 2:
                length, at = _varint(data, at)
                body = data[at : at + length]
                at += length
                shown = f"sha256 {digest(body)}"
                if length <= _READABLE_LIMIT and body.isascii():
                    text = body.decode()
                    if text.isprintable():
                        shown = repr(text)
                lines.append(f"{name} ({length}) {shown}")
            elif wire in (1, 5):
                width = 8 if wire == 1 else 4
                lines.append(f"{name} sha256 {digest(data[at : at + width])}")
                at += width
            else:
                msg = f"unknown wire type {wire}"
                raise ValueError(msg)  # noqa: TRY301 -- caught below, into a note
    except (IndexError, ValueError):
        return [f"{_indent(depth)}<not protobuf: {len(data)} bytes, sha256 {digest(data)}>"]

    return lines


# --- the assertion -----------------------------------------------------------------


def transcript(name: str, data: bytes, body: Sequence[str] = ()) -> list[str]:
    """Wrap a structural description in the two lines that are the actual assertion."""
    return [
        name,
        f"  bytes  {len(data)}",
        f"  sha256 {hashlib.sha256(data).hexdigest()}",
        *(["  structure:"] if body else []),
        *body,
    ]


def assert_golden(name: str, lines: Sequence[str]) -> None:
    """
    Compare a transcript against its committed copy.

    :param name: File name under `tests/golden/`, without an extension.
    """
    path = GOLDEN_DIR / f"{name}.txt"
    text = "\n".join(lines).rstrip() + "\n"

    if UPDATE:
        GOLDEN_DIR.mkdir(exist_ok=True)
        path.write_text(text)
        return

    if not path.exists():
        msg = (
            f"No committed transcript for {name}. If this is a new one, write it with:\n"
            f"    UPDATE_GOLDEN=1 python -m pytest tests/test_golden.py\n"
            f"and read the diff before committing it."
        )
        raise AssertionError(msg)

    committed = path.read_text()
    if committed != text:
        msg = (
            f"{path} no longer describes what the library writes.\n\n"
            f"--- committed\n{committed}\n--- now\n{text}\n"
            f"If the change is intended, regenerate with:\n"
            f"    UPDATE_GOLDEN=1 python -m pytest tests/test_golden.py\n"
            f"and say in the commit message why the bytes moved. If it is not intended, "
            f"something that writes to Apple has changed shape without anyone deciding to."
        )
        raise AssertionError(msg)
