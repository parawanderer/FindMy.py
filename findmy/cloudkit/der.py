"""
A small DER reader, for the one part of this protocol that is not protobuf.

A record's protection structure is DER-encoded ASN.1 rather than protobuf -- the single
place in the whole flow where the encoding changes. Only what reading those structures
needs is implemented: definite-length elements, explicit context tags, and the handful of
universal types they use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from findmy.errors import UnhandledProtocolError

if TYPE_CHECKING:
    from collections.abc import Iterator

CLASS_UNIVERSAL = 0x00
CLASS_APPLICATION = 0x40
CLASS_CONTEXT = 0x80

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_SEQUENCE = 0x10
TAG_SET = 0x11
TAG_UTF8_STRING = 0x0C
TAG_GENERALIZED_TIME = 0x18


class DerError(UnhandledProtocolError):
    """Raised when a DER structure is not shaped the way it was expected to be."""


@dataclass(frozen=True)
class DerElement:
    """One tag-length-value element."""

    tag_class: int
    """`CLASS_UNIVERSAL`, `CLASS_APPLICATION` or `CLASS_CONTEXT`."""

    constructed: bool
    """Whether the content is itself a sequence of elements."""

    tag_number: int
    """The tag number, within its class."""

    content: bytes
    """The element's contents, with tag and length stripped."""

    raw: bytes = b""
    """
    The element's own bytes, tag and length included.

    Kept because the protection structure's HMAC is computed over the DER of two of its
    members. DER is canonical, so retaining the original encoding is equivalent to
    re-encoding it and cannot disagree with what the server signed.
    """

    def is_context(self, number: int) -> bool:
        """Whether this is context tag `number`."""
        return self.tag_class == CLASS_CONTEXT and self.tag_number == number

    def is_universal(self, number: int) -> bool:
        """Whether this is universal tag `number`."""
        return self.tag_class == CLASS_UNIVERSAL and self.tag_number == number

    def children(self) -> list[DerElement]:
        """Parse this element's content as a sequence of elements."""
        if not self.constructed:
            msg = f"Cannot read children of a primitive element (tag {self.tag_number})"
            raise DerError(msg)
        return parse_all(self.content)

    def unwrap(self) -> DerElement:
        """
        Step inside an explicitly tagged element.

        Explicit tagging wraps the real element in a constructed context tag, so reading
        the value means unwrapping one layer.
        """
        inner = self.children()
        if len(inner) != 1:
            msg = f"Expected exactly one element inside tag {self.tag_number}, got {len(inner)}"
            raise DerError(msg)
        return inner[0]

    def as_int(self) -> int:
        """Read this element as an INTEGER."""
        if not self.content:
            return 0
        return int.from_bytes(self.content, "big", signed=True)

    def as_bytes(self) -> bytes:
        """Read this element's content as raw bytes."""
        return self.content

    def as_str(self) -> str:
        """Read this element as a text string."""
        return self.content.decode("utf-8")


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    """Read a definite-form length, returning it and the offset past it."""
    if offset >= len(data):
        msg = "Truncated DER: no length byte"
        raise DerError(msg)

    first = data[offset]
    offset += 1

    if first < 0x80:
        return first, offset

    num_bytes = first & 0x7F
    if num_bytes == 0:
        msg = "Indefinite-length DER is not supported"
        raise DerError(msg)
    if offset + num_bytes > len(data):
        msg = "Truncated DER: length runs past the end"
        raise DerError(msg)

    return int.from_bytes(data[offset : offset + num_bytes], "big"), offset + num_bytes


def parse_one(data: bytes, offset: int = 0) -> tuple[DerElement, int]:
    """Parse one element, returning it and the offset just past it."""
    if offset >= len(data):
        msg = "Truncated DER: no tag byte"
        raise DerError(msg)

    start = offset
    identifier = data[offset]
    offset += 1

    tag_class = identifier & 0xC0
    constructed = bool(identifier & 0x20)
    tag_number = identifier & 0x1F

    if tag_number == 0x1F:  # high tag number form
        tag_number = 0
        while True:
            if offset >= len(data):
                msg = "Truncated DER: unterminated high tag number"
                raise DerError(msg)
            byte = data[offset]
            offset += 1
            tag_number = (tag_number << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break

    length, offset = _read_length(data, offset)
    if offset + length > len(data):
        msg = f"Truncated DER: element claims {length} bytes, {len(data) - offset} remain"
        raise DerError(msg)

    element = DerElement(
        tag_class=tag_class,
        constructed=constructed,
        tag_number=tag_number,
        content=data[offset : offset + length],
        raw=bytes(data[start : offset + length]),
    )
    return element, offset + length


def parse_all(data: bytes) -> list[DerElement]:
    """Parse a concatenation of elements until the data runs out."""
    return list(iter_elements(data))


def iter_elements(data: bytes) -> Iterator[DerElement]:
    """Iterate over a concatenation of elements."""
    offset = 0
    while offset < len(data):
        element, offset = parse_one(data, offset)
        yield element


def expect_application(data: bytes, tag_number: int) -> DerElement:
    """
    Parse an `[APPLICATION n] EXPLICIT` wrapper and return what is inside it.

    Application tag 1 is used by two different structures, told apart by where they
    appear rather than by their tag -- so a caller must say which one it expects rather
    than dispatching on the tag alone.
    """
    element, _ = parse_one(data)
    if element.tag_class != CLASS_APPLICATION or element.tag_number != tag_number:
        msg = (
            f"Expected an [APPLICATION {tag_number}] element, got class"
            f" 0x{element.tag_class:02x} tag {element.tag_number}"
        )
        raise DerError(msg)
    return element.unwrap()
