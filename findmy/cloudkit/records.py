"""
Reading values out of CloudKit records.

A record is a bag of named fields whose interesting members are ciphertext. This module
deals with the shape of that bag -- names, types, which fields are encrypted -- and stops
at the point where a key is needed. Decryption is :mod:`findmy.cloudkit.pcs`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from google.protobuf.message import DecodeError

from .constants import ValueType
from .proto import cloudkit_pb2 as ck

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

logger = logging.getLogger(__name__)

_WIRE_BYTES = 2


def iter_wire_fields(data: bytes) -> Iterator[tuple[int, int, bytes]]:  # noqa: C901, PLR0912
    """
    Walk a protobuf payload's top-level fields without knowing its schema.

    Yields `(field_number, wire_type, payload)`, the payload being meaningful only for
    length-delimited fields. Stops rather than raising when it runs off the end.

    This exists for the moment a message does not decode as expected. Several field
    numbers in this protocol were inferred rather than observed, and naming what actually
    arrived is worth more than any guess about why the guess was wrong -- it is how the
    record-sync response's undocumented fields were identified, and how a share entry's
    shape gets settled.
    """
    offset = 0
    while offset < len(data):
        tag = 0
        shift = 0
        while True:
            if offset >= len(data):
                return
            byte = data[offset]
            offset += 1
            tag |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7

        field_number, wire_type = tag >> 3, tag & 0x07

        if wire_type == _WIRE_BYTES:
            length = 0
            shift = 0
            while True:
                if offset >= len(data):
                    return
                byte = data[offset]
                offset += 1
                length |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
            payload = data[offset : offset + length]
            if len(payload) != length:
                return
            offset += length
            yield field_number, wire_type, payload
        elif wire_type == 0:  # varint
            while offset < len(data) and data[offset] & 0x80:
                offset += 1
            offset += 1
            yield field_number, wire_type, b""
        elif wire_type == 5:  # fixed32
            offset += 4
            yield field_number, wire_type, b""
        elif wire_type == 1:  # fixed64
            offset += 8
            yield field_number, wire_type, b""
        else:  # groups, or a malformed payload -- give up rather than guess
            return


@dataclass(frozen=True)
class RecordField:
    """One named field of a record, before any decryption has happened."""

    name: str
    """The field's name, e.g. `privateKey`."""

    value_type: int
    """
    What the field's PLAINTEXT is, as a :class:`.ValueType`.

    Not what is on the wire. An encrypted string field declares STRING_TYPE while carrying
    ciphertext, so this is a promise about what decryption will yield -- and, since the
    plaintext of everything but ENCRYPTED_BYTES_TYPE is a wrapper message, it is also what
    says whether there is a wrapper to unpack.
    """

    is_encrypted: bool
    """Whether :attr:`raw` is ciphertext. Branch on this, never on :attr:`value_type`."""

    raw: bytes | None
    """Ciphertext, if encrypted; otherwise the bytes value, if the field had one."""

    value: ck.Record.Value
    """The whole wire value, for a field this class does not model."""

    @property
    def type_name(self) -> str:
        """The value type's name, or its number if it is not one this library knows."""
        try:
            return ValueType(self.value_type).name
        except ValueError:
            return f"type {self.value_type}"


def plain_value(value: ck.Record.Value) -> object:
    """
    Read an unencrypted field's value, whichever typed member holds it.

    Records outside the accessory zone -- a key share, a view key -- carry their values in
    the clear, so there is a value to read rather than ciphertext to decrypt.
    """
    for name in ("string_value", "signed_value", "bytes_value", "double_value"):
        if value.HasField(name):
            return getattr(value, name)
    return None


def reference_name(value: ck.Record.Value) -> str:
    """
    Read the record name a reference points at.

    A reference's own wrapper tags are not specified, so rather than trusting a field
    number this scans its submessages for one that parses as a `RecordIdentifier` naming
    something. A wrong guess about the wrapper therefore costs nothing, where a hardcoded
    field number would yield an empty name and no indication why.
    """
    if not value.HasField("reference_value"):
        return ""

    data = value.reference_value

    reference = ck.Reference()
    try:
        reference.ParseFromString(data)
    except DecodeError:
        pass
    else:
        if reference.record_identifier.value.name:
            return reference.record_identifier.value.name

    for _, wire, payload in iter_wire_fields(data):
        if wire != 2:
            continue
        identifier = ck.RecordIdentifier()
        try:
            identifier.ParseFromString(payload)
        except DecodeError:
            continue
        if identifier.value.name:
            return identifier.value.name

    return ""


def named_fields(record: ck.Record) -> dict[str, object]:
    """
    Read a record's fields into a plain mapping of name to value.

    For a record whose members are addressed by name rather than by number -- which is how
    everything outside the accessory zone is shaped.
    """
    return {
        field.identifier.name: plain_value(field.value)
        for field in record.record_field
        if field.identifier.name
    }


@dataclass(frozen=True)
class CloudKitRecord:
    """A record as fetched, with its fields indexed by name."""

    name: str
    """The record's own identifier within its zone."""

    zone_name: str
    """
    The zone this record was fetched from.

    Carried because PCS authenticates a field against its zone, record and field names, so
    decryption needs a record's position and not only its bytes.
    """

    record_type: str
    """The record's type, e.g. `MasterBeaconRecord`."""

    fields: dict[str, RecordField]
    """The record's fields, keyed by name."""

    protection_info: bytes | None
    """
    The DER-encoded structure describing which key protects this record.

    Present on every record observed. Its absence means the record cannot be decrypted.
    """

    etag: str
    """Version tag, as CloudKit reports it."""

    @classmethod
    def from_proto(cls, record: ck.Record, zone_name: str) -> CloudKitRecord:
        """Build from a fetched record."""
        fields: dict[str, RecordField] = {}
        for field in record.record_field:
            name = field.identifier.name
            value = field.value

            raw: bytes | None = None
            if value.HasField("bytes_value"):
                raw = value.bytes_value

            if not name:
                logger.warning("Record %s carries a field with no name; skipping it", record.etag)
                continue

            fields[name] = RecordField(
                name=name,
                value_type=value.type,
                is_encrypted=value.is_encrypted,
                raw=raw,
                value=value,
            )

        protection = None
        if record.HasField("protection_info") and record.protection_info.protection_info:
            protection = record.protection_info.protection_info

        return cls(
            name=record.record_identifier.value.name,
            zone_name=zone_name or record.record_identifier.zone_identifier.value.name,
            record_type=record.type.name,
            fields=fields,
            protection_info=protection,
            etag=record.etag,
        )


def records_from_changes(
    changes: Iterable[ck.RecordChange],
    zone_name: str = "",
) -> list[CloudKitRecord]:
    """
    Turn fetched changes into records, dropping the ones that carry no record.

    A change need not carry a record -- a deletion does not -- so an implementation that
    assumes one is present will fail on an ordinary zone.

    :param changes: The fetched changes.
    :param zone_name: The zone they came from. Needed for decryption later; falls back to
        the zone named inside each record's own identifier.
    """
    records: list[CloudKitRecord] = []
    for change in changes:
        if not change.HasField("record"):
            logger.debug(
                "Change for %s carries no record; skipping",
                change.identifier.value.name or "<unnamed>",
            )
            continue

        record = CloudKitRecord.from_proto(change.record, zone_name)
        if not record.record_type and change.HasField("record_type"):
            # The record itself did not name its type, but the change did.
            record = CloudKitRecord(
                name=record.name,
                zone_name=record.zone_name,
                record_type=change.record_type.name,
                fields=record.fields,
                protection_info=record.protection_info,
                etag=record.etag,
            )
        records.append(record)

    return records
