"""
Find My accessories, read straight from iCloud.

Implements Stage 6 of the Find My key-export protocol specification, and ties Stages 4 and
5 together into something usable: a logged-in account in, :class:`FindMyAccessory` out.

Stage 6 is deliberately thin. The plists a Mac writes are a local copy of these very
CloudKit records, so there is no format to design -- only key material to unwrap, one field
to rename, and records to join.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from google.protobuf.message import DecodeError

from findmy.accessory import FindMyAccessory, _extract_serial_from_stable_id

from .constants import (
    BEACON_STORE_ZONE,
    PRIVACY_SENSITIVE_RECORD_TYPES,
    RecordType,
    ValueType,
)
from .pcs import (
    FieldContext,
    MissingKeyError,
    PCSError,
    ShareProtection,
    decrypt_field,
    unwrap_protection,
    unwrap_zone,
)
from .proto import cloudkit_pb2 as ck
from .records import CloudKitRecord, records_from_changes

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from cryptography.hazmat.primitives.asymmetric import ec

    from findmy.reports.account import AsyncAppleAccount

    from .client import AsyncCloudKitClient

logger = logging.getLogger(__name__)

APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
"""CloudKit's own epoch. Whether a decrypted date uses it is not established."""

UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
"""The other candidate. See :func:`_as_datetime`."""

# The PCS master key is the tail of the stored private key, not the whole of it.
_MASTER_KEY_TAIL = 28


class BeaconExportError(PCSError):
    """Raised when a decrypted record cannot be turned into an accessory."""


# --------------------------------------------------------------------------------------
# Interpreting plaintext
# --------------------------------------------------------------------------------------
#
# A field's declared type says what shape its plaintext takes, and there are exactly two:
# ENCRYPTED_BYTES_TYPE decrypts to raw bytes with no wrapper, and everything else decrypts
# to an EncryptedValue message. So this is a branch on the declared type, not a search.


def _as_datetime(seconds: float) -> datetime:
    """
    Turn a decrypted date's double into a moment.

    Which epoch it counts from is not established -- CloudKit's own is 2001-01-01, but the
    Unix epoch is equally plausible for a value this deep in the format. Both are tried and
    the one that lands in a range an accessory could have been paired in wins; a value that
    fits neither is refused rather than exported, because a date wrong by thirty-one years
    is worse than a date that is missing.
    """
    now = datetime.now(tz=timezone.utc)
    earliest = datetime(2019, 1, 1, tzinfo=timezone.utc)  # Find My accessories postdate this

    for epoch in (APPLE_EPOCH, UNIX_EPOCH):
        try:
            moment = epoch + timedelta(seconds=seconds)
        except (OverflowError, ValueError):
            continue
        if earliest <= moment <= now + timedelta(days=1):
            return moment

    msg = (
        f"Decrypted date {seconds} is not a plausible pairing time under either epoch."
        " The epoch a decrypted date counts from is an open question."
    )
    raise BeaconExportError(msg)


def interpret_plaintext(value_type: int, data: bytes) -> Any:  # noqa: ANN401
    """
    Turn a decrypted field's bytes into the value its declared type promises.

    :param value_type: The field's declared type, which describes its plaintext.
    :param data: The decrypted bytes.
    :raises BeaconExportError: If the plaintext does not hold what its type promised.
    """
    if value_type in (ValueType.BYTES_TYPE, ValueType.ENCRYPTED_BYTES_TYPE):
        return data

    wrapper = ck.EncryptedValue()
    try:
        wrapper.ParseFromString(data)
    except DecodeError as e:
        msg = f"Decrypted field is not an EncryptedValue: {e}"
        raise BeaconExportError(msg) from None

    if value_type == ValueType.STRING_TYPE:
        if not wrapper.HasField("string_value"):
            msg = f"Field declares STRING_TYPE but its plaintext carries no string: {data!r}"
            raise BeaconExportError(msg)
        return wrapper.string_value

    if value_type == ValueType.INT64_TYPE:
        if not wrapper.HasField("signed_value"):
            msg = f"Field declares INT64_TYPE but its plaintext carries no integer: {data!r}"
            raise BeaconExportError(msg)
        return wrapper.signed_value

    if value_type == ValueType.DATE_TYPE:
        if not wrapper.HasField("date_value"):
            msg = f"Field declares DATE_TYPE but its plaintext carries no date: {data!r}"
            raise BeaconExportError(msg)
        return _as_datetime(wrapper.date_value.time)

    if value_type == ValueType.DOUBLE_TYPE:
        return (
            wrapper.date_value.time
            if wrapper.HasField("date_value")
            else float(
                wrapper.signed_value,
            )
        )

    # A type this library does not model. The wrapper is returned whole rather than
    # guessed at, so nothing is lost and nothing is invented.
    return wrapper


# --------------------------------------------------------------------------------------
# Decrypting a record
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DecryptedRecord:
    """A record whose fields have been decrypted and interpreted."""

    name: str
    record_type: str
    values: dict[str, Any]
    raw_values: dict[str, bytes] = field(default_factory=dict)
    """The decrypted bytes before interpretation, for a field this library misreads."""

    undecryptable: dict[str, str] = field(default_factory=dict)
    """Fields that could not be read, and why. Never silently dropped."""


def decrypt_record(
    record: CloudKitRecord,
    private_keys: Sequence[ec.EllipticCurvePrivateKey],
    *,
    allow_privacy_sensitive: bool = False,
) -> DecryptedRecord:
    """
    Decrypt every encrypted field of one record.

    :param record: The fetched record.
    :param private_keys: Keys from the `Manatee` keychain view.
    :param allow_privacy_sensitive: Decrypt record types this library otherwise refuses.
        `SafeLocation` holds the user's home and work coordinates; it arrives whether it
        is wanted or not, and discarding it is a decision rather than an omission.
    :raises MissingKeyError: If no local key protects this record.
    """
    if record.record_type in PRIVACY_SENSITIVE_RECORD_TYPES and not allow_privacy_sensitive:
        msg = (
            f"Refusing to decrypt a {record.record_type} record: it holds the user's own"
            " locations and nothing here has any use for it. Pass"
            " allow_privacy_sensitive=True to override."
        )
        raise BeaconExportError(msg)

    if record.protection_info is None:
        msg = f"Record {record.name} carries no protection info and cannot be decrypted"
        raise BeaconExportError(msg)

    unwrapped = unwrap_protection(ShareProtection.from_der(record.protection_info), private_keys)

    values: dict[str, Any] = {}
    raw_values: dict[str, bytes] = {}
    undecryptable: dict[str, str] = {}

    for name, field_value in record.fields.items():
        if not field_value.is_encrypted:
            values[name] = field_value.raw
            continue
        if field_value.raw is None:
            undecryptable[name] = "encrypted but carried no bytes"
            continue

        context = FieldContext(
            zone_name=record.zone_name,
            record_name=record.name,
            field_name=name,
        )
        try:
            plaintext = decrypt_field(field_value.raw, unwrapped, context)
        except PCSError as e:
            undecryptable[name] = str(e)
            continue

        raw_values[name] = plaintext
        try:
            values[name] = interpret_plaintext(field_value.value_type, plaintext)
        except BeaconExportError as e:
            undecryptable[name] = str(e)

    if undecryptable:
        logger.warning(
            "Record %s (%s): %d field(s) could not be read: %s",
            record.name,
            record.record_type,
            len(undecryptable),
            ", ".join(undecryptable),
        )

    return DecryptedRecord(
        name=record.name,
        record_type=record.record_type,
        values=values,
        raw_values=raw_values,
        undecryptable=undecryptable,
    )


# --------------------------------------------------------------------------------------
# Assembling accessories
# --------------------------------------------------------------------------------------


def accessory_from_record(
    beacon: DecryptedRecord,
    *,
    naming: DecryptedRecord | None = None,
    alignment: DecryptedRecord | None = None,
) -> FindMyAccessory:
    """
    Turn a decrypted `MasterBeaconRecord` into an accessory.

    :param beacon: The decrypted beacon record.
    :param naming: Its naming record, if it has one. Not every accessory does.
    :param alignment: Its key alignment record, if it has one.
    :raises BeaconExportError: If a field the accessory cannot do without is missing.
    """
    values = beacon.values

    private_key = _require_bytes(values, "privateKey", beacon)
    skn = _require_bytes(values, "sharedSecret", beacon)

    # The secondary secret is `sharedSecret2` here and `secondarySharedSecret` in the
    # plists a Mac writes: the one rename in the whole mapping. An iDevice carries
    # `secureLocationsSharedSecret` in its place.
    sks = values.get("sharedSecret2") or values.get("secureLocationsSharedSecret")
    if not isinstance(sks, bytes):
        msg = (
            f"Record {beacon.name} has neither sharedSecret2 nor"
            " secureLocationsSharedSecret; it cannot generate secondary keys"
        )
        raise BeaconExportError(msg)

    paired_at = values.get("pairingDate")
    if not isinstance(paired_at, datetime):
        msg = f"Record {beacon.name} has no readable pairingDate"
        raise BeaconExportError(msg)

    stable_identifier = values.get("stableIdentifier")
    serial_number = None
    if isinstance(stable_identifier, str):
        # CloudKit carries a single string where the plist carries a list of them.
        serial_number = _extract_serial_from_stable_id([stable_identifier])

    alignment_date = None
    alignment_index = None
    if alignment is not None:
        observed = alignment.values.get("lastIndexObservationDate")
        index = alignment.values.get("lastIndexObserved")
        if isinstance(observed, datetime) and isinstance(index, int):
            alignment_date, alignment_index = observed, index
        else:
            logger.warning(
                "Alignment record %s is unreadable; the accessory will start its key"
                " search from its pairing date instead",
                alignment.name,
            )

    return FindMyAccessory(
        master_key=private_key[-_MASTER_KEY_TAIL:],
        skn=skn,
        sks=sks,
        paired_at=paired_at,
        name=naming.values.get("name") if naming else None,
        model=values.get("model"),
        identifier=beacon.name,
        group_identifier=values.get("groupIdentifier"),
        serial_number=serial_number,
        alignment_date=alignment_date,
        alignment_index=alignment_index,
    )


def _require_bytes(values: dict[str, Any], name: str, record: DecryptedRecord) -> bytes:
    value = values.get(name)
    if not isinstance(value, bytes):
        msg = f"Record {record.name} has no readable {name}"
        raise BeaconExportError(msg)
    return value


@dataclass(frozen=True)
class RecordGroup:
    """
    One master beacon together with the records that describe it.

    What :func:`group_records` produces. Either companion may be absent, and both
    routinely are -- see there.
    """

    beacon: DecryptedRecord
    naming: DecryptedRecord | None = None
    alignment: DecryptedRecord | None = None


def group_records(records: Iterable[DecryptedRecord]) -> list[RecordGroup]:
    """
    Group decrypted records by the beacon each describes.

    The join everything downstream needs, on its own rather than buried inside
    :func:`accessories_from_records` -- which does exactly this and then throws the
    records away in favour of assembled accessories. A caller rendering plists needs the
    records themselves, and reimplementing the join is how the tolerate-absence rule gets
    quietly dropped.

    **The two join keys differ, and they look like they should not.** A naming record
    names its accessory in `associatedBeacon`; an alignment record names it in
    `beaconIdentifier`. Both point at a master beacon's own identifier.

    **Absence is the normal case, not the edge one.** One real account returned six master
    beacons, five naming records and four alignment records, so both companions are
    optional here and neither is an error. What that absence *means* differs, though:

    - **No naming record** is how a master beacon that is not a tag presents. The zone
      holds them for other things -- an account with no iPad produced an `iPad13,18`
      entry, unnamed and serial-less. :func:`accessories_from_records` discards those;
      this does not, because rendering them is a decision for the caller.
    - **No alignment record** is genuine optionality. Exports before format `0.0.2` carry
      none, and an accessory without one still works by probing, if slowly.

    :param records: Decrypted records of any type. Anything that is not one of the three
        is ignored rather than rejected.
    :returns: One group per master beacon, in the order the beacons arrived.
    """
    records = list(records)

    naming = {
        r.values.get("associatedBeacon"): r
        for r in records
        if r.record_type == RecordType.BEACON_NAMING
    }
    alignment = {
        r.values.get("beaconIdentifier"): r
        for r in records
        if r.record_type == RecordType.KEY_ALIGNMENT
    }

    return [
        RecordGroup(
            beacon=beacon,
            naming=naming.get(beacon.name),
            alignment=alignment.get(beacon.name),
        )
        for beacon in records
        if beacon.record_type == RecordType.MASTER_BEACON
    ]


def accessories_from_records(records: Iterable[DecryptedRecord]) -> list[FindMyAccessory]:
    """
    Join decrypted records into accessories.

    Joins on `associatedBeacon` and `beaconIdentifier`, via :func:`group_records`.

    **A master beacon with no naming record is not an accessory**, and is discarded rather
    than exported unnamed. The zone holds master beacons for things that are not tags --
    an account with no iPad produced an `iPad13,18` entry, unnamed and serial-less, dated
    the day of the export -- and resolving to a naming record is what distinguishes a tag
    from one of those. OpenTagViewer discards them for the same reason.

    Key alignment is genuinely optional and its absence is tolerated: exports before
    format `0.0.2` carry none, and an accessory without one still works by probing.
    """
    records = list(records)
    groups = group_records(records)

    # Counted from the records rather than the groups: "how many were fetched" and "how
    # many joined" are different numbers, and their difference is the diagnostic below.
    naming = [r for r in records if r.record_type == RecordType.BEACON_NAMING]
    alignment = [r for r in records if r.record_type == RecordType.KEY_ALIGNMENT]

    unnamed = [group.beacon for group in groups if group.naming is None]
    if unnamed:
        # Counted and named, never dropped quietly: "fewer accessories than expected" and
        # "some of those records were never accessories" look identical from the outside.
        logger.info(
            "Discarding %d master beacon(s) with no naming record, so not accessories: %s",
            len(unnamed),
            ", ".join(sorted(b.name for b in unnamed)),
        )

    # An accessory that gets no alignment record searches its whole history when located
    # -- tens of thousands of keys against a service answering a few hundred at a time --
    # and until now that happened with nothing said. A record that is *present but
    # unreadable* warns; one that simply did not join was silent, which is the worse of
    # the two because it looks like an accessory that never had one.
    named = [group for group in groups if group.naming is not None]
    unaligned = [group.beacon.name for group in named if group.alignment is None]
    if unaligned:
        logger.warning(
            "%d of %d accessor(ies) have no key-alignment record and will search their"
            " whole history when located: %s. %d alignment record(s) were fetched, so if"
            " that number is not zero these did not join.",
            len(unaligned),
            len(named),
            ", ".join(sorted(unaligned)),
            len(alignment),
        )

    accessories: list[FindMyAccessory] = []
    for group in named:
        try:
            accessories.append(
                accessory_from_record(
                    group.beacon,
                    naming=group.naming,
                    alignment=group.alignment,
                ),
            )
        except BeaconExportError:  # noqa: PERF203 -- per accessory, deliberately
            # take the rest of the export with it
            logger.exception("Skipping accessory %s", group.beacon.name)

    logger.info(
        "Assembled %d accessor%s from %d beacon, %d naming and %d alignment record(s)",
        len(accessories),
        "y" if len(accessories) == 1 else "ies",
        len(groups),
        len(naming),
        len(alignment),
    )
    return accessories


def to_owned_beacon_plist(beacon: DecryptedRecord) -> dict[str, Any]:
    """
    Render a decrypted beacon record in the layout a Mac's own cache uses.

    A compatibility path for tooling that already reads that layout, not the primary
    output: it predates fields the protocol now carries, and `groupIdentifier` in
    particular has nowhere to live in it. Prefer :meth:`FindMyAccessory.to_json`.

    Every key and secret is nested two levels deep rather than stored as bare bytes. That
    wrapping carries no information -- it is an artefact of the framework that wrote the
    cache -- but omitting it produces a file that fails to import for a reason nothing
    will explain.
    """
    values = beacon.values
    plist: dict[str, Any] = {"identifier": beacon.name}

    for source, target in (
        ("privateKey", "privateKey"),
        ("publicKey", "publicKey"),
        ("sharedSecret", "sharedSecret"),
        ("sharedSecret2", "secondarySharedSecret"),  # the one rename
        ("secureLocationsSharedSecret", "secureLocationsSharedSecret"),
    ):
        if isinstance(values.get(source), bytes):
            plist[target] = {"key": {"data": values[source]}}

    for name in ("productId", "vendorId", "model", "systemVersion", "batteryLevel"):
        if name in values:
            plist[name] = values[name]

    if "pairingDate" in values:
        plist["pairingDate"] = values["pairingDate"]
    if "isZeus" in values:
        plist["isZeus"] = bool(values["isZeus"])  # an integer here, a boolean there
    if "stableIdentifier" in values:
        # A single string in CloudKit, a list in the plist.
        plist["stableIdentifier"] = [values["stableIdentifier"]]

    # Real CloudKit system fields are not synthesised. A placeholder is preferred to
    # omitting the key, which is what the fixtures that read this format expect.
    plist["cloudKitMetadata"] = b""

    return plist


def to_beacon_naming_plist(naming: DecryptedRecord) -> dict[str, Any]:
    """
    Render a decrypted naming record in the layout a Mac's own cache uses.

    Nearly a pass-through: the fields map exactly, same names and same camelCase, with no
    renames and no type changes. What it adds is the record's own `identifier`, which is
    the record's name rather than one of its fields, and the `cloudKitMetadata`
    placeholder -- the same two additions :func:`to_owned_beacon_plist` makes.

    Every field is optional. `emoji` is genuinely absent on some real records, and a
    record missing one is not a broken record.

    **This names its accessory in `associatedBeacon`** -- not `beaconIdentifier`, which is
    what the alignment record uses for the same association. :func:`group_records` does
    the join if you would rather not.
    """
    values = naming.values
    plist: dict[str, Any] = {"identifier": naming.name}

    for name in ("name", "associatedBeacon", "roleId", "emoji"):
        if name in values:
            plist[name] = values[name]

    plist["cloudKitMetadata"] = b""

    return plist


def to_key_alignment_plist(alignment: DecryptedRecord) -> dict[str, Any]:
    """
    Render a decrypted key-alignment record in the layout a Mac's own cache uses.

    A pass-through on the same terms as :func:`to_beacon_naming_plist`, with `identifier`
    and `cloudKitMetadata` added.

    **`beaconIdentifier` is kept.** The plist layout drops it, carrying the association in
    a directory name instead, but a writer that discards it forces its caller to re-derive
    a grouping that was already in the data. Costing nothing to carry, and ignorable by a
    reader that does not want it, it stays.

    Worth exporting whenever one exists: an accessory imported without an alignment record
    starts its key search at index zero from its pairing date, which for an
    eighteen-month-old tag means deriving tens of thousands of keys and issuing hundreds
    of requests. That is an account-flagging risk rather than merely slow. Not every
    accessory has one, though, and absence is normal.
    """
    values = alignment.values
    plist: dict[str, Any] = {"identifier": alignment.name}

    for name in ("beaconIdentifier", "lastIndexObserved", "lastIndexObservationDate"):
        if name in values:
            plist[name] = values[name]

    plist["cloudKitMetadata"] = b""

    return plist


# --------------------------------------------------------------------------------------
# The whole flow
# --------------------------------------------------------------------------------------


class AsyncBeaconStore:
    """
    Reads Find My accessories out of a user's iCloud account.

    Fetching and decrypting are cleanly separable: every record in the zone can be
    retrieved with no keychain state at all, and the keys are needed only to read what has
    already been fetched. So :meth:`fetch_records` works on any logged-in account, while
    :meth:`fetch_accessories` additionally needs keys from the `Manatee` keychain view.
    """

    def __init__(
        self,
        account: AsyncAppleAccount,
        *,
        client: AsyncCloudKitClient | None = None,
    ) -> None:
        """
        Initialize the store.

        :param account: A logged-in account.
        :param client: A CloudKit client to use. One is created if not supplied.
        """
        from .client import AsyncCloudKitClient  # noqa: PLC0415 -- avoids a circular import

        self._account = account
        self._client = client or AsyncCloudKitClient(account)

    @property
    def client(self) -> AsyncCloudKitClient:
        """The underlying CloudKit client."""
        return self._client

    async def close(self) -> None:
        """Close the underlying client."""
        await self._client.close()

    async def fetch_records(
        self,
        *,
        continuation_token: bytes | None = None,
    ) -> list[CloudKitRecord]:
        """
        Fetch every record in the accessory zone, still encrypted.

        Needs no keychain state, no trust circle and no device passcode.

        :param continuation_token: Resume from a previous fetch rather than reading the
            whole zone. Persisting this token is how a later run notices a newly-paired
            accessory without refetching everything.
        """
        changes = [
            change
            async for change in self._client.iter_records(
                BEACON_STORE_ZONE,
                continuation_token=continuation_token,
            )
        ]
        return records_from_changes(changes, BEACON_STORE_ZONE)

    async def zone_keys(
        self,
        service_keys: Sequence[ec.EllipticCurvePrivateKey],
    ) -> list[ec.EllipticCurvePrivateKey]:
        """
        Unwrap the zone's protection structure into the keys its records use.

        **§4 step 0, and the level a reader is most likely to skip.** A record's keyset
        names a zone key rather than the keychain service key, so going straight from the
        keychain to a record finds nothing -- and reports it as the record being protected
        for someone else, which is indistinguishable from being locked out.

        :param service_keys: The keychain service keys, from Stage 3.
        :raises PCSError: If the zone is absent or carries no protection structure.
        """
        zones = await self._client.zone_retrieve()

        protection = next(
            (
                z.target_zone.protection_info.protection_info
                for z in zones
                if z.target_zone.zone_identifier.value.name == BEACON_STORE_ZONE
                and z.target_zone.HasField("protection_info")
            ),
            None,
        )
        if not protection:
            names = ", ".join(
                z.target_zone.zone_identifier.value.name or "<unnamed>" for z in zones
            )
            msg = (
                f"The {BEACON_STORE_ZONE} zone carries no protection structure, so there"
                f" are no keys for its records. Zones retrieved: {names or 'none'}"
            )
            raise PCSError(msg)

        return unwrap_zone(protection, service_keys)

    async def fetch_accessories(
        self,
        service_keys: Sequence[ec.EllipticCurvePrivateKey],
        *,
        continuation_token: bytes | None = None,
    ) -> list[FindMyAccessory]:
        """
        Fetch and decrypt the account's accessories.

        Two unwraps, not one: the zone's structure is opened with the keychain service
        keys, and the records are opened with what the zone yields.

        :param service_keys: Keys from the `Manatee` keychain view -- what Stage 3
            produces. **Not** the keys a record's keyset names; see :meth:`zone_keys`.
        :param continuation_token: As :meth:`fetch_records`.
        """
        keys = await self.zone_keys(service_keys)
        records = await self.fetch_records(continuation_token=continuation_token)
        return accessories_from_records(decrypt_records(records, keys))


def decrypt_records(
    records: Iterable[CloudKitRecord],
    private_keys: Sequence[ec.EllipticCurvePrivateKey],
) -> list[DecryptedRecord]:
    """
    Decrypt the records worth decrypting, and report rather than hide what was skipped.

    Records this client holds no key for are counted and reported, not raised on: a zone
    legitimately contains records protected for other parties.

    **The first missing key is reported in full**, not merely counted. "No key held" is the
    same count whether the records really belong to someone else or the keys are compared
    in the wrong encoding, and those lead in opposite directions -- so the one message that
    tells them apart must not be swallowed by the tally that summarises it.
    """
    wanted = {RecordType.MASTER_BEACON, RecordType.BEACON_NAMING, RecordType.KEY_ALIGNMENT}

    decrypted: list[DecryptedRecord] = []
    skipped: dict[str, int] = {}
    first_miss: str | None = None

    for record in records:
        if record.record_type not in wanted:
            skipped[record.record_type or "<untyped>"] = skipped.get(record.record_type, 0) + 1
            continue
        try:
            decrypted.append(decrypt_record(record, private_keys))
        except MissingKeyError as e:
            skipped["no key held"] = skipped.get("no key held", 0) + 1
            first_miss = first_miss or str(e)
        except PCSError:
            logger.exception("Could not decrypt %s (%s)", record.name, record.record_type)

    if skipped:
        logger.info("Skipped records: %s", ", ".join(f"{k} x{v}" for k, v in skipped.items()))

    if first_miss is not None:
        logger.info("Why no key was held: %s", first_miss)

    return decrypted
