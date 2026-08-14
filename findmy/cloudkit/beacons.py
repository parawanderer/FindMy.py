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


def accessories_from_records(records: Iterable[DecryptedRecord]) -> list[FindMyAccessory]:
    """
    Join decrypted records into accessories.

    The three record types are **not** one-to-one -- six accessories with five naming
    records and four alignment records is an ordinary account -- so this joins on
    `associatedBeacon` and `beaconIdentifier` and tolerates absence. An accessory with no
    name is normal and is still exported.
    """
    records = list(records)

    beacons = [r for r in records if r.record_type == RecordType.MASTER_BEACON]
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

    accessories: list[FindMyAccessory] = []
    for beacon in beacons:
        try:
            accessories.append(
                accessory_from_record(
                    beacon,
                    naming=naming.get(beacon.name),
                    alignment=alignment.get(beacon.name),
                ),
            )
        except BeaconExportError:  # noqa: PERF203 -- one accessory failing must not
            # take the rest of the export with it
            logger.exception("Skipping accessory %s", beacon.name)

    logger.info(
        "Assembled %d accessor%s from %d beacon, %d naming and %d alignment record(s)",
        len(accessories),
        "y" if len(accessories) == 1 else "ies",
        len(beacons),
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

    async def fetch_accessories(
        self,
        private_keys: Sequence[ec.EllipticCurvePrivateKey],
        *,
        continuation_token: bytes | None = None,
    ) -> list[FindMyAccessory]:
        """
        Fetch and decrypt the account's accessories.

        :param private_keys: Keys from the `Manatee` keychain view. Obtaining them is
            Stage 3 of the specification and is not implemented by this library.
        :param continuation_token: As :meth:`fetch_records`.
        """
        records = await self.fetch_records(continuation_token=continuation_token)
        return accessories_from_records(decrypt_records(records, private_keys))


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
