"""Tests for turning decrypted records into accessories (Stage 6)."""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from findmy.cloudkit import beacons, pcs
from findmy.cloudkit.beacons import (
    APPLE_EPOCH,
    UNIX_EPOCH,
    BeaconExportError,
    DecryptedRecord,
    accessories_from_records,
    accessory_from_record,
    decrypt_record,
    decrypt_records,
    interpret_plaintext,
    to_owned_beacon_plist,
)
from findmy.cloudkit.constants import RecordType, ValueType
from findmy.cloudkit.proto import cloudkit_pb2 as ck
from findmy.cloudkit.records import CloudKitRecord

from test_pcs import build_protection, wrap_master_key

PAIRED_AT = datetime(2024, 3, 1, 12, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------------------
# Interpreting plaintext
# --------------------------------------------------------------------------------------


def encrypted_value(**kwargs: object) -> bytes:
    """Build the wrapper a decrypted scalar field parses as."""
    return ck.EncryptedValue(**kwargs).SerializeToString()  # pyright: ignore [reportArgumentType]


def test_bytes_fields_pass_through_with_no_wrapper() -> None:
    # ENCRYPTED_BYTES_TYPE is the one type whose plaintext is raw. It is also the one
    # that carries the key material, which is why this is the unambiguous half.
    payload = bytes(range(32))

    assert interpret_plaintext(ValueType.ENCRYPTED_BYTES_TYPE, payload) == payload


def test_a_string_field_is_read_out_of_its_wrapper() -> None:
    assert interpret_plaintext(ValueType.STRING_TYPE, encrypted_value(string_value="AirTag")) == (
        "AirTag"
    )


def test_a_string_fields_plaintext_is_eight_bytes_for_airtag() -> None:
    # The arithmetic that established the wrapper's field numbers without a key: a
    # 38-byte ciphertext minus 30 bytes of overhead leaves tag + length + six characters.
    assert len(encrypted_value(string_value="AirTag")) == 8


def test_an_integer_field_is_read_out_of_its_wrapper() -> None:
    assert interpret_plaintext(ValueType.INT64_TYPE, encrypted_value(signed_value=76)) == 76


def test_an_integer_fields_plaintext_is_two_bytes() -> None:
    # A protobuf varint field carries no length prefix, which is why the smallest
    # scalars came back as 32-byte ciphertexts.
    assert len(encrypted_value(signed_value=1)) == 2


def test_a_date_is_read_out_of_its_nested_date_message() -> None:
    seconds = (PAIRED_AT - APPLE_EPOCH).total_seconds()
    plaintext = encrypted_value(date_value=ck.Date(time=seconds))

    assert interpret_plaintext(ValueType.DATE_TYPE, plaintext) == PAIRED_AT
    assert len(plaintext) == 11  # tag + length + a 9-byte Date holding a double


def test_a_date_is_also_read_if_it_counts_from_the_unix_epoch() -> None:
    # Which epoch a decrypted date uses is not established, so both are tried and
    # plausibility decides.
    seconds = (PAIRED_AT - UNIX_EPOCH).total_seconds()

    assert interpret_plaintext(
        ValueType.DATE_TYPE,
        encrypted_value(date_value=ck.Date(time=seconds)),
    ) == PAIRED_AT


def test_a_date_plausible_under_neither_epoch_is_refused() -> None:
    # A date wrong by thirty-one years is worse than a date that is missing.
    with pytest.raises(BeaconExportError, match="plausible"):
        interpret_plaintext(ValueType.DATE_TYPE, encrypted_value(date_value=ck.Date(time=1e12)))


def test_a_future_date_is_refused() -> None:
    future = (datetime.now(tz=timezone.utc) + timedelta(days=400) - APPLE_EPOCH).total_seconds()

    with pytest.raises(BeaconExportError):
        interpret_plaintext(ValueType.DATE_TYPE, encrypted_value(date_value=ck.Date(time=future)))


def test_plaintext_that_is_not_a_wrapper_at_all_is_reported() -> None:
    with pytest.raises(BeaconExportError):
        interpret_plaintext(ValueType.STRING_TYPE, b"\xff\xfe\xfd\xfc")


def test_a_wrapper_missing_the_value_its_type_promised_is_reported() -> None:
    with pytest.raises(BeaconExportError, match="carries no string"):
        interpret_plaintext(ValueType.STRING_TYPE, encrypted_value(signed_value=1))


# --------------------------------------------------------------------------------------
# Building an accessory
# --------------------------------------------------------------------------------------


def beacon_record(
    name: str = "BEACON-1",
    *,
    secondary_field: str = "sharedSecret2",
    extra: dict | None = None,
) -> DecryptedRecord:
    values = {
        "privateKey": bytes(range(32)),
        "publicKey": b"\x04" + bytes(range(64)),
        "sharedSecret": bytes(range(32, 64)),
        secondary_field: bytes(range(64, 96)),
        "pairingDate": PAIRED_AT,
        "model": "AirTag1,1",
        "productId": 1,
        "vendorId": 76,
        "isZeus": 0,
        "systemVersion": "2.0.61",
        "batteryLevel": 100,
        "stableIdentifier": "2006~#abcdef~#HXY1234ABCD",
        **(extra or {}),
    }
    return DecryptedRecord(name=name, record_type=RecordType.MASTER_BEACON, values=values)


def naming_record(beacon: str = "BEACON-1", label: str = "Keys") -> DecryptedRecord:
    """The record that makes a master beacon an accessory rather than a device."""
    return DecryptedRecord(
        name=f"NAMING-{beacon}",
        record_type=RecordType.BEACON_NAMING,
        values={"associatedBeacon": beacon, "name": label},
    )


def test_accessory_takes_the_master_key_from_the_tail_of_the_private_key() -> None:
    record = beacon_record()
    accessory = accessory_from_record(record)

    assert accessory.master_key == record.values["privateKey"][-28:]
    assert accessory.skn == record.values["sharedSecret"]
    assert accessory.sks == record.values["sharedSecret2"]
    assert accessory.paired_at == PAIRED_AT


def test_the_secondary_secret_is_renamed_from_shared_secret_2() -> None:
    # The one rename in the whole mapping.
    accessory = accessory_from_record(beacon_record())

    assert accessory.sks == bytes(range(64, 96))


def test_an_idevice_uses_the_secure_locations_secret_instead() -> None:
    record = beacon_record(secondary_field="secureLocationsSharedSecret")

    assert accessory_from_record(record).sks == bytes(range(64, 96))


def test_a_record_with_neither_secondary_secret_is_refused() -> None:
    record = beacon_record()
    del record.values["sharedSecret2"]

    with pytest.raises(BeaconExportError, match="secureLocationsSharedSecret"):
        accessory_from_record(record)


def test_a_record_without_a_readable_pairing_date_is_refused() -> None:
    record = beacon_record()
    record.values["pairingDate"] = b"nonsense"

    with pytest.raises(BeaconExportError, match="pairingDate"):
        accessory_from_record(record)


def test_the_serial_is_extracted_from_a_stable_identifier_string() -> None:
    # CloudKit carries a single string where the plist carries a list of them.
    assert accessory_from_record(beacon_record()).serial_number == "HXY1234ABCD"


def test_the_group_identifier_survives_which_the_plist_format_cannot_carry() -> None:
    record = beacon_record(extra={"groupIdentifier": "GROUP-7"})

    assert accessory_from_record(record).group_identifier == "GROUP-7"


def test_a_naming_record_supplies_the_accessory_name() -> None:
    naming = DecryptedRecord(
        name="NAME-1",
        record_type=RecordType.BEACON_NAMING,
        values={"name": "Keys", "associatedBeacon": "BEACON-1"},
    )

    assert accessory_from_record(beacon_record(), naming=naming).name == "Keys"


def test_an_alignment_record_avoids_searching_the_whole_key_history() -> None:
    # Without one, a freshly imported accessory starts at index 0 from its pairing date.
    observed = PAIRED_AT + timedelta(days=200)
    alignment = DecryptedRecord(
        name="ALIGN-1",
        record_type=RecordType.KEY_ALIGNMENT,
        values={
            "beaconIdentifier": "BEACON-1",
            "lastIndexObserved": 19200,
            "lastIndexObservationDate": observed,
        },
    )

    accessory = accessory_from_record(beacon_record(), alignment=alignment)

    assert accessory.get_min_index(observed) == 19200


def test_an_unreadable_alignment_record_degrades_rather_than_failing() -> None:
    alignment = DecryptedRecord(
        name="ALIGN-1",
        record_type=RecordType.KEY_ALIGNMENT,
        values={"beaconIdentifier": "BEACON-1", "lastIndexObserved": b"bad"},
    )

    accessory = accessory_from_record(beacon_record(), alignment=alignment)

    assert accessory.paired_at == PAIRED_AT


# --------------------------------------------------------------------------------------
# Joining records
# --------------------------------------------------------------------------------------


def test_records_are_joined_by_identifier_not_by_position() -> None:
    # The naming record for BEACON-2 arrives before the one for BEACON-1, so a join by
    # position would name them the wrong way round.
    records = [
        beacon_record("BEACON-1"),
        beacon_record("BEACON-2"),
        naming_record("BEACON-2", "Second"),
        naming_record("BEACON-1", "First"),
    ]

    accessories = {a.identifier: a for a in accessories_from_records(records)}

    assert accessories["BEACON-1"].name == "First"
    assert accessories["BEACON-2"].name == "Second"


def test_a_master_beacon_with_no_naming_record_is_not_an_accessory() -> None:
    # [observed] The zone holds master beacons for things that are not tags: an account
    # with no iPad produced an `iPad13,18` entry, unnamed and serial-less, dated the day
    # of the export. Resolving to a naming record is what tells a tag from one of those.
    assert accessories_from_records([beacon_record()]) == []


def test_discarded_beacons_are_named_rather_than_dropped_quietly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # "Fewer accessories than expected" and "some of those were never accessories" look
    # identical from the outside, so the difference has to be said.
    import logging  # noqa: PLC0415

    with caplog.at_level(logging.INFO, logger="findmy.cloudkit.beacons"):
        accessories_from_records([beacon_record("NOT-A-TAG")])

    assert "NOT-A-TAG" in caplog.text
    assert "no naming record" in caplog.text


def test_one_bad_accessory_does_not_take_the_rest_of_the_export_with_it() -> None:
    broken = beacon_record("BROKEN")
    del broken.values["sharedSecret"]

    accessories = accessories_from_records(
        [broken, beacon_record("FINE"), naming_record("BROKEN"), naming_record("FINE")],
    )

    assert [a.identifier for a in accessories] == ["FINE"]


def test_accessories_serialise_to_findmy_own_format() -> None:
    (accessory,) = accessories_from_records([beacon_record(), naming_record()])
    payload = accessory.to_json()

    assert payload["type"] == "accessory"
    assert payload["identifier"] == "BEACON-1"
    assert payload["serial_number"] == "HXY1234ABCD"


# --------------------------------------------------------------------------------------
# The compatibility plist layout
# --------------------------------------------------------------------------------------


def test_plist_nests_key_material_two_levels_deep() -> None:
    # Omitting the wrapping produces a file that fails to import for a reason nothing
    # will explain.
    plist = to_owned_beacon_plist(beacon_record())

    assert plist["privateKey"] == {"key": {"data": bytes(range(32))}}
    assert plist["sharedSecret"]["key"]["data"] == bytes(range(32, 64))


def test_plist_applies_the_one_rename() -> None:
    plist = to_owned_beacon_plist(beacon_record())

    assert "sharedSecret2" not in plist
    assert plist["secondarySharedSecret"]["key"]["data"] == bytes(range(64, 96))


def test_plist_turns_is_zeus_into_a_boolean_and_stable_id_into_a_list() -> None:
    plist = to_owned_beacon_plist(beacon_record())

    assert plist["isZeus"] is False
    assert plist["stableIdentifier"] == ["2006~#abcdef~#HXY1234ABCD"]


def test_plist_carries_a_cloudkit_metadata_placeholder_rather_than_omitting_the_key() -> None:
    assert "cloudKitMetadata" in to_owned_beacon_plist(beacon_record())


# --------------------------------------------------------------------------------------
# Decrypting whole records
# --------------------------------------------------------------------------------------


def make_encrypted_record(
    private_key: ec.EllipticCurvePrivateKey,
    master_key: bytes,
    fields: dict[str, tuple[int, bytes]],
    *,
    record_type: str = RecordType.MASTER_BEACON,
    name: str = "BEACON-1",
) -> tuple[CloudKitRecord, pcs.UnwrappedProtection]:
    """Build a record encrypted the way a real one is said to be."""
    ciphertext = wrap_master_key(private_key.public_key(), master_key)
    protection_der = build_protection(
        entries=[(pcs.compress_public_key(private_key.public_key()), ciphertext, None)],
        truncated_key_id=pcs.compute_key_id(master_key)[:4],
        version=5,
        hmac_master_key=master_key,
    )
    unwrapped = pcs.unwrap_protection(pcs.ShareProtection.from_der(protection_der), [private_key])

    record = ck.Record(
        etag="e",
        record_identifier=ck.RecordIdentifier(value=ck.Identifier(name=name)),
        type=ck.NameWrapper(name=record_type),
        protection_info=ck.ProtectionInfo(protection_info=protection_der),
    )
    for index, (field_name, (value_type, plaintext)) in enumerate(fields.items()):
        context = pcs.FieldContext(
            zone_name="BeaconStore",
            record_name=name,
            field_name=field_name,
        )
        sealed = pcs.encrypt_field(plaintext, unwrapped, context, iv=bytes([index]) * 12)
        record.record_field.append(
            ck.Record.Field(
                identifier=ck.NameWrapper(name=field_name),
                value=ck.Record.Value(type=value_type, bytes_value=sealed, is_encrypted=True),
            ),
        )

    return CloudKitRecord.from_proto(record, "BeaconStore"), unwrapped


def test_a_record_decrypts_field_by_field() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    seconds = (PAIRED_AT - APPLE_EPOCH).total_seconds()

    record, _ = make_encrypted_record(
        private_key,
        bytes(range(16)),
        {
            "privateKey": (ValueType.ENCRYPTED_BYTES_TYPE, bytes(range(32))),
            "model": (ValueType.STRING_TYPE, encrypted_value(string_value="AirTag1,1")),
            "pairingDate": (
                ValueType.DATE_TYPE,
                encrypted_value(date_value=ck.Date(time=seconds)),
            ),
        },
    )

    decrypted = decrypt_record(record, [private_key])

    assert decrypted.values["privateKey"] == bytes(range(32))
    assert decrypted.values["model"] == "AirTag1,1"
    assert decrypted.values["pairingDate"] == PAIRED_AT
    assert decrypted.undecryptable == {}


def test_a_safe_location_record_is_refused_by_default() -> None:
    # It holds the user's home and work coordinates and arrives whether wanted or not.
    private_key = ec.generate_private_key(ec.SECP256R1())
    record, _ = make_encrypted_record(
        private_key,
        bytes(range(16)),
        {"name": (ValueType.STRING_TYPE, encrypted_value(string_value="Home"))},
        record_type=RecordType.SAFE_LOCATION,
    )

    with pytest.raises(BeaconExportError, match="Refusing"):
        decrypt_record(record, [private_key])

    allowed = decrypt_record(record, [private_key], allow_privacy_sensitive=True)
    assert allowed.values["name"] == "Home"


def test_decrypt_records_skips_types_that_are_not_wanted() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    master = bytes(range(16))

    wanted, _ = make_encrypted_record(
        private_key,
        master,
        {"model": (ValueType.STRING_TYPE, encrypted_value(string_value="AirTag1,1"))},
    )
    unwanted, _ = make_encrypted_record(
        private_key,
        master,
        {"latitude": (ValueType.STRING_TYPE, encrypted_value(string_value="51.5"))},
        record_type=RecordType.SAFE_LOCATION,
        name="SAFE-1",
    )

    decrypted = decrypt_records([wanted, unwanted], [private_key])

    assert [d.name for d in decrypted] == ["BEACON-1"]


def test_a_record_we_hold_no_key_for_is_skipped_not_raised_on() -> None:
    # A zone legitimately contains records protected for other parties.
    ours = ec.generate_private_key(ec.SECP256R1())
    theirs = ec.generate_private_key(ec.SECP256R1())

    record, _ = make_encrypted_record(
        theirs,
        bytes(range(16)),
        {"model": (ValueType.STRING_TYPE, encrypted_value(string_value="AirTag1,1"))},
    )

    assert decrypt_records([record], [ours]) == []


def test_a_field_that_cannot_be_read_is_reported_rather_than_dropped() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    record, _ = make_encrypted_record(
        private_key,
        bytes(range(16)),
        {
            "model": (ValueType.STRING_TYPE, encrypted_value(string_value="AirTag1,1")),
            "pairingDate": (ValueType.DATE_TYPE, b"\xff\xfe\xfd\xfc"),
        },
    )

    decrypted = decrypt_record(record, [private_key])

    assert decrypted.values["model"] == "AirTag1,1"
    assert "pairingDate" in decrypted.undecryptable
    assert decrypted.raw_values["pairingDate"] == b"\xff\xfe\xfd\xfc"


def test_the_whole_flow_from_encrypted_records_to_an_accessory() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    master = bytes(range(16))
    seconds = (PAIRED_AT - APPLE_EPOCH).total_seconds()

    beacon, _ = make_encrypted_record(
        private_key,
        master,
        {
            "privateKey": (ValueType.ENCRYPTED_BYTES_TYPE, bytes(range(32))),
            "sharedSecret": (ValueType.ENCRYPTED_BYTES_TYPE, bytes(range(32, 64))),
            "sharedSecret2": (ValueType.ENCRYPTED_BYTES_TYPE, bytes(range(64, 96))),
            "pairingDate": (
                ValueType.DATE_TYPE,
                encrypted_value(date_value=ck.Date(time=seconds)),
            ),
            "model": (ValueType.STRING_TYPE, encrypted_value(string_value="AirTag1,1")),
        },
    )
    naming, _ = make_encrypted_record(
        private_key,
        master,
        {
            "name": (ValueType.STRING_TYPE, encrypted_value(string_value="Backpack")),
            "associatedBeacon": (
                ValueType.STRING_TYPE,
                encrypted_value(string_value="BEACON-1"),
            ),
        },
        record_type=RecordType.BEACON_NAMING,
        name="NAME-1",
    )

    accessories = accessories_from_records(decrypt_records([beacon, naming], [private_key]))

    assert len(accessories) == 1
    assert accessories[0].name == "Backpack"
    assert accessories[0].model == "AirTag1,1"
    assert accessories[0].master_key == bytes(range(32))[-28:]

    # And the keys it generates are real ones.
    assert len(accessories[0].keys_at(0)) == 3


def test_apple_epoch_is_2001_not_1970() -> None:
    assert beacons.APPLE_EPOCH.year == 2001


def test_a_missing_key_is_explained_once_and_not_only_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # "No key held" is the same count whether the records belong to someone else or the
    # keys were compared in the wrong encoding, and those lead in opposite directions. The
    # tally that summarises the failure must not swallow the message that explains it.
    import logging  # noqa: PLC0415

    ours = ec.generate_private_key(ec.SECP256R1())
    theirs = ec.generate_private_key(ec.SECP256R1())

    master = bytes(range(16))
    protection = build_protection(
        entries=[
            (pcs.compress_public_key(theirs.public_key()), wrap_master_key(theirs.public_key(), master), None),
        ],
        truncated_key_id=pcs.compute_key_id(master)[:4],
        version=5,
        hmac_master_key=master,
    )

    record = CloudKitRecord(
        name="a-record",
        zone_name="BeaconStore",
        record_type=RecordType.MASTER_BEACON,
        fields={},
        protection_info=protection,
        etag="",
    )

    with caplog.at_level(logging.INFO, logger="findmy.cloudkit.beacons"):
        decrypt_records([record], [ours])

    assert "Why no key was held" in caplog.text
    # The sizes are what distinguish "not for us" from "compared the wrong bytes".
    assert "bytes; the forms compared against are" in caplog.text
