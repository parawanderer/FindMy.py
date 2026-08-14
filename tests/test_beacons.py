"""Tests for turning decrypted records into accessories (Stage 6)."""

from __future__ import annotations

import struct
from dataclasses import replace
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
    build_plaintext,
    decrypt_record,
    decrypt_records,
    group_records,
    interpret_plaintext,
    to_beacon_naming_plist,
    to_key_alignment_plist,
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


def test_a_beacon_with_no_private_key_is_not_an_accessory() -> None:
    # The test is privateKey, and only privateKey. Without one the accessory cannot be
    # located, so exporting it produces an entry that can never do anything -- whatever
    # kind of thing the record turns out to be. It is also the rule the macOS exporter
    # has always used, so a bundle from this route holds what a bundle from a Mac holds.
    device = beacon_record("A-DEVICE")
    del device.values["privateKey"]

    assert accessories_from_records([device, naming_record("A-DEVICE")]) == []


def test_a_locatable_beacon_with_no_naming_record_is_still_exported() -> None:
    # The rule this replaced. A missing naming record is a reason to look at what came
    # back, not the test itself: an accessory that is genuinely nameless is an accessory.
    (accessory,) = accessories_from_records([beacon_record("NAMELESS")])

    assert accessory.identifier == "NAMELESS"


def test_a_nameless_beacon_is_reported_even_though_it_is_kept(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # It is how one account's stale device entry got noticed, so it is worth saying even
    # now that it decides nothing.
    import logging  # noqa: PLC0415

    with caplog.at_level(logging.INFO, logger="findmy.cloudkit.beacons"):
        accessories_from_records([beacon_record("NAMELESS")])

    assert "NAMELESS" in caplog.text
    assert "no naming record" in caplog.text


def test_discarded_beacons_are_named_rather_than_dropped_quietly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # "Fewer accessories than expected" and "some of those were never accessories" look
    # identical from the outside, so the difference has to be said.
    import logging  # noqa: PLC0415

    device = beacon_record("NOT-A-TAG")
    del device.values["privateKey"]

    with caplog.at_level(logging.INFO, logger="findmy.cloudkit.beacons"):
        accessories_from_records([device])

    assert "NOT-A-TAG" in caplog.text
    assert "no private key" in caplog.text


def test_a_discarded_beacon_reports_which_secondary_secret_it_carries(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # §2.3's discriminator: an accessory carries sharedSecret2, an iPhone, iPad or Mac
    # carries secureLocationsSharedSecret. It decides nothing -- privateKey does -- but
    # nothing else records it, because the discard happens before any secret is read, and
    # a client that drops these silently can never answer the question it raises.
    import logging  # noqa: PLC0415

    device = beacon_record("A-DEVICE", secondary_field="secureLocationsSharedSecret")
    device.values["model"] = "iPad13,18"
    del device.values["privateKey"]

    with caplog.at_level(logging.INFO, logger="findmy.cloudkit.beacons"):
        accessories_from_records([device])

    assert "secondary=secureLocationsSharedSecret" in caplog.text
    assert "iPad13,18" in caplog.text


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


def test_a_naming_record_maps_across_unchanged() -> None:
    # No renames and no type changes -- the one plist mapping that really is a
    # pass-through, which is worth pinning precisely because it looks too dull to test.
    naming = DecryptedRecord(
        name="NAMING-1",
        record_type=RecordType.BEACON_NAMING,
        values={
            "name": "Keys",
            "associatedBeacon": "BEACON-1",
            "roleId": 999,
            "emoji": "\U0001f511",
        },
    )

    assert to_beacon_naming_plist(naming) == {
        "identifier": "NAMING-1",
        "name": "Keys",
        "associatedBeacon": "BEACON-1",
        "roleId": 999,
        "emoji": "\U0001f511",
        "cloudKitMetadata": b"",
    }


def test_a_naming_records_identifier_is_the_records_own_name() -> None:
    # Not one of its fields. `associatedBeacon` names the accessory; `identifier` names
    # the naming record itself, and confusing the two makes every record claim to be its
    # own accessory.
    plist = to_beacon_naming_plist(naming_record("BEACON-1"))

    assert plist["identifier"] == "NAMING-BEACON-1"
    assert plist["associatedBeacon"] == "BEACON-1"


def test_a_naming_record_without_an_emoji_is_still_written() -> None:
    # [observed] Genuinely absent on real records. A missing field is not a broken record.
    plist = to_beacon_naming_plist(naming_record())

    assert "emoji" not in plist
    assert plist["name"] == "Keys"


def test_an_alignment_record_keeps_the_identifier_it_joins_on() -> None:
    # The plist layout drops it and carries the association in a directory name instead.
    # Keeping it costs nothing and saves the caller re-deriving a grouping it had.
    plist = to_key_alignment_plist(alignment_record())

    assert plist["beaconIdentifier"] == "BEACON-1"
    assert plist["identifier"] == "ALIGN-BEACON-1"
    assert plist["lastIndexObserved"] == 50_000


def test_an_alignment_record_missing_its_index_is_still_written() -> None:
    partial = DecryptedRecord(
        name="ALIGN-1",
        record_type=RecordType.KEY_ALIGNMENT,
        values={"beaconIdentifier": "BEACON-1"},
    )

    assert to_key_alignment_plist(partial) == {
        "identifier": "ALIGN-1",
        "beaconIdentifier": "BEACON-1",
        "cloudKitMetadata": b"",
    }


def test_the_writers_produce_the_keys_a_mac_actually_writes() -> None:
    # A real oracle, which most fixtures here are not. These key sets are read off
    # OpenTagViewer's committed macOS export (app/src/test/resources/19032025/), written
    # by Apple's own framework -- so they are what the format contains rather than what
    # this implementation believes it contains.
    beacon = to_owned_beacon_plist(beacon_record())
    naming = to_beacon_naming_plist(
        DecryptedRecord(
            name="NAMING-1",
            record_type=RecordType.BEACON_NAMING,
            values={
                "name": "cat",
                "associatedBeacon": "BEACON-1",
                "roleId": 999,
                "emoji": "\U0001f408",
            },
        ),
    )

    assert set(beacon) == {
        "batteryLevel", "cloudKitMetadata", "identifier", "isZeus", "model", "pairingDate",
        "privateKey", "productId", "publicKey", "secondarySharedSecret", "sharedSecret",
        "stableIdentifier", "systemVersion", "vendorId",
    }  # fmt: skip
    assert set(naming) == {
        "associatedBeacon", "cloudKitMetadata", "emoji", "identifier", "name", "roleId",
    }  # fmt: skip


def test_an_accessorys_model_is_empty_and_its_identity_is_the_product_ids() -> None:
    # [observed] The committed macOS export's AirTag carries model='' and identifies
    # itself through productId and vendorId. Devices do not: an unnamed master beacon in
    # a real zone carried model='iPad13,18', the <family><major>,<minor> form Apple
    # devices use. So the model alone nearly answers what an unnamed record is, and the
    # secondary-secret check of _describe_unnamed confirms rather than discovers.
    record = beacon_record(extra={"model": ""})

    plist = to_owned_beacon_plist(record)

    assert plist["model"] == ""
    assert plist["productId"] == 1
    assert plist["vendorId"] == 76


def test_both_new_writers_carry_the_metadata_placeholder() -> None:
    assert to_beacon_naming_plist(naming_record())["cloudKitMetadata"] == b""
    assert to_key_alignment_plist(alignment_record())["cloudKitMetadata"] == b""


# --------------------------------------------------------------------------------------
# Grouping, for a caller that wants the records rather than accessories
# --------------------------------------------------------------------------------------


def test_grouping_joins_on_two_differently_named_keys() -> None:
    # They look symmetrical and are not: a naming record says `associatedBeacon`, an
    # alignment record says `beaconIdentifier`, and both mean the master beacon's name.
    (group,) = group_records([beacon_record(), naming_record(), alignment_record()])

    assert group.naming is not None
    assert group.alignment is not None
    assert group.beacon.name == "BEACON-1"


def test_grouping_keeps_a_beacon_that_has_no_naming_record() -> None:
    # Where accessories_from_records discards it as not-a-tag. Rendering it is a decision
    # for the caller, so the join does not make it for them.
    (group,) = group_records([beacon_record("NOT-A-TAG")])

    assert group.beacon.name == "NOT-A-TAG"
    assert group.naming is None
    assert group.alignment is None


def test_grouping_pairs_each_beacon_with_its_own_records() -> None:
    groups = {
        g.beacon.name: g
        for g in group_records(
            [
                beacon_record("BEACON-1"),
                beacon_record("BEACON-2"),
                naming_record("BEACON-2", "Second"),
                alignment_record("BEACON-1"),
            ],
        )
    }

    assert groups["BEACON-1"].naming is None
    assert groups["BEACON-1"].alignment is not None
    assert groups["BEACON-2"].naming is not None
    assert groups["BEACON-2"].alignment is None


def test_grouping_ignores_record_types_it_knows_nothing_about() -> None:
    other = DecryptedRecord(name="X", record_type="SomethingElse", values={})

    assert len(group_records([beacon_record(), other])) == 1


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


def alignment_record(beacon: str = "BEACON-1") -> DecryptedRecord:
    """The record that stops an accessory searching its whole history."""
    return DecryptedRecord(
        name=f"ALIGN-{beacon}",
        record_type=RecordType.KEY_ALIGNMENT,
        values={
            "beaconIdentifier": beacon,
            "lastIndexObserved": 50_000,
            "lastIndexObservationDate": PAIRED_AT,
        },
    )


def test_an_accessory_with_no_alignment_record_is_named_not_merely_absent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Without one it searches its whole history when located -- tens of thousands of keys
    # against a service answering a few hundred at a time. An unreadable record warns; one
    # that simply did not join was silent, which looks like an accessory that never had
    # one rather than a join that failed.
    import logging  # noqa: PLC0415

    with caplog.at_level(logging.WARNING, logger="findmy.cloudkit.beacons"):
        accessories_from_records([beacon_record("TAG-1"), naming_record("TAG-1")])

    assert "TAG-1" in caplog.text
    assert "whole history" in caplog.text


def test_an_accessory_that_joined_its_alignment_record_is_not_warned_about(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging  # noqa: PLC0415

    records = [beacon_record("TAG-1"), naming_record("TAG-1"), alignment_record("TAG-1")]

    with caplog.at_level(logging.WARNING, logger="findmy.cloudkit.beacons"):
        accessories = accessories_from_records(records)

    assert len(accessories) == 1
    assert "whole history" not in caplog.text


def test_the_warning_says_how_many_alignment_records_were_fetched(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The difference between "this account has none" and "they did not join" is the whole
    # question, and a count of accessories without one does not answer it.
    import logging  # noqa: PLC0415

    records = [
        beacon_record("TAG-1"),
        naming_record("TAG-1"),
        alignment_record("SOMETHING-ELSE"),
    ]

    with caplog.at_level(logging.WARNING, logger="findmy.cloudkit.beacons"):
        accessories_from_records(records)

    assert "1 alignment record(s) were fetched" in caplog.text


# --------------------------------------------------------------------------------------
# Writing: renaming an accessory (S4 §4, S5 §6.1)
# --------------------------------------------------------------------------------------


def test_a_string_plaintext_is_wrapped_and_a_bytes_one_is_not() -> None:
    # The asymmetry interpret_plaintext reads back. Writing a bare string where the
    # wrapper belongs produces a field that decrypts cleanly and then fails to parse.
    wrapped = build_plaintext(ValueType.STRING_TYPE, "Keys")

    assert interpret_plaintext(ValueType.STRING_TYPE, wrapped) == "Keys"
    assert build_plaintext(ValueType.ENCRYPTED_BYTES_TYPE, b"raw") == b"raw"


def test_an_integer_plaintext_round_trips() -> None:
    wrapped = build_plaintext(ValueType.INT64_TYPE, 999)

    assert interpret_plaintext(ValueType.INT64_TYPE, wrapped) == 999


def test_a_value_of_the_wrong_python_type_is_refused() -> None:
    with pytest.raises(BeaconExportError, match="needs a string"):
        build_plaintext(ValueType.STRING_TYPE, 7)

    with pytest.raises(BeaconExportError, match="needs bytes"):
        build_plaintext(ValueType.ENCRYPTED_BYTES_TYPE, "not bytes")


def test_a_type_this_library_cannot_write_is_refused_rather_than_approximated() -> None:
    # A field written in a form Apple cannot read is worse than one this declines to
    # write, because only the second says so.
    with pytest.raises(BeaconExportError, match="does not build plaintext"):
        build_plaintext(ValueType.DATE_TYPE, PAIRED_AT)


def test_the_tag_precedes_the_ciphertext_as_the_layout_says() -> None:
    # Checked by slicing at the offsets the specification gives and decrypting with a
    # bare cipher, NOT by round-tripping through parse_encrypted_field. A writer and a
    # reader that both put the tag last agree with each other perfectly and produce
    # something no Apple device can read, so a round trip cannot detect this at all.
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: PLC0415

    master_key = bytes(range(16))
    private_key = ec.generate_private_key(ec.SECP256R1())
    _, unwrapped = make_encrypted_record(private_key, master_key, {})

    context = pcs.FieldContext(zone_name="BeaconStore", record_name="R", field_name="name")
    sealed = pcs.encrypt_field(b"the plaintext", unwrapped, context, iv=b"\x00" * 12)

    header_length = 4 + sealed[3]
    header = sealed[:header_length]
    body = sealed[header_length:]
    iv, tag, ciphertext = body[:12], body[12:24], body[24:]

    decryptor = Cipher(
        algorithms.AES(pcs.derive_encryption_key(master_key)),
        modes.GCM(iv, tag, min_tag_length=12),
    ).decryptor()
    decryptor.authenticate_additional_data(header + context.as_bytes())

    assert decryptor.update(ciphertext) + decryptor.finalize() == b"the plaintext"


def test_each_encryption_uses_a_fresh_nonce() -> None:
    # GCM under a repeated nonce and the same key leaks the plaintexts, and a record with
    # several encrypted fields is exactly where one gets reused by accident.
    master_key = bytes(range(16))
    private_key = ec.generate_private_key(ec.SECP256R1())
    _, unwrapped = make_encrypted_record(private_key, master_key, {})

    context = pcs.FieldContext(zone_name="Z", record_name="R", field_name="name")
    first = pcs.encrypt_field(b"same", unwrapped, context)
    second = pcs.encrypt_field(b"same", unwrapped, context)

    assert first != second


class FakeClient:
    """A CloudKit client that records what it was asked to save."""

    def __init__(self) -> None:
        self.saved: list[dict] = []

    async def zone_retrieve(self) -> list:
        return []

    async def record_save(self, record, **kwargs) -> object:  # noqa: ANN001, ANN003
        self.saved.append({"record": record, **kwargs})
        return record


def a_naming_record(
    master_key: bytes = bytes(range(16)),
) -> tuple[CloudKitRecord, ec.EllipticCurvePrivateKey]:
    """A fetched naming record, encrypted the way a real one is."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    record, _ = make_encrypted_record(
        private_key,
        master_key,
        {
            "name": (ValueType.STRING_TYPE, build_plaintext(ValueType.STRING_TYPE, "Old")),
            "associatedBeacon": (
                ValueType.STRING_TYPE,
                build_plaintext(ValueType.STRING_TYPE, "BEACON-1"),
            ),
        },
        record_type=RecordType.BEACON_NAMING,
        name="NAMING-1",
    )
    return record, private_key


def a_store(client: FakeClient) -> beacons.AsyncBeaconStore:
    store = object.__new__(beacons.AsyncBeaconStore)
    store._client = client  # noqa: SLF001
    return store


@pytest.mark.asyncio
async def test_only_a_naming_record_may_be_written() -> None:
    # A master beacon holds the accessory's key material and a botched write costs the
    # accessory; an alignment record is Apple's observation, not this client's to assert.
    store = a_store(FakeClient())
    record, private_key = a_naming_record()

    for record_type in (RecordType.MASTER_BEACON, RecordType.KEY_ALIGNMENT):
        wrong = replace(record, record_type=record_type)
        with pytest.raises(BeaconExportError, match="Only BeaconNamingRecord"):
            await store.save_naming_record(wrong, [private_key], name="New")


@pytest.mark.asyncio
async def test_a_field_the_record_does_not_carry_is_refused() -> None:
    # A field's declared type is what says how to encode its plaintext, and a field that
    # is not there has none to read.
    store = a_store(FakeClient())
    record, private_key = a_naming_record()

    with pytest.raises(BeaconExportError, match="carries no field"):
        await store.save_naming_record(record, [private_key], nickname="New")


@pytest.mark.asyncio
async def test_the_whole_record_is_sent_with_untouched_fields_unchanged() -> None:
    # Merging is the safety net, not the plan. associatedBeacon is the join key that makes
    # a naming record findable at all, and a rename must not disturb it.
    client = FakeClient()
    store = a_store(client)
    record, private_key = a_naming_record()
    before = record.fields["associatedBeacon"].raw

    await store.save_naming_record(record, [private_key], name="New")

    (call,) = client.saved
    sent = {f.identifier.name: f.value.bytes_value for f in call["record"].record_field}
    assert sent["associatedBeacon"] == before
    assert sent["name"] != record.fields["name"].raw


@pytest.mark.asyncio
async def test_the_new_value_is_encrypted_under_this_field_s_own_context() -> None:
    master_key = bytes(range(16))
    client = FakeClient()
    store = a_store(client)
    record, private_key = a_naming_record(master_key)

    await store.save_naming_record(record, [private_key], name="New")

    saved = CloudKitRecord.from_proto(client.saved[0]["record"], "BeaconStore")
    decrypted = decrypt_record(saved, [private_key])
    assert decrypted.values["name"] == "New"
    assert decrypted.values["associatedBeacon"] == "BEACON-1"


@pytest.mark.asyncio
async def test_the_save_presents_the_tag_the_record_currently_carries() -> None:
    # It is a lock. Presenting a stale one is a lost update rather than an error to retry.
    client = FakeClient()
    store = a_store(client)
    record, private_key = a_naming_record()
    record = replace(record, protection_info_tag="the-current-tag")

    await store.save_naming_record(record, [private_key], name="New")

    assert client.saved[0]["record_protection_info_tag"] == "the-current-tag"


# --------------------------------------------------------------------------------------
# The zone-level default keys (S5 §4 step 0's other branch)
# --------------------------------------------------------------------------------------


def test_a_pcs_key_selects_the_default_whose_key_id_it_prefixes() -> None:
    # pcsKey is a key-id PREFIX, not a key. It is the same comparison the encrypted-field
    # header makes, against the same derivation.
    keys = [bytes([1]) * 16, bytes([2]) * 16, bytes([3]) * 16]
    wanted = pcs.compute_key_id(keys[1])[:4]

    assert pcs.select_default_master_key(keys, wanted) == keys[1]


def test_a_pcs_key_matching_nothing_selects_nothing() -> None:
    assert pcs.select_default_master_key([bytes([1]) * 16], b"\xff\xff\xff\xff") is None


def test_no_pcs_key_is_unambiguous_only_when_there_is_one_default() -> None:
    # With one candidate there is nothing to choose between; with several, guessing would
    # surface as a wrong key rather than as a missing selector.
    only = bytes([1]) * 16

    assert pcs.select_default_master_key([only], b"") == only
    assert pcs.select_default_master_key([only, bytes([2]) * 16], b"") is None


def test_a_record_with_no_protection_falls_back_to_the_zone_default() -> None:
    master_key = bytes(range(16))
    private_key = ec.generate_private_key(ec.SECP256R1())
    record, _ = make_encrypted_record(
        private_key,
        master_key,
        {"name": (ValueType.STRING_TYPE, build_plaintext(ValueType.STRING_TYPE, "Keys"))},
        record_type=RecordType.BEACON_NAMING,
    )

    # As it would arrive with no structure of its own, naming the zone's default instead.
    stripped = replace(
        record,
        protection_info=None,
        pcs_key=pcs.compute_key_id(master_key)[:4],
    )

    decrypted = decrypt_record(stripped, [], default_master_keys=[master_key])

    assert decrypted.values["name"] == "Keys"


def test_a_record_with_no_protection_and_no_default_says_which_is_missing() -> None:
    record, _ = make_encrypted_record(ec.generate_private_key(ec.SECP256R1()), bytes(16), {})
    stripped = replace(record, protection_info=None)

    with pytest.raises(BeaconExportError, match="no recordProtectionInfo"):
        decrypt_record(stripped, [], default_master_keys=[])


def test_the_fallback_warns_that_it_has_never_run_for_real(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Shipping an unexercised branch is acceptable only because it is read-only and says
    # so. Without this line it is just an untested path.
    import logging  # noqa: PLC0415

    master_key = bytes(range(16))
    record, _ = make_encrypted_record(ec.generate_private_key(ec.SECP256R1()), master_key, {})
    stripped = replace(record, protection_info=None)

    with caplog.at_level(logging.WARNING, logger="findmy.cloudkit.beacons"):
        decrypt_record(stripped, [], default_master_keys=[master_key])

    assert "never run against a real account" in caplog.text


# --------------------------------------------------------------------------------------
# Finding a naming record by the accessory's own identifier
# --------------------------------------------------------------------------------------


class FetchingClient(FakeClient):
    """A client that also answers a fetch, so the identifier lookup has something to find."""

    def __init__(self, changes: list) -> None:
        super().__init__()
        self.changes = changes

    async def iter_records(self, zone_name, *, continuation_token=None):  # noqa: ANN001, ANN202, ARG002
        for change in self.changes:
            yield change


def a_store_with(records: list[CloudKitRecord]) -> beacons.AsyncBeaconStore:
    """A store whose fetch returns these records."""
    changes = [
        ck.RecordChange(record=record.source)
        for record in records
        if record.source is not None
    ]
    return a_store(FetchingClient(changes))


@pytest.mark.asyncio
async def test_a_naming_record_is_found_by_its_accessorys_identifier() -> None:
    # The lookup that lets a caller rename holding only what accessories() gave it.
    # associatedBeacon is encrypted, so finding one means fetching and decrypting.
    master_key = bytes(range(16))
    record, private_key = a_naming_record(master_key)
    store = a_store_with([record])

    found = await store.find_naming_record("BEACON-1", [private_key])

    assert found.name == record.name


@pytest.mark.asyncio
async def test_an_identifier_that_names_no_accessory_says_so() -> None:
    record, private_key = a_naming_record()
    store = a_store_with([record])

    with pytest.raises(BeaconExportError, match="no accessory with that identifier"):
        await store.find_naming_record("NOT-HERE", [private_key])


@pytest.mark.asyncio
async def test_an_accessory_present_but_unnamed_is_distinguished_from_an_absent_one() -> None:
    # The two lead in opposite directions: one is gone from the account, the other is
    # there and has no name to change.
    master_key = bytes(range(16))
    naming, private_key = a_naming_record(master_key)
    beacon, _ = make_encrypted_record(private_key, master_key, {}, name="LONELY")

    store = a_store_with([naming, beacon])

    with pytest.raises(BeaconExportError, match="carries no naming record"):
        await store.find_naming_record("LONELY", [private_key])


@pytest.mark.asyncio
async def test_two_naming_records_for_one_accessory_are_refused() -> None:
    # Never seen, and not something to pick between: writing the wrong one would change a
    # name that appears nowhere and leave the visible one alone.
    master_key = bytes(range(16))
    first, private_key = a_naming_record(master_key)
    second, _ = make_encrypted_record(
        private_key,
        master_key,
        {
            "name": (ValueType.STRING_TYPE, build_plaintext(ValueType.STRING_TYPE, "Other")),
            "associatedBeacon": (
                ValueType.STRING_TYPE,
                build_plaintext(ValueType.STRING_TYPE, "BEACON-1"),
            ),
        },
        record_type=RecordType.BEACON_NAMING,
        name="NAMING-2",
    )

    store = a_store_with([first, second])

    with pytest.raises(BeaconExportError, match="named by 2 records"):
        await store.find_naming_record("BEACON-1", [private_key])
