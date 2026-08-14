"""
Tests for keychain items (Stage 3 §6.8.1).

The additional data is where this goes wrong, and every way it goes wrong is silent: a map
that keeps insertion order produces a stable, repeatable, wrong order; the `wrappedkey`
entry means a different thing from the `wrappedkey` field; and `encver` decides how many
entries there are at all. None of those announces itself -- they all surface as an
authentication failure with no diagnostic.
"""

from __future__ import annotations

import plistlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from findmy.cloudkit.proto import cloudkit_pb2 as ck
from findmy.cloudkit.records import CloudKitRecord, reference_name
from findmy.keychain.items import (
    SERVICE_KEY_TAG,
    ItemError,
    additional_data,
    decrypt_item,
    find_by_account,
    parent_key_uuid,
    payload_of,
    service_key_item,
    split_view_records,
    strip_padding,
)
from findmy.keychain.servicekey import (
    PRIVATE_KEY_V2_TAG,
    ServiceKeyError,
    service_keys_from_der,
)
from findmy.keychain.shares import ViewKeyring

PARENT_UUID = "11111111-2222-3333-4444-555555555555"
ITEM_NAME = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"


def a_reference(name: str) -> bytes:
    """A reference value naming a record."""
    return ck.Reference(
        record_identifier=ck.RecordIdentifier(value=ck.Identifier(name=name)),
    ).SerializeToString()


def a_record(name: str, record_type: str, **fields: object) -> CloudKitRecord:
    """Build a record whose members are addressed by name."""
    record = ck.Record(
        record_identifier=ck.RecordIdentifier(value=ck.Identifier(name=name)),
        type=ck.NameWrapper(name=record_type),
    )

    for field_name, value in fields.items():
        wire = ck.Record.Value()
        if field_name in ("parentkeyref", "item"):
            wire.reference_value = a_reference(str(value))
        elif isinstance(value, bytes):
            wire.bytes_value = value
        elif isinstance(value, bool):
            wire.signed_value = int(value)
        elif isinstance(value, int):
            wire.signed_value = value
        elif isinstance(value, float):
            wire.double_value = value
        else:
            wire.string_value = str(value)

        record.record_field.append(
            ck.Record.Field(identifier=ck.NameWrapper(name=field_name), value=wire),
        )

    return CloudKitRecord.from_proto(record, "Manatee")


def pad(plaintext: bytes) -> bytes:
    """Pad to a multiple of twenty with the 0x80 marker, as an item is padded."""
    padded = plaintext + b"\x80"
    while len(padded) % 20:
        padded += b"\x00"
    return padded


def an_item(
    top_level: bytes,
    item_dict: dict[str, object],
    *,
    encver: int = 1,
    gen: int = 1,
    extra: dict[str, object] | None = None,
) -> tuple[CloudKitRecord, ViewKeyring]:
    """Build an item record and the keyring that opens it, sealed as the real one is."""
    item_key = AESSIV.generate_key(512)
    wrapped = AESSIV(top_level).encrypt(item_key, None)

    record = a_record(
        ITEM_NAME,
        "item",
        wrappedkey=wrapped,
        parentkeyref=PARENT_UUID,
        encver=encver,
        gen=gen,
        uploadver="1",
        data=b"placeholder",
        **(extra or {}),
    )

    iv = bytes(range(16))
    headers = [iv, *additional_data(record, PARENT_UUID)]
    plaintext = pad(plistlib.dumps(item_dict, fmt=plistlib.FMT_BINARY))
    ciphertext = AESSIV(item_key).encrypt(plaintext, headers)

    sealed = a_record(
        ITEM_NAME,
        "item",
        wrappedkey=wrapped,
        parentkeyref=PARENT_UUID,
        encver=encver,
        gen=gen,
        uploadver="1",
        data=iv + ciphertext,
        **(extra or {}),
    )

    return sealed, ViewKeyring(by_uuid={PARENT_UUID: top_level}, by_slot={"tlk": top_level})


# --------------------------------------------------------------------------------------
# References
# --------------------------------------------------------------------------------------


def test_a_reference_yields_the_record_it_names() -> None:
    value = ck.Record.Value()
    value.reference_value = a_reference("the-target")

    assert reference_name(value) == "the-target"


def test_a_reference_whose_wrapper_tags_differ_is_still_read() -> None:
    # The wrapper's own field numbers are not specified, so the identifier is found by
    # scanning rather than by trusting field 1. A wrong guess must cost nothing.
    identifier = ck.RecordIdentifier(value=ck.Identifier(name="the-target"))
    value = ck.Record.Value()
    # Field 7, not 1.
    value.reference_value = b"\x3a" + bytes([len(identifier.SerializeToString())])
    value.reference_value += identifier.SerializeToString()

    assert reference_name(value) == "the-target"


def test_a_field_that_is_not_a_reference_names_nothing() -> None:
    value = ck.Record.Value()
    value.string_value = "not a reference"

    assert reference_name(value) == ""


def test_the_parent_key_is_read_from_the_reference_not_from_a_class_name() -> None:
    record = a_record(ITEM_NAME, "item", parentkeyref=PARENT_UUID)

    assert parent_key_uuid(record) == PARENT_UUID


# --------------------------------------------------------------------------------------
# The additional data
# --------------------------------------------------------------------------------------


def test_encver_one_passes_exactly_four_values_in_sorted_order() -> None:
    record = a_record(
        ITEM_NAME,
        "item",
        encver=1,
        gen=7,
        wrappedkey=b"the wrapped key",
        parentkeyref=PARENT_UUID,
        uploadver="1",
        data=b"x",
    )

    values = additional_data(record, PARENT_UUID)

    # Sorted by name: UUID, encver, gen, wrappedkey -- uppercase sorts first.
    assert values == [
        ITEM_NAME.encode(),
        (1).to_bytes(8, "little"),
        (7).to_bytes(8, "little"),
        PARENT_UUID.encode(),
    ]


def test_the_wrappedkey_entry_is_the_parent_uuid_not_the_wrapped_key() -> None:
    # The name means two different things one line apart, and using the field's value
    # produces an authentication failure with nothing to say why.
    record = a_record(
        ITEM_NAME,
        "item",
        encver=1,
        gen=1,
        wrappedkey=b"THE-ACTUAL-WRAPPED-KEY-BYTES",
        parentkeyref=PARENT_UUID,
    )

    values = additional_data(record, PARENT_UUID)

    assert PARENT_UUID.encode() in values
    assert b"THE-ACTUAL-WRAPPED-KEY-BYTES" not in values


def test_the_order_comes_from_sorting_and_not_from_insertion() -> None:
    # This is the trap: the names are discarded, so nothing downstream can detect a wrong
    # order. It is stable, repeatable, and wrong on every item.
    record = a_record(
        ITEM_NAME,
        "item",
        # Deliberately inserted in an order that is not the sorted one.
        wrappedkey=b"w",
        gen=2,
        encver=1,
        parentkeyref=PARENT_UUID,
    )

    values = additional_data(record, PARENT_UUID)

    assert values[0] == ITEM_NAME.encode()
    assert values[1] == (1).to_bytes(8, "little")
    assert values[2] == (2).to_bytes(8, "little")
    assert values[3] == PARENT_UUID.encode()


def test_encver_two_admits_the_other_fields_as_well() -> None:
    record = a_record(
        ITEM_NAME,
        "item",
        encver=2,
        gen=1,
        wrappedkey=b"w",
        parentkeyref=PARENT_UUID,
        data=b"x",
        uploadver="1",
        pcsservice=82,
        agrp="com.apple.ProtectedCloudStorage",
        vwht="Manatee",
    )

    values = additional_data(record, PARENT_UUID)

    assert b"com.apple.ProtectedCloudStorage" in values
    assert b"Manatee" in values
    assert (82).to_bytes(8, "little") in values


def test_the_reserved_names_do_not_join_a_second_time() -> None:
    # `uploadver` is on the record and is reserved, so it must not appear -- and `data`
    # certainly must not, since it is the ciphertext being authenticated.
    record = a_record(
        ITEM_NAME,
        "item",
        encver=2,
        gen=1,
        wrappedkey=b"w",
        parentkeyref=PARENT_UUID,
        data=b"THE-CIPHERTEXT",
        uploadver="THE-UPLOAD-VERSION",
    )

    values = additional_data(record, PARENT_UUID)

    assert b"THE-CIPHERTEXT" not in values
    assert b"THE-UPLOAD-VERSION" not in values


def test_server_set_fields_never_join() -> None:
    record = a_record(
        ITEM_NAME,
        "item",
        encver=2,
        gen=1,
        wrappedkey=b"w",
        parentkeyref=PARENT_UUID,
        server_wascurrent=1,
        labl="a label",
    )

    values = additional_data(record, PARENT_UUID)

    assert b"a label" in values
    assert len(values) == 5  # the four, plus labl -- not server_wascurrent


def test_a_double_is_cast_to_an_integer_first() -> None:
    record = a_record(
        ITEM_NAME,
        "item",
        encver=2,
        gen=1,
        wrappedkey=b"w",
        parentkeyref=PARENT_UUID,
        tomb=3.7,
    )

    values = additional_data(record, PARENT_UUID)

    assert (3).to_bytes(8, "little") in values


def test_a_negative_integer_does_not_raise() -> None:
    # As in §6.7.0's signature: a real record carries negatives, and raising here would
    # take down a whole view rather than one item.
    record = a_record(
        ITEM_NAME,
        "item",
        encver=1,
        gen=-1,
        wrappedkey=b"w",
        parentkeyref=PARENT_UUID,
    )

    values = additional_data(record, PARENT_UUID)

    assert b"\xff" * 8 in values


# --------------------------------------------------------------------------------------
# Padding
# --------------------------------------------------------------------------------------


def test_padding_is_stripped_back_to_the_marker() -> None:
    assert strip_padding(pad(b"the item")) == b"the item"


def test_a_plaintext_that_exactly_fills_a_block_still_strips() -> None:
    payload = b"x" * 19
    assert strip_padding(pad(payload)) == payload


def test_padding_ending_in_something_else_says_the_decryption_is_wrong() -> None:
    with pytest.raises(ItemError, match="did not decrypt correctly"):
        strip_padding(b"payload\x7f\x00\x00")


def test_an_all_zero_plaintext_has_no_marker() -> None:
    with pytest.raises(ItemError, match="entirely zeros"):
        strip_padding(bytes(20))


# --------------------------------------------------------------------------------------
# Decrypting an item
# --------------------------------------------------------------------------------------


def test_an_item_decrypts_to_its_dictionary() -> None:
    top_level = AESSIV.generate_key(512)
    record, keyring = an_item(top_level, {"class": "genp", "acct": "abc", "v_Data": b"key"})

    item = decrypt_item(record, keyring)

    assert item["class"] == "genp"
    assert item["v_Data"] == b"key"


def test_an_item_with_more_fields_decrypts_under_encver_two() -> None:
    top_level = AESSIV.generate_key(512)
    record, keyring = an_item(
        top_level,
        {"acct": "abc"},
        encver=2,
        extra={"agrp": "com.apple.ProtectedCloudStorage", "pcsservice": 82},
    )

    assert decrypt_item(record, keyring)["acct"] == "abc"


def test_an_item_whose_key_is_not_held_names_the_uuid_it_wanted() -> None:
    top_level = AESSIV.generate_key(512)
    record, _ = an_item(top_level, {"acct": "abc"})

    with pytest.raises(ItemError, match=PARENT_UUID):
        decrypt_item(record, ViewKeyring(by_uuid={}, by_slot={"tlk": top_level}))


def test_an_item_naming_no_parent_key_says_so() -> None:
    record = a_record(ITEM_NAME, "item", wrappedkey=b"w", data=b"d")

    with pytest.raises(ItemError, match="names no parent key"):
        decrypt_item(record, ViewKeyring())


def test_a_wrong_additional_data_order_fails_and_the_message_says_where_to_look() -> None:
    # The point of the message: the item key unwrapping proves the view key is right, so
    # what remains is the additional data. Without that, this failure looks like a bad key.
    top_level = AESSIV.generate_key(512)
    record, keyring = an_item(top_level, {"acct": "abc"})

    # Re-seal with the values reversed, which is what an insertion-ordered map would give.
    item_key = AESSIV(top_level).decrypt(
        record.fields["wrappedkey"].value.bytes_value,
        None,
    )
    iv = record.fields["data"].value.bytes_value[:16]
    wrong = [iv, *reversed(additional_data(record, PARENT_UUID))]
    resealed = AESSIV(item_key).encrypt(pad(plistlib.dumps({"acct": "abc"})), wrong)

    broken = a_record(
        ITEM_NAME,
        "item",
        wrappedkey=record.fields["wrappedkey"].value.bytes_value,
        parentkeyref=PARENT_UUID,
        encver=1,
        gen=1,
        uploadver="1",
        data=iv + resealed,
    )

    with pytest.raises(ItemError, match="additional data is what to doubt"):
        decrypt_item(broken, keyring)


def test_an_item_that_decrypts_to_something_that_is_not_a_plist_says_so() -> None:
    top_level = AESSIV.generate_key(512)
    item_key = AESSIV.generate_key(512)
    wrapped = AESSIV(top_level).encrypt(item_key, None)

    scaffold = a_record(
        ITEM_NAME,
        "item",
        wrappedkey=wrapped,
        parentkeyref=PARENT_UUID,
        encver=1,
        gen=1,
        data=b"placeholder",
    )
    iv = bytes(16)
    headers = [iv, *additional_data(scaffold, PARENT_UUID)]
    ciphertext = AESSIV(item_key).encrypt(pad(b"not a plist"), headers)

    record = a_record(
        ITEM_NAME,
        "item",
        wrappedkey=wrapped,
        parentkeyref=PARENT_UUID,
        encver=1,
        gen=1,
        data=iv + ciphertext,
    )
    keyring = ViewKeyring(by_uuid={PARENT_UUID: top_level}, by_slot={"tlk": top_level})

    with pytest.raises(ItemError, match="not a property list"):
        decrypt_item(record, keyring)


# --------------------------------------------------------------------------------------
# Finding an item
# --------------------------------------------------------------------------------------


def test_the_service_key_is_found_by_following_its_pointer() -> None:
    top_level = AESSIV.generate_key(512)
    record, keyring = an_item(top_level, {"acct": "abc", "v_Data": b"the key"})
    pointer = a_record(SERVICE_KEY_TAG, "currentitem", item=ITEM_NAME)

    contents = split_view_records([record, pointer])

    assert service_key_item(contents, keyring)["v_Data"] == b"the key"


def test_a_view_without_the_pointer_lists_the_tags_it_does_have() -> None:
    top_level = AESSIV.generate_key(512)
    record, keyring = an_item(top_level, {"acct": "abc"})
    other = a_record("com.apple.something-else", "currentitem", item=ITEM_NAME)

    contents = split_view_records([record, other])

    with pytest.raises(ItemError, match="com.apple.something-else"):
        service_key_item(contents, keyring)


def test_a_pointer_to_an_absent_item_is_distinguished_from_an_absent_pointer() -> None:
    pointer = a_record(SERVICE_KEY_TAG, "currentitem", item="SOMETHING-NOT-HERE")

    contents = split_view_records([pointer])

    with pytest.raises(ItemError, match="not in this view"):
        service_key_item(contents, ViewKeyring())


def test_other_record_types_are_ignored_rather_than_failing() -> None:
    top_level = AESSIV.generate_key(512)
    record, _ = an_item(top_level, {"acct": "abc"})

    contents = split_view_records(
        [record, a_record("whatever", "tlkshare"), a_record("x", "synckey")],
    )

    assert len(contents.items) == 1
    assert contents.pointers == {}


def test_an_item_is_found_by_its_account_as_the_other_way_in() -> None:
    top_level = AESSIV.generate_key(512)
    record, keyring = an_item(top_level, {"acct": "the-compressed-key", "v_Data": b"k"})

    contents = split_view_records([record])

    found = find_by_account(contents, keyring, b"the-compressed-key")
    assert found["v_Data"] == b"k"


def test_no_item_with_that_account_says_how_many_were_searched() -> None:
    top_level = AESSIV.generate_key(512)
    record, keyring = an_item(top_level, {"acct": "one-key"})

    with pytest.raises(ItemError, match="1 item"):
        find_by_account(split_view_records([record]), keyring, b"another-key")


def test_an_item_with_no_payload_says_it_holds_no_key() -> None:
    with pytest.raises(ItemError, match="no v_Data"):
        payload_of({"acct": "abc", "class": "genp"})


# --------------------------------------------------------------------------------------
# The payload, which is where symmetric becomes elliptic-curve
# --------------------------------------------------------------------------------------


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_length(len(body)) + body


def a_v2_payload(encryption: bytes, signing: bytes | None = None) -> bytes:
    """`[APPLICATION 5] EXPLICIT SEQUENCE { data OCTET STRING }` around a protobuf."""
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    keys = cf.PcsServiceKeys(encryption_key=cf.PcsPrivateKey(key=encryption))
    if signing is not None:
        keys.signing_key.key = signing

    inner = der(0x04, keys.SerializeToString())
    sequence = der(0x30, inner)
    return der(0x60 | 0x20 | PRIVATE_KEY_V2_TAG, sequence)


def test_a_v2_payload_yields_the_encryption_key() -> None:
    scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    raw = scalar.to_bytes(32, "big")

    keys = service_keys_from_der(a_v2_payload(raw))

    assert keys.encryption_key.private_numbers().private_value == scalar
    assert keys.signing_key is None


def test_a_v2_payload_carrying_both_keys_yields_both_in_order() -> None:
    first = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    second = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value

    keys = service_keys_from_der(
        a_v2_payload(first.to_bytes(32, "big"), second.to_bytes(32, "big")),
    )

    assert keys.encryption_key.private_numbers().private_value == first
    assert keys.signing_key is not None
    assert keys.signing_key.private_numbers().private_value == second
    assert keys.for_pcs()[0] is keys.encryption_key


def test_the_application_tag_is_explicit_so_the_sequence_is_a_level_deeper() -> None:
    # An implicit reading would treat the [APPLICATION 5] contents as the sequence's own
    # members rather than as a sequence, and find no octet string at all.
    scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    payload = a_v2_payload(scalar.to_bytes(32, "big"))

    from findmy.cloudkit import der as der_module  # noqa: PLC0415

    element, _ = der_module.parse_one(payload)
    assert element.tag_class == der_module.CLASS_APPLICATION
    assert element.tag_number == PRIVATE_KEY_V2_TAG
    assert element.unwrap().is_universal(0x10)  # a SEQUENCE, one level in


def test_a_v1_payload_is_read_too_since_the_structure_is_a_choice() -> None:
    scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    v1 = der(0x30, der(0x04, scalar.to_bytes(32, "big")))

    keys = service_keys_from_der(v1)

    assert keys.encryption_key.private_numbers().private_value == scalar


def test_a_payload_whose_keys_are_all_the_wrong_length_reports_its_size() -> None:
    # It does not reach the curve lookup: nothing scalar-shaped is found at all, and
    # saying how big the payload was is what distinguishes this from a parse failure.
    with pytest.raises(ServiceKeyError, match="carries no key of a recognised length"):
        service_keys_from_der(a_v2_payload(b"\x01" * 17))


def test_a_scalar_of_an_unknown_length_names_the_lengths_it_expected() -> None:
    from findmy.keychain.servicekey import private_key_from_scalar  # noqa: PLC0415

    with pytest.raises(ServiceKeyError, match="matches no curve"):
        private_key_from_scalar(b"\x01" * 17)


def test_something_that_is_not_der_says_that_rather_than_guessing() -> None:
    with pytest.raises(ServiceKeyError, match="not DER"):
        service_keys_from_der(b"\xff\xff\xff\xff")


def test_a_p384_key_is_recognised_rather_than_rejected() -> None:
    # PCS is P-256 throughout, but reading the curve from the length rather than assuming
    # it means another curve is recognised instead of reported as malformed.
    scalar = ec.generate_private_key(ec.SECP384R1()).private_numbers().private_value

    keys = service_keys_from_der(a_v2_payload(scalar.to_bytes(48, "big")))

    assert keys.encryption_key.curve.name == "secp384r1"


def an_implicit_v2_payload(encryption: bytes) -> bytes:
    """
    The `[APPLICATION 5]` form as a real account writes it.

    Implicit tagging: the application tag **replaces** the SEQUENCE's own tag, so the
    octet string sits directly inside the wrapper rather than one level further in.
    """
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    keys = cf.PcsServiceKeys(encryption_key=cf.PcsPrivateKey(key=encryption))
    return der(0x60 | 0x20 | PRIVATE_KEY_V2_TAG, der(0x04, keys.SerializeToString()))


def test_the_implicit_tagging_a_real_account_uses_is_read() -> None:
    # [observed] The tag replaces the SEQUENCE's tag rather than wrapping it, so the octet
    # string is one level shallower. Assuming the explicit form fails with "cannot read
    # children of a primitive element", which names neither the structure nor the choice.
    scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value

    keys = service_keys_from_der(an_implicit_v2_payload(scalar.to_bytes(32, "big")))

    assert keys.encryption_key.private_numbers().private_value == scalar


def test_both_nestings_yield_the_same_key() -> None:
    # The difference is invisible until it fails, so both are read rather than one being
    # chosen -- there is no cost to accepting the other and a whole round trip to guessing.
    scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    raw = scalar.to_bytes(32, "big")

    implicit = service_keys_from_der(an_implicit_v2_payload(raw))
    explicit = service_keys_from_der(a_v2_payload(raw))

    assert implicit.encryption_key.private_numbers().private_value == scalar
    assert explicit.encryption_key.private_numbers().private_value == scalar


def test_a_v2_structure_holding_no_octet_string_says_what_it_holds() -> None:
    empty_sequence = der(0x60 | 0x20 | PRIVATE_KEY_V2_TAG, der(0x30, der(0x02, b"\x01")))

    with pytest.raises(ServiceKeyError, match="holds no octet string"):
        service_keys_from_der(empty_sequence)
