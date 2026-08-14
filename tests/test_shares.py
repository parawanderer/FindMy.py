"""
Tests for key shares (Stage 3 SS6.7.0).

The cipher is specified exactly, so there is no search here -- one construction, and the
things that made a correct implementation of it fail anyway: the ciphertext member
overruns the ciphertext, the plaintext's key is symmetric rather than an EC key, and the
class keys use a different algorithm from the share that carried them.
"""

from __future__ import annotations

import hashlib
import plistlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.keychain.shares import (
    ShareError,
    archived_bytes,
    parse_key_material,
    sfies_decrypt_archive,
    sfies_parts,
    summarise,
    unarchive,
    unwrap_class_key,
    unwrap_share,
    unwrap_view_keys,
)


def archive(payload: bytes) -> bytes:
    """Build an NSKeyedArchiver archive holding one payload."""
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {"root": plistlib.UID(1)},
            "$objects": ["$null", payload],
        },
        fmt=plistlib.FMT_BINARY,
    )


def sfies_archive(
    public_key,  # noqa: ANN001
    plaintext: bytes,
    *,
    overrun: bytes | None = None,
    names: tuple[str, str, str] = (
        "SFEphemeralSenderPublicKeyExternaRepresentation",
        "SFCiphertext",
        "SFIESAuthenticationCode",
    ),
) -> bytes:
    """
    Seal exactly as the specification describes, and archive it as Apple does.

    `overrun` is the trailing rubbish the real `SFCiphertext` carries. It defaults to the
    real behaviour -- as many bytes as the point and code together -- because a test that
    omits it would pass against an implementation that never learned to trim.
    """
    ephemeral = ec.generate_private_key(public_key.curve)
    point = ephemeral.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    shared = ephemeral.exchange(ec.ECDH(), public_key)

    out, counter = b"", 1
    while len(out) < 48:
        out += hashlib.sha256(shared + counter.to_bytes(4, "big") + point).digest()
        counter += 1

    encryptor = Cipher(algorithms.AES(out[:32]), modes.GCM(out[32:48])).encryptor()
    body = encryptor.update(plaintext) + encryptor.finalize()

    trailing = bytes(len(point) + len(encryptor.tag)) if overrun is None else overrun

    point_name, ciphertext_name, code_name = names
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {"root": plistlib.UID(1)},
            "$objects": [
                "$null",
                {code_name: plistlib.UID(2), ciphertext_name: plistlib.UID(3),
                 point_name: plistlib.UID(4)},
                encryptor.tag,
                body + trailing,
                point,
            ],
        },
        fmt=plistlib.FMT_BINARY,
    )


def key_material(key: bytes, *, view: str = "Manatee") -> bytes:
    """The message a share decrypts to."""
    return cf.TlkKeyMaterial(
        uuid="1234-5678",
        zone_name=view,
        key_class="tlk",
        key=key,
    ).SerializeToString()


# --------------------------------------------------------------------------------------
# NSKeyedArchiver
# --------------------------------------------------------------------------------------


def test_an_archive_resolves_its_uid_references() -> None:
    assert unarchive(archive(b"the-payload")) == {"root": b"the-payload"}


def test_the_payload_is_pulled_out_of_an_archive() -> None:
    assert archived_bytes(archive(b"the-payload")) == b"the-payload"


def test_something_that_is_not_an_archive_is_reported_as_such() -> None:
    with pytest.raises(ShareError, match="[Nn]ot a property list"):
        unarchive(b"\xff\xfe not a plist")


def test_a_plist_that_is_not_an_archive_is_distinguished() -> None:
    with pytest.raises(ShareError, match="not an NSKeyedArchiver"):
        unarchive(plistlib.dumps({"just": "a plist"}))


def test_an_archive_with_no_payload_is_reported() -> None:
    empty = plistlib.dumps(
        {"$objects": ["$null"], "$top": {"root": plistlib.UID(0)}},
        fmt=plistlib.FMT_BINARY,
    )

    with pytest.raises(ShareError, match="no byte string"):
        archived_bytes(empty)


# --------------------------------------------------------------------------------------
# SFIES -- one construction, and the overrun that hid it
# --------------------------------------------------------------------------------------


def test_a_share_decrypts_under_the_specified_construction() -> None:
    key = ec.generate_private_key(ec.SECP384R1())

    sealed = sfies_archive(key.public_key(), b"the view key")

    assert sfies_decrypt_archive(key, sealed) == b"the view key"


def test_the_ciphertext_member_is_trimmed_by_the_other_two_members() -> None:
    # This is the whole reason a correct implementation still failed: SFCiphertext runs
    # past the ciphertext by exactly the point and code sizes, and the tag rejects the
    # excess exactly as it would reject a wrong key or a wrong cipher parameter.
    key = ec.generate_private_key(ec.SECP384R1())

    parts = sfies_parts(sfies_archive(key.public_key(), b"the view key"))

    assert len(parts.point) == 97
    assert len(parts.code) == 16
    assert len(parts.ciphertext) == len(b"the view key")


def test_the_overrun_is_derived_and_not_the_number_113() -> None:
    # 97 + 16 is a P-384 number. A different curve makes it a different number, so the
    # trim has to come from the members rather than from a constant.
    key = ec.generate_private_key(ec.SECP256R1())

    parts = sfies_parts(sfies_archive(key.public_key(), b"a shorter curve"))

    assert len(parts.point) == 65
    assert len(parts.ciphertext) == len(b"a shorter curve")
    assert sfies_decrypt_archive(key, sfies_archive(key.public_key(), b"x")) == b"x"


def test_uninitialised_trailing_bytes_do_not_change_the_result() -> None:
    # The overrun is heap, so it differs run to run and must not reach any computation.
    key = ec.generate_private_key(ec.SECP384R1())

    noisy = sfies_archive(key.public_key(), b"the view key", overrun=bytes(range(113)))

    assert sfies_decrypt_archive(key, noisy) == b"the view key"


def test_apples_misspelled_member_name_is_the_one_that_must_match() -> None:
    # The archived key reads "ExternaRepresentation", missing its final l. Matching the
    # correctly spelled name finds nothing on real data.
    key = ec.generate_private_key(ec.SECP384R1())

    misspelled = sfies_archive(key.public_key(), b"the view key")
    correct = sfies_archive(
        key.public_key(),
        b"the view key",
        names=(
            "SFEphemeralSenderPublicKeyExternalRepresentation",
            "SFCiphertext",
            "SFIESAuthenticationCode",
        ),
    )

    assert sfies_decrypt_archive(key, misspelled) == b"the view key"
    assert sfies_decrypt_archive(key, correct) == b"the view key"


def test_a_ciphertext_for_another_key_does_not_authenticate() -> None:
    theirs = ec.generate_private_key(ec.SECP384R1())
    ours = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(ShareError, match="did not authenticate"):
        sfies_decrypt_archive(ours, sfies_archive(theirs.public_key(), b"not for us"))


def test_an_archive_that_is_not_an_sfies_ciphertext_names_what_it_holds() -> None:
    key = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(ShareError, match="not an SFIESCiphertext"):
        sfies_decrypt_archive(key, archive(b"just one blob"))


def test_a_ciphertext_member_shorter_than_its_overrun_is_refused() -> None:
    key = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(ShareError, match="not longer than"):
        sfies_parts(sfies_archive(key.public_key(), b"", overrun=b""))


# --------------------------------------------------------------------------------------
# What a share decrypts to
# --------------------------------------------------------------------------------------


def test_the_plaintext_carries_the_key_itself_at_field_four() -> None:
    # Not a container holding a key, and not an EC private key: reading it as a scalar
    # fails on every share because the bytes were never that.
    material = parse_key_material(key_material(bytes(range(64))))

    assert material.key == bytes(range(64))
    assert material.zone_name == "Manatee"


def test_a_plaintext_with_no_key_says_so_rather_than_yielding_nothing() -> None:
    without = cf.TlkKeyMaterial(uuid="1234", zone_name="Manatee").SerializeToString()

    with pytest.raises(ShareError, match="no key at field 4"):
        parse_key_material(without)


def test_a_plaintext_that_is_not_a_key_message_reports_its_fields() -> None:
    with pytest.raises(ShareError, match="not a key message"):
        parse_key_material(b"\xff\xff\xff\xff")


# --------------------------------------------------------------------------------------
# The class keys, which are not ECIES
# --------------------------------------------------------------------------------------


def test_a_class_key_is_unwrapped_with_aes_siv_and_no_headers() -> None:
    top_level = AESSIV.generate_key(512)
    wrapped = AESSIV(top_level).encrypt(b"the class A key", None)

    assert unwrap_class_key(wrapped, top_level) == b"the class A key"


def test_an_empty_header_vector_is_not_a_vector_holding_an_empty_header() -> None:
    # The two are different associated data and give different results. Getting it wrong
    # fails as an authentication failure with nothing to say the header count was why.
    top_level = AESSIV.generate_key(512)

    with_one_empty = AESSIV(top_level).encrypt(b"the class A key", [b""])

    with pytest.raises(ShareError, match="did not authenticate"):
        unwrap_class_key(with_one_empty, top_level)


def test_a_class_key_under_the_wrong_top_level_key_does_not_authenticate() -> None:
    wrapped = AESSIV(AESSIV.generate_key(512)).encrypt(b"the class A key", None)

    with pytest.raises(ShareError, match="did not authenticate"):
        unwrap_class_key(wrapped, AESSIV.generate_key(512))


def test_a_top_level_key_of_the_wrong_size_says_that_rather_than_failing_the_tag() -> None:
    wrapped = AESSIV(AESSIV.generate_key(512)).encrypt(b"the class A key", None)

    with pytest.raises(ShareError, match="not a usable AES-SIV key"):
        unwrap_class_key(wrapped, b"too short")


# --------------------------------------------------------------------------------------
# Three keys, not four
# --------------------------------------------------------------------------------------


def a_view_key(slot: str, wrapped: bytes = b""):  # noqa: ANN201
    from findmy.keychain.shares import ViewKey  # noqa: PLC0415

    return ViewKey(key_class=slot, wrapped_key=wrapped, upload_version=1, slot=slot)


def test_the_top_level_key_is_the_plaintext_and_is_not_unwrapped_again() -> None:
    # The tlk record carries what the share already decrypted to, so treating it as a
    # fourth thing to unwrap looks for a wrapping that is not there.
    top_level = AESSIV.generate_key(512)

    keys = unwrap_view_keys([a_view_key("tlk", b"whatever")], key_material(top_level))

    assert keys.by_slot == {"tlk": top_level}


def test_an_entry_yields_three_keys() -> None:
    top_level = AESSIV.generate_key(512)
    siv = AESSIV(top_level)

    keys = unwrap_view_keys(
        [
            a_view_key("tlk", b"ignored"),
            a_view_key("classA", siv.encrypt(b"class A key", None)),
            a_view_key("classB", siv.encrypt(b"class B key", None)),
        ],
        key_material(top_level),
    )

    assert keys.by_slot == {
        "tlk": top_level,
        "classA": b"class A key",
        "classB": b"class B key",
    }


def test_a_class_key_that_will_not_unwrap_does_not_cost_the_top_level_one() -> None:
    top_level = AESSIV.generate_key(512)

    keys = unwrap_view_keys([a_view_key("classA", b"not a wrapping")], key_material(top_level))

    assert keys.by_slot == {"tlk": top_level}


def test_a_plaintext_that_is_not_a_key_message_yields_no_keys_rather_than_raising() -> None:
    assert not unwrap_view_keys([a_view_key("classA", b"x")], b"\xff\xff\xff\xff")


# --------------------------------------------------------------------------------------
# Shares
# --------------------------------------------------------------------------------------


def a_record(**fields: object):  # noqa: ANN201
    """Build a CloudKit record whose members are addressed by name."""
    from findmy.cloudkit.proto import cloudkit_pb2 as ck  # noqa: PLC0415

    record = ck.Record()
    for name, value in fields.items():
        wire = ck.Record.Value()
        if isinstance(value, bytes):
            wire.bytes_value = value
        elif isinstance(value, int):
            wire.signed_value = value
        else:
            wire.string_value = str(value)
        record.record_field.append(
            ck.Record.Field(identifier=ck.NameWrapper(name=name), value=wire),
        )
    return record


def a_share(key, payload: bytes = b"the view key"):  # noqa: ANN001, ANN201
    """An entry as `fetch_recoverable_shares` returns them."""
    from findmy.keychain.shares import ShareEntry, ShareRecord  # noqa: PLC0415

    record = a_record(
        sender="PEER-SENDER",
        receiver="PEER-US",
        wrappedkey=sfies_archive(key.public_key(), payload),
        curve=1,
        epoch=1,
        version=1,
    )
    return ShareEntry(view="Manatee", share=ShareRecord.from_record(record), view_keys=[])


def test_a_share_unwraps_to_its_key_material() -> None:
    key = ec.generate_private_key(ec.SECP384R1())

    share = unwrap_share(a_share(key), key)

    assert share.plaintext == b"the view key"
    assert share.service == "Manatee"
    assert share.error is None


def test_a_share_this_key_cannot_read_records_why_rather_than_raising() -> None:
    # A listing legitimately contains shares for views this client has no interest in,
    # and one unreadable share must not hide the readable ones.
    theirs = ec.generate_private_key(ec.SECP384R1())
    ours = ec.generate_private_key(ec.SECP384R1())

    share = unwrap_share(a_share(theirs), ours)

    assert share.plaintext is None
    assert share.error is not None
    assert share.service == "Manatee"


def test_a_share_is_not_reported_verified_without_a_directory() -> None:
    # Nothing to check against means not verified, which is different from failing.
    key = ec.generate_private_key(ec.SECP384R1())

    assert unwrap_share(a_share(key), key).sender_verified is False


def test_a_summary_counts_what_was_readable() -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    theirs = ec.generate_private_key(ec.SECP384R1())

    shares = [unwrap_share(a_share(key), key), unwrap_share(a_share(theirs), key)]

    assert "1/2 unwrapped" in summarise(shares)
    assert "Manatee" in summarise(shares)


# --------------------------------------------------------------------------------------
# Reading an entry whose shape the specification does not give
# --------------------------------------------------------------------------------------


def test_the_view_name_is_on_the_message_not_on_the_record() -> None:
    # [observed] The record has no service and no key id at all. A reader looking there
    # for the view name finds nothing, which is exactly what happened.
    from findmy.keychain.shares import decode_share_entry  # noqa: PLC0415

    record = a_record(sender="PEER-S", receiver="PEER-R", wrappedkey=b"wrapped")
    entry = cf.RecoverableTlkShare(
        service="Manatee",
        share=cf.RecordWrapper(record=record.SerializeToString()),
    )

    read = decode_share_entry(entry.SerializeToString())

    assert read is not None
    assert read.view == "Manatee"
    assert read.share.sender == "PEER-S"
    assert read.share.wrapped_key == b"wrapped"


def test_a_views_keys_are_read_from_their_own_records() -> None:
    from findmy.keychain.shares import decode_share_entry  # noqa: PLC0415

    def synckey(name: str) -> cf.RecordWrapper:
        return cf.RecordWrapper(
            record=a_record(**{"class": name, "wrappedkey": b"k", "uploadver": 1}).SerializeToString(),
        )

    entry = cf.RecoverableTlkShare(
        service="Manatee",
        share=cf.RecordWrapper(record=a_record(sender="S", wrappedkey=b"w").SerializeToString()),
        viewkeys=cf.ViewKeySet(tlk=synckey("tlk"), class_a=synckey("classA")),
    )

    read = decode_share_entry(entry.SerializeToString())

    assert read is not None
    assert [k.key_class for k in read.view_keys] == ["tlk", "classA"]


def test_an_entry_with_neither_a_view_nor_shares_reports_its_actual_fields() -> None:
    # "It did not parse" is not actionable; the field numbers that arrived are.
    from findmy.keychain.shares import decode_share_entry  # noqa: PLC0415

    with pytest.raises(ShareError, match="top-level fields"):
        decode_share_entry(b"\x40\x01")  # field 8, varint -- nothing an entry has


def test_the_wire_walker_describes_a_payload_it_has_no_schema_for() -> None:
    from findmy.keychain.shares import describe_wire  # noqa: PLC0415

    described = describe_wire(cf.TlkShare(service="Manatee", curve=7).SerializeToString())

    assert "1:bytes" in described
    assert "2:varint" in described


# --------------------------------------------------------------------------------------
# The share signature: seven fields, and the integers are little-endian
# --------------------------------------------------------------------------------------


def test_the_signed_fields_are_little_endian_unlike_everything_else() -> None:
    # CloudKit's protobuf, the KeyVault framing and the PCS structures are all big-endian.
    # This one construction is not, and getting it wrong fails with nothing to say why.
    import struct  # noqa: PLC0415

    from findmy.keychain.shares import share_signed_data  # noqa: PLC0415

    from findmy.keychain.shares import ShareRecord  # noqa: PLC0415

    share = ShareRecord.from_record(
        a_record(version=1, curve=2, epoch=3, poisoned=4, receiver="R", sender="S"),
    )
    signed = share_signed_data(share)

    assert signed.startswith(struct.pack("<I", 1))
    assert struct.pack("<Q", 2) in signed
    assert struct.pack(">I", 1) not in signed[:4]


def test_the_wrapped_key_contributes_its_decoded_bytes() -> None:
    # Not the base64 text the field carries.
    import base64  # noqa: PLC0415

    from findmy.keychain.shares import share_signed_data  # noqa: PLC0415

    from findmy.keychain.shares import ShareRecord  # noqa: PLC0415

    raw = b"\x01\x02\x03\x04"
    share = ShareRecord.from_record(a_record(wrappedkey=base64.b64encode(raw).decode()))

    assert raw in share_signed_data(share)


def test_a_share_verifies_against_its_sending_peer() -> None:
    import base64  # noqa: PLC0415

    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        Encoding,
        PublicFormat,
    )

    from findmy.keychain.peers import Peer  # noqa: PLC0415
    from findmy.keychain.shares import share_signed_data, verify_share_signature  # noqa: PLC0415

    from findmy.keychain.shares import ShareRecord  # noqa: PLC0415

    sender_key = ec.generate_private_key(ec.SECP384R1())
    unsigned = ShareRecord.from_record(
        a_record(version=1, sender="PEER-S", receiver="PEER-R", curve=1, epoch=1),
    )
    signature = sender_key.sign(share_signed_data(unsigned), ec.ECDSA(hashes.SHA256()))
    share = ShareRecord.from_record(
        a_record(
            version=1,
            sender="PEER-S",
            receiver="PEER-R",
            curve=1,
            epoch=1,
            signature=signature,
        ),
    )

    peer = Peer(
        hash="PEER-S",
        signing_key=sender_key.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        ),
        encryption_key=b"",
        machine_id="",
        model_id="",
    )

    assert verify_share_signature(share, peer) is True

    other = ec.generate_private_key(ec.SECP384R1())
    impostor = Peer(
        hash="PEER-S",
        signing_key=other.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        ),
        encryption_key=b"",
        machine_id="",
        model_id="",
    )
    assert verify_share_signature(share, impostor) is False


# --------------------------------------------------------------------------------------
# An archive holding the ECIES parts separately
# --------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------
# Which of the two identical-looking failures this is
# --------------------------------------------------------------------------------------


def a_share_addressed_to(key, wrapped_to, *, as_der: bool = False):  # noqa: ANN001, ANN201
    """A share naming the key it was wrapped to, so a mismatch is visible before trying."""
    from findmy.keychain.shares import ShareEntry, ShareRecord  # noqa: PLC0415

    named = wrapped_to.public_key()
    declared = (
        named.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if as_der
        else named.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    )

    record = a_record(
        sender="PEER-SENDER",
        receiver="PEER-US",
        receiverPublicEncryptionKey=declared,
        wrappedkey=sfies_archive(key.public_key(), b"the view key"),
        curve=1,
        epoch=1,
        version=1,
    )
    return ShareEntry(view="Manatee", share=ShareRecord.from_record(record), view_keys=[])


def test_a_share_wrapped_to_another_key_says_so_rather_than_blaming_the_cipher() -> None:
    # A wrong key and a wrong construction both fail as an authentication tag that does
    # not check, and they lead in opposite directions -- one back to the recovery, the
    # other to the ECIES parameters. Guessing wrong costs a passcode-authenticated run.
    theirs = ec.generate_private_key(ec.SECP384R1())
    ours = ec.generate_private_key(ec.SECP384R1())

    share = unwrap_share(a_share_addressed_to(theirs, theirs), ours)

    assert share.plaintext is None
    assert "none of ours" in (share.error or "")
    assert "recovery is what to look at" in (share.error or "")


def test_a_failure_says_whether_the_key_or_the_construction_is_in_doubt() -> None:
    # The two failures are indistinguishable by outcome, so the message must separate
    # them. A share addressed to a key we hold means the key is settled.
    ours = ec.generate_private_key(ec.SECP384R1())
    entry = a_share_addressed_to(ours, ours)

    # Replace the ciphertext with one this key cannot read, keeping the declared receiver.
    from findmy.keychain.shares import ShareEntry, ShareRecord  # noqa: PLC0415

    theirs = ec.generate_private_key(ec.SECP384R1())
    record = a_record(
        sender="PEER-SENDER",
        receiver="PEER-US",
        receiverPublicEncryptionKey=public_point_of(ours),
        wrappedkey=sfies_archive(theirs.public_key(), b"not for us"),
        curve=1,
        epoch=1,
        version=1,
    )
    entry = ShareEntry(view="Manatee", share=ShareRecord.from_record(record), view_keys=[])

    share = unwrap_share(entry, ours)

    assert "addressed to our encryption key" in (share.error or "")
    assert "the construction is what remains" in (share.error or "")


def test_a_share_naming_no_key_says_that_it_establishes_nothing() -> None:
    # Silence is not confirmation. Reporting "the key is fine" from an absent field would
    # send the next hour after the cipher on no evidence at all.
    ours = ec.generate_private_key(ec.SECP384R1())
    theirs = ec.generate_private_key(ec.SECP384R1())

    share = unwrap_share(a_share(theirs), ours)

    assert "names no receiver key" in (share.error or "")
    assert "nothing here confirms" in (share.error or "")


def public_point_of(key) -> bytes:  # noqa: ANN001
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def test_a_share_addressed_to_our_key_is_not_reported_as_a_mismatch() -> None:
    ours = ec.generate_private_key(ec.SECP384R1())

    share = unwrap_share(a_share_addressed_to(ours, ours), ours)

    assert share.plaintext == b"the view key"


def test_the_named_key_is_compared_by_meaning_not_by_spelling() -> None:
    # The same key written as a SubjectPublicKeyInfo rather than a bare point is the same
    # key. Comparing bytes would refuse every share on an encoding difference.
    ours = ec.generate_private_key(ec.SECP384R1())

    share = unwrap_share(a_share_addressed_to(ours, ours, as_der=True), ours)

    assert share.error is None
    assert share.plaintext == b"the view key"


def test_a_share_that_names_no_key_is_not_a_mismatch() -> None:
    # Silence is not disagreement: refusing a share because it declined to say which key
    # it was wrapped to would reject perfectly good material.
    ours = ec.generate_private_key(ec.SECP384R1())

    share = unwrap_share(a_share(ours), ours)

    assert share.plaintext == b"the view key"


# --------------------------------------------------------------------------------------
# Values a real record carries and an unsigned reading cannot express
# --------------------------------------------------------------------------------------


def test_a_negative_field_is_rendered_rather_than_refused() -> None:
    # These are declared int64 and real records carry negative values. Packing them
    # unsigned raises, and a raise here aborts every remaining share -- so the run dies
    # on the first odd one instead of reporting it and reading the other twenty.
    from findmy.keychain.shares import ShareRecord, share_signed_data  # noqa: PLC0415

    share = ShareRecord(
        sender="S",
        receiver="R",
        receiver_public_encryption_key=b"",
        wrapped_key=b"",
        signature=b"",
        curve=1,
        epoch=-1,
        poisoned=0,
        version=1,
    )

    data = share_signed_data(share)

    # curve, epoch, poisoned -- eight bytes each, poisoned included.
    assert data.endswith(b"\x01" + bytes(7) + b"\xff" * 8 + bytes(8))


def test_every_signed_integer_is_eight_bytes_including_the_uint32_ones() -> None:
    # version and poisoned are uint32 on the message and their own type on the record.
    # The signed form is neither: all four are eight bytes. At four, both being zero on
    # real shares leaves the digest short and the share is skipped -- which reads as a
    # peer with no shares to give rather than as a verification failure.
    from findmy.keychain.shares import ShareRecord, share_signed_data  # noqa: PLC0415

    share = ShareRecord(
        sender="",
        receiver="",
        receiver_public_encryption_key=b"",
        wrapped_key=b"",
        signature=b"",
        curve=4,
        epoch=1,
        poisoned=0,
        version=0,
    )

    assert len(share_signed_data(share)) == 4 * 8


def test_a_negative_value_is_two_s_complement_not_an_absolute_value() -> None:
    from findmy.keychain.shares import _little_endian  # noqa: PLC0415

    assert _little_endian(-1, 4) == b"\xff\xff\xff\xff"
    assert _little_endian(-2, 8) == b"\xfe" + b"\xff" * 7
    assert _little_endian(1, 4) == b"\x01\x00\x00\x00"


def test_a_share_that_cannot_be_checked_counts_as_unverified_rather_than_raising() -> None:
    # Whatever goes wrong in verification, the listing must survive it: twenty readable
    # shares hidden by one unreadable one is the outcome worth preventing.
    from findmy.keychain.peers import Peer  # noqa: PLC0415
    from findmy.keychain.shares import ShareRecord, verify_share_signature  # noqa: PLC0415

    sender = Peer(
        hash="PEER-SENDER",
        signing_key=a_public_key_bytes(),
        encryption_key=b"",
        machine_id="",
        model_id="",
    )
    share = ShareRecord(
        sender="S",
        receiver="R",
        receiver_public_encryption_key=b"",
        wrapped_key=b"",
        signature=b"not a signature",
        curve=1,
        epoch=-1,
        poisoned=0,
        version=1,
    )

    assert verify_share_signature(share, sender) is False


def a_public_key_bytes() -> bytes:
    key = ec.generate_private_key(ec.SECP384R1()).public_key()
    return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)




def test_a_share_for_another_peer_is_named_as_such_not_as_a_cipher_failure() -> None:
    # If the receiver is not the recovered peer, no cipher parameter was ever going to
    # open it -- so reporting this as a decryption failure would send the search after a
    # construction that is not the problem.
    ours = ec.generate_private_key(ec.SECP384R1())

    share = unwrap_share(a_share(ours), ours, expected_receiver="PEER-SOMEONE-ELSE")

    assert share.plaintext is None
    assert "not the recovered peer" in (share.error or "")


def test_a_share_for_the_recovered_peer_passes_that_check() -> None:
    ours = ec.generate_private_key(ec.SECP384R1())

    share = unwrap_share(a_share(ours), ours, expected_receiver="PEER-US")

    assert share.plaintext == b"the view key"


# --------------------------------------------------------------------------------------
# Creating a share (§6.9.2)
# --------------------------------------------------------------------------------------


def _key():
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    return ec.generate_private_key(ec.SECP384R1())


def _material() -> bytes:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    return cf.TlkKeyMaterial(
        uuid="7F0A2C1E-0000-4000-8000-000000000001",
        zone_name="Manatee",
        key_class="tlk",
        key=b"\x11" * 32,
    ).SerializeToString()


def test_a_written_share_is_one_the_reader_can_open() -> None:
    # The decisive test for the writer: the reader was built from §6.7.0, describing the
    # same archive from the receiving side, and it trims the overrun the writer has to
    # produce. If the two disagree about that quantity, nothing comes back.
    from findmy.keychain.shares import archive_sfies, sfies_decrypt_archive, sfies_encrypt  # noqa: PLC0415

    key = _key()
    archive = archive_sfies(sfies_encrypt(key.public_key(), _material()))

    assert sfies_decrypt_archive(key, archive) == _material()


def test_the_archived_ciphertext_carries_the_overrun_and_it_is_zeros() -> None:
    from findmy.keychain.shares import (  # noqa: PLC0415
        archive_sfies,
        sfies_encrypt,
        sfies_parts,
    )

    parts = sfies_encrypt(_key().public_key(), _material())
    archived = sfies_parts(archive_sfies(parts))

    # The reader trims by len(point) + len(code), so what it recovers is what was encrypted.
    assert archived.ciphertext == parts.ciphertext

    from findmy.keychain.shares import archived_members  # noqa: PLC0415

    members = archive_sfies(parts)
    raw = next(v for k, v in archived_members(members).items() if "SFCiphertext" in k)

    assert len(raw) == len(parts.ciphertext) + len(parts.point) + len(parts.code)
    # Zeros, not the uninitialised heap Apple leaks: the overrun has to exist, its
    # contents do not have to be anybody's memory.
    assert raw[len(parts.ciphertext) :] == bytes(len(parts.point) + len(parts.code))


def test_the_misspelled_member_name_is_written_as_apple_spells_it() -> None:
    # A reader can match the fragment and forgive it. A writer cannot: the correctly
    # spelled name is one Apple's unarchiver will not find the ephemeral key under.
    from findmy.keychain.shares import archive_sfies, archived_members, sfies_encrypt  # noqa: PLC0415

    members = archived_members(archive_sfies(sfies_encrypt(_key().public_key(), b"x")))
    names = " ".join(members)

    assert "ExternaRepresentation" in names
    assert "ExternalRepresentation" not in names


def test_a_created_share_verifies_under_the_peer_that_made_it() -> None:
    # End to end: the seven-part signature, the widths, the endianness and the field
    # values, checked by the verifier used on shares that arrive.
    import base64  # noqa: PLC0415

    from findmy.keychain.peers import Peer  # noqa: PLC0415
    from findmy.keychain.shares import (  # noqa: PLC0415
        ShareRecord,
        make_share,
        verify_share_signature,
    )

    signing, encryption = _key(), _key()
    share = make_share(
        _material(),
        peer_id="SHA256:abc",
        encryption_key=encryption.public_key(),
        signing_key=signing,
    )

    record = ShareRecord(
        sender=share.sender,
        receiver=share.receiver,
        receiver_public_encryption_key=base64.b64decode(share.receiver_public_encryption_key),
        wrapped_key=base64.b64decode(share.wrapped_key),
        signature=base64.b64decode(share.signature),
        curve=share.curve,
        epoch=share.epoch,
        poisoned=share.poisoned,
        version=share.version,
    )
    sender = Peer(
        hash="SHA256:abc",
        signing_key=signing.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        ),
        encryption_key=b"",
        machine_id="",
        model_id="",
    )

    assert verify_share_signature(record, sender)


def test_a_created_share_names_itself_at_both_ends() -> None:
    from findmy.keychain.shares import make_share  # noqa: PLC0415

    share = make_share(
        _material(),
        peer_id="SHA256:me",
        encryption_key=_key().public_key(),
        signing_key=_key(),
    )

    assert share.sender == share.receiver == "SHA256:me"
    assert share.service == "Manatee"
    assert share.key_id == "7F0A2C1E-0000-4000-8000-000000000001"
    assert share.curve == 4
    assert share.epoch == 1
    # Omitted from the message, and signed as zero regardless.
    assert not share.HasField("poisoned")
    assert not share.HasField("version")


def test_the_receiver_key_travels_as_a_point_not_as_der() -> None:
    # The one place in this stage where a public key does not travel as DER SPKI.
    import base64  # noqa: PLC0415

    from findmy.keychain.shares import make_share  # noqa: PLC0415

    encryption = _key()
    share = make_share(
        _material(),
        peer_id="SHA256:me",
        encryption_key=encryption.public_key(),
        signing_key=_key(),
    )
    decoded = base64.b64decode(share.receiver_public_encryption_key)

    assert decoded[0] == 0x04  # uncompressed
    assert len(decoded) == 97


def test_key_material_with_no_zone_is_refused() -> None:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415
    from findmy.keychain.shares import ShareError, make_share  # noqa: PLC0415

    with pytest.raises(ShareError, match="no zone or no uuid"):
        make_share(
            cf.TlkKeyMaterial(key=b"\x00" * 32).SerializeToString(),
            peer_id="SHA256:me",
            encryption_key=_key().public_key(),
            signing_key=_key(),
        )
