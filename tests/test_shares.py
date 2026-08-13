"""Tests for key shares (Stage 3 §6.7.0)."""

from __future__ import annotations

import hashlib
import plistlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.keychain.shares import (
    ShareError,
    archived_bytes,
    ecies_decrypt,
    summarise,
    unarchive,
    unwrap_share,
)


def archive(payload: bytes) -> bytes:
    """Build an NSKeyedArchiver archive of the shape a wrapped key arrives in."""
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {"root": plistlib.UID(1)},
            "$objects": ["$null", payload],
        },
        fmt=plistlib.FMT_BINARY,
    )


def ecies_encrypt(public_key, plaintext: bytes, *, key_length: int = 16) -> bytes:  # noqa: ANN001
    ephemeral = ec.generate_private_key(public_key.curve)
    point = ephemeral.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    shared = ephemeral.exchange(ec.ECDH(), public_key)

    out, counter = b"", 1
    while len(out) < key_length:
        out += hashlib.sha256(shared + counter.to_bytes(4, "big") + point).digest()
        counter += 1

    encryptor = Cipher(algorithms.AES(out[:key_length]), modes.GCM(bytes(16))).encryptor()
    encryptor.authenticate_additional_data(point)
    body = encryptor.update(plaintext) + encryptor.finalize()
    return point + body + encryptor.tag


# --------------------------------------------------------------------------------------
# NSKeyedArchiver
# --------------------------------------------------------------------------------------


def test_an_archive_resolves_its_uid_references() -> None:
    # References are stored as UIDs into a flat table, so a naive plist read gives back
    # indices rather than data.
    resolved = unarchive(archive(b"the-payload"))

    assert resolved == {"root": b"the-payload"}


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
# ECIES
# --------------------------------------------------------------------------------------


def test_an_ecies_ciphertext_roundtrips() -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    sealed = ecies_encrypt(key.public_key(), b"the view key")

    assert ecies_decrypt(key, sealed) == b"the view key"


def test_the_ephemeral_key_is_the_authenticated_data() -> None:
    # The detail most likely to be missed: it is both the KDF's shared info and the AAD.
    key = ec.generate_private_key(ec.SECP384R1())
    sealed = bytearray(ecies_encrypt(key.public_key(), b"the view key"))
    sealed[0:1] = b"\x04"  # leave it a valid prefix but corrupt the point below

    with pytest.raises(ShareError):
        ecies_decrypt(key, bytes(sealed[:1]) + bytes(96) + bytes(sealed[97:]))


def test_a_ciphertext_for_another_key_does_not_authenticate() -> None:
    theirs = ec.generate_private_key(ec.SECP384R1())
    ours = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(ShareError, match="None of the ECIES variants"):
        ecies_decrypt(ours, ecies_encrypt(theirs.public_key(), b"not for us"))


def test_a_ciphertext_too_short_to_hold_anything_is_refused() -> None:
    key = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(ShareError, match="No uncompressed point"):
        ecies_decrypt(key, b"\x04" + bytes(100))


def test_a_ciphertext_behind_a_header_is_still_found() -> None:
    # What an archive hands back does not always begin at the point, so every position
    # where one could start is tried. GCM's tag makes a wrong offset free to reject.
    key = ec.generate_private_key(ec.SECP384R1())
    sealed = ecies_encrypt(key.public_key(), b"the view key")

    assert ecies_decrypt(key, b"\x01\x02\x03" + sealed) == b"the view key"


def test_bytes_with_no_point_anywhere_say_what_they_start_with() -> None:
    key = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(ShareError, match="It starts"):
        ecies_decrypt(key, b"\xaa" * 200)  # no 0x04 anywhere, so no point can start


def test_both_key_lengths_are_found() -> None:
    # The specification does not say whether the derived material is 16 or 32 bytes, and
    # GCM's tag settles it without a round trip.
    key = ec.generate_private_key(ec.SECP384R1())

    for length in (16, 32):
        sealed = ecies_encrypt(key.public_key(), b"payload", key_length=length)
        assert ecies_decrypt(key, sealed) == b"payload"


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

    sealed = ecies_encrypt(key.public_key(), payload)
    record = a_record(
        sender="PEER-SENDER",
        receiver="PEER-US",
        wrappedkey=archive(sealed),
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


def split_archive(public_key, plaintext: bytes) -> bytes:  # noqa: ANN001
    """Archive an ECIES ciphertext as separate members, the way a share carries one."""
    import plistlib as pl  # noqa: PLC0415

    sealed = ecies_encrypt(public_key, plaintext)
    point, body, tag = sealed[:97], sealed[97:-16], sealed[-16:]

    return pl.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {"root": pl.UID(1)},
            "$objects": [
                "$null",
                {"pub": pl.UID(2), "ct": pl.UID(3), "tag": pl.UID(4)},
                point,
                body,
                tag,
            ],
        },
        fmt=pl.FMT_BINARY,
    )


def test_an_archive_holding_the_parts_separately_still_decrypts() -> None:
    # "Expands to an ECIES ciphertext structure" means members, not one blob. A reader
    # expecting a single payload hands the wrong 16 bytes to the point parser.
    from findmy.keychain.shares import ecies_decrypt_archive  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP384R1())

    assert ecies_decrypt_archive(key, split_archive(key.public_key(), b"the key")) == b"the key"


def test_an_archive_holding_one_concatenated_member_also_decrypts() -> None:
    from findmy.keychain.shares import ecies_decrypt_archive  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP384R1())
    sealed = ecies_encrypt(key.public_key(), b"the key")

    assert ecies_decrypt_archive(key, archive(sealed)) == b"the key"


def test_an_archive_that_does_not_authenticate_names_its_members() -> None:
    # "It did not decrypt" is not actionable; the member names and sizes are.
    from findmy.keychain.shares import ecies_decrypt_archive  # noqa: PLC0415

    ours = ec.generate_private_key(ec.SECP384R1())
    theirs = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(ShareError, match="It holds:"):
        ecies_decrypt_archive(ours, split_archive(theirs.public_key(), b"not for us"))


# --------------------------------------------------------------------------------------
# The parameters the specification does not pin down
# --------------------------------------------------------------------------------------


def sealed_with(  # noqa: PLR0913
    public_key,  # noqa: ANN001
    plaintext: bytes,
    *,
    digest: str = "sha256",
    key_length: int = 16,
    iv_length: int = 16,
    derived_iv: bool = False,
    info_point: bool = True,
    aad_point: bool = True,
) -> bytes:
    """Seal under one specific parameter choice, to check that choice is recognised."""
    ephemeral = ec.generate_private_key(public_key.curve)
    point = ephemeral.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    shared = ephemeral.exchange(ec.ECDH(), public_key)

    shared_info = point if info_point else b""
    length = key_length + (iv_length if derived_iv else 0)

    out, counter = b"", 1
    while len(out) < length:
        out += hashlib.new(digest, shared + counter.to_bytes(4, "big") + shared_info).digest()
        counter += 1

    key = out[:key_length]
    iv = out[key_length:length] if derived_iv else bytes(iv_length)

    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    if aad_point:
        encryptor.authenticate_additional_data(point)
    body = encryptor.update(plaintext) + encryptor.finalize()
    return point + body + encryptor.tag


@pytest.mark.parametrize(
    "choice",
    [
        {"digest": "sha384"},
        {"key_length": 32},
        {"iv_length": 12},
        {"derived_iv": True, "iv_length": 12},
        {"info_point": False},
        {"aad_point": False},
        {"digest": "sha384", "key_length": 32, "iv_length": 12, "aad_point": False},
    ],
)
def test_every_plausible_ecies_parameter_choice_is_recognised(choice: dict) -> None:
    # The specification names the construction but not these. Each combination costs
    # microseconds and fails on the tag, so searching them is free -- whereas guessing one
    # costs a round trip against a real account, with a passcode, per guess.
    from findmy.keychain.shares import ecies_decrypt  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP384R1())

    assert ecies_decrypt(key, sealed_with(key.public_key(), b"the key", **choice)) == b"the key"


def test_a_twelve_byte_nonce_and_a_sixteen_byte_one_are_not_the_same_thing() -> None:
    # Both are all zeroes and both are "a zero IV", but AES-GCM derives a different
    # counter block from each, so one authenticates and the other does not.
    from findmy.keychain.shares import ecies_decrypt  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP384R1())
    twelve = sealed_with(key.public_key(), b"the key", iv_length=12)
    sixteen = sealed_with(key.public_key(), b"the key", iv_length=16)

    assert twelve != sixteen
    assert ecies_decrypt(key, twelve) == b"the key"
    assert ecies_decrypt(key, sixteen) == b"the key"


def test_a_matching_variant_is_named_so_the_answer_can_be_recorded(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The point of the search is to end it: whichever authenticates is the real
    # construction, and saying which turns a sweep into something specifiable.
    import logging  # noqa: PLC0415

    from findmy.keychain.shares import ecies_decrypt  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP384R1())
    sealed = sealed_with(key.public_key(), b"the key", digest="sha384", key_length=32)

    with caplog.at_level(logging.INFO, logger="findmy.keychain.shares"):
        ecies_decrypt(key, sealed)

    assert "sha384/aes256-gcm" in caplog.text


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
        wrappedkey=archive(ecies_encrypt(key.public_key(), b"the view key")),
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
    assert "wrapped to a different key" in (share.error or "")
    assert "recovery is what to look at" in (share.error or "")


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

    assert data.endswith(b"\x01\x00\x00\x00\x00\x00\x00\x00" + b"\xff" * 8 + bytes(4))


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
