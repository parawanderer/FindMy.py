"""
Tests for the join message layer (Stage 3 §6.9).

Four things in these messages fail silently rather than loudly, and each has a test here:
the signature covers serialised bytes rather than a parsed message, OTBottle reserves
fields 3 to 7, OTInternalBottle starts at field 3, and TlkShare declares binary-looking
members as strings.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.descriptor import FieldDescriptor

from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.keychain.join import (
    TYPE_VOUCHER,
    JoinError,
    SignedBlob,
    make_join_request,
    make_peer,
    make_voucher,
    require_key_shares,
)


def signing_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def a_share() -> cf.TlkShare:
    return cf.TlkShare(service="Manatee", key_id="KEY-1", receiver="PEER-NEW")


# --------------------------------------------------------------------------------------
# The signature covers bytes, not a message
# --------------------------------------------------------------------------------------


def test_a_signed_blob_verifies_against_the_bytes_it_signed() -> None:
    key = signing_key()
    blob = SignedBlob.sign(b"some serialised message", key, TYPE_VOUCHER)

    assert blob.verify(key.public_key()) is True


def test_a_signed_blob_does_not_verify_under_another_key() -> None:
    blob = SignedBlob.sign(b"some serialised message", signing_key(), TYPE_VOUCHER)

    assert blob.verify(signing_key().public_key()) is False


def test_a_signed_blob_carries_its_bytes_through_untouched() -> None:
    # The point of the type: there is nothing here to re-encode, so a signature cannot be
    # invalidated by a re-serialisation that changes bytes without changing content.
    key = signing_key()
    voucher = cf.Voucher(reason=0, beneficiary="PEER-NEW", sponsor="PEER-OLD")
    serialised = voucher.SerializeToString()

    blob = SignedBlob.sign(serialised, key, TYPE_VOUCHER)

    assert blob.info == serialised
    assert blob.to_proto().info == serialised
    assert blob.verify(key.public_key()) is True


def test_a_signed_blob_survives_a_round_trip_through_the_wire_message() -> None:
    key = signing_key()
    voucher = cf.Voucher(beneficiary="B", sponsor="S").SerializeToString()
    blob = SignedBlob.sign(voucher, key, TYPE_VOUCHER)

    wire = cf.SignedInfo.FromString(blob.to_proto().SerializeToString())
    recovered = SignedBlob(info=wire.info, signature=wire.signature)

    # The type string is not sent: a reader knows which field it is reading and supplies
    # it. That is what stops a blob of one kind being presented as another.
    assert recovered.verify(key.public_key(), TYPE_VOUCHER) is True
    assert recovered.verify(key.public_key(), b"TPPB.PeerStableInfo") is False


# --------------------------------------------------------------------------------------
# Vouchers
# --------------------------------------------------------------------------------------


def test_a_voucher_is_three_fields_and_a_signature() -> None:
    key = signing_key()
    blob = make_voucher("PEER-NEW", "PEER-OLD", key)

    voucher = cf.Voucher.FromString(blob.info)
    assert voucher.beneficiary == "PEER-NEW"
    assert voucher.sponsor == "PEER-OLD"
    assert blob.verify(key.public_key()) is True


def test_a_peer_cannot_vouch_for_itself() -> None:
    with pytest.raises(JoinError, match="itself"):
        make_voucher("PEER-1", "PEER-1", signing_key())


def test_a_voucher_needs_both_parties() -> None:
    with pytest.raises(JoinError):
        make_voucher("", "PEER-OLD", signing_key())


# --------------------------------------------------------------------------------------
# The join request
# --------------------------------------------------------------------------------------


def a_peer() -> cf.CuttlefishPeer:
    key = signing_key()
    blob = SignedBlob.sign(b"info", key, TYPE_VOUCHER)
    return make_peer(
        "PEER-NEW",
        permanent_info=blob,
        stable_info=blob,
        dynamic_info=blob,
        voucher=make_voucher("PEER-NEW", "PEER-OLD", key),
    )


def test_a_join_request_puts_its_members_at_the_right_numbers() -> None:
    # The establish request carries the same four members in a different order, so a
    # mistake here would serialise cleanly and mean something else entirely.
    request = make_join_request(a_peer(), cf.Bottle(bottle_id="B-1"), [a_share()])
    fields = {f.number: f.name for f, _ in request.ListFields()}

    assert fields[2] == "peer"
    assert fields[3] == "bottle"
    assert fields[4] == "shares"


def test_a_join_request_sends_no_view_keys() -> None:
    # ViewKeys is for establishing keys rather than receiving them.
    request = make_join_request(a_peer(), cf.Bottle(), [a_share()])

    assert list(request.keys) == []


def test_a_restore_point_is_only_sent_when_there_is_one() -> None:
    without = make_join_request(a_peer(), cf.Bottle(), [a_share()])
    with_token = make_join_request(a_peer(), cf.Bottle(), [a_share()], restore_point="tok")

    assert not without.HasField("restore_point")
    assert with_token.restore_point == "tok"


def test_joining_without_key_shares_is_refused() -> None:
    # It would succeed and yield nothing, while leaving a peer in the circle and an
    # escrow record on the account.
    with pytest.raises(JoinError, match="no key shares"):
        make_join_request(a_peer(), cf.Bottle(), [])

    with pytest.raises(JoinError):
        require_key_shares([])


def test_establishing_a_circle_is_not_expressible() -> None:
    # `establish` and `joinWithVoucher` differ by one branch, and the first destroys the
    # user's existing trust circle. Its message is undefined so nothing can build one.
    assert not [name for name in dir(cf) if "establish" in name.lower()]


# --------------------------------------------------------------------------------------
# Field numbering that looks like a bug and is not
# --------------------------------------------------------------------------------------


def test_ot_bottle_reserves_fields_three_to_seven() -> None:
    numbers = {field.number for field in cf.OTBottle.DESCRIPTOR.fields}

    assert numbers.isdisjoint({3, 4, 5, 6, 7})
    assert {1, 2, 8, 9, 10, 11, 12} <= numbers


def test_the_inner_bottle_has_no_field_one_or_two() -> None:
    numbers = {field.number for field in cf.OTInternalBottle.DESCRIPTOR.fields}

    assert numbers == {3, 4}


def test_the_outer_bottle_has_no_field_one() -> None:
    numbers = {field.number for field in cf.Bottle.DESCRIPTOR.fields}

    assert 1 not in numbers
    assert numbers == {2, 3, 4, 5, 6, 7}


def test_peer_stable_info_has_no_field_seventeen() -> None:
    numbers = {field.number for field in cf.PeerStableInfo.DESCRIPTOR.fields}

    assert 17 not in numbers
    assert 18 in numbers


def test_tlk_share_declares_its_binary_looking_members_as_strings() -> None:
    # Whatever the encoding turns out to be, the wire type is a string. Declaring these
    # as bytes would be a different message.
    by_name = {field.name: field for field in cf.TlkShare.DESCRIPTOR.fields}

    for name in ("wrapped_key", "signature", "receiver_public_encryption_key"):
        assert by_name[name].type == FieldDescriptor.TYPE_STRING


def test_the_authenticated_ciphertext_carries_its_tag_separately() -> None:
    # It must be appended to the ciphertext before decryption, or handed to a
    # detached-tag interface.
    numbers = {field.name: field.number for field in cf.OTAuthenticatedCiphertext.DESCRIPTOR.fields}

    assert numbers == {
        "ciphertext": 1,
        "authentication_code": 2,
        "initialization_vector": 3,
    }


def test_a_signature_does_not_carry_across_blob_types() -> None:
    # The prefix is the protection: without it, a stable-info blob could be presented as
    # a voucher and verify. Omitting it does not merely fail -- it removes that.
    key = signing_key()
    payload = b"the same bytes either way"

    as_voucher = SignedBlob.sign(payload, key, TYPE_VOUCHER)
    as_stable = SignedBlob.sign(payload, key, b"TPPB.PeerStableInfo")

    assert as_voucher.signature != as_stable.signature
    assert as_voucher.verify(key.public_key(), b"TPPB.PeerStableInfo") is False
