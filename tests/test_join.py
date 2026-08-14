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


# --------------------------------------------------------------------------------------
# The identity a join sends (§6.8.2)
# --------------------------------------------------------------------------------------


def a_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def _trusting(
    name: str,
    clock: int,
    *,
    includeds: list[str] | None = None,
    excludeds: list[str] | None = None,
    key: ec.EllipticCurvePrivateKey | None = None,
):
    from findmy.keychain.join import public_spki  # noqa: PLC0415
    from findmy.keychain.peers import Peer  # noqa: PLC0415

    return Peer(
        hash=name,
        signing_key=public_spki((key or a_key()).public_key()),
        encryption_key=b"",
        machine_id="",
        model_id="",
        dynamic_clock=clock,
        includeds=tuple(includeds or []),
        excludeds=tuple(excludeds or []),
    )


def _vouched_by(  # noqa: PLR0913
    name: str,
    clock: int,
    *,
    sponsor: str,
    key: ec.EllipticCurvePrivateKey,
    beneficiary: str | None = None,
    includeds: list[str] | None = None,
):
    """A peer carrying a voucher signed by `key` and naming `sponsor` as its sponsor."""
    import dataclasses  # noqa: PLC0415

    from findmy.keychain.join import make_voucher  # noqa: PLC0415

    voucher = make_voucher(beneficiary or name, sponsor, key)
    return dataclasses.replace(
        _trusting(name, clock, includeds=includeds),
        voucher_info=voucher.info,
        voucher_signature=voucher.signature,
    )


def a_circle(*peers):
    from findmy.keychain.peers import PeerDirectory  # noqa: PLC0415

    return PeerDirectory(peers={peer.hash: peer for peer in peers})


def test_a_joining_peers_stable_clock_is_the_circles_highest_plus_one() -> None:
    from findmy.keychain.join import next_stable_clock  # noqa: PLC0415
    from findmy.keychain.peers import Peer, PeerDirectory  # noqa: PLC0415

    def peer(name: str, clock: int) -> Peer:
        return Peer(
            hash=name,
            signing_key=b"",
            encryption_key=b"",
            machine_id="",
            model_id="",
            stable_clock=clock,
        )

    directory = PeerDirectory(peers={"a": peer("a", 3), "b": peer("b", 7)})

    assert next_stable_clock(directory) == 8


def test_a_first_peer_sends_clock_one_not_zero() -> None:
    # Zero is the DYNAMIC info's value. Both fields are called clock and they differ.
    from findmy.keychain.join import next_stable_clock  # noqa: PLC0415
    from findmy.keychain.peers import PeerDirectory  # noqa: PLC0415

    assert next_stable_clock(PeerDirectory()) == 1


def test_a_joining_peer_inherits_its_sponsors_trust_and_adds_itself() -> None:
    # The corrected §6.8.2. An empty includeds with clock 0 is the ESTABLISH shape, and
    # sending it on a join admits a peer that claims to trust nobody.
    from findmy.keychain.join import merge_trust  # noqa: PLC0415

    directory = a_circle(
        _trusting("sponsor", 4, includeds=["sponsor", "old"], excludeds=["gone"]),
    )

    trust = merge_trust(directory, peer_id="new", sponsor="sponsor")

    assert trust.clock == 5
    assert trust.includeds == ("sponsor", "old", "new")
    assert trust.excludeds == ("gone",)


def test_a_higher_clocked_peer_is_merged_and_its_removals_applied_after() -> None:
    from findmy.keychain.join import merge_trust  # noqa: PLC0415

    directory = a_circle(
        _trusting("sponsor", 4, includeds=["sponsor", "doomed", "ahead"]),
        _trusting("ahead", 9, includeds=["sponsor", "extra"], excludeds=["doomed"]),
    )

    trust = merge_trust(directory, peer_id="new", sponsor="sponsor")

    # Includes first, then excludes: "doomed" is carried in from the sponsor and removed
    # by the later peer, not the other way round.
    assert "doomed" not in trust.includeds
    assert trust.includeds == ("sponsor", "ahead", "extra", "new")
    assert trust.excludeds == ("doomed",)
    assert trust.clock == 10


def test_peers_are_fast_forwarded_in_ascending_clock_order() -> None:
    # Out of order, a removal made by a newer peer can be undone by an older one's
    # inclusion, and the result silently re-trusts a peer the circle removed.
    from findmy.keychain.join import merge_trust  # noqa: PLC0415

    directory = a_circle(
        _trusting("sponsor", 1, includeds=["sponsor", "later", "earlier"]),
        _trusting("later", 8, excludeds=["revoked"]),
        _trusting("earlier", 3, includeds=["revoked"]),
    )

    trust = merge_trust(directory, peer_id="new", sponsor="sponsor")

    assert "revoked" not in trust.includeds
    assert trust.excludeds == ("revoked",)
    assert trust.clock == 9


def test_an_unvouched_peers_update_is_ignored() -> None:
    # A peer asserting membership is how an untrusted party would write itself into the
    # circle. Without a valid voucher its whole update is dropped, not merged.
    from findmy.keychain.join import merge_trust  # noqa: PLC0415

    directory = a_circle(
        _trusting("sponsor", 2, includeds=["sponsor"]),
        _trusting("stranger", 6, includeds=["stranger", "friend"]),
    )

    trust = merge_trust(directory, peer_id="new", sponsor="sponsor")

    assert trust.includeds == ("sponsor", "new")
    assert trust.clock == 3


def test_a_vouched_peer_is_adopted() -> None:
    from findmy.keychain.join import merge_trust  # noqa: PLC0415

    sponsor_key = a_key()
    directory = a_circle(
        _trusting("sponsor", 2, includeds=["sponsor"], key=sponsor_key),
        _vouched_by("newcomer", 6, sponsor="sponsor", key=sponsor_key, includeds=["newcomer"]),
    )

    trust = merge_trust(directory, peer_id="new", sponsor="sponsor")

    assert "newcomer" in trust.includeds
    assert trust.clock == 7


def test_a_voucher_signed_by_the_wrong_key_does_not_admit() -> None:
    from findmy.keychain.join import merge_trust  # noqa: PLC0415

    directory = a_circle(
        _trusting("sponsor", 2, includeds=["sponsor"], key=a_key()),
        # Vouched, but signed by a key that is not the sponsor's.
        _vouched_by("newcomer", 6, sponsor="sponsor", key=a_key(), includeds=["newcomer"]),
    )

    assert "newcomer" not in merge_trust(directory, peer_id="new", sponsor="sponsor").includeds


def test_a_voucher_for_somebody_else_does_not_admit_the_bearer() -> None:
    from findmy.keychain.join import merge_trust  # noqa: PLC0415

    sponsor_key = a_key()
    directory = a_circle(
        _trusting("sponsor", 2, includeds=["sponsor"], key=sponsor_key),
        _vouched_by(
            "newcomer",
            6,
            sponsor="sponsor",
            key=sponsor_key,
            beneficiary="somebody-else",
            includeds=["newcomer"],
        ),
    )

    assert "newcomer" not in merge_trust(directory, peer_id="new", sponsor="sponsor").includeds


def test_an_excluded_peer_is_not_readmitted_by_its_own_voucher() -> None:
    from findmy.keychain.join import merge_trust  # noqa: PLC0415

    sponsor_key = a_key()
    directory = a_circle(
        _trusting("sponsor", 2, includeds=["sponsor"], excludeds=["newcomer"], key=sponsor_key),
        _vouched_by("newcomer", 6, sponsor="sponsor", key=sponsor_key, includeds=["newcomer"]),
    )

    assert "newcomer" not in merge_trust(directory, peer_id="new", sponsor="sponsor").includeds


def test_joining_without_a_sponsor_in_the_circle_is_refused() -> None:
    from findmy.keychain.join import JoinError, merge_trust  # noqa: PLC0415
    from findmy.keychain.peers import PeerDirectory  # noqa: PLC0415

    with pytest.raises(JoinError, match="no trust to inherit"):
        merge_trust(PeerDirectory(), peer_id="new", sponsor="absent")


def test_the_signed_dynamic_info_is_what_was_merged() -> None:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415
    from findmy.keychain.join import make_dynamic_info, merge_trust  # noqa: PLC0415

    directory = a_circle(_trusting("sponsor", 4, includeds=["sponsor"]))
    trust = merge_trust(directory, peer_id="new", sponsor="sponsor")

    info = cf.PeerDynamicInfo()
    info.ParseFromString(make_dynamic_info(a_key(), trust).info)

    assert info.clock == 5
    assert list(info.includeds) == ["sponsor", "new"]


def test_the_empty_shape_survives_where_it_belongs() -> None:
    # clock 0 with everything cleared is the reset a client applies when it finds itself
    # outside the circle -- not the join.
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415
    from findmy.keychain.join import reset_dynamic_info  # noqa: PLC0415

    info = cf.PeerDynamicInfo()
    info.ParseFromString(reset_dynamic_info(a_key()).info)

    assert info.clock == 0
    assert list(info.includeds) == []


def test_the_stable_info_carries_both_policies_verbatim() -> None:
    # Digests of Apple's own policy documents, not anything to compute. A wrong value is
    # not detectable locally, which is why they are constants rather than defaults.
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415
    from findmy.keychain.join import make_stable_info  # noqa: PLC0415

    blob = make_stable_info(a_key(), clock=4, os_version="18.1", serial_number="X")

    info = cf.PeerStableInfo()
    info.ParseFromString(blob.info)
    assert info.frozen_policy_version == 5
    assert info.frozen_policy_hash == b"SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo="
    assert info.flexible_policy_version == 20
    assert info.flexible_policy_hash == b"SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY="
    assert info.user_controllable_view_status == 1
    assert info.is_inherited_account is False


def test_each_blob_is_signed_under_its_own_type_string() -> None:
    # The prefix is what stops a blob of one kind being presented as another, so a blob
    # must not verify under a different kind's prefix.
    from findmy.keychain.join import (  # noqa: PLC0415
        TYPE_DYNAMIC_INFO,
        TYPE_STABLE_INFO,
        make_dynamic_info,
    )

    from findmy.keychain.join import TrustSet  # noqa: PLC0415

    key = a_key()
    blob = make_dynamic_info(key, TrustSet(clock=1, includeds=("a",), excludeds=()))

    assert blob.verify(key.public_key())
    assert not blob.verify(key.public_key(), TYPE_STABLE_INFO)
    assert blob.verify(key.public_key(), TYPE_DYNAMIC_INFO)


def test_a_peers_identifier_is_the_digest_of_the_permanent_info_it_signed() -> None:
    # The end-to-end shape of §6.8.2: the bytes that get signed are the bytes that get
    # digested, and the identifier is what a voucher's beneficiary must equal.
    from findmy.keychain.join import make_permanent_info  # noqa: PLC0415
    from findmy.keychain.peers import peer_identifier  # noqa: PLC0415

    key = a_key()
    blob = make_permanent_info(
        key,
        signing_public=b"\x04" + bytes(96),
        encryption_public=b"\x04" + bytes(96),
        machine_id="MACHINE",
        model_id="iPhone14,2",
        creation_time=1700000000,
    )

    assert blob.verify(key.public_key())
    assert peer_identifier(blob.info, blob.signature).startswith("SHA256:")


def test_every_field_the_specification_types_is_declared_that_way() -> None:
    # `string` and `bytes` share a protobuf wire type, so a wrongly declared field decodes
    # cleanly, reads correctly, and passes every test -- until something has to write it.
    # That has happened twice in this stage, both times on values only ever read before.
    # So a type is transcribed as carefully as a field number, and checked here.
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    text, data = FieldDescriptor.TYPE_STRING, FieldDescriptor.TYPE_BYTES
    expected = {
        cf.SignedInfo: {"info": data, "signature": data},
        cf.Voucher: {"beneficiary": text, "sponsor": text},
        cf.PeerPermanentInfo: {
            "signing_key": data,
            "encryption_key": data,
            "machine_id": text,
            "model_id": text,
        },
        cf.PeerDynamicInfo: {"includeds": text, "excludeds": text, "preapprovals": text},
        cf.Bottle: {
            "bottle": data,
            "escrowed_signing_key": data,
            "escrowed_key_signature": data,
            "peer_key_signature": data,
            "peer_id": text,
            "bottle_id": text,
        },
        cf.OTBottle: {"peer_id": text, "bottle_id": text, "escrowed_signing_key": data},
        # Binary-looking, and string on the wire regardless.
        cf.TlkShare: {
            "wrapped_key": text,
            "signature": text,
            "receiver_public_encryption_key": text,
            "service": text,
            "key_id": text,
        },
        # The token that comes back from a join is the one a join sends: a string at both
        # ends, which is the pair that was wrong before anything had to write it.
        cf.CuttlefishChanges: {"sync_token": text},
        cf.FetchChangesRequest: {"sync_token": text},
        cf.CuttlefishJoinWithVoucherRequest: {"restore_point": text},
        cf.CuttlefishUpdateTrustRequest: {"restore_point": text, "peer_id": text},
        # The one bytes field among four, against §6.9's pattern of declaring
        # binary-looking values as strings.
        cf.TlkKeyMaterial: {
            "uuid": text,
            "zone_name": text,
            "key_class": text,
            "key": data,
        },
    }

    for message, fields in expected.items():
        declared = {field.name: field.type for field in message.DESCRIPTOR.fields}
        for name, kind in fields.items():
            assert declared[name] == kind, f"{message.DESCRIPTOR.name}.{name}"


def test_view_keys_type_is_transcribed_but_has_never_been_written() -> None:
    # Asserted for the same reason as the rest, and separately from them: **nothing in
    # this project constructs a ViewKey**, so unlike every other message here this has
    # never been exercised in the direction that would catch a wrong type. Its `key` is a
    # string, following TlkShare rather than the key material message a few structures
    # away, and the fifth field really is spelled `harware`. This checks the transcription
    # and claims nothing more.
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    declared = {field.name: field.type for field in cf.ViewKey.DESCRIPTOR.fields}

    assert declared["key_id"] == FieldDescriptor.TYPE_STRING
    assert declared["top_level_key_id"] == FieldDescriptor.TYPE_STRING
    assert declared["key_number"] == FieldDescriptor.TYPE_UINT32
    assert declared["key"] == FieldDescriptor.TYPE_STRING
    # Apple's spelling. Correcting it would name a field nothing is looking for.
    assert declared["harware"] == FieldDescriptor.TYPE_STRING
    assert "hardware" not in declared

    # And the enclosing message, which this project always sends empty.
    assert {f.name: f.number for f in cf.ViewKeys.DESCRIPTOR.fields} == {
        "service": 1,
        "top_level_key": 2,
        "class_a": 3,
        "class_c": 4,
        "old_top_level_key": 5,
    }
