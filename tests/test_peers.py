"""
Tests for the trust-circle directory (Stage 3 §5.3).

Everything here fails silently rather than loudly. A response shape read one level too
flat, a loop that stops on the first page, a change of an unexpected kind, an expired
token -- each yields an *empty directory* rather than an error, and an empty directory
does not announce itself. It surfaces much later as key shares whose senders cannot be
identified, which points at the shares rather than at this.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from findmy.cloudkit.client import CloudKitError
from findmy.cloudkit.proto import cloudkit_pb2 as ck
from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.keychain.peers import (
    Peer,
    PeerDirectory,
    PeerDirectoryError,
    _peer_from_proto,
    check_peer_identifiers,
    fetch_peer_directory,
    load_public_key,
    peer_identifier,
)


def a_public_key() -> bytes:
    key = ec.generate_private_key(ec.SECP384R1())
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def a_peer(peer_hash: str) -> cf.CuttlefishPeer:
    info = cf.PeerPermanentInfo(
        signing_key=a_public_key(),
        encryption_key=a_public_key(),
        machine_id="MACHINE",
        model_id="MacBookPro18,1",
    )
    return cf.CuttlefishPeer(
        hash=peer_hash,
        permanent_info=cf.SignedInfo(info=info.SerializeToString(), signature=b"sig"),
    )


def a_page(peers: list[str], token: str | None = None) -> bytes:
    """One `fetchChanges` response, with the nesting the real one has."""
    changes = cf.CuttlefishChanges(changes=[cf.CuttlefishChange(add=a_peer(h)) for h in peers])
    if token is not None:
        changes.sync_token = token
    return cf.FetchChangesResponse(changes=changes).SerializeToString()


class FakeClient:
    """A CloudKit client that hands back a scripted sequence of pages."""

    def __init__(self, pages: list[bytes | Exception]) -> None:
        self.pages = pages
        self.tokens_sent: list[str | None] = []

    async def function_invoke(self, _service: str, _method: str, payload: bytes) -> bytes:
        request = cf.FetchChangesRequest.FromString(payload)
        self.tokens_sent.append(request.sync_token if request.HasField("sync_token") else None)

        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page


def an_expired_token_error() -> CloudKitError:
    result = ck.Result(code=1)
    result.error.error_key = "CKErrorDomain.changeTokenExpired"
    return CloudKitError("the change token expired", result)


# --------------------------------------------------------------------------------------
# The response is nested one level deeper than it looks
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_changes_are_nested_inside_a_container() -> None:
    # Reading `changes` as a repeated field directly on the response parses cleanly and
    # finds no peers, which is indistinguishable from an account with an empty circle.
    client = FakeClient([a_page(["PEER-1", "PEER-2"]), a_page([])])

    directory = await fetch_peer_directory(client)  # type: ignore[arg-type]

    assert len(directory) == 2
    assert "PEER-1" in directory


@pytest.mark.asyncio
async def test_the_sync_token_comes_from_the_container_too() -> None:
    client = FakeClient([a_page(["PEER-1"], token="tok-1"), a_page([], token="tok-2")])

    directory = await fetch_peer_directory(client)  # type: ignore[arg-type]

    assert directory.sync_token == "tok-2"


# --------------------------------------------------------------------------------------
# It is a loop, and only an empty page ends it
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_first_page_carrying_no_peers_does_not_end_the_loop() -> None:
    # This is the whole reason a single call reports an empty circle: the first page
    # legitimately carries changes and no peers, and stopping there finds nobody.
    empty_of_peers = cf.FetchChangesResponse(
        changes=cf.CuttlefishChanges(changes=[cf.CuttlefishChange()], sync_token="tok-1"),
    ).SerializeToString()

    client = FakeClient([empty_of_peers, a_page(["PEER-1"], token="tok-2"), a_page([])])

    directory = await fetch_peer_directory(client)  # type: ignore[arg-type]

    assert len(directory) == 1


@pytest.mark.asyncio
async def test_the_loop_stops_only_when_a_page_carries_no_changes() -> None:
    client = FakeClient([a_page(["P1"]), a_page(["P2"]), a_page(["P3"]), a_page([])])

    directory = await fetch_peer_directory(client)  # type: ignore[arg-type]

    assert len(directory) == 3
    assert client.pages == []


@pytest.mark.asyncio
async def test_each_call_carries_the_token_the_last_one_returned() -> None:
    client = FakeClient([a_page(["P1"], token="tok-1"), a_page([], token="tok-2")])

    await fetch_peer_directory(client)  # type: ignore[arg-type]

    assert client.tokens_sent == [None, "tok-1"]


@pytest.mark.asyncio
async def test_a_stored_token_is_sent_on_the_first_call() -> None:
    client = FakeClient([a_page([])])

    await fetch_peer_directory(client, sync_token="stored")

    assert client.tokens_sent == ["stored"]


@pytest.mark.asyncio
async def test_a_feed_that_never_empties_is_stopped_by_the_backstop() -> None:
    client = FakeClient([a_page(["P1"]) for _ in range(10)])

    directory = await fetch_peer_directory(client, max_pages=3)  # type: ignore[arg-type]

    assert len(client.pages) == 7
    assert len(directory) == 1


# --------------------------------------------------------------------------------------
# Changes of other kinds
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_change_that_is_not_an_add_is_skipped_rather_than_failing() -> None:
    # A change carrying something else at another number is normal traffic, not an error.
    other = cf.CuttlefishChange()
    other.MergeFromString(b"\x0a\x03abc")  # field 1, bytes -- not an `add`

    page = cf.FetchChangesResponse(
        changes=cf.CuttlefishChanges(changes=[other, cf.CuttlefishChange(add=a_peer("P1"))]),
    ).SerializeToString()

    directory = await fetch_peer_directory(FakeClient([page, a_page([])]))  # type: ignore[arg-type]

    assert len(directory) == 1


@pytest.mark.asyncio
async def test_a_peer_without_a_signing_key_is_not_admitted() -> None:
    peer = cf.CuttlefishPeer(
        hash="P1",
        permanent_info=cf.SignedInfo(info=cf.PeerPermanentInfo().SerializeToString()),
    )
    page = cf.FetchChangesResponse(
        changes=cf.CuttlefishChanges(changes=[cf.CuttlefishChange(add=peer)]),
    ).SerializeToString()

    directory = await fetch_peer_directory(FakeClient([page, a_page([])]))  # type: ignore[arg-type]

    assert len(directory) == 0


# --------------------------------------------------------------------------------------
# An expired token is recoverable, not fatal
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_expired_token_restarts_the_read_from_nothing() -> None:
    client = FakeClient([an_expired_token_error(), a_page(["P1"]), a_page([])])

    directory = await fetch_peer_directory(client, sync_token="stale")

    assert len(directory) == 1
    assert client.tokens_sent == ["stale", None, None]


@pytest.mark.asyncio
async def test_a_restart_discards_what_was_read_under_the_old_token() -> None:
    # The peers read before the reset belong to a circle that no longer exists. Keeping
    # them would mix two circles' membership, which is worse than having read nothing.
    client = FakeClient(
        [a_page(["GONE"], token="tok-1"), an_expired_token_error(), a_page(["P1"]), a_page([])],
    )

    directory = await fetch_peer_directory(client)  # type: ignore[arg-type]

    assert "GONE" not in directory
    assert "P1" in directory


@pytest.mark.asyncio
async def test_restarting_is_tried_once_and_not_forever() -> None:
    client = FakeClient([an_expired_token_error(), an_expired_token_error()])

    with pytest.raises(CloudKitError):
        await fetch_peer_directory(client)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_any_other_cloudkit_error_is_raised_rather_than_retried() -> None:
    result = ck.Result(code=1)
    result.error.error_key = "CKErrorDomain.notAuthenticated"

    client = FakeClient([CloudKitError("not authenticated", result)])

    with pytest.raises(CloudKitError, match="not authenticated"):
        await fetch_peer_directory(client)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_a_response_that_does_not_decode_says_which_layer_is_wrong() -> None:
    client = FakeClient([b"\xff\xff\xff\xff"])

    with pytest.raises(PeerDirectoryError, match="CloudKit envelope"):
        await fetch_peer_directory(client)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------
# Reading a peer's key
# --------------------------------------------------------------------------------------


def test_a_public_key_is_read_whichever_way_it_is_written() -> None:
    key = ec.generate_private_key(ec.SECP384R1()).public_key()

    as_point = key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    as_der = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    assert load_public_key(as_point) == key
    assert load_public_key(as_der) == key


def test_something_that_is_not_a_key_reads_as_nothing() -> None:
    assert load_public_key(b"not a key") is None


def test_an_empty_directory_holds_nobody() -> None:
    assert len(PeerDirectory()) == 0
    assert "anyone" not in PeerDirectory()


# --------------------------------------------------------------------------------------
# Peer identifiers (§6.9, and what makes a join checkable before it is irreversible)
# --------------------------------------------------------------------------------------


def a_real_peer(signature: bytes = b"sig") -> cf.CuttlefishPeer:
    """A peer whose hash is the one its own permanent info derives, as a real one's is."""
    peer = a_peer("placeholder")
    peer.hash = peer_identifier(peer.permanent_info.info, signature)
    peer.permanent_info.signature = signature
    return peer


def test_a_peer_identifier_digests_the_info_then_the_signature() -> None:
    info, signature = b"the-info", b"the-signature"
    expected = base64.b64encode(hashlib.sha256(info + signature).digest()).decode()

    assert peer_identifier(info, signature) == f"SHA256:{expected}"


def test_the_prefix_is_part_of_the_identifier_not_decoration_on_a_label() -> None:
    assert peer_identifier(b"a", b"b").startswith("SHA256:")


def test_the_two_halves_are_not_interchangeable() -> None:
    assert peer_identifier(b"aa", b"bb") != peer_identifier(b"bb", b"aa")


def test_a_peer_keeps_the_bytes_its_identifier_is_computed_over() -> None:
    # Not a re-encoding of the parsed message: protobuf does not promise those match, and
    # a re-encoded permanent info would produce a different peer id for the same peer.
    proto = a_real_peer()

    peer = _peer_from_proto(proto)

    assert peer is not None
    assert peer.permanent_info == proto.permanent_info.info
    assert peer.permanent_signature == proto.permanent_info.signature


def test_the_derivation_is_confirmed_against_peers_already_in_the_circle() -> None:
    # The whole point: every existing peer is a worked example, checking costs nothing and
    # writes nothing, and reproducing a SHA-256 digest by accident does not happen. This
    # is what turns joinWithVoucher from an irreversible guess into an ordinary call.
    peer = _peer_from_proto(a_real_peer())
    assert peer is not None

    check = check_peer_identifiers(PeerDirectory(peers={peer.hash: peer}))

    assert check.confirmed
    assert check.matched == [peer.hash]


def test_a_derivation_that_misses_is_reported_rather_than_averaged_away() -> None:
    proto = a_real_peer()
    proto.hash = "SHA256:not-what-it-derives-to"
    peer = _peer_from_proto(proto)
    assert peer is not None

    check = check_peer_identifiers(PeerDirectory(peers={peer.hash: peer}))

    assert not check.confirmed
    assert check.mismatched == ["SHA256:not-what-it-derives-to"]


def test_a_peer_with_nothing_to_digest_neither_confirms_nor_denies() -> None:
    # Counted separately, because "checked and wrong" and "could not be checked" say
    # opposite things about whether a voucher is safe to build.
    peer = Peer(
        hash="SHA256:whatever",
        signing_key=a_public_key(),
        encryption_key=b"",
        machine_id="m",
        model_id="",
    )

    check = check_peer_identifiers(PeerDirectory(peers={peer.hash: peer}))

    assert check.uncheckable == ["SHA256:whatever"]
    assert not check.confirmed
