"""
Who is in the trust circle, and what they sign with.

Implements Stage 3 §5.3 of the Find My key-export protocol specification: an incremental
feed of the circle's peers, and the directory built from it.

**This is not optional bookkeeping.** Two checks depend on it and neither can be done
without it: a key share's signature is verified against its *sending* peer's key, and a
recovered bottle carries a signature from its *sponsoring* peer. Both name a peer by hash
and nothing else in the protocol says what that peer's key is. That is why a recovery
sequence begins by syncing trust -- to populate this before anything needs to consult it.

A peer genuinely absent from the directory is a reason to **reject** the share or bottle
that names it, not to proceed. Unwrapping the user's keychain with material from a party
nothing can identify is not a small thing to wave through.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from google.protobuf.message import DecodeError

from findmy.cloudkit.client import CloudKitError
from findmy.cloudkit.constants import CUTTLEFISH_SERVICE
from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.errors import UnhandledProtocolError

if TYPE_CHECKING:
    from findmy.cloudkit.client import AsyncCloudKitClient

logger = logging.getLogger(__name__)

METHOD_FETCH_CHANGES = "fetchChanges"

# A backstop against a feed that never stops handing back tokens.
MAX_PAGES = 50

# The circle was reset, so the stored token names a history that no longer exists. Not
# fatal: discarding the token and everything read under it and starting again recovers.
CHANGE_TOKEN_EXPIRED = "changeTokenExpired"  # noqa: S105 -- a CloudKit error name

# Only an `add` builds the directory. A change may carry other kinds at other numbers, and
# treating one of those as a peer -- or as an error -- is how a working feed looks broken.
CHANGE_ADD = "add"


class PeerDirectoryError(UnhandledProtocolError):
    """Raised when the circle's peers cannot be read."""


def load_public_key(data: bytes) -> ec.EllipticCurvePublicKey | None:
    """
    Read a peer's public key, whichever way it is encoded.

    Encodings observed in this protocol vary by structure -- a bottle escrows DER
    SubjectPublicKeyInfo, a peer key travels as a raw point beside its scalar -- and
    nothing states which a peer's permanent info uses. All are tried; they are
    distinguishable, so a wrong guess is not possible rather than merely unlikely.

    :returns: The key, or None if the bytes are not a public key at all.
    """
    with contextlib.suppress(ValueError, UnsupportedAlgorithm):
        loaded = load_der_public_key(data)
        if isinstance(loaded, ec.EllipticCurvePublicKey):
            return loaded

    for curve in (ec.SECP384R1(), ec.SECP256R1()):
        with contextlib.suppress(ValueError):
            return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)

    return None


@dataclass(frozen=True)
class Peer:
    """One peer of the trust circle, as far as verifying against it requires."""

    hash: str
    """How everything else names this peer."""

    signing_key: bytes
    """Its public signing key, from the permanent info. What signatures verify against."""

    encryption_key: bytes
    machine_id: str
    model_id: str

    def signing_public_key(self) -> ec.EllipticCurvePublicKey | None:
        """Load the signing key, or None if it is not in a shape this understands."""
        return load_public_key(self.signing_key)


@dataclass(frozen=True)
class PeerDirectory:
    """The peers of a trust circle, indexed by hash."""

    peers: dict[str, Peer] = field(default_factory=dict)

    sync_token: bytes | None = None
    """
    Where the feed reached.

    Worth persisting. Fetching from the beginning every run re-reads the whole circle for
    no benefit.
    """

    def get(self, peer_hash: str) -> Peer | None:
        """Look up a peer, or None if the circle does not contain one by that name."""
        return self.peers.get(peer_hash)

    def __len__(self) -> int:
        """How many peers the directory holds."""
        return len(self.peers)

    def __contains__(self, peer_hash: object) -> bool:
        """Whether a peer is known."""
        return peer_hash in self.peers


def _peer_from_proto(peer: cf.CuttlefishPeer) -> Peer | None:
    """Read a peer's permanent info, which is where its keys live."""
    if not peer.hash:
        return None

    info = cf.PeerPermanentInfo()
    try:
        info.ParseFromString(peer.permanent_info.info)
    except DecodeError:
        logger.warning("Peer %s has permanent info that does not decode", peer.hash)
        return None

    if not info.signing_key:
        logger.warning("Peer %s carries no signing key", peer.hash)
        return None

    return Peer(
        hash=peer.hash,
        signing_key=info.signing_key,
        encryption_key=info.encryption_key,
        machine_id=info.machine_id,
        model_id=info.model_id,
    )


async def fetch_peer_directory(
    client: AsyncCloudKitClient,
    *,
    sync_token: bytes | None = None,
    max_pages: int = MAX_PAGES,
) -> PeerDirectory:
    """
    Read the circle's peers.

    Read-only, and creates nothing. Note that the signed blobs a peer carries are **not
    verified here** -- this establishes who exists and what they claim to sign with, which
    is the prerequisite for verifying anything else.

    :param client: A CloudKit client on the keychain container.
    :param sync_token: Resume from a previous read rather than starting over.
    :param max_pages: A backstop against a feed that never ends.
    """
    peers: dict[str, Peer] = {}
    token = sync_token
    restarted = False

    for page in range(max_pages):
        try:
            response = await _fetch_page(client, token)
        except CloudKitError as e:
            if not _is_change_token_expired(e) or restarted:
                raise
            # The circle was reset under us, so both the token and everything read under
            # it name a history that no longer exists. Starting over is the recovery;
            # treating this as fatal strands a client that could just resynchronise.
            logger.info("The trust circle's change token expired; reading it again in full")
            restarted = True
            peers.clear()
            token = None
            continue

        changes = response.changes.change
        added = 0
        for change in changes:
            # Anything that is not an `add` is another kind of change, not a peer and not
            # a problem. Skipping quietly is the correct handling of both -- a change at
            # a field this does not know parses into the unknown set and lands here.
            if not change.HasField(CHANGE_ADD):
                continue
            peer = _peer_from_proto(change.add)
            if peer is not None:
                peers[peer.hash] = peer
                added += 1

        if response.changes.HasField("sync_token"):
            token = response.changes.sync_token

        logger.debug(
            "Trust page %d: %d change(s), %d peer(s) added",
            page + 1,
            len(changes),
            added,
        )

        # An empty page is the *only* thing that ends this. A page carrying no peers is
        # not empty and does not end it either: the first page routinely carries none,
        # so stopping on "no peers yet" reports an empty circle for an account that has
        # one. That failure is silent -- every share then has an unidentifiable sender.
        #
        # Note this tests the repeated field and not `response.changes`, which is a
        # message and therefore always truthy however empty it is.
        if not changes:
            break
    else:
        logger.warning(
            "Stopped reading the trust circle after %d pages; it may be incomplete",
            max_pages,
        )

    logger.info("Trust circle holds %d peer(s)", len(peers))
    return PeerDirectory(peers=peers, sync_token=token)


async def _fetch_page(
    client: AsyncCloudKitClient,
    token: bytes | None,
) -> cf.FetchChangesResponse:
    """Ask for one page of the trust circle's changes."""
    request = cf.FetchChangesRequest()
    if token is not None:
        request.sync_token = token

    serialized = await client.function_invoke(
        CUTTLEFISH_SERVICE,
        METHOD_FETCH_CHANGES,
        request.SerializeToString(),
    )

    response = cf.FetchChangesResponse()
    try:
        response.ParseFromString(serialized)
    except DecodeError as e:
        msg = (
            f"CloudKit accepted the call but its result did not decode as a"
            f" {METHOD_FETCH_CHANGES} response ({e}). The inner message layer is what"
            " is wrong, not the CloudKit envelope."
        )
        raise PeerDirectoryError(msg) from None

    return response


def _is_change_token_expired(error: CloudKitError) -> bool:
    """Whether a CloudKit failure is the circle saying the stored token is stale."""
    return CHANGE_TOKEN_EXPIRED in error.error_key or CHANGE_TOKEN_EXPIRED in str(error)
