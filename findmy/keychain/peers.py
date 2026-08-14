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

import base64
import contextlib
import hashlib
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


PEER_ID_PREFIX = "SHA256:"
"""
Part of the identifier, not decoration on it.

`CuttlefishPeer.hash` carries it, and §5.1's escrow labels embed the whole thing.
"""


def peer_identifier(permanent_info: bytes, signature: bytes) -> str:
    """
    Derive a peer's identifier from its signed permanent info.

    `SHA256:` followed by base64 of a SHA-256 over the serialised `PeerPermanentInfo`
    concatenated with its signature -- the payload bytes then the signature bytes, in that
    order, with nothing between them.

    **[observed] Confirmed: this reproduces all 13 peers of a real trust circle.** That is
    a stronger result than most confirmations in this project, because the oracle is an
    exact SHA-256 match -- thirteen accidental digest collisions is not a thing that
    happens, so one run settles the construction outright.

    It is also why the check exists. A voucher names its beneficiary by this identifier,
    derived for an identity that does not exist yet, so nothing about a join can validate
    it: a wrong derivation surfaces *after* `joinWithVoucher`, the one call in this project
    that cannot be taken back. Every peer already in the circle was named by the same rule,
    so :func:`check_peer_identifiers` settles it while still read-only.

    :param permanent_info: The serialised `PeerPermanentInfo`, **as it arrived**. Not a
        re-encoding of a parsed one: protobuf does not promise those are the same bytes.
    :param signature: The signature over it, from the same `SignedInfo`.
    """
    digest = hashlib.sha256(permanent_info + signature).digest()
    return PEER_ID_PREFIX + base64.b64encode(digest).decode()


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

    permanent_info: bytes = b""
    """
    The serialised `PeerPermanentInfo`, exactly as it arrived.

    Kept because :func:`peer_identifier` is a digest over these bytes, and protobuf gives
    no guarantee that re-encoding a parsed message reproduces its input -- so a peer id
    recomputed from :attr:`signing_key` and friends would be a different peer id.
    """

    permanent_signature: bytes = b""
    """The signature over the above. The other half of what the identifier digests."""

    stable_clock: int = 0
    """
    This peer's `PeerStableInfo.clock`.

    Kept for one reason: a joining peer's own clock is the highest in the circle plus one,
    so building an identity means reading everyone else's -- see
    :func:`~findmy.keychain.join.next_stable_clock`.
    """

    dynamic_clock: int = 0
    """This peer's `PeerDynamicInfo.clock`. A different clock from :attr:`stable_clock`."""

    includeds: tuple[str, ...] = ()
    """Who this peer trusts. A joining peer starts from its sponsor's copy of this."""

    excludeds: tuple[str, ...] = ()
    """Who this peer has removed. Applied after :attr:`includeds` when merging."""

    voucher_info: bytes = b""
    """
    The serialised `Voucher` that admitted this peer, as it arrived.

    Kept so that a trust update from a peer not already trusted can be checked rather than
    believed -- without it, any peer asserting membership would be taken at its word.
    """

    voucher_signature: bytes = b""
    """The signature over the above, by the sponsor the voucher names."""

    def signing_public_key(self) -> ec.EllipticCurvePublicKey | None:
        """Load the signing key, or None if it is not in a shape this understands."""
        return load_public_key(self.signing_key)

    @property
    def derived_hash(self) -> str:
        """What :func:`peer_identifier` makes of this peer's own permanent info."""
        return peer_identifier(self.permanent_info, self.permanent_signature)

    @property
    def hash_is_derivable(self) -> bool:
        """Whether the hash this peer reports is the one its permanent info produces."""
        return bool(self.permanent_info) and self.derived_hash == self.hash


@dataclass(frozen=True)
class PeerDirectory:
    """The peers of a trust circle, indexed by hash."""

    peers: dict[str, Peer] = field(default_factory=dict)

    sync_token: str | None = None
    """
    Where the feed reached.

    Worth persisting: fetching from the beginning every run re-reads the whole circle for
    no benefit. It is also what a join sends back as its `restorePoint`, and what the
    join's own response returns a fresh one of -- a **string** at both ends, so nothing
    here encodes or decodes it. Send back exactly what Cuttlefish last sent.
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

    def updated(self, changes: cf.CuttlefishChanges) -> PeerDirectory:
        """
        Fold a batch of changes in, returning a new directory.

        Every call that reports trust changes returns the same message -- `fetchChanges`,
        `joinWithVoucher`, `updateTrust` -- so they all arrive here rather than each
        growing its own reading of what a change is.
        """
        peers = dict(self.peers)
        apply_changes(peers, changes)

        token = changes.sync_token if changes.HasField("sync_token") else self.sync_token
        return PeerDirectory(peers=peers, sync_token=token)


def apply_changes(peers: dict[str, Peer], changes: cf.CuttlefishChanges) -> int:
    """
    Fold one batch of changes into a peer map, in place.

    Anything that is not an `add` is another kind of change, not a peer and not a problem:
    a change at a field this does not know parses into the unknown set and lands here.

    :returns: How many peers were added.
    """
    added = 0
    for change in changes.changes:
        if not change.HasField(CHANGE_ADD):
            continue
        peer = _peer_from_proto(change.add)
        if peer is not None:
            peers[peer.hash] = peer
            added += 1

    return added


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

    dynamic = _dynamic_info(peer)

    return Peer(
        hash=peer.hash,
        signing_key=info.signing_key,
        encryption_key=info.encryption_key,
        machine_id=info.machine_id,
        model_id=info.model_id,
        # As they arrived. The identifier is a digest over exactly these bytes, so a
        # re-encoding of `info` above would produce a different peer id for the same peer.
        permanent_info=peer.permanent_info.info,
        permanent_signature=peer.permanent_info.signature,
        stable_clock=_stable_clock(peer),
        dynamic_clock=dynamic.clock,
        includeds=tuple(dynamic.includeds),
        excludeds=tuple(dynamic.excludeds),
        voucher_info=peer.voucher.info,
        voucher_signature=peer.voucher.signature,
    )


def _dynamic_info(peer: cf.CuttlefishPeer) -> cf.PeerDynamicInfo:
    """
    Read a peer's dynamic info, treating an unreadable one as asserting nothing.

    An empty result contributes no trust rather than removing any: a joining peer merges
    these, and a peer whose claims could not be read should widen nothing rather than
    silently narrowing what its neighbours already established.
    """
    info = cf.PeerDynamicInfo()
    try:
        info.ParseFromString(peer.dynamic_info.info)
    except DecodeError:
        logger.debug("Peer %s has dynamic info that does not decode", peer.hash)
        return cf.PeerDynamicInfo()

    return info


def _stable_clock(peer: cf.CuttlefishPeer) -> int:
    """
    Read a peer's stable clock, treating an unreadable one as zero.

    Zero is the safe direction: a joining peer takes the highest clock in the circle and
    adds one, so a peer whose clock could not be read lowers the result rather than
    raising it, and a clock that is too low is a peer that looks stale rather than one
    that claims to supersede peers it has never seen.
    """
    info = cf.PeerStableInfo()
    try:
        info.ParseFromString(peer.stable_info.info)
    except DecodeError:
        logger.debug("Peer %s has stable info that does not decode", peer.hash)
        return 0

    return info.clock


@dataclass(frozen=True)
class IdentifierCheck:
    """What recomputing every peer's identifier found."""

    matched: list[str] = field(default_factory=list)
    mismatched: list[str] = field(default_factory=list)
    uncheckable: list[str] = field(default_factory=list)
    """Peers carrying no permanent info to digest, so neither confirming nor denying."""

    @property
    def confirmed(self) -> bool:
        """Whether the derivation reproduced every identifier it could be tested against."""
        return bool(self.matched) and not self.mismatched

    def describe(self) -> str:
        """One line, for a caller deciding whether it is safe to build a voucher."""
        parts = [f"{len(self.matched)} matched", f"{len(self.mismatched)} did not"]
        if self.uncheckable:
            parts.append(f"{len(self.uncheckable)} carried nothing to check")
        return ", ".join(parts)


def check_peer_identifiers(directory: PeerDirectory) -> IdentifierCheck:
    """
    Recompute every known peer's identifier and compare it against the one it reports.

    **Do this before building a voucher.** A voucher names its beneficiary by an
    identifier this client derives for an identity it just generated, and a wrong
    derivation produces a voucher for a peer that does not exist -- a failure that lands
    after `joinWithVoucher`, which cannot be taken back. Every peer already in the circle
    is a worked example of the same derivation, free to check and read-only.

    A match is decisive: reproducing a SHA-256 digest by accident is not a thing that
    happens. So this is a search whose oracle is exact, unlike one over plausible-looking
    outputs.

    :param directory: The circle, from :func:`fetch_peer_directory`.
    """
    check = IdentifierCheck()
    for peer in directory.peers.values():
        if not peer.permanent_info:
            check.uncheckable.append(peer.hash)
        elif peer.hash_is_derivable:
            check.matched.append(peer.hash)
        else:
            check.mismatched.append(peer.hash)

    if check.mismatched:
        logger.warning(
            "The peer identifier derivation does not reproduce %d of %d known peer(s)."
            " Building a voucher on it would name a beneficiary that does not exist, and"
            " that failure only surfaces after the join has been sent.",
            len(check.mismatched),
            len(directory.peers),
        )
    elif check.matched:
        logger.info(
            "The peer identifier derivation reproduces all %d checkable peer(s)",
            len(check.matched),
        )

    return check


async def fetch_peer_directory(
    client: AsyncCloudKitClient,
    *,
    sync_token: str | None = None,
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

        changes = response.changes.changes
        added = apply_changes(peers, response.changes)

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
    token: str | None,
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
