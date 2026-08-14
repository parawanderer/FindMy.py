"""
Building the messages that join a keychain trust circle.

Implements the message layer of Stage 3 §6.9 of the Find My key-export protocol
specification: constructing a peer, signing its blobs, and assembling a
`joinWithVoucher` request.

**Nothing here sends anything.** Joining writes to the user's account -- it creates an
escrow record and adds a peer to the circle protecting every password they have -- so this
module builds and signs, and :mod:`findmy.keychain.session` is where the sequence that
sends lives. What is here can be exercised offline in full.

.. warning::
    ``establish`` forms a **new** circle rather than joining an existing one, and falling
    back to it on error would silently destroy the user's trust circle. The message it
    takes is not defined anywhere in this package, so no code here can build one. Keep it
    that way.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.message import DecodeError

from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.errors import UnhandledProtocolError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .peers import Peer, PeerDirectory

logger = logging.getLogger(__name__)

# The reason a voucher carries. The rest of the enumeration is unspecified; this is the
# value §6.9.4 step 3 names for the join this project performs.
VOUCHER_REASON_DEFAULT = 1

# A SignedInfo's signature covers a type string prepended to the serialised message, not
# the message alone. That prefix is what stops a blob of one kind being presented as
# another, so omitting it does not merely fail verification -- it removes a protection.
TYPE_PERMANENT_INFO = b"TPPB.PeerPermanentInfo"
TYPE_STABLE_INFO = b"TPPB.PeerStableInfo"
TYPE_DYNAMIC_INFO = b"TPPB.PeerDynamicInfo"
TYPE_VOUCHER = b"TPPB.Voucher"


class JoinError(UnhandledProtocolError):
    """Raised when a join cannot be assembled or should not be attempted."""


@dataclass(frozen=True)
class SignedBlob:
    """
    A serialised message together with the signature over **those exact bytes**.

    This type exists to make one mistake impossible. The signature covers the serialised
    bytes, not the message they parse to, and protobuf offers no guarantee that
    re-encoding a parsed message reproduces its input -- field ordering and default
    handling are implementation details. So a client that parses a blob, holds the
    message, and re-serialises it before sending can invalidate a perfectly good signature
    over content that has not changed by a single field.

    Holding the bytes rather than the message removes the opportunity: there is nothing
    here to re-encode.
    """

    info: bytes
    signature: bytes

    type_name: bytes = b""
    """
    The type string the signature covers, prepended to :attr:`info`.

    Carried so that a blob can be re-verified without the caller having to remember which
    kind it is -- which is exactly the confusion the prefix exists to prevent.
    """

    def to_proto(self) -> cf.SignedInfo:
        """Render as the wire message, passing the signed bytes through untouched."""
        return cf.SignedInfo(info=self.info, signature=self.signature)

    @classmethod
    def sign(
        cls,
        message: bytes,
        signing_key: ec.EllipticCurvePrivateKey,
        type_name: bytes,
    ) -> SignedBlob:
        """
        Sign an already-serialised message, under its type.

        Takes bytes rather than a message on purpose: the caller serialises once, and
        those are the bytes that both get signed and get sent.

        :param message: The serialised message to sign.
        :param signing_key: A P-384 private key.
        :param type_name: The type string, e.g. :data:`TYPE_VOUCHER`. Prepended to the
            message before signing, and **not** sent -- the receiver knows which field it
            is reading and prepends the same thing.
        """
        signature = signing_key.sign(type_name + message, ec.ECDSA(hashes.SHA384()))
        return cls(info=message, signature=signature, type_name=type_name)

    def verify(
        self,
        public_key: ec.EllipticCurvePublicKey,
        type_name: bytes | None = None,
    ) -> bool:
        """
        Check the signature against the type and bytes it covers.

        :param type_name: Overrides the one this blob was built with, for a blob read off
            the wire rather than signed here.
        """
        prefix = type_name if type_name is not None else self.type_name
        try:
            public_key.verify(self.signature, prefix + self.info, ec.ECDSA(hashes.SHA384()))
        except Exception:  # noqa: BLE001 -- cryptography raises InvalidSignature and more
            return False
        return True


# The two policy hashes are constants -- digests of Apple's own trust policy documents. A
# client asserts which policy version it speaks rather than deriving anything, so these are
# sent verbatim. **A wrong value here is not detectable locally**, which is why they are
# named constants rather than parameters with defaults.
POLICY_FROZEN_VERSION = 5
POLICY_FROZEN_HASH = b"SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo="
POLICY_FLEXIBLE_VERSION = 20
POLICY_FLEXIBLE_HASH = b"SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY="

USER_CONTROLLABLE_VIEWS_ENABLED = 1
"""What a real client sends for `userControllableViewStatus`."""

PERMANENT_INFO_EPOCH = 1
"""What a peer's permanent info declares. Not zero, which is the protobuf default."""


def next_stable_clock(directory: PeerDirectory) -> int:
    """
    Work out the `clock` a joining peer's stable info should carry.

    **The highest clock in the circle plus one, so a first peer sends 1 rather than 0.**
    Zero is the dynamic info's value, not this one, and the two being different is easy to
    miss when both fields are called `clock`.

    :param directory: The circle, from :func:`~findmy.keychain.peers.fetch_peer_directory`.
    """
    return max((peer.stable_clock for peer in directory.peers.values()), default=0) + 1


def public_spki(key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Encode a public key the way a peer's permanent info carries it: **DER SPKI**.

    Not a raw point. The identifier of §6.8.2 digests the signed blob these sit inside, so
    the encoding is part of the peer's identity -- the same key written as an uncompressed
    point is a different peer, with a different id, vouched for by nobody.
    """
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def make_permanent_info(  # noqa: PLR0913 -- every field of the message, and it is six
    signing_key: ec.EllipticCurvePrivateKey,
    *,
    signing_public: bytes,
    encryption_public: bytes,
    machine_id: str,
    model_id: str,
    epoch: int = PERMANENT_INFO_EPOCH,
    creation_time: int,
) -> SignedBlob:
    """
    Build and sign the permanent info, which is what a peer's identifier digests.

    **Nothing in it may change afterwards.** The peer's identifier is a digest over these
    exact bytes and their signature, so a peer that re-issues its permanent info is a
    different peer -- and every voucher, share and escrow label naming the old one stops
    resolving.

    :param signing_key: The new identity's own signing key. A peer signs its own permanent
        info; the sponsor's key signs only the voucher.
    :param signing_public: The new identity's public signing key, **DER SPKI** -- see
        :func:`public_spki`.
    :param encryption_public: Its public encryption key, likewise DER SPKI.
    :param machine_id: The Anisette `X-Apple-I-MD-M` header, which is the machine identity
        the session itself is bound to. A peer created under local Anisette and one created
        against a server carry different ids **permanently**, because this blob is signed
        at generation and never rewritten.
    :param model_id: The model this client claims to be.
    :param creation_time: When this identity was made, in **milliseconds** since the epoch,
        not seconds. Passed in rather than read from the clock so that the bytes are
        reproducible, which matters for a value a digest covers.
    """
    info = cf.PeerPermanentInfo(
        epoch=epoch,
        signing_key=signing_public,
        encryption_key=encryption_public,
        machine_id=machine_id,
        model_id=model_id,
        creation_time=creation_time,
    )
    return SignedBlob.sign(info.SerializeToString(), signing_key, TYPE_PERMANENT_INFO)


def make_stable_info(
    signing_key: ec.EllipticCurvePrivateKey,
    *,
    clock: int,
    os_version: str,
    serial_number: str,
    device_name: str = "",
) -> SignedBlob:
    """
    Build and sign the stable info: what this peer asserts about itself.

    **An incomplete one is admitted and then behaves oddly rather than refused**, which is
    the worse failure and lands long after the join. So the policy fields are always sent,
    at the constants above, and everything the specification does not list is omitted
    rather than defaulted.

    :param clock: From :func:`next_stable_clock`. **Not zero** -- see there.
    :param os_version: This client's OS string.
    :param serial_number: The serial this client declares, as Stage 1 §2.2 uses.
    :param device_name: How this peer appears to the user. May be empty, and naming it
        after a person is a choice the README's labelling rules cover.
    """
    info = cf.PeerStableInfo(
        clock=clock,
        frozen_policy_version=POLICY_FROZEN_VERSION,
        frozen_policy_hash=POLICY_FROZEN_HASH,
        flexible_policy_version=POLICY_FLEXIBLE_VERSION,
        flexible_policy_hash=POLICY_FLEXIBLE_HASH,
        os_version=os_version,
        device_name=device_name,
        serial_number=serial_number,
        user_controllable_view_status=USER_CONTROLLABLE_VIEWS_ENABLED,
        is_inherited_account=False,
    )
    return SignedBlob.sign(info.SerializeToString(), signing_key, TYPE_STABLE_INFO)


@dataclass(frozen=True)
class TrustSet:
    """A dynamic info's three merged values, before it is signed."""

    clock: int
    includeds: tuple[str, ...]
    excludeds: tuple[str, ...]

    def to_proto(self) -> cf.PeerDynamicInfo:
        """Render as the message, with nothing else set."""
        return cf.PeerDynamicInfo(
            clock=self.clock,
            includeds=list(self.includeds),
            excludeds=list(self.excludeds),
        )


def merge_trust(directory: PeerDirectory, *, peer_id: str, sponsor: str) -> TrustSet:
    """
    Work out the trust a joining peer asserts: its sponsor's, brought forward, plus itself.

    **A joining peer inherits trust rather than inventing it, and never sends an empty
    set.** An empty `includeds` with `clock: 0` is the `establish` shape -- the call this
    project must never make -- and sending it on a join produces a peer that is admitted
    while claiming to trust nobody. That is the "accepted, then behaves oddly" failure,
    landing long after the irreversible call.

    The steps are §6.8.2's: start from the sponsor's `includeds`, `excludeds` and `clock`;
    fast-forward over every peer with a higher clock in ascending order, adopting what it
    includes and then applying what it excludes; add this peer's own id; increment.

    :param directory: The circle, and it must be **current** -- everything here reads it.
    :param peer_id: The joining peer's identifier, which it adds to its own trust.
    :param sponsor: The recovered peer that signed the voucher.
    :raises JoinError: If the sponsor is not in the directory, since there is then nothing
        to inherit and the alternative is asserting a set this client invented.
    """
    seed = directory.get(sponsor)
    if seed is None:
        msg = (
            f"The sponsoring peer {sponsor} is not in the trust circle, so there is no"
            " trust to inherit. Joining with a set this client invented is what the"
            " empty-includeds failure looks like from the other direction."
        )
        raise JoinError(msg)

    includeds = list(seed.includeds)
    excludeds = list(seed.excludeds)
    clock = seed.dynamic_clock

    # Ascending, because each peer's excludeds are applied on top of what earlier ones
    # established. Out of order, a removal can be undone by an older peer's inclusion.
    ahead = sorted(
        (p for p in directory.peers.values() if p.dynamic_clock > clock),
        key=lambda p: p.dynamic_clock,
    )

    for peer in ahead:
        trusted = peer.hash in includeds
        if not trusted and not _voucher_admits(peer, includeds, excludeds, directory):
            # Not believed. A peer asserting membership is exactly how an untrusted party
            # would write itself into the circle, so an unvouched update is ignored rather
            # than merged -- and said out loud, since silently dropping trust changes
            # looks identical to a circle that never had them.
            logger.info(
                "Ignoring the trust update from %s: it is not already trusted and carries"
                " no valid voucher from a peer that is.",
                peer.hash,
            )
            continue

        for included in peer.includeds:
            if included not in includeds:
                includeds.append(included)
        for excluded in peer.excludeds:
            if excluded in includeds:
                includeds.remove(excluded)
            if excluded not in excludeds:
                excludeds.append(excluded)

        clock = peer.dynamic_clock

    if peer_id not in includeds:
        includeds.append(peer_id)

    # One past everything it was derived from, so the info sent supersedes its sources.
    return TrustSet(clock=clock + 1, includeds=tuple(includeds), excludeds=tuple(excludeds))


def _voucher_admits(
    peer: Peer,
    includeds: Sequence[str],
    excludeds: Sequence[str],
    directory: PeerDirectory,
) -> bool:
    """
    Whether a peer not already trusted has earned being adopted.

    Four conditions, and all of them: the voucher's sponsor is already trusted, its
    signature verifies under that sponsor's signing key, its beneficiary is the peer
    presenting it, and that beneficiary has not been excluded. Anything less and a peer
    could join the circle by asserting that it had.
    """
    if not peer.voucher_info or peer.hash in excludeds:
        return False

    try:
        voucher = cf.Voucher.FromString(peer.voucher_info)
    except DecodeError:
        return False

    if voucher.beneficiary != peer.hash or voucher.sponsor not in includeds:
        return False

    sponsor = directory.get(voucher.sponsor)
    key = sponsor.signing_public_key() if sponsor else None
    if key is None:
        return False

    blob = SignedBlob(info=peer.voucher_info, signature=peer.voucher_signature)
    return blob.verify(key, TYPE_VOUCHER)


def make_dynamic_info(signing_key: ec.EllipticCurvePrivateKey, trust: TrustSet) -> SignedBlob:
    """
    Build and sign the dynamic info a *joining* peer sends.

    :param signing_key: The joining peer's own signing key.
    :param trust: From :func:`merge_trust`. Not assembled here, so that what is asserted
        can be inspected -- and tested -- before it is signed and sent.
    """
    return SignedBlob.sign(trust.to_proto().SerializeToString(), signing_key, TYPE_DYNAMIC_INFO)


def reset_dynamic_info(signing_key: ec.EllipticCurvePrivateKey) -> SignedBlob:
    """
    Build the dynamic info of a client that finds itself **outside** the circle.

    `clock: 0` with everything cleared, which is the one place that shape is right. It is
    the reset, not the join: a client that has been removed starts again rather than
    resending whatever it last asserted about a circle it is no longer in.

    **Not for joining.** :func:`merge_trust` is what a join sends.
    """
    return SignedBlob.sign(
        cf.PeerDynamicInfo(clock=0).SerializeToString(),
        signing_key,
        TYPE_DYNAMIC_INFO,
    )


def make_voucher(
    beneficiary: str,
    sponsor: str,
    signing_key: ec.EllipticCurvePrivateKey,
    *,
    reason: int = VOUCHER_REASON_DEFAULT,
) -> SignedBlob:
    """
    Build and sign a voucher: one peer saying it trusts another.

    Three fields, and this is the whole mechanism by which a device joins the circle that
    protects the user's keychain. All the weight is on the signature.

    :param beneficiary: The peer being vouched for -- the new identity.
    :param sponsor: The peer vouching -- the identity recovered from the bottle.
    :param signing_key: The sponsor's signing key, from opening the bottle.
    """
    if not beneficiary or not sponsor:
        msg = "A voucher needs both a beneficiary and a sponsor"
        raise JoinError(msg)
    if beneficiary == sponsor:
        msg = "A peer cannot vouch for itself"
        raise JoinError(msg)

    voucher = cf.Voucher(reason=reason, beneficiary=beneficiary, sponsor=sponsor)
    return SignedBlob.sign(voucher.SerializeToString(), signing_key, TYPE_VOUCHER)


def make_peer(
    peer_hash: str,
    *,
    permanent_info: SignedBlob,
    stable_info: SignedBlob,
    dynamic_info: SignedBlob,
    voucher: SignedBlob,
) -> cf.CuttlefishPeer:
    """Assemble a peer from its four signed blobs."""
    return cf.CuttlefishPeer(
        hash=peer_hash,
        permanent_info=permanent_info.to_proto(),
        stable_info=stable_info.to_proto(),
        dynamic_info=dynamic_info.to_proto(),
        voucher=voucher.to_proto(),
    )


def make_join_request(
    peer: cf.CuttlefishPeer,
    bottle: cf.Bottle,
    shares: Sequence[cf.TlkShare],
    *,
    restore_point: str | None = None,
) -> cf.CuttlefishJoinWithVoucherRequest:
    """
    Assemble a `joinWithVoucher` request.

    :param peer: The new identity being introduced.
    :param bottle: The escrow record being created for it, so it is recoverable later.
    :param shares: The view-key shares re-shared to the new peer. **Must not be empty** --
        see :func:`require_key_shares`.
    :param restore_point: The client's sync token, if it has one.
    :raises JoinError: If there are no key shares to carry.
    """
    require_key_shares(shares)

    request = cf.CuttlefishJoinWithVoucherRequest(
        peer=peer,
        bottle=bottle,
        shares=list(shares),
    )
    if restore_point is not None:
        request.restore_point = restore_point

    # `keys` is for establishing keys rather than receiving them, so it stays empty.
    return request


def require_key_shares(shares: Sequence[cf.TlkShare]) -> None:
    """
    Refuse to join when the sponsoring peer holds no key shares.

    Joining without them **succeeds** and yields no keys, which is worse than failing
    because it looks like it worked -- and it is not free: a join leaves a peer in the
    user's trust circle and an escrow record on their account, both permanent, in exchange
    for nothing. Checking first is the difference between a failed attempt and two pieces
    of irreversible clutter.

    :raises JoinError: If there are no shares.
    """
    if not shares:
        msg = (
            "The sponsoring peer holds no key shares, so joining would succeed and yield"
            " no keys. Refusing: a join is not free, and would leave a peer in the trust"
            " circle and an escrow record on the account in exchange for nothing."
        )
        raise JoinError(msg)


@dataclass(frozen=True)
class NewIdentity:
    """
    A freshly generated peer: its keys, its signed permanent info, and its identifier.

    The permanent info is signed **once, here**, and those bytes are what everything after
    it refers to -- the identifier digests them, the peer message carries them, the bottle
    is built around the peer they name. Re-encoding the message later gives a different
    signature and therefore a different peer.
    """

    signing_key: ec.EllipticCurvePrivateKey
    encryption_key: ec.EllipticCurvePrivateKey
    permanent: SignedBlob
    peer_id: str


def generate_identity(*, machine_id: str, model_id: str, creation_time: int) -> NewIdentity:
    """
    Generate the identity a join introduces, per §6.9.1.

    Both keys are P-384 and fresh, and both public halves travel as DER SPKI.

    :param machine_id: The Anisette `X-Apple-I-MD-M` header. **This binds the peer to the
        Anisette in use, permanently**: the blob is signed at generation and never
        rewritten, so a peer created under local Anisette and one created against a server
        are different peers for good.
    :param model_id: The hardware model this client claims to be.
    :param creation_time: Milliseconds since the epoch, not seconds.
    """
    from .peers import peer_identifier  # noqa: PLC0415 -- avoids a circular import

    signing = ec.generate_private_key(ec.SECP384R1())
    encryption = ec.generate_private_key(ec.SECP384R1())

    permanent = make_permanent_info(
        signing,
        signing_public=public_spki(signing.public_key()),
        encryption_public=public_spki(encryption.public_key()),
        machine_id=machine_id,
        model_id=model_id,
        creation_time=creation_time,
    )

    return NewIdentity(
        signing_key=signing,
        encryption_key=encryption,
        permanent=permanent,
        peer_id=peer_identifier(permanent.info, permanent.signature),
    )
