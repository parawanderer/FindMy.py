"""
Building the messages that join a keychain trust circle.

Implements the message layer of Stage 3 §6.9 of the Find My key-export protocol
specification: constructing a peer, signing its blobs, and assembling a
`joinWithVoucher` request.

**Sending one is not implemented, and deliberately so.** Joining writes to the user's
account -- it creates an escrow record and adds a peer to the circle protecting every
password they have -- and it depends on the passcode-authenticated recovery of §6.2 to
§6.5, which is not built either. What is here is the part that can be written and tested
without touching an account: the structures, the signing discipline, and the check that
must happen before a join is worth attempting at all.

.. warning::
    ``establish`` forms a **new** circle rather than joining an existing one, and falling
    back to it on error would silently destroy the user's trust circle. The message it
    takes is not defined anywhere in this package, so no code here can build one. Keep it
    that way.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.errors import UnhandledProtocolError

if TYPE_CHECKING:
    from collections.abc import Sequence

# The voucher reason this project uses. The enumeration is not specified; zero is the
# protobuf default and is what an unset reason would serialise as.
VOUCHER_REASON_DEFAULT = 0

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
