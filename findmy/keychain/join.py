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

    from .peers import PeerDirectory

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


def next_stable_clock(directory: PeerDirectory) -> int:
    """
    Work out the `clock` a joining peer's stable info should carry.

    **The highest clock in the circle plus one, so a first peer sends 1 rather than 0.**
    Zero is the dynamic info's value, not this one, and the two being different is easy to
    miss when both fields are called `clock`.

    :param directory: The circle, from :func:`~findmy.keychain.peers.fetch_peer_directory`.
    """
    return max((peer.stable_clock for peer in directory.peers.values()), default=0) + 1


def make_permanent_info(  # noqa: PLR0913 -- every field of the message, and it is six
    signing_key: ec.EllipticCurvePrivateKey,
    *,
    signing_public: bytes,
    encryption_public: bytes,
    machine_id: str,
    model_id: str,
    epoch: int = 0,
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
    :param signing_public: The new identity's public signing key, as sent.
    :param encryption_public: Its public encryption key.
    :param machine_id: This installation's machine identifier.
    :param model_id: The model this client claims to be.
    :param creation_time: When this identity was made. Passed in rather than read from the
        clock so that the bytes are reproducible, which matters for a value a digest
        covers.
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


def make_dynamic_info(signing_key: ec.EllipticCurvePrivateKey) -> SignedBlob:
    """
    Build and sign the dynamic info a *joining* peer sends: `clock: 0` and nothing else.

    **`includeds` is empty**, which is the opposite of what the field's name suggests.
    Trust is asserted afterwards by a separate `updateTrust`, once the peer is in the
    circle and has synced it -- a peer trying to enter has nothing to assert about the
    circle yet, and enumerating the one it wants to join is not what the message means.

    The same reset applies later: a client that finds itself *not* in the circle returns
    here rather than resending whatever it last asserted.
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
