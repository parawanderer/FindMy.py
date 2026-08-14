"""
The keys sealed inside a bottled peer.

Implements steps 2 to 4 of Stage 3 §6.7 of the Find My key-export protocol specification:
deriving the three keys a bottle is sealed under, checking them against the bottle, and
opening it. What comes out is the sponsoring peer's own private keys.

Vouching and joining -- step 5 -- are elsewhere and are not wired up.

**What a bottle is, and why the sequence is not one step.** Recovering an escrow record
does not yield the keychain. It yields a *bottled peer*: the sealed identity of a device
that was already in the user's trust circle. Recovering it lets this client borrow that
device's identity just long enough for it to vouch for a **new** identity of our own, and
the new identity is what actually joins. Everything in this module is the first move of
that sequence -- turning recovered entropy into the three keys the bottle is sealed under.

.. warning::
    Two hazards live in the steps this module does not implement, and both are worth
    knowing before anyone adds them.

    **Never call ``establish``.** It and ``joinWithVoucher`` differ by one branch and are
    catastrophically different: the first forms a *new* circle where none exists, the
    second joins an existing one. An implementation that falls back from the second to the
    first on error silently destroys the user's trust circle. There is no reason this
    project should ever call it, which is why no function here can.

    **Stop if the recovered peer holds no key shares.** Joining would succeed and yield no
    keys, which is worse than failing because it looks like success -- and it would leave a
    registered device and an escrow record on the account in exchange for nothing.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from google.protobuf.message import DecodeError

from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.errors import UnhandledProtocolError

from .peers import load_public_key

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .peers import Peer

INFO_SYMMETRIC = b"Escrow Symmetric Key"
INFO_SIGNING = b"Escrow Signing Private Key"
INFO_ENCRYPTION = b"Escrow Encryption Private Key"

SYMMETRIC_KEY_LENGTH = 32
EC_KEY_MATERIAL_LENGTH = 56
"""
448 bits, which is P-384's 384 plus the 64 extra FIPS 186-4 B.5.1 asks for.

That method generates more bits than the order needs and reduces, rather than generating
exactly enough and retrying on a value out of range.
"""

# The order of P-384.
_P384_ORDER = int(
    "ffffffffffffffffffffffffffffffffffffffffffffffff"
    "c7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    16,
)


# §6.7 step 4: the tag travels beside the ciphertext rather than appended to it.
GCM_TAG_LENGTH = 16


class BottleError(UnhandledProtocolError):
    """Raised when a bottle's key material cannot be derived or the bottle not opened."""


@dataclass(frozen=True)
class BottleKeys:
    """The three keys a bottled peer is sealed under."""

    symmetric: bytes
    """32 bytes. Opens the bottle, under AES-256-GCM."""

    signing: ec.EllipticCurvePrivateKey
    """P-384. Its public part must equal the bottle's escrowed signing key."""

    encryption: ec.EllipticCurvePrivateKey
    """P-384. Its public part must equal the bottle's escrowed encryption key."""


def _scalar_from_extra_random_bits(material: bytes) -> int:
    """
    Convert 56 bytes into a P-384 scalar, by FIPS 186-4 B.5.1.

    The extra-random-bits method: read the whole thing as an integer, reduce modulo one
    less than the order, and add one. Note that it is *not* a plain modulo by the order --
    the off-by-one is what keeps zero out of the range.
    """
    if len(material) != EC_KEY_MATERIAL_LENGTH:
        msg = f"Expected {EC_KEY_MATERIAL_LENGTH} bytes of key material, got {len(material)}"
        raise BottleError(msg)

    return (int.from_bytes(material, "big") % (_P384_ORDER - 1)) + 1


def _hkdf(entropy: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Run HKDF-SHA384 once."""
    return HKDF(
        algorithm=hashes.SHA384(),
        length=length,
        salt=salt,
        info=info,
    ).derive(entropy)


def derive_bottle_keys(entropy: bytes, adsid: str) -> BottleKeys:
    """
    Derive a bottled peer's three keys from its entropy.

    All three come from HKDF-SHA384 over the same entropy, distinguished only by their
    info strings.

    :param entropy: The bottled-peer entropy blob recovered from the escrow record.
    :param adsid: The account identifier, used as the HKDF **salt**. Not a random value:
        two accounts recovering the same entropy derive different keys, which is the
        point of salting with it.
    :raises BottleError: If the entropy is empty or the account identifier is missing.
    """
    if not entropy:
        msg = "Bottled peer entropy is empty; nothing to derive from"
        raise BottleError(msg)
    if not adsid:
        msg = "The account identifier is the HKDF salt and cannot be empty"
        raise BottleError(msg)

    salt = adsid.encode("utf-8")

    return BottleKeys(
        symmetric=_hkdf(entropy, salt, INFO_SYMMETRIC, SYMMETRIC_KEY_LENGTH),
        signing=ec.derive_private_key(
            _scalar_from_extra_random_bits(
                _hkdf(entropy, salt, INFO_SIGNING, EC_KEY_MATERIAL_LENGTH),
            ),
            ec.SECP384R1(),
        ),
        encryption=ec.derive_private_key(
            _scalar_from_extra_random_bits(
                _hkdf(entropy, salt, INFO_ENCRYPTION, EC_KEY_MATERIAL_LENGTH),
            ),
            ec.SECP384R1(),
        ),
    )


# The encodings a public key might arrive in. Which one a bottle uses is not stated, and
# they are distinguishable by length, so all are tried and the match is reported.
_PUBLIC_KEY_ENCODINGS = (
    ("x962-uncompressed", Encoding.X962, PublicFormat.UncompressedPoint),
    ("x962-compressed", Encoding.X962, PublicFormat.CompressedPoint),
    ("der-spki", Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
)


def public_key_encodings(key: ec.EllipticCurvePrivateKey) -> dict[str, bytes]:
    """Render a key's public half every way a bottle might carry it."""
    return {
        name: key.public_key().public_bytes(encoding, fmt)
        for name, encoding, fmt in _PUBLIC_KEY_ENCODINGS
    }


def match_public_key(derived: ec.EllipticCurvePrivateKey, escrowed: bytes) -> str | None:
    """
    Find the encoding under which a derived key equals an escrowed one.

    :returns: The encoding's name, or None if none matched.
    """
    for name, encoded in public_key_encodings(derived).items():
        if encoded == escrowed:
            return name
    return None


def keys_match_bottle(
    derived: BottleKeys,
    escrowed_signing_key: bytes,
    escrowed_encryption_key: bytes,
) -> bool:
    """
    Check derived public keys against the ones the bottle carries.

    The first two of §6.7 step 3's four verifications, and the cheapest confirmation
    available that recovery and derivation both went right: both sides are in memory, so
    no further call is needed. Failing means the passcode produced the wrong entropy,
    which is a different problem from a bottle that is not what it claims.

    :param derived: What :func:`derive_bottle_keys` produced.
    :param escrowed_signing_key: The bottle's escrowed signing public key.
    :param escrowed_encryption_key: Likewise for encryption.
    """
    return (
        match_public_key(derived.signing, escrowed_signing_key) is not None
        and match_public_key(derived.encryption, escrowed_encryption_key) is not None
    )


def find_bottle_keys(
    entropy: bytes,
    salts: Sequence[str],
    escrowed_signing_key: bytes,
    escrowed_encryption_key: bytes,
) -> tuple[BottleKeys, str]:
    """
    Derive the bottle's keys, trying each candidate salt until one matches.

    The salt is the account's `adsid`, and an account carries more than one identifier of
    that shape -- `adsid` and `dsid` are different values that both look like account
    numbers, and the exchange itself hands out a third. Since the check is free, offline
    and unambiguous -- the derived public keys either equal the escrowed ones or they do
    not -- trying the candidates is better than picking one and reporting a wrong passcode
    when it fails.

    :param entropy: The bottled-peer entropy.
    :param salts: Candidate salts, most likely first.
    :param escrowed_signing_key: What the bottle says the signing key should be.
    :param escrowed_encryption_key: Likewise for encryption.
    :returns: The keys, and the salt that produced them.
    :raises BottleError: If no candidate matched.
    """
    tried: list[str] = []
    for salt in salts:
        if not salt or salt in tried:
            continue
        tried.append(salt)

        keys = derive_bottle_keys(entropy, salt)
        if keys_match_bottle(keys, escrowed_signing_key, escrowed_encryption_key):
            return keys, salt

    msg = (
        f"None of {len(tried)} candidate salt(s) produced keys matching the ones this"
        f" bottle escrowed ({len(escrowed_signing_key)} bytes each). Either the passcode"
        " produced the wrong entropy, or the salt is a value not tried here."
    )
    raise BottleError(msg)


# A P-384 key as a bottle carries it: a 97-byte uncompressed public point followed by the
# 48-byte private scalar. Not DER, not PKCS#8 -- a plain concatenation.
PEER_PUBLIC_POINT_LENGTH = 97
PEER_PRIVATE_SCALAR_LENGTH = 48
PEER_KEY_LENGTH = PEER_PUBLIC_POINT_LENGTH + PEER_PRIVATE_SCALAR_LENGTH


def parse_peer_private_key(data: bytes) -> ec.EllipticCurvePrivateKey:
    """
    Read a peer's private key as a bottle carries it.

    **[observed] 145 bytes**: the uncompressed public point, then the private scalar. The
    two halves are checked against each other -- deriving the public key from the scalar
    must reproduce the point that came with it -- which makes a misread layout fail here
    rather than three steps later at a signature that will not verify.

    The scalar-first layout is accepted too, since the ordering is not stated and the
    check distinguishes them unambiguously.

    :raises BottleError: If the length is wrong, or the halves disagree.
    """
    if len(data) != PEER_KEY_LENGTH:
        msg = (
            f"A peer key is {PEER_KEY_LENGTH} bytes -- a {PEER_PUBLIC_POINT_LENGTH}-byte"
            f" point and a {PEER_PRIVATE_SCALAR_LENGTH}-byte scalar -- not {len(data)}"
        )
        raise BottleError(msg)

    layouts = (
        ("point-then-scalar", data[:PEER_PUBLIC_POINT_LENGTH], data[PEER_PUBLIC_POINT_LENGTH:]),
        ("scalar-then-point", data[PEER_PRIVATE_SCALAR_LENGTH:], data[:PEER_PRIVATE_SCALAR_LENGTH]),
    )

    for name, point, scalar in layouts:
        try:
            key = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP384R1())
        except ValueError:
            continue

        derived = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        if derived == point:
            logger.debug("Peer key layout is %s", name)
            return key

    msg = (
        "A peer key's halves do not agree: deriving a public key from the scalar does not"
        " reproduce the point beside it, under either ordering. The layout is not what"
        " this reads it as."
    )
    raise BottleError(msg)


def _verify_signatures(
    bottle: cf.Bottle,
    inner: cf.OTBottle,
    sponsor: Peer | None,
) -> tuple[bool, bool]:
    """
    Check both of a bottle's signatures, and say which passed.

    They are reported separately because they mean different things: the escrowed-key
    signature says the bottle is internally consistent, and the sponsor's says a peer the
    circle knows put it there.
    """
    escrowed = _verify(
        bottle.escrowed_key_signature,
        bottle.bottle,
        load_public_key(inner.escrowed_signing_key),
    )
    if not escrowed:
        logger.warning("A bottle's signature under its own escrowed key did not verify")

    if sponsor is None:
        return escrowed, False

    sponsored = _verify(bottle.peer_key_signature, bottle.bottle, sponsor.signing_public_key())
    if not sponsored:
        logger.warning("A bottle's signature under its sponsoring peer's key did not verify")

    return escrowed, sponsored


def _verify(signature: bytes, signed: bytes, key: ec.EllipticCurvePublicKey | None) -> bool:
    """Check one of a bottle's signatures. SHA-384, over the bytes exactly as received."""
    if not signature or key is None:
        return False

    try:
        key.verify(signature, signed, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        return False
    return True


@dataclass(frozen=True)
class OpenedBottle:
    """A bottle's contents: the sponsoring peer's own private keys."""

    signing_key: bytes
    """The sponsor's P-384 signing private key, as the bottle carries it."""

    encryption_key: bytes
    """The sponsor's P-384 encryption private key."""

    def signing(self) -> ec.EllipticCurvePrivateKey:
        """Parse the signing key. This is what signs a voucher."""
        return parse_peer_private_key(self.signing_key)

    def encryption(self) -> ec.EllipticCurvePrivateKey:
        """Parse the encryption key. A key share would be wrapped to this."""
        return parse_peer_private_key(self.encryption_key)

    signing_key_type: int
    encryption_key_type: int

    key_encoding: str
    """
    Which encoding the escrowed public keys matched under.

    Recorded because the specification does not say, and one live bottle settles it.
    """

    sponsor_known: bool = False
    """Whether the peer that sealed this bottle was found in the trust circle."""

    sponsor_verified: bool = False
    """Whether the sponsoring peer's signature over the bottle verified."""

    escrowed_key_verified: bool = False
    """Whether the bottle's signature under its own escrowed signing key verified."""


def open_bottle(
    bottle: cf.Bottle,
    keys: BottleKeys,
    *,
    verify_keys: bool = True,
    sponsor: Peer | None = None,
    require_sponsor: bool = False,
) -> OpenedBottle:
    """
    Open a bottle with the keys derived from its entropy.

    Two of §6.7 step 3's four checks happen here -- that the derived public keys equal the
    ones the bottle escrowed -- and they are worth doing even though the AES-GCM tag would
    catch a wrong key anyway, because they say *which* thing is wrong. A key mismatch means
    the passcode produced the wrong entropy; a tag failure with matching keys means the
    bottle is not what it claims.

    Both signatures of step 3 are checked. They cover the **raw serialised `OTBottle`
    bytes exactly as received** -- nothing prepended, nothing re-encoded, which makes this
    the only signed-data construction in the stage that is simply a field's bytes. Both
    are SHA-384: one under the key the bottle escrows, one under the sponsoring peer's.

    :param bottle: The bottle, as `fetchViableBottles` returns it.
    :param keys: What :func:`derive_bottle_keys` produced from the recovered entropy.
    :param verify_keys: Check the derived keys against the escrowed ones first.
    :param sponsor: The peer that sponsored this bottle, from the trust circle. None when
        the circle could not be read.
    :param require_sponsor: Refuse a bottle whose sponsoring peer is not in the circle.
    :raises BottleError: If the keys do not match, the sponsor is unknown and required, or
        the bottle does not authenticate.
    """
    if require_sponsor and sponsor is None:
        msg = (
            f"The peer that sponsored this bottle ({bottle.peer_id!r}) is not in the trust"
            " circle, so nothing identifies who sealed it. Refusing rather than opening"
            " key material from an unidentifiable party."
        )
        raise BottleError(msg)
    if not bottle.bottle:
        msg = "This bottle carries no sealed contents"
        raise BottleError(msg)

    inner = cf.OTBottle()
    try:
        inner.ParseFromString(bottle.bottle)
    except DecodeError as e:
        msg = f"A bottle's sealed contents did not decode: {e}"
        raise BottleError(msg) from None

    encoding = "unchecked"
    if verify_keys:
        signing_match = match_public_key(keys.signing, inner.escrowed_signing_key)
        encryption_match = match_public_key(keys.encryption, inner.escrowed_encryption_key)

        if signing_match is None or encryption_match is None:
            msg = (
                "The keys derived from the recovered entropy do not match the ones this"
                " bottle escrowed, which means the passcode produced the wrong entropy."
                f" Escrowed keys are {len(inner.escrowed_signing_key)} and"
                f" {len(inner.escrowed_encryption_key)} bytes."
            )
            raise BottleError(msg)
        encoding = signing_match

    escrowed_verified, sponsor_verified = _verify_signatures(bottle, inner, sponsor)

    sealed = inner.ciphertext
    if not sealed.ciphertext:
        msg = "This bottle carries no ciphertext to open"
        raise BottleError(msg)

    # The tag is carried beside the ciphertext rather than appended to it, so it is
    # supplied to a detached-tag interface rather than concatenated.
    decryptor = Cipher(
        algorithms.AES(keys.symmetric),
        modes.GCM(
            sealed.initialization_vector,
            sealed.authentication_code,
            min_tag_length=min(GCM_TAG_LENGTH, len(sealed.authentication_code)),
        ),
    ).decryptor()

    try:
        plaintext = decryptor.update(sealed.ciphertext) + decryptor.finalize()
    except InvalidTag:
        msg = (
            "The bottle did not authenticate under its symmetric key. With the escrowed"
            " keys matching, this says the bottle is not what it claims rather than that"
            " the passcode was wrong."
        )
        raise BottleError(msg) from None

    contents = cf.OTInternalBottle()
    try:
        contents.ParseFromString(plaintext)
    except DecodeError as e:
        msg = f"A bottle opened but its contents did not decode: {e}"
        raise BottleError(msg) from None

    return OpenedBottle(
        signing_key=contents.signing_key.key_data,
        encryption_key=contents.encryption_key.key_data,
        signing_key_type=contents.signing_key.key_type,
        encryption_key_type=contents.encryption_key.key_type,
        key_encoding=encoding,
        sponsor_known=sponsor is not None,
        sponsor_verified=sponsor_verified,
        escrowed_key_verified=escrowed_verified,
    )


# --------------------------------------------------------------------------------------
# Creating a bottle (§6.9.3)
# --------------------------------------------------------------------------------------

BOTTLE_IV_LENGTH = 32
"""
The seal's IV. **Not 12, and not 16** -- both of which a GCM implementation would offer as
its default or its obvious alternative, and neither of which is this.
"""

OT_PRIVATE_KEY_TYPE = 1
"""What `OTPrivateKey.keyType` carries. The rest of the enumeration is unspecified."""


def peer_key_material(key: ec.EllipticCurvePrivateKey) -> bytes:
    """
    Render a peer's private key the way a bottle carries it.

    The **uncompressed public point followed by the private scalar**, 97 + 48 bytes on
    P-384, which is what :func:`parse_peer_private_key` reads back.

    Not to be confused with the 64-byte layout of §6.8.1 -- public x then scalar, with no
    point prefix and no y. Two Apple key blobs, two layouts, one stage.
    """
    point = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    scalar = key.private_numbers().private_value.to_bytes(PEER_PRIVATE_SCALAR_LENGTH, "big")
    return point + scalar


def _spki(key: ec.EllipticCurvePrivateKey) -> bytes:
    """Render a private key's public half as DER SubjectPublicKeyInfo."""
    return key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


@dataclass(frozen=True)
class CreatedBottle:
    """
    A bottle for a new identity, and the two values its escrow record must agree with.

    Those two are here rather than left to a caller to recompute because they must come
    from **one** derivation. An escrow record built from separately generated entropy
    enrols cleanly, joins cleanly, and recovers to a peer that does not exist.
    """

    bottle: cf.Bottle
    entropy: bytes
    """The 72 bytes this bottle was derived from. What the escrow record escrows."""

    escrowed_spki: bytes
    """`OTBottle.escrowedSigningKey`, which is also the record's `escrowedSPKI`."""

    @property
    def bottle_id(self) -> str:
        """The bottle's UUID, which the escrow record's metadata also carries."""
        return self.bottle.bottle_id


def seal_bottle(  # noqa: PLR0913 -- the identity, the account, and the entropy
    *,
    peer_id: str,
    signing_key: ec.EllipticCurvePrivateKey,
    encryption_key: ec.EllipticCurvePrivateKey,
    entropy: bytes,
    adsid: str,
    bottle_id: str,
) -> CreatedBottle:
    """
    Seal a bottle for a newly generated identity, inverting §6.7 steps 2 to 4.

    The three escrow keys come from the entropy exactly as recovery derives them, with the
    `adsid` as salt -- so a bottle sealed here opens with nothing but that entropy and that
    account, which is what makes the new peer recoverable at all.

    **Both signatures are by the peer the bottle belongs to.** §6.7 step 3 describes the
    second as verifying "under the sponsoring peer's signing key", which is accurate for a
    bottle being *read*: the bottle recovered was created by the peer sponsoring us. The
    general rule is the peer the bottle is for, and for every bottle this project creates
    that is this client.

    :param peer_id: The new peer's identifier.
    :param signing_key: The new peer's signing key. Sealed inside, and signs the outside.
    :param encryption_key: The new peer's encryption key. Sealed inside.
    :param entropy: 72 fresh bytes, from
        :func:`~findmy.keychain.enrolment.new_bottle_entropy`. **The same bytes the escrow
        record escrows** -- see :class:`CreatedBottle`.
    :param adsid: The account identifier, the HKDF salt.
    :param bottle_id: A v4 UUID, upper-case. Passed in so that the record and the bottle
        cannot be given different ones.
    """
    keys = derive_bottle_keys(entropy, adsid)

    inner = cf.OTInternalBottle(
        signing_key=cf.OTPrivateKey(
            key_type=OT_PRIVATE_KEY_TYPE,
            key_data=peer_key_material(signing_key),
        ),
        encryption_key=cf.OTPrivateKey(
            key_type=OT_PRIVATE_KEY_TYPE,
            key_data=peer_key_material(encryption_key),
        ),
    )

    iv = secrets.token_bytes(BOTTLE_IV_LENGTH)
    encryptor = Cipher(algorithms.AES(keys.symmetric), modes.GCM(iv)).encryptor()
    sealed = encryptor.update(inner.SerializeToString()) + encryptor.finalize()

    escrowed_spki = _spki(keys.signing)
    contents = cf.OTBottle(
        peer_id=peer_id,
        bottle_id=bottle_id,
        escrowed_signing_key=escrowed_spki,
        escrowed_encryption_key=_spki(keys.encryption),
        peer_signing_key=_spki(signing_key),
        peer_encryption_key=_spki(encryption_key),
        ciphertext=cf.OTAuthenticatedCiphertext(
            ciphertext=sealed,
            # Beside the ciphertext rather than appended to it, which is how §6.7 step 4
            # reads it back.
            authentication_code=encryptor.tag,
            initialization_vector=iv,
        ),
    )

    # Serialised once. Both signatures cover exactly these bytes and these bytes are what
    # gets sent -- re-encoding the message before sending would invalidate both over
    # content that has not changed.
    payload = contents.SerializeToString()

    return CreatedBottle(
        bottle=cf.Bottle(
            bottle=payload,
            escrowed_signing_key=escrowed_spki,
            escrowed_key_signature=keys.signing.sign(payload, ec.ECDSA(hashes.SHA384())),
            peer_key_signature=signing_key.sign(payload, ec.ECDSA(hashes.SHA384())),
            peer_id=peer_id,
            bottle_id=bottle_id,
        ),
        entropy=entropy,
        escrowed_spki=escrowed_spki,
    )
