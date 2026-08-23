"""
Protected Cloud Storage: turning an encrypted CloudKit record field into plaintext.

Implements Stage 5 of the Find My key-export protocol specification. This is where the
keys recovered from the iCloud Keychain are finally spent.

**[observed] The read and write paths both work against a real account**: every record in
a live accessory zone unwrapped and decrypted, and a field written by :func:`encrypt_field`
displayed correctly in Apple's own Find My. One branch remains unexercised and says so
where it is -- :func:`unwrap_zone_record_defaults`, for records carrying no protection
structure of their own, which no record on the account examined did.

Three details are worth knowing before reading, because each fails in a way that does not
point at its own cause:

* **The GCM tag is 12 bytes, not 16.** A library left at its default rejects every
  message, and the failure looks like corruption.
* **The authenticated data is the ciphertext header *and* a context string** naming the
  zone, record and field. Decryption therefore needs a field's identity, not just its
  bytes -- see :class:`FieldContext`.
* **The master EC key derivation has four traps in five lines**: ten PBKDF2 iterations, a
  little-endian output that must be reversed, a mask that keeps the low bits rather than
  the high ones, and a reduction by conditional subtraction rather than modulo.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import secrets
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from findmy.errors import UnhandledProtocolError

from . import der

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------

MASTER_KEY_LENGTH = 16
"""Length of the PCS master key, and of every key derived from it."""

# Every label is exactly twenty characters. That is not a coincidence and not something to
# normalise: they are opaque fixed byte strings, spaces included.
LABEL_SHARE_KEY = b"MsaeEooevaX fooo 012"
LABEL_HMAC_KEY = b"hmackey-of-masterkey"
LABEL_KEY_ID = b"master key id labell"
LABEL_ENCRYPTION_KEY = b"encryption key key m"
KEY_ID_INPUT = b"M key input data 2 u"

MASTER_EC_SALT = b"full master key"
MASTER_EC_ITERATIONS = 10
"""Ten. Not a realistic PBKDF2 count, and not a typo in the specification."""
MASTER_EC_LENGTH = 128

ENCRYPTION_VERSION = 3
"""The only field encryption version this module describes. Anything else is refused."""

GCM_IV_LENGTH = 12
GCM_TAG_LENGTH = 12
"""Twelve, not GCM's default sixteen. A library left at its default rejects every message,
and the failure looks like corruption rather than misconfiguration."""

SIGNATURE_DATA_VERSION_NO_SHARE_KEY = 5
"""The version at which the share-key derivation is skipped."""

PCS_SERVICE_SEARCHPARTY = 82
"""The PCS service type Find My is identified by."""

KEYCHAIN_VIEW_MANATEE = "Manatee"
KEYCHAIN_VIEW_PCS = "ProtectedCloudStorage"
SEARCHPARTY_SERVICE_KEY_LABEL = "com.apple.ProtectedCloudStorage-com.apple.icloud.searchparty"

ALL_LABELS = (
    LABEL_SHARE_KEY,
    LABEL_HMAC_KEY,
    LABEL_KEY_ID,
    LABEL_ENCRYPTION_KEY,
    KEY_ID_INPUT,
)
"""Every fixed string in this module. Each is exactly twenty characters."""


class PCSError(UnhandledProtocolError):
    """Raised when a protection structure cannot be unwrapped or a field decrypted."""


class MissingKeyError(PCSError):
    """
    Raised when no key held locally appears in a record's protection structure.

    This is not a decryption failure and retrying will not help: the record is protected
    for parties this client is not one of.
    """


# --------------------------------------------------------------------------------------
# Key derivation (§5)
# --------------------------------------------------------------------------------------


def derive_key(
    master_key: bytes,
    label: bytes,
    *,
    length: int | None = None,
) -> bytes:
    """
    Derive a key from the PCS master key.

    NIST SP 800-108 counter-mode KDF with HMAC-SHA256, over the fixed input

        be32(i) | label | 0x00 | context | be32(bits)

    with an empty context and the counter starting at 1. Every use here asks for 16 bytes
    and SHA-256 produces 32, so the counter never advances in practice -- the loop is here
    so that it would be right if one ever did.

    :param master_key: The master key.
    :param label: One of the module's twenty-character labels.
    :param length: Output length in bytes. Defaults to the input key's length.
    """
    length = length or len(master_key)

    out = b""
    counter = 1
    while len(out) < length:
        block = struct.pack(">I", counter) + label + b"\x00" + struct.pack(">I", length * 8)
        out += hmac.new(master_key, block, hashlib.sha256).digest()
        counter += 1

    return out[:length]


def compute_key_id(master_key: bytes) -> bytes:
    """
    Compute a key's id, which is a two-stage construction rather than a plain digest.

    A label key is derived first, and the id is an HMAC under *that* over a second fixed
    string.
    """
    label_key = derive_key(master_key, LABEL_KEY_ID)
    return hmac.new(label_key, KEY_ID_INPUT, hashlib.sha256).digest()


def derive_encryption_key(master_key: bytes) -> bytes:
    """Derive the AES-128 key that field ciphertext is encrypted under."""
    return derive_key(master_key, LABEL_ENCRYPTION_KEY, length=MASTER_KEY_LENGTH)


def derive_hmac_key(master_key: bytes) -> bytes:
    """
    Derive the HMAC key the protection structure's own HMAC is computed under.

    What it covers is the DER of `keyset`, then the raw bytes of `meta`, then the DER of
    `signatureData` -- see :func:`verify_protection_hmac`.
    """
    return derive_key(master_key, LABEL_HMAC_KEY)


def derive_master_ec_private_key(master_key: bytes) -> int:
    """
    Derive the private scalar of the EC key that signs a protection structure.

    Four traps in five lines, each worth stating rather than reading out of the code. The
    PBKDF2 count is **ten**. The output is produced little-endian and must be **reversed**.
    The truncation is a **mask keeping the low 256 bits**, not the `bits2int` convention
    that keeps the high ones -- and the two are indistinguishable by the arithmetic that
    follows, so nothing downstream would catch the wrong choice. The reduction is a single
    **conditional subtraction**, not a modulo.

    :param master_key: The PCS master key.
    """
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        master_key,
        MASTER_EC_SALT,
        MASTER_EC_ITERATIONS,
        dklen=MASTER_EC_LENGTH,
    )

    # Produced little-endian, consumed big-endian.
    value = int.from_bytes(raw[::-1], "big")

    # A mask keeping the LOW bits, not bits2int's leading ones.
    value &= (1 << _P256_ORDER.bit_length()) - 1

    # A single conditional subtraction, not a modulo. It suffices because a value masked
    # to the order's bit length is always below twice the order.
    if value > _P256_ORDER:
        value -= _P256_ORDER

    if not 1 <= value < _P256_ORDER:
        msg = "Derived master EC scalar is out of range for P-256"
        raise PCSError(msg)

    return value


_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# --------------------------------------------------------------------------------------
# The protection structure (§3)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ShareKey:
    """One party's wrapped copy of the record's master key."""

    key_type: int
    public_key: bytes
    """The compressed EC public key this entry is for. Match on this; never index."""

    ciphertext: bytes
    """The RFC 6637 wrapped key."""

    flags: int | None = None

    @property
    def read_only(self) -> bool:
        """Whether bit 0 of the flags is set."""
        return bool((self.flags or 0) & 1)


@dataclass(frozen=True)
class SignatureData:
    """Carries the version the share-key derivation branches on."""

    version: int
    data: bytes


@dataclass(frozen=True)
class KeyRef:
    """A reference to a key: its type, and its compressed public part."""

    key_type: int
    public_key: bytes


@dataclass(frozen=True)
class Signature:
    """A signature over a protection structure."""

    key_id: bytes
    """
    When non-empty, the **compressed public key of the signer** -- not a hash and not an
    identifier. Empty means self-signed.
    """

    digest: int
    """1 = SHA-256. Nothing observed uses 2 (SHA-512)."""

    signature: bytes


@dataclass(frozen=True)
class ObjectSignature:
    """
    What `SignatureData.data` decodes to.

    It is DER in its own right, nested inside the protection structure's DER -- and the
    data it signs is neither: see :func:`build_signed_data`.
    """

    roll_count: int
    outer_sign_key_type: int
    public: KeyRef
    signature: Signature
    symm_key_count: int | None = None
    signature2: Signature | None = None
    """A "past" signature. Trying it when the first fails is key rotation, not corruption."""

    ec_key_list_der: bytes = b""
    attributes_der: bytes = b""

    @classmethod
    def from_der(cls, data: bytes) -> ObjectSignature:
        """Parse an ObjectSignature."""
        element, _ = der.parse_one(data)
        parts = element.children()
        if len(parts) < 4:
            msg = f"ObjectSignature has {len(parts)} members, expected at least 4"
            raise PCSError(msg)

        key_ref = parts[2].children()
        if len(key_ref) < 2:
            msg = "ObjectSignature's public key reference is incomplete"
            raise PCSError(msg)

        symm_key_count: int | None = None
        signature2: Signature | None = None
        ec_key_list_der = b""
        attributes_der = b""

        for extra in parts[4:]:
            if extra.is_context(0):
                symm_key_count = extra.unwrap().as_int()
            elif extra.is_context(1):
                signature2 = _parse_signature(extra.unwrap())
            elif extra.is_context(2):
                ec_key_list_der = extra.unwrap().raw
            elif extra.is_context(3):
                attributes_der = extra.unwrap().raw

        return cls(
            roll_count=parts[0].as_int(),
            outer_sign_key_type=parts[1].as_int(),
            public=KeyRef(key_type=key_ref[0].as_int(), public_key=key_ref[1].as_bytes()),
            signature=_parse_signature(parts[3]),
            symm_key_count=symm_key_count,
            signature2=signature2,
            ec_key_list_der=ec_key_list_der,
            attributes_der=attributes_der,
        )


@dataclass(frozen=True)
class Attribute:
    """An attribute whose value is itself DER, interpreted per key."""

    key: int
    value: bytes


@dataclass(frozen=True)
class ShareProtection:
    """What a record's `protectionInfo` bytes decode to."""

    keys: list[ShareKey]
    meta: bytes
    signature_data: SignatureData
    hmac: bytes
    truncated_key_id: bytes
    """The first four bytes of the key id. One of the two checks that catch a wrong key."""
    signature: Signature | None = None
    attributes: list[Attribute] = field(default_factory=list)

    keyset_der: bytes = b""
    """The keyset's own DER, retained because the structure's HMAC covers it."""

    signature_data_der: bytes = b""
    """The signature data's own DER, likewise."""

    @classmethod
    def from_der(cls, data: bytes) -> ShareProtection:
        """
        Parse a record's protection structure.

        Note that `hmac` sits between two context-tagged fields without a tag of its own,
        so this walks the sequence rather than assuming tags ascend.
        """
        sequence = der.expect_application(data, 1)
        children = sequence.children()

        keys: list[ShareKey] = []
        keyset_der = b""
        meta = b""
        signature_data: SignatureData | None = None
        signature_data_der = b""
        hmac_value = b""
        truncated_key_id = b""
        signature: Signature | None = None
        attributes: list[Attribute] = []

        for element in children:
            if element.is_universal(der.TAG_SEQUENCE) and not keyset_der:
                keys = _parse_keyset(element)
                keyset_der = element.raw
            elif element.is_context(0):
                meta = element.unwrap().as_bytes()
            elif element.is_context(1):
                inner = element.unwrap()
                signature_data = _parse_signature_data(inner)
                signature_data_der = inner.raw
            elif element.is_universal(der.TAG_OCTET_STRING):
                hmac_value = element.as_bytes()
            elif element.is_context(2):
                truncated_key_id = element.unwrap().as_bytes()
            elif element.is_context(3):
                signature = _parse_signature(element.unwrap())
            elif element.is_context(4):
                attributes = [_parse_attribute(child) for child in element.unwrap().children()]

        if signature_data is None:
            msg = "Protection structure carries no signature data"
            raise PCSError(msg)

        return cls(
            keys=keys,
            meta=meta,
            signature_data=signature_data,
            hmac=hmac_value,
            truncated_key_id=truncated_key_id,
            signature=signature,
            attributes=attributes,
            keyset_der=keyset_der,
            signature_data_der=signature_data_der,
        )


def _parse_keyset(element: der.DerElement) -> list[ShareKey]:
    """Parse the KeySet: an integer, then a SET OF ShareKey."""
    keys: list[ShareKey] = []
    for child in element.children():
        if not child.is_universal(der.TAG_SET):
            continue
        # A SET, so the entries are unordered and must be searched, never indexed.
        keys.extend(_parse_share_key(entry) for entry in child.children())
    return keys


def _parse_share_key(element: der.DerElement) -> ShareKey:
    """Parse one ShareKey: a key reference, its ciphertext, and optional flags."""
    parts = element.children()
    if len(parts) < 2:
        msg = f"ShareKey has {len(parts)} members, expected at least 2"
        raise PCSError(msg)

    key_ref = parts[0].children()
    if len(key_ref) < 2:
        msg = "KeyRef is missing its public key"
        raise PCSError(msg)

    return ShareKey(
        key_type=key_ref[0].as_int(),
        public_key=key_ref[1].as_bytes(),
        ciphertext=parts[1].as_bytes(),
        flags=parts[2].as_int() if len(parts) > 2 else None,
    )


def _parse_signature_data(element: der.DerElement) -> SignatureData:
    parts = element.children()
    return SignatureData(
        version=parts[0].as_int() if parts else 0,
        data=parts[1].as_bytes() if len(parts) > 1 else b"",
    )


def _parse_signature(element: der.DerElement) -> Signature:
    parts = element.children()
    return Signature(
        key_id=parts[0].as_bytes() if parts else b"",
        digest=parts[1].as_int() if len(parts) > 1 else 0,
        signature=parts[2].as_bytes() if len(parts) > 2 else b"",
    )


def _parse_attribute(element: der.DerElement) -> Attribute:
    parts = element.children()
    return Attribute(
        key=parts[0].as_int() if parts else 0,
        value=parts[1].as_bytes() if len(parts) > 1 else b"",
    )


# --------------------------------------------------------------------------------------
# Keychain-held keys (§3.2)
# --------------------------------------------------------------------------------------


def parse_keychain_private_key(data: bytes) -> ec.EllipticCurvePrivateKey:
    """
    Read a private key as the iCloud Keychain stores it.

    Find My is a v2 service, so its keys take the `[APPLICATION 5]` form: a sequence
    holding a single octet string. The scalar inside is read as a P-256 private key.

    The specification writes this structure without the EXPLICIT keyword it uses on every
    other application tag in the set, which leaves it genuinely unclear whether the tag
    replaces the SEQUENCE's own tag or wraps it. Both are accepted here rather than
    picking one: the difference is a single level of nesting and is unambiguous to detect.

    :raises PCSError: If the structure is not a v2 private key.
    """
    element, _ = der.parse_one(data)
    if element.tag_class != der.CLASS_APPLICATION or element.tag_number != 5:
        msg = (
            "Expected a v2 [APPLICATION 5] private key. The v1 form exists but Find My"
            " does not use it."
        )
        raise PCSError(msg)

    parts = element.children()
    if len(parts) == 1 and parts[0].is_universal(der.TAG_SEQUENCE):
        parts = parts[0].children()  # explicitly tagged: unwrap one more level

    scalar = next(
        (part.as_bytes() for part in parts if part.is_universal(der.TAG_OCTET_STRING)),
        None,
    )
    if scalar is None:
        msg = "Private key structure carries no octet string to read a scalar from"
        raise PCSError(msg)

    try:
        return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
    except ValueError as e:
        msg = f"Private key scalar is not valid for P-256: {e}"
        raise PCSError(msg) from None


def compress_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Encode a public key the way a protection structure refers to it."""
    return public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def bare_x(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Render the x coordinate alone, which is how this protocol writes a public key.

    Not the X9.62 compressed form: no sign byte, no `0x04` marker. See §2's note.
    """
    uncompressed = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    coordinate = (public_key.curve.key_size + 7) // 8
    return uncompressed[1 : 1 + coordinate]


def public_key_forms(public_key: ec.EllipticCurvePublicKey) -> set[bytes]:
    """
    Every way this protocol writes a public key, for matching one against another.

    **"Compressed" does not mean X9.62 here.** The service key item's `acct` is
    **[observed]** 32 bytes beginning `0xb5` -- a bare x coordinate, with neither the
    `0x02`/`0x03` sign byte of a compressed point nor the `0x04` of an uncompressed one --
    and Stage 3 §6.8.1's key blobs are written the same way. A reader comparing 33-byte
    X9.62 bytes against those never matches, and the failure presents as "this record is
    not encrypted for this client", which is a different and much more discouraging claim.

    Matching on a bare x is slightly weaker than matching on a full point, since x alone
    does not fix the sign of y. That ambiguity is the protocol's own -- it is what storing
    x alone means -- and it is not introduced here.
    """
    uncompressed = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    coordinate = (public_key.curve.key_size + 7) // 8

    return {
        public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint),
        uncompressed,
        uncompressed[1 : 1 + coordinate],  # the bare x coordinate
        uncompressed[1:],  # x and y, without the 0x04 marker
    }


# --------------------------------------------------------------------------------------
# Unwrapping (§4)
# --------------------------------------------------------------------------------------

# RFC 6637's parameter block, as PCS builds it: length-prefixed P-256 OID, the ECDH
# algorithm id, the fixed 0x03 0x01 pair, SHA-256 as the KDF hash, AES-128 as the
# key-wrap cipher, the twenty-character sender string, and a fingerprint slot.
_RFC6637_PARAM = (
    bytes([8])
    + bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
    + bytes([0x12, 0x03, 0x01, 0x08, 0x07])
    + b"Anonymous Sender    "
    # Not a key fingerprint, not a hash of anything: the literal ASCII word, right-padded
    # with zeros to fill the 20-byte slot an ordinary fingerprint would occupy.
    + b"fingerprint".ljust(20, b"\x00")
)

_KEK_LENGTH = 16
_WRAPPED_ALGORITHM_ID = 1
_CHECKSUM_MODULUS = 65536

# y^2 = x^3 - 3x + b over P-256.
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def _decompress_x(x_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """
    Rebuild a P-256 public key from an x coordinate alone.

    The ephemeral key is sent as a 32-byte compact point -- x with no sign bit -- so the
    y coordinate has to be recovered by solving the curve equation. Either root will do:
    a point and its negation share an x, and ECDH takes only the x of the shared secret,
    so both give the same answer.
    """
    x = int.from_bytes(x_bytes, "big")
    alpha = (pow(x, 3, _P256_P) - 3 * x + _P256_B) % _P256_P

    # p = 3 (mod 4), so the square root is a single exponentiation.
    y = pow(alpha, (_P256_P + 1) // 4, _P256_P)
    if pow(y, 2, _P256_P) != alpha:
        msg = "Ephemeral point's x coordinate is not on P-256"
        raise PCSError(msg)

    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _split_wrapped_key(ciphertext: bytes) -> tuple[bytes, bytes]:
    """
    Split a wrapped key into its ephemeral point and the wrapped material.

    The layout is OpenPGP's MPI encoding, not X9.62: a two-byte big-endian count of
    **bits** in the point, the point itself, then a one-byte length and the wrapped key.
    Note the first number counts bits -- reading it as bytes overruns immediately.
    """
    if len(ciphertext) < 3:
        msg = f"Wrapped key is {len(ciphertext)} bytes, too short to carry an MPI"
        raise PCSError(msg)

    point_bits = int.from_bytes(ciphertext[:2], "big")
    point_length = (point_bits + 7) // 8
    point_end = 2 + point_length

    if len(ciphertext) <= point_end:
        msg = f"Wrapped key claims a {point_bits}-bit point but is only {len(ciphertext)} bytes"
        raise PCSError(msg)

    point = ciphertext[2:point_end]
    wrapped_length = ciphertext[point_end]
    wrapped = ciphertext[point_end + 1 : point_end + 1 + wrapped_length]

    if len(wrapped) != wrapped_length:
        msg = f"Wrapped key claims {wrapped_length} bytes but only {len(wrapped)} remain"
        raise PCSError(msg)

    return point, wrapped


def _unframe_master_key(plaintext: bytes) -> bytes:
    """
    Read the master key out of the frame RFC 6637 wraps it in.

    The unwrapped material is an algorithm byte, the key, a two-byte checksum, and
    self-describing padding whose every byte equals its own length. Both the checksum and
    the padding are checked: they are free, and they catch a wrong key here rather than
    three steps later.
    """
    if len(plaintext) < 4:
        msg = f"Unwrapped material is {len(plaintext)} bytes, too short to be framed"
        raise PCSError(msg)

    if plaintext[0] != _WRAPPED_ALGORITHM_ID:
        msg = (
            f"Unwrapped material announces algorithm {plaintext[0]}, expected"
            f" {_WRAPPED_ALGORITHM_ID}. The key-encryption key is most likely wrong."
        )
        raise PCSError(msg)

    padding_length = plaintext[-1]
    key_length = len(plaintext) - padding_length - 3
    if key_length <= 0 or padding_length == 0 or padding_length > len(plaintext) - 3:
        msg = f"Unwrapped material has an implausible padding length of {padding_length}"
        raise PCSError(msg)

    key = plaintext[1 : 1 + key_length]
    checksum = int.from_bytes(plaintext[1 + key_length : 3 + key_length], "big")
    padding = plaintext[3 + key_length :]

    if sum(key) % _CHECKSUM_MODULUS != checksum:
        msg = "Unwrapped key fails its checksum; the key-encryption key is wrong"
        raise PCSError(msg)
    if any(byte != padding_length for byte in padding):
        msg = "Unwrapped material's padding is malformed"
        raise PCSError(msg)

    return key


def unwrap_share_key(
    private_key: ec.EllipticCurvePrivateKey,
    ciphertext: bytes,
) -> bytes:
    """
    Recover a PCS master key from one keyset entry's wrapped ciphertext.

    RFC 6637's ECDH key wrap: agree a shared secret with the ephemeral point, derive an
    AES-128 key-encryption key from it, and unwrap with RFC 3394. The unwrap's own
    integrity check is the first signal that everything above was assembled correctly.

    :param private_key: Our private key, whose public half appears in the keyset.
    :param ciphertext: The entry's wrapped key.
    :raises PCSError: If the ciphertext is malformed or the key is wrong.
    """
    point, wrapped = _split_wrapped_key(ciphertext)
    shared = private_key.exchange(ec.ECDH(), _decompress_x(point))

    kek = hashlib.sha256(struct.pack(">I", 1) + shared + _RFC6637_PARAM).digest()

    try:
        plaintext = aes_key_unwrap(kek[:_KEK_LENGTH], wrapped)
    except InvalidUnwrap:
        msg = (
            "AES key unwrap failed its integrity check. Either this entry is not for us,"
            " or the key-encryption key was derived differently than expected."
        )
        raise PCSError(msg) from None

    return _unframe_master_key(plaintext)


def build_signed_data(protection: ShareProtection, signature: ObjectSignature) -> bytes:
    """
    Assemble the bytes a protection structure's signature covers.

    A **hand-built concatenation, not a DER structure** -- nothing re-encodes these as one
    message, so they go in exactly this order: the keyset's DER, the raw meta, four
    big-endian 32-bit integers, the signing public key, and then two optional DER blobs.

    Note the asymmetry in the middle, which is the part that bites: an **absent
    `symmKeyCount` contributes four zero bytes**, while absent `attributes` or `ecKeyList`
    contribute **nothing at all**. Getting that the wrong way round is a four-byte
    difference whose only symptom is a signature that will not verify.
    """
    return b"".join(
        (
            protection.keyset_der,
            protection.meta,
            struct.pack(">I", signature.outer_sign_key_type),
            struct.pack(">I", signature.roll_count),
            # Absent means zero here, not omitted.
            struct.pack(">I", signature.symm_key_count or 0),
            struct.pack(">I", signature.public.key_type),
            signature.public.public_key,
            # Absent means omitted here, not zero.
            signature.attributes_der,
            signature.ec_key_list_der,
        ),
    )


SIGNATURE_ABSENT = "the structure carries no signature data at all"
SIGNATURE_UNPARSEABLE = "its signature data would not parse"
SIGNATURE_WRONG_SIGNER = "every signature names a signer other than this record's master EC key"
SIGNATURE_REJECTED = (
    "the signature parsed, named the right key, and did not verify over the signed data"
)
"""
Why a protection structure's signature check came back negative.

**Four causes, and they lead in four directions**, which is why the caller reports which
one rather than one sentence covering all of them. Absent is a structure that was never
signed. Unparseable is this module's reading of the signature *container*. Wrong-signer is
a key question. Only the fourth is evidence about the layout of the signed data -- and that
was the diagnosis the single message used to offer for all four.
"""


def describe_protection_signature(protection: ShareProtection, master_key: bytes) -> str | None:
    """
    Verify a protection structure's own signature, and say what went wrong if it did.

    ECDSA over SHA-256, against the key derived by
    :func:`derive_master_ec_private_key` -- which is what makes that derivation's
    low-bit masking load-bearing rather than decorative.

    Falls back to the "past" signature if the first fails: that is key rotation, not
    corruption.

    :returns: None when a signature verified, otherwise one of :data:`SIGNATURE_ABSENT`,
        :data:`SIGNATURE_UNPARSEABLE`, :data:`SIGNATURE_WRONG_SIGNER` or
        :data:`SIGNATURE_REJECTED`.
    """
    if not protection.signature_data.data:
        return SIGNATURE_ABSENT

    try:
        object_signature = ObjectSignature.from_der(protection.signature_data.data)
    except (PCSError, der.DerError):
        return SIGNATURE_UNPARSEABLE

    public_key = ec.derive_private_key(
        derive_master_ec_private_key(master_key),
        ec.SECP256R1(),
    ).public_key()

    signed = build_signed_data(protection, object_signature)

    candidates = [object_signature.signature]
    if object_signature.signature2 is not None:
        candidates.append(object_signature.signature2)

    considered = 0
    for candidate in candidates:
        # A non-empty keyid is the signer's compressed public key. Checking it first names
        # the wrong key immediately, where a failed verification does not.
        if candidate.key_id and candidate.key_id != compress_public_key(public_key):
            continue

        considered += 1
        try:
            public_key.verify(candidate.signature, signed, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            continue
        return None

    return SIGNATURE_REJECTED if considered else SIGNATURE_WRONG_SIGNER


def verify_protection_signature(protection: ShareProtection, master_key: bytes) -> bool:
    """
    Verify a protection structure's own signature under the master EC key.

    See :func:`describe_protection_signature`, which says *why* when this is False.
    """
    return describe_protection_signature(protection, master_key) is None


def verify_protection_hmac(protection: ShareProtection, master_key: bytes) -> bool:
    """
    Check the protection structure's HMAC under a candidate master key.

    It covers three things in order and nothing else: the DER of `keyset`, the raw bytes
    of `meta`, and the DER of the **`ObjectSignature`**.

    Note that `keyset` is used as the bytes that arrived rather than re-encoded. DER sorts
    a `SET OF` by encoded value and `keyset` is one, so an encoder preserving parse order
    would produce different bytes for entries that arrived unsorted -- retaining the
    original span sidesteps that question entirely rather than answering it correctly.

    **The third part is the inner structure, not the `SignatureData` wrapper around it.**
    `SignatureData` is `SEQUENCE { version, data }`, and what the HMAC covers is what
    `data` *holds* -- which is simply that OCTET STRING's contents, taken as bytes rather
    than re-encoded at all. Encoding the wrapper instead adds the version and the octet
    string's own header, and the HMAC then fails on **every** structure while the key id
    still matches. That asymmetry is the signature of this mistake: a wrong key fails both
    checks, and only a wrong construction fails one.
    """
    if not protection.hmac:
        return False

    signed = protection.keyset_der + protection.meta + protection.signature_data.data
    expected = hmac.new(derive_hmac_key(master_key), signed, hashlib.sha256).digest()

    return hmac.compare_digest(expected[: len(protection.hmac)], protection.hmac)


@dataclass(frozen=True)
class MetaContents:
    """
    What a protection structure's `meta` holds once decrypted.

    **This is where the keys actually are.** Steps 1 to 5 yield exactly one key -- the
    master key wrapped to us -- and everything else the structure carries lives here,
    encrypted under it.
    """

    symmetric_keys: list[bytes] = field(default_factory=list)
    """Additional PCS master keys, from `symmKeys`. These decrypt fields."""

    private_keys: list[ec.EllipticCurvePrivateKey] = field(default_factory=list)
    """
    The EC private keys, from every identity's nested keyset.

    **These unwrap the next level down**, and are what §4 step 0 keeps at the zone. They
    are not what decrypts a field, and taking the wrong half at a level is the mistake the
    two-level table exists to prevent.
    """


@dataclass(frozen=True)
class UnwrappedProtection:
    """A record's master key, and how it was arrived at."""

    master_key: bytes
    """The key every field of this record is encrypted under."""

    share_key_derived: bool
    """Whether the share-key derivation of §4 step 3 was applied."""

    read_only: bool
    """Whether our keyset entry is marked read-only."""

    hmac_verified: bool
    """Whether the structure's own HMAC checked out under this key."""

    signature_verified: bool | None
    """
    Whether the structure's signature verified under the master EC key.

    None when the check was skipped, which the read-only flag causes.
    """

    meta: MetaContents = field(default_factory=MetaContents)
    """
    What `meta` held. Empty when it could not be decrypted, which is not fatal at the
    record level -- the master key alone decrypts fields -- and is fatal at the zone level,
    since the zone's whole purpose is the keys inside it.
    """

    @property
    def master_keys(self) -> list[bytes]:
        """Every key that might decrypt a field: ours first, then `symmKeys`."""
        return [self.master_key, *self.meta.symmetric_keys]

    @property
    def private_keys(self) -> list[ec.EllipticCurvePrivateKey]:
        """The EC keys this structure carries, for unwrapping the level below."""
        return self.meta.private_keys


def unwrap_protection(
    protection: ShareProtection,
    private_keys: Sequence[ec.EllipticCurvePrivateKey],
    *,
    require_hmac: bool = False,
    require_signature: bool = False,
) -> UnwrappedProtection:
    """
    Recover a record's master key from its protection structure.

    :param private_keys: Keys held locally, from the `Manatee` keychain view. The one
        whose public part appears in the structure is used; the rest are ignored.
    :param require_hmac: Fail if the structure's HMAC does not verify. Off by default
        because neither check has been exercised against a real record, and a key that
        passes the truncated key id is already strong evidence.
    :param require_signature: Fail if the structure's signature does not verify. Skipped
        entirely, rather than failed, when our keyset entry is read-only.
    :raises MissingKeyError: If no key held locally appears in the structure.
    :raises PCSError: If a key matched but the resulting master key fails its checks.
    """
    share_key, private_key = _find_our_key(protection, private_keys)

    master_key = unwrap_share_key(private_key, share_key.ciphertext)

    # The share-key derivation is easy to miss and produces a key that fails every
    # subsequent check, which is why the check below exists rather than pressing on.
    share_key_derived = (
        protection.signature_data.version != SIGNATURE_DATA_VERSION_NO_SHARE_KEY
        and not share_key.read_only
    )
    if share_key_derived:
        master_key = derive_key(master_key, LABEL_SHARE_KEY)

    if protection.truncated_key_id:
        key_id = compute_key_id(master_key)
        if key_id[: len(protection.truncated_key_id)] != protection.truncated_key_id:
            msg = (
                "Recovered a key, but its key id does not match the one the protection"
                " structure carries. Either the share-key branch was taken wrongly or the"
                " key derivation does not match what wrote this record."
            )
            raise PCSError(msg)
    else:
        logger.warning("Protection structure carries no truncated key id; cannot verify the key")

    hmac_verified = verify_protection_hmac(protection, master_key)
    if not hmac_verified:
        message = (
            "Protection structure's HMAC did not verify. The key id matched, so the key"
            " is most likely right and this module's reading of what the HMAC covers is"
            " most likely wrong."
        )
        if require_hmac:
            raise PCSError(message)
        logger.warning(message)

    # The master-key check is skipped when the entry is read-only, rather than expected
    # to fail: there is nothing to verify against in that case.
    signature_verified: bool | None = None
    if not share_key.read_only:
        reason = describe_protection_signature(protection, master_key)
        signature_verified = reason is None
        if reason is not None:
            # The layout diagnosis belongs to exactly one of the four causes. Offering it
            # for all of them -- which the single message used to do -- sends somebody
            # reading a log for an unsigned structure looking for a parsing bug that is
            # not there.
            message = f"Protection structure's signature was not confirmed: {reason}."
            if reason == SIGNATURE_REJECTED:
                message += (
                    " The key id matched, so this is more likely a misreading of the"
                    " signed data's layout than a wrong key."
                )
            if require_signature:
                raise PCSError(message)
            logger.warning(message)

    return UnwrappedProtection(
        master_key=master_key,
        share_key_derived=share_key_derived,
        read_only=share_key.read_only,
        hmac_verified=hmac_verified,
        signature_verified=signature_verified,
        meta=read_meta(protection.meta, master_key),
    )


def unwrap_zone(
    protection_info: bytes,
    service_keys: Sequence[ec.EllipticCurvePrivateKey],
) -> list[ec.EllipticCurvePrivateKey]:
    """
    Unwrap a zone's protection structure into the keys its records are protected under.

    **This is §4 step 0, and skipping it is undetectable from the record level.** A
    record's keyset does not name the keychain service key; it names a *zone* key, and zone
    keys live inside the zone's own structure. A reader that takes the service key straight
    to a record finds no matching entry and reports that the record is protected for
    someone else -- which is what being locked out looks like, and is not what happened.

    Note which half is taken. Unwrapping yields both master keys and EC private keys; the
    zone level wants the **EC private keys**, and the record level below wants the master
    keys. Taking the same half at both is the next mistake available.

    :param protection_info: The zone's `protectionInfo` bytes.
    :param service_keys: The keychain service keys, from Stage 3.
    :raises MissingKeyError: If no service key appears in the zone's keyset.
    :raises PCSError: If the structure cannot be unwrapped.
    """
    unwrapped = unwrap_protection(ShareProtection.from_der(protection_info), service_keys)

    # The identity keys, plus the one construction in this protocol that turns a
    # zone-level *secret* into an elliptic-curve key: §5's master EC key, derived from each
    # master key the zone carries. It exists to verify signatures, but a record's keyset
    # names a public x and this produces one, so it costs nothing to offer and a record
    # naming it would answer where zone keys come from outright.
    keys = [*unwrapped.private_keys, *master_ec_keys(unwrapped.master_keys)]

    if not keys:
        msg = (
            "The zone's protection structure unwrapped but yields no elliptic-curve keys,"
            " so there is nothing for its records to be protected under. Its meta is where"
            " those keys live, and it held"
            f" {len(unwrapped.meta.symmetric_keys)} symmetric key(s) and none of the other"
            " kind. Its DER shape is logged at DEBUG, and that is what tells a meta this"
            " reader looked in the wrong place from one that is genuinely empty."
        )
        raise PCSError(msg)

    # Name them the way a record names a key -- as a bare x coordinate -- because the next
    # failure is a record asking for one, and the only useful question then is whether it
    # is among these. Public keys, so naming them discloses nothing.
    named = ", ".join(bare_x(key.public_key())[:8].hex() for key in keys[:6])
    logger.info(
        "The zone yields %d key(s) for its records (%d from identities, %d derived): %s",
        len(keys),
        len(unwrapped.private_keys),
        len(keys) - len(unwrapped.private_keys),
        named,
    )
    return keys


def unwrap_zone_record_defaults(
    record_protection_info: bytes,
    zone_keys: Sequence[ec.EllipticCurvePrivateKey],
) -> list[bytes]:
    """
    Unwrap a zone's `recordProtectionInfo` into the default keys its records may use.

    **§4 step 0's other branch, and it covers a record that carries no structure of its
    own.** A zone has room for two protection structures: `protectionInfo`, which gives
    the zone keys, and this one, which is decoded *against* those and gives master keys
    directly. It is an alternative to a record's own keyset, never an input to one --
    neither this nor the key ids inside it feed a record's structure.

    Which of them applies to a given record is named by that record's `pcsKey`, a key-id
    prefix -- see :func:`select_default_master_key`.

    .. warning::
        **Never exercised.** Every record on the one account examined carried its own
        `protectionInfo` and none carried a `pcsKey`, so this branch has not run against
        anything real. It is read-only and cannot damage an account, but if decryption
        fails on a record that reached it, this is the first thing to suspect.

    :param record_protection_info: The zone's `recordProtectionInfo` bytes.
    :param zone_keys: What :func:`unwrap_zone` returned. **Not** the service keys.
    :raises MissingKeyError: If no zone key appears in its keyset.
    :raises PCSError: If the structure cannot be unwrapped.
    """
    unwrapped = unwrap_protection(ShareProtection.from_der(record_protection_info), zone_keys)
    keys = unwrapped.master_keys

    logger.warning(
        "Using the zone's recordProtectionInfo, which yielded %d default record key(s)."
        " This path has never run against a real account -- every record on the one"
        " examined carried its own protectionInfo -- so if decryption fails below, this"
        " is the first place to look.",
        len(keys),
    )
    return keys


def select_default_master_key(
    master_keys: Sequence[bytes],
    pcs_key: bytes,
) -> bytes | None:
    """
    Pick the default record key a record's `pcsKey` names.

    `pcsKey` is a **key-id prefix**, not a key: it is compared against the leading bytes
    of each candidate's key id, the same comparison the encrypted-field header check makes.

    An empty `pcsKey` names nothing. With exactly one default key that is unambiguous
    anyway, so it is used and said; with several there is no way to choose, and guessing
    would produce a decryption failure that reads as the wrong key rather than as no
    selector.

    :returns: The key, or None if nothing matches.
    """
    if not pcs_key:
        if len(master_keys) == 1:
            logger.info("The record names no pcsKey, and the zone offers exactly one default")
            return master_keys[0]
        return None

    for key in master_keys:
        if compute_key_id(key)[: len(pcs_key)] == pcs_key:
            return key

    return None


def master_ec_keys(master_keys: Sequence[bytes]) -> list[ec.EllipticCurvePrivateKey]:
    """
    Derive the master EC key from each of a structure's master keys.

    §5's derivation is the only construction here that turns a symmetric secret into an
    elliptic-curve key. It exists to verify a structure's own signature, but the key it
    produces is an ordinary P-256 key with a public x like any other -- so where a level
    below names a key by its public part and the level above holds only secrets, this is
    the one bridge between them.

    Offered rather than assumed: a record either names one of these or does not, and the
    check costs a PBKDF2 with ten iterations.
    """
    keys: list[ec.EllipticCurvePrivateKey] = []

    for master_key in master_keys:
        try:
            keys.append(
                ec.derive_private_key(derive_master_ec_private_key(master_key), ec.SECP256R1()),
            )
        except ValueError as e:  # noqa: PERF203 -- one bad key must not cost the others
            logger.debug("A master key yields no master EC key: %s", e)

    return keys


# --------------------------------------------------------------------------------------
# The meta member, which is where the keys are (§4 step 6)
# --------------------------------------------------------------------------------------

_META_SYMM_KEYS = 0
_META_IDENTITIES = 2


def read_meta(meta: bytes, master_key: bytes) -> MetaContents:
    """
    Decrypt a protection structure's `meta` and read the keys out of it.

    Steps 1 to 5 yield **one** key. The rest of what a structure carries is here: further
    master keys under `symmKeys`, and -- more importantly -- the EC private keys that
    unwrap the *next level down*. A reader that stops at the master key has the means to
    decrypt this level's fields and nothing with which to reach the level below, which is
    exactly the shape of "no key is held for this record".

    Failures are reported rather than raised: at the record level `meta` is not needed to
    decrypt a field, so an unreadable one should not cost the master key that was already
    recovered. A caller that *does* need the keys inside should check the result is not
    empty.
    """
    if not meta:
        return MetaContents()

    try:
        # A structure member has no zone, record or field name to bind to, so the AAD is
        # the header alone. The one place §6's context rule does not apply.
        plaintext = decrypt_field(
            meta,
            UnwrappedProtection(
                master_key=master_key,
                share_key_derived=False,
                read_only=False,
                hmac_verified=False,
                signature_verified=None,
            ),
            FieldContext.none(),
            check_key_id=False,
        )
    except PCSError as e:
        logger.warning("A protection structure's meta did not decrypt: %s", e)
        return MetaContents()

    try:
        return parse_meta(plaintext)
    except (der.DerError, PCSError) as e:
        logger.warning("A protection structure's meta decrypted but did not parse: %s", e)
        return MetaContents()


def parse_meta(plaintext: bytes) -> MetaContents:
    """
    Read the DER a decrypted `meta` holds.

    `[0]` is `symmKeys`, more master keys. `[2]` is `identities`, and the EC keys are one
    level further in: each identity carries a `keyset` **OCTET STRING that is itself DER**,
    whose `keys` are the same private-key CHOICE a keychain item's `v_Data` uses.

    `[1]` is carried and not understood, and skipping it is deliberate rather than an
    omission.
    """
    element, _ = der.parse_one(plaintext)

    # Every other structure in this protocol is wrapped in an application tag, so descend
    # through one rather than requiring the members to be at the top. A wrapper that is
    # not there costs nothing to look for.
    if element.tag_class == der.CLASS_APPLICATION and element.constructed:
        with contextlib.suppress(der.DerError):
            element = element.unwrap()

    symmetric: list[bytes] = []
    private: list[ec.EllipticCurvePrivateKey] = []

    for child in element.children():
        if child.is_context(_META_SYMM_KEYS):
            symmetric.extend(entry.as_bytes() for entry in child.unwrap().children())
        elif child.is_context(_META_IDENTITIES):
            for identity in child.unwrap().children():
                # Always, not only on failure. Which member a key came out of is the
                # difference between reading a keyset and reading its checksum, and a
                # 32-byte value is exactly the size of both a P-256 scalar and a SHA-256.
                logger.debug("Identity shape: %s", der.describe(identity, depth=6))
                found = _identity_keys(identity)
                if not found:
                    # The member is present and the reader got nothing out of it, so what
                    # is unknown is the shape below it -- and one level deeper each round
                    # is how this has taken three. Describe it far enough to end.
                    logger.warning(
                        "An identity yielded no keys. Its shape is: %s",
                        der.describe(identity, depth=6),
                    )
                private.extend(found)

    if not symmetric and not private:
        # DEBUG, not WARNING, because whether this matters depends entirely on the level
        # and this function cannot see it. At the RECORD level it is the normal case: the
        # master key comes from steps 1-5 and `meta` only supplies extra keys, so a record
        # with none carries a meta holding just `[1]` -- every record on a real account
        # did, which made this fifteen identical warnings per run for nothing. At the ZONE
        # level it IS fatal, and `unwrap_zone` raises for it with a message that can say
        # so, because up there the keys are the whole point.
        #
        # Still logged: the shape is what settles "looking in the wrong place" against
        # "genuinely empty", and that took three rounds to establish once already.
        logger.debug(
            "A decrypted meta carries neither symmKeys nor identities. Its shape is: %s",
            der.describe(element, depth=4),
        )

    logger.debug(
        "meta holds %d symmetric key(s) and %d private key(s)",
        len(symmetric),
        len(private),
    )
    return MetaContents(symmetric_keys=symmetric, private_keys=private)


def _identity_keys(identity: der.DerElement, depth: int = 6) -> list[ec.EllipticCurvePrivateKey]:
    """
    Read the EC private keys out of one identity, wherever in it they sit.

    The keys are inside a `keyset` **OCTET STRING that is itself DER**, one level down --
    and the members around it are unnamed, so their positions are not something to rely
    on. This therefore walks the identity rather than indexing into it.

    **That is safe to do here for the reason a length-match search was not.** A candidate
    is accepted only if it parses as the private-key CHOICE *and* yields a scalar of a
    known length, so a wrong element does not produce a wrong key -- it produces no key.
    """
    from findmy.keychain.servicekey import (  # noqa: PLC0415 -- avoids an import cycle
        KeyBlobError,
        ServiceKeyError,
        service_keys_from_der,
    )

    if depth <= 0:
        return []

    keys: list[ec.EllipticCurvePrivateKey] = []

    for member in _members_of(identity):
        # **A SET is a container of keys, never a key.** Handing a whole SET to the key
        # reader is not merely wrong, it half-works: the reader returns a pair, so a set of
        # five keys yields two and the list looks complete. Both levels inside `meta` are
        # SET OF -- the identities and each keyset's keys -- so this is the shape that
        # silently produces a short answer, and it is the shape N1 already had once.
        if not member.is_universal(der.TAG_SET):
            try:
                keys.extend(service_keys_from_der(member.raw).for_pcs())
            except KeyBlobError:
                # Distinct from "this is not a key": the halves of something shaped exactly
                # like a key disagree. A search that swallows this is how a valid-but-wrong
                # key reached five levels downstream and reported as no key at all.
                logger.warning("A key blob's halves disagree", exc_info=True)
            except (ServiceKeyError, der.DerError):
                pass

        # A keyset carries its own checksum, and checking it here is what tells a
        # structure that *holds* keys from one that *is* a key -- the distinction this
        # walk got wrong by returning a 32-byte digest.
        #
        # DEBUG, and phrased as a doubt about the check rather than about the data,
        # because [observed] it does not match on any real keyset. Everything downstream
        # of these keys works -- the zone unwraps, records decrypt, a write reached an
        # Apple device -- so the keys are right and it is this digest's construction that
        # is not established. Warning per record that correct data looks wrong is worse
        # than not checking, and nothing here acts on the result.
        checked = verify_keyset_hash(member)
        if checked is False:
            logger.debug(
                "A keyset's checksum did not match the digest computed for it, which is"
                " expected until the construction is established. Its shape is: %s",
                der.describe(member, depth=3),
            )

        # **Descend even when the member already yielded a key.** A `ShareProtectionKeySet`
        # is `{ name, keys, set, hash }`, and reading it *as* a key succeeds -- its 32-byte
        # `hash` is exactly a scalar's length, and nothing about an unverifiable 32-byte
        # blob says it is a checksum rather than a secret. Stopping there returns the
        # digest and never looks inside `keys`, where the real 64-byte blob is.
        #
        # So this collects rather than settles. An extra key that is not a key costs one
        # failed comparison; a missed one costs everything below it.
        if member.constructed:
            keys.extend(_identity_keys(member, depth - 1))
            continue

        with contextlib.suppress(der.DerError):
            nested, _ = der.parse_one(member.as_bytes())

            # The keyset arrives here: an OCTET STRING whose contents are `APP 2` wrapping
            # the SEQUENCE. Checked at *this* level as well as at the SEQUENCE below,
            # because "the structure with hash omitted" reads either way and the two
            # differ by the application tag and its length. A digest match settles which.
            _report_keyset_framing(nested)

            keys.extend(_identity_keys(nested, depth - 1))

    return keys


def _report_keyset_framing(element: der.DerElement) -> None:
    """Log which framing of a keyset's checksum matched, if a keyset is what this is."""
    framing = keyset_hash_framing(element)
    if framing is None:
        return

    if framing:
        # The first real keyset to match. It settles the construction outright -- a wrong
        # framing cannot produce a 32-byte digest match -- so it is worth saying loudly
        # once rather than hiding at DEBUG with the failures.
        logger.info(
            "A keyset's checksum verifies, over the %s framing. This was open; it is not"
            " any more, and the framing named here is the answer.",
            framing,
        )
    else:
        logger.debug(
            "A keyset's checksum matched neither framing at %s. Its shape is: %s",
            der.describe(element, depth=1),
            der.describe(element, depth=4),
        )


# A keyset's checksum is a SHA-256 digest, and so is exactly the length of a P-256 scalar.
# That coincidence is why a reader can return the checksum where the key was meant.
_KEYSET_HASH_LENGTH = 32


def keyset_hash_framing(keyset: der.DerElement) -> str | None:  # noqa: PLR0911
    """
    Say which framing of a keyset's DER its checksum covers, if either does.

    `ShareProtectionKeySet` arrives **explicitly** application-tagged -- `APP 2` wrapping a
    `SEQUENCE` -- so "the structure with `hash` omitted" has two readings, and they differ
    by four bytes of tag and length:

    | Framing | What is hashed |
    | --- | --- |
    | `sequence` | the inner `SEQUENCE`, rebuilt without `hash` |
    | `wrapper` | that, re-wrapped in its `APP` tag |

    **Trying both is sound here, where trying key layouts was not.** The oracle is an exact
    32-byte digest match: a wrong framing cannot produce one without a preimage collision,
    so a match identifies the framing outright. A search is only untrustworthy when its
    oracle is "something plausible came out", which is what made the key-blob search
    worthless.

    :param keyset: Either the `SEQUENCE` or the application-tagged element wrapping it.
    :returns: The framing's name, `""` if neither matched, or None if there is no
        checksum here to check.
    """
    members = _members_of(keyset)
    if not members:
        return None

    # Handed the wrapper: the checksum lives in the SEQUENCE inside it, and the bytes
    # covered are the whole wrapper.
    if (
        keyset.tag_class == der.CLASS_APPLICATION
        and len(members) == 1
        and members[0].constructed
    ):
        inner = members[0]
        digest = _trailing_digest(inner)
        if digest is None:
            return None
        try:
            body = der.rebuild_without(inner, len(_members_of(inner)) - 1)
        except der.DerError:
            return None
        rewrapped = keyset.raw[:1] + der.encode_length(len(body)) + body
        return "wrapper" if hashlib.sha256(rewrapped).digest() == digest else ""

    digest = _trailing_digest(keyset)
    if digest is None:
        return None
    try:
        rebuilt = der.rebuild_without(keyset, len(members) - 1)
    except der.DerError:
        return None

    return "sequence" if hashlib.sha256(rebuilt).digest() == digest else ""


def _trailing_digest(element: der.DerElement) -> bytes | None:
    """Read the structure's `hash` member, which is its last. None if it carries none."""
    members = _members_of(element)
    if not members:
        return None

    last = members[-1]
    if not last.is_universal(der.TAG_OCTET_STRING) or len(last.as_bytes()) != _KEYSET_HASH_LENGTH:
        return None

    return last.as_bytes()


def verify_keyset_hash(keyset: der.DerElement) -> bool | None:
    """
    Check a nested keyset's own checksum.

    SHA-256 over the structure's DER **with `hash` itself removed** -- so the structure is
    re-encoded without that member and hashed, the same shape as §4 step 5's HMAC.

    Worth doing for a reason beyond correctness: this digest is the very thing that was
    being returned *as* a key, because it is thirty-two bytes and so is a P-256 scalar.
    Checking it names that mistake immediately, where otherwise it surfaces as a valid key
    that matches nothing, five levels away.

    .. warning::
        **[observed] This returned False on every real keyset, and the keys were fine.**
        The zone unwraps, records decrypt, and a field written under these keys reached an
        Apple device -- so what is unestablished is this digest's construction, not the
        data. Which framing it covers is now checked both ways; see
        :func:`keyset_hash_framing`.

        So **nothing acts on the result**, and a False is logged at DEBUG rather than
        warned about. Do not turn this into a check that rejects anything until a real
        keyset has been seen to pass it.

    :returns: Whether it matched, or None if the structure carries no checksum to check.
    """
    framing = keyset_hash_framing(keyset)
    if framing is None:
        return None

    return bool(framing)


def _members_of(element: der.DerElement) -> list[der.DerElement]:
    """List a constructed element's children, or nothing for a primitive one."""
    if not element.constructed:
        return []
    try:
        return element.children()
    except der.DerError:
        return []


def _find_our_key(
    protection: ShareProtection,
    private_keys: Sequence[ec.EllipticCurvePrivateKey],
) -> tuple[ShareKey, ec.EllipticCurvePrivateKey]:
    """Find the keyset entry whose public key is one we hold the private half of."""
    by_public: dict[bytes, ec.EllipticCurvePrivateKey] = {}
    for key in private_keys:
        for form in public_key_forms(key.public_key()):
            by_public[form] = key

    for share_key in protection.keys:
        private_key = by_public.get(share_key.public_key)
        if private_key is not None:
            return share_key, private_key

    # Naming the sizes distinguishes the two reasons this fails, which lead in opposite
    # directions: an entry the same size as one of our forms means the record really is
    # for someone else, while sizes that appear nowhere in ours means the encoding is
    # wrong and no key would ever have matched.
    theirs = sorted({len(k.public_key) for k in protection.keys})
    ours = sorted(
        {len(form) for key in private_keys for form in public_key_forms(key.public_key())},
    )

    # With the sizes agreeing, the only thing that moves this forward is *which* key the
    # record names -- a public key, so naming it costs nothing and identifies the holder.
    named = ", ".join(k.public_key[:8].hex() for k in protection.keys[:4])

    msg = (
        f"None of the {len(private_keys)} key(s) held locally appears among the"
        f" {len(protection.keys)} entries protecting this record. Their public keys are"
        f" {theirs} bytes; the forms compared against are {ours}."
        f" The record names: {named}"
    )
    raise MissingKeyError(msg)


# --------------------------------------------------------------------------------------
# Field decryption (§6)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldContext:
    """
    Which field a ciphertext belongs to.

    PCS binds every field to its position: the zone, the record and the field name are
    authenticated alongside the ciphertext, so the same bytes moved to another field, or
    another record, or another zone will not decrypt. That is deliberate, and it is why
    decrypting needs a field's identity and not merely its bytes.
    """

    zone_name: str
    record_name: str
    field_name: str

    def as_bytes(self) -> bytes:
        """Render the context the way it is authenticated: names joined by hyphens."""
        if not (self.zone_name or self.record_name or self.field_name):
            # A structure member has no zone, record or field name to bind to, so the AAD
            # is the header alone. §4 step 6's `meta` is the one place this applies -- the
            # exception to §6's rule rather than a contradiction of it.
            return b""
        return f"{self.zone_name}-{self.record_name}-{self.field_name}".encode("ascii")

    @classmethod
    def none(cls) -> FieldContext:
        """Build the empty context, for a structure member rather than a record field."""
        return cls(zone_name="", record_name="", field_name="")


@dataclass(frozen=True)
class EncryptedField:
    """An encrypted field value, split into its parts."""

    version: int
    key_id: bytes
    """The two ranges of key id, concatenated -- the length byte between them dropped."""
    header: bytes
    """The whole header. It is the first half of the authenticated data."""
    iv: bytes
    tag: bytes
    ciphertext: bytes


def parse_encrypted_field(data: bytes) -> EncryptedField:
    """
    Split an encrypted field value into header, IV, tag and ciphertext.

    The header is variable-length and carries the key id in two pieces, separated by the
    length byte of the second. The reconstructed id is those two ranges concatenated --
    the length byte itself is not part of it, though it *is* part of the authenticated
    data. A real header is six bytes: version 3, two key-id bytes, a length of 2, and two
    more key-id bytes.

    :raises PCSError: If the value is truncated or announces a version this module does
        not describe.
    """
    if len(data) < 4:
        msg = f"Encrypted field is {len(data)} bytes, too short to carry a header"
        raise PCSError(msg)

    version = data[0]
    if version != ENCRYPTION_VERSION:
        msg = (
            f"Encrypted field announces version {version}, and only version"
            f" {ENCRYPTION_VERSION} is described. Refusing rather than guessing."
        )
        raise PCSError(msg)

    second_length = data[3]
    header_length = 4 + second_length
    if len(data) < header_length + GCM_IV_LENGTH + GCM_TAG_LENGTH:
        msg = "Encrypted field is truncated: header, IV and tag do not fit"
        raise PCSError(msg)

    header = data[:header_length]
    key_id = data[1:3] + data[4:header_length]

    body = data[header_length:]
    return EncryptedField(
        version=version,
        key_id=key_id,
        header=header,
        iv=body[:GCM_IV_LENGTH],
        tag=body[GCM_IV_LENGTH : GCM_IV_LENGTH + GCM_TAG_LENGTH],
        ciphertext=body[GCM_IV_LENGTH + GCM_TAG_LENGTH :],
    )


def build_aad(header: bytes, context: FieldContext) -> bytes:
    """
    Build the authenticated data for one field.

    Two parts, concatenated with no separator: the entire header -- version byte and
    length byte included, not merely the key id -- and then the context string naming the
    zone, record and field.
    """
    return header + context.as_bytes()


def decrypt_field(
    data: bytes,
    unwrapped: UnwrappedProtection,
    context: FieldContext,
    *,
    check_key_id: bool = True,
) -> bytes:
    """
    Decrypt one field value.

    AES-128-GCM with a **12-byte** tag, authenticating the header and the field's context.

    :param data: The field's ciphertext, header and all.
    :param unwrapped: The record's master key, from :func:`unwrap_protection`.
    :param context: Which field this is. Not optional: it is authenticated, so a wrong or
        missing context fails exactly as a wrong key does.
    :param check_key_id: Whether to compare the header's key id against the derived key
        first. It is the cheapest chance to notice a wrong key.
    :raises PCSError: If the key is wrong, or the ciphertext does not authenticate.
    """
    parsed = parse_encrypted_field(data)

    if check_key_id and parsed.key_id:
        expected = compute_key_id(unwrapped.master_key)
        if expected[: len(parsed.key_id)] != parsed.key_id:
            msg = (
                "This field is encrypted under a different key than the one recovered"
                " from the record's protection structure."
            )
            raise PCSError(msg)

    key = derive_encryption_key(unwrapped.master_key)

    # min_tag_length is the whole point: the default rejects a 12-byte tag outright, and
    # the high-level AESGCM helper cannot express one at all.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(parsed.iv, parsed.tag, min_tag_length=GCM_TAG_LENGTH),
    ).decryptor()
    decryptor.authenticate_additional_data(build_aad(parsed.header, context))

    try:
        return decryptor.update(parsed.ciphertext) + decryptor.finalize()
    except InvalidTag:
        msg = (
            f"Field {context.field_name!r} of record {context.record_name!r} failed to"
            " authenticate. Two things cause this and neither says so: a tag length other"
            " than 12 bytes, and authenticated data that is not the header followed by"
            f" {context.as_bytes()!r}."
        )
        raise PCSError(msg) from None


def encrypt_field(
    plaintext: bytes,
    unwrapped: UnwrappedProtection,
    context: FieldContext,
    *,
    key_id_split: tuple[int, int] = (2, 2),
    iv: bytes | None = None,
) -> bytes:
    """
    Encrypt a field the way :func:`decrypt_field` expects to find it.

    The same key that reads a field writes one, so nothing further has to be recovered to
    change a value -- which is what makes renaming an accessory possible at all, and also
    what makes it easy to write something Apple's own devices cannot read.

    .. note::
        **The tag precedes the ciphertext**, and almost every AEAD interface in every
        language returns it appended. Written the natural way this produces a value that
        fails authentication -- and :func:`decrypt_field`, written to the same layout,
        round-trips it happily, so a round trip through this library proves nothing about
        the layout at all.

        **[observed] The layout is right.** A name written by this function displayed
        correctly in Apple's own Find My on a Mac, which is the only check that could
        establish it. Before that, this docstring said not to believe a round trip.

    :param plaintext: What to encrypt. For everything but a bytes field this is the
        wrapper message, not the bare value -- see
        :func:`findmy.cloudkit.beacons.build_plaintext`.
    :param unwrapped: The master key to encrypt under.
    :param context: Which field this is, authenticated alongside the header. A wrong one
        writes a value that will never decrypt where it was put.
    :param key_id_split: How many key-id bytes go before and after the length byte.
    :param iv: The nonce, generated fresh if not supplied. **Twelve bytes, and never
        reused under one key** -- GCM under a repeated nonce leaks the plaintexts, and a
        record with several encrypted fields is exactly where one gets reused by accident.
        Pass one only to reproduce a known value in a test.
    """
    if iv is None:
        iv = secrets.token_bytes(GCM_IV_LENGTH)

    if len(iv) != GCM_IV_LENGTH:
        msg = f"IV must be {GCM_IV_LENGTH} bytes"
        raise PCSError(msg)

    first_len, second_len = key_id_split
    if first_len != 2:
        msg = "The first key-id part is fixed at 2 bytes by the field format"
        raise PCSError(msg)

    key_id = compute_key_id(unwrapped.master_key)
    header = (
        bytes([ENCRYPTION_VERSION])
        + key_id[:first_len]
        + bytes([second_len])
        + key_id[first_len : first_len + second_len]
    )

    key = derive_encryption_key(unwrapped.master_key)

    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    encryptor.authenticate_additional_data(build_aad(header, context))
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # A truncated GCM tag is the leading bytes of the full one.
    return header + iv + encryptor.tag[:GCM_TAG_LENGTH] + ciphertext
