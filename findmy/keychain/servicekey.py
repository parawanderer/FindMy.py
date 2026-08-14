"""
The PCS service key, as a keychain item carries it.

Implements the last part of Stage 3 §6.8.1 and the key side of
[Stage 5 §3.2](../cloudkit/pcs.py): reading an item's `v_Data` into the elliptic-curve
private keys that unwrap a record's protection structure.

**This is where the two halves finally meet.** Everything before it is symmetric -- view
keys, item keys, AES-SIV -- and everything after it is elliptic-curve. `v_Data` is the
boundary, and it holds a DER structure rather than a key.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from google.protobuf.message import DecodeError

from findmy.cloudkit import der
from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.cloudkit.records import describe_wire, iter_wire_fields
from findmy.errors import UnhandledProtocolError

logger = logging.getLogger(__name__)

# `PrivateKey ::= CHOICE { v1 SEQUENCE {...}, v2 [APPLICATION 5] EXPLICIT SEQUENCE {...} }`.
# Find My's service key is the v2 form.
PRIVATE_KEY_V2_TAG = 5

# The Find My service's PCS type, for checking an item is the one expected.
FIND_MY_PCS_SERVICE = 82

# A private scalar's length says which curve it belongs to. PCS is P-256 throughout, but
# reading the length rather than assuming it means a P-384 key is recognised rather than
# rejected as malformed.
_CURVES_BY_SCALAR_LENGTH = {
    32: ec.SECP256R1,
    48: ec.SECP384R1,
    66: ec.SECP521R1,
}


class ServiceKeyError(UnhandledProtocolError):
    """Raised when an item's key material cannot be read."""


@dataclass(frozen=True)
class ServiceKeys:
    """
    The keys a v2 PCS private key structure carries.

    Two of them, and they are not interchangeable: the encryption key is what unwraps a
    record's protection structure, and the signing key is what a caller-supplied signing
    key would otherwise be.
    """

    encryption_key: ec.EllipticCurvePrivateKey
    signing_key: ec.EllipticCurvePrivateKey | None = None

    def for_pcs(self) -> list[ec.EllipticCurvePrivateKey]:
        """
        List the keys to hand Stage 5, in the order it should try them.

        The encryption key first, because that is the one a protection structure's keyset
        is expected to name. The signing key is included because it costs nothing to try
        and because §3.2's structure carries both without saying which a given record's
        keyset matches -- a wrong one simply fails to match rather than mis-decrypting.
        """
        keys = [self.encryption_key]
        if self.signing_key is not None:
            keys.append(self.signing_key)
        return keys


def private_key_from_scalar(scalar: bytes) -> ec.EllipticCurvePrivateKey:
    """
    Build an EC private key from its raw scalar.

    :raises ServiceKeyError: If the length matches no curve this understands.
    """
    curve = _CURVES_BY_SCALAR_LENGTH.get(len(scalar))
    if curve is None:
        msg = (
            f"A {len(scalar)}-byte private scalar matches no curve this understands"
            f" ({', '.join(str(n) for n in sorted(_CURVES_BY_SCALAR_LENGTH))} expected)"
        )
        raise ServiceKeyError(msg)

    try:
        return ec.derive_private_key(int.from_bytes(scalar, "big"), curve())
    except ValueError as e:
        msg = f"A {len(scalar)}-byte scalar is not a valid private key for {curve.name}: {e}"
        raise ServiceKeyError(msg) from None


def scalar_in(blob: bytes) -> bytes | None:
    """
    Read a private scalar out of a key blob, whatever it is carried alongside.

    A "compressed private key" is not always a bare scalar. §6.7.0's peer keys are a
    public point followed by their scalar, and the same layout appears here -- so a blob
    is taken as a scalar if its length says so, and otherwise its **trailing** scalar-sized
    run is tried against whatever precedes it.

    That check is self-verifying and free: deriving the public key from the candidate
    scalar must reproduce the leading bytes exactly, in one of the two point encodings. So
    a wrong reading is not merely unlikely, it is impossible rather than plausible -- which
    is what makes trying this better than guessing at a layout.

    :returns: The scalar, or None if the blob holds none.
    """
    if len(blob) in _CURVES_BY_SCALAR_LENGTH:
        return blob

    for length, curve in _CURVES_BY_SCALAR_LENGTH.items():
        if len(blob) <= length:
            continue

        scalar, prefix = blob[-length:], blob[:-length]
        try:
            key = ec.derive_private_key(int.from_bytes(scalar, "big"), curve())
        except ValueError:
            continue

        public = key.public_key()
        encodings = (
            public.public_bytes(Encoding.X962, PublicFormat.CompressedPoint),
            public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
        )
        if prefix in encodings:
            logger.debug(
                "A %d-byte key blob is a point followed by its %d-byte scalar",
                len(blob),
                length,
            )
            return scalar

    return None


def _scalars_in(payload: bytes) -> list[bytes]:
    """
    Pull the private scalars out of the v2 payload, in the order they appear.

    The payload is a protobuf carrying an encryption key and a signing key, each with its
    key bytes and an optional DER public structure -- but **the field numbers are not
    specified**. So rather than trusting a guess, this walks the wire in order and takes
    the first length-delimited member of each submessage that yields a scalar.

    Order is the discriminator, as the specification gives it: encryption key first.
    """
    scalars: list[bytes] = []

    for _, wire, member in iter_wire_fields(payload):
        if wire != 2 or not member:
            continue

        # A member may be the key blob itself, or a message wrapping one.
        found = scalar_in(member)
        if found is not None:
            scalars.append(found)
            continue

        for _, inner_wire, inner in iter_wire_fields(member):
            if inner_wire != 2 or not inner:
                continue
            found = scalar_in(inner)
            if found is not None:
                scalars.append(found)
                break

    return scalars


def service_keys_from_der(payload: bytes) -> ServiceKeys:
    """
    Read an item's `v_Data` into its keys.

    The structure is a CHOICE and Find My's service uses the **v2** form:
    `[APPLICATION 5] EXPLICIT SEQUENCE { data OCTET STRING }`, where that octet string is a
    protobuf carrying the two keys. The application tag is **explicit**, so the sequence is
    one level deeper than an implicit reading places it.

    The v1 form -- `SEQUENCE { key OCTET STRING, public PublicKey OPTIONAL }` -- is also
    read, since the structure is a CHOICE and refusing the other branch would fail on a
    service that used it rather than saying so.

    :raises ServiceKeyError: If the payload is neither form, or carries no usable key.
    """
    try:
        element, _ = der.parse_one(payload)
    except der.DerError as e:
        msg = f"An item's v_Data is not DER at all: {e}"
        raise ServiceKeyError(msg) from None

    if element.tag_class == der.CLASS_APPLICATION and element.tag_number == PRIVATE_KEY_V2_TAG:
        return _from_v2(element)

    return _from_v1(element)


DER_SEQUENCE = 0x10
DER_OCTET_STRING = 0x04


def _v2_payload(element: der.DerElement) -> bytes:
    """
    Find the octet string inside a v2 structure, whichever way its tag is written.

    **`[APPLICATION 5]` is written without `EXPLICIT`**, alone among this protocol's
    application tags, and that is deliberate rather than a typo -- **[observed]** on a real
    account the tag *replaces* the SEQUENCE's own tag, so the octet string sits directly
    inside it rather than one level further in.

    Both nestings are read, because the difference is invisible until it fails and the
    failure is "cannot read children of a primitive element", which names neither the
    structure nor the ambiguity.
    """
    children = element.children()
    if not children:
        msg = "A v2 private key structure carries no data element"
        raise ServiceKeyError(msg)

    # The explicit reading: the wrapper holds a SEQUENCE that holds the octet string.
    if len(children) == 1 and children[0].constructed and children[0].is_universal(DER_SEQUENCE):
        children = children[0].children()

    payload = next(
        (child for child in children if child.is_universal(DER_OCTET_STRING)),
        None,
    )
    if payload is None:
        shapes = ", ".join(f"tag {c.tag_number}" for c in children)
        msg = (
            f"A v2 private key structure holds no octet string. It holds: {shapes or 'nothing'}"
        )
        raise ServiceKeyError(msg)

    return payload.as_bytes()


def _from_v2(element: der.DerElement) -> ServiceKeys:
    """Read the `[APPLICATION 5]` form, whose octet string holds a protobuf."""
    payload = _v2_payload(element)

    # Try the declared shape first; fall back to reading the wire positionally, because the
    # field numbers below are assumed rather than specified.
    keys = cf.PcsServiceKeys()
    try:
        keys.ParseFromString(payload)
    except DecodeError:
        keys = cf.PcsServiceKeys()

    declared = [scalar_in(blob) for blob in (keys.encryption_key.key, keys.signing_key.key)]
    scalars = [s for s in declared if s is not None]

    if not scalars:
        scalars = _scalars_in(payload)
        if scalars:
            logger.debug(
                "The v2 payload's key field numbers differ from the assumed ones; read"
                " %d scalar(s) positionally instead",
                len(scalars),
            )

    if not scalars:
        msg = (
            f"A v2 private key structure's {len(payload)}-byte payload carries no usable"
            " private key. A key blob is taken as a scalar by its length, or as a point"
            " followed by its scalar when the two check each other, and neither was found."
            f" Its wire structure is: {describe_wire(payload)}"
        )
        raise ServiceKeyError(msg)

    encryption = private_key_from_scalar(scalars[0])
    signing = private_key_from_scalar(scalars[1]) if len(scalars) > 1 else None

    return ServiceKeys(encryption_key=encryption, signing_key=signing)


def _from_v1(element: der.DerElement) -> ServiceKeys:
    """Read the v1 form: a sequence whose first member is the key octets."""
    children = element.children()
    if not children:
        msg = (
            "An item's v_Data is neither a v2 [APPLICATION 5] structure nor a sequence"
            f" holding a key (class {element.tag_class:#04x}, tag {element.tag_number})"
        )
        raise ServiceKeyError(msg)

    return ServiceKeys(encryption_key=private_key_from_scalar(children[0].as_bytes()))
