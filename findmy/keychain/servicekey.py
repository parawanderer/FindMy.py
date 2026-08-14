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

# A private scalar's length says which curve it belongs to.
#
# **P-521 is deliberately absent.** Nothing in this protocol uses it -- PCS is P-256
# throughout (Stage 5 §5) and peer keys are P-384 (§6.7.0) -- and including it made a
# 66-byte member of the payload match by length alone and be taken as a key it is not.
# A speculative entry here is not free: length matching has nothing to check it against,
# so every extra length is a way to be confidently wrong.
_CURVES_BY_SCALAR_LENGTH = {
    32: ec.SECP256R1,
    48: ec.SECP384R1,
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


@dataclass(frozen=True)
class ScalarCandidate:
    """A possible private scalar, and whether anything actually confirmed it."""

    scalar: bytes

    verified: bool
    """
    Whether the blob carried a public point that this scalar reproduces.

    The distinction matters more than it looks. A **verified** candidate cannot be wrong:
    deriving its public key reproduced the leading bytes exactly. An unverified one matched
    on **length alone**, which is a guess with nothing checking it -- and taking one of
    those in preference to a verified one is how a 66-byte member became a P-521 key.
    """


def scalar_in(blob: bytes) -> ScalarCandidate | None:
    """
    Read a private scalar out of a key blob, whatever it is carried alongside.

    A "compressed private key" is not always a bare scalar. §6.7.0's peer keys are a
    public point followed by their scalar, and the same layout appears here -- so a blob
    is tried as a point followed by its **trailing** scalar-sized run, and taken as a bare
    scalar only if nothing else fits.

    The compound reading is self-verifying and free: deriving the public key from the
    candidate must reproduce the leading bytes exactly, in one of the two point encodings.
    That reading cannot be wrong. The bare-length reading can, so it is reported as
    unverified rather than treated as equivalent.

    :returns: The candidate, or None if the blob holds no plausible scalar.
    """
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
            return ScalarCandidate(scalar=scalar, verified=True)

    if len(blob) in _CURVES_BY_SCALAR_LENGTH:
        return ScalarCandidate(scalar=blob, verified=False)

    return None


def _candidates_in(payload: bytes) -> list[ScalarCandidate]:
    """
    Collect every plausible private scalar in the v2 payload, in wire order.

    The payload is a protobuf carrying an encryption key and a signing key, each with its
    key bytes and an optional DER public structure -- but **the field numbers are not
    specified**, so this walks the wire rather than trusting a guess.

    Everything plausible is collected rather than the first match taken, because a member
    that merely has a scalar's length may not be a key at all, and the reader cannot tell
    until it has seen what else is on offer.
    """
    found: list[ScalarCandidate] = []

    def consider(blob: bytes) -> bool:
        candidate = scalar_in(blob)
        if candidate is None:
            return False
        found.append(candidate)
        return True

    for _, wire, member in iter_wire_fields(payload):
        if wire != 2 or not member:
            continue

        # A member may be the key blob itself, or a message wrapping one.
        if consider(member):
            continue

        for _, inner_wire, inner in iter_wire_fields(member):
            if inner_wire == 2 and inner and consider(inner):
                break

    return found


def _keys_from_candidates(
    candidates: list[ScalarCandidate],
) -> list[ec.EllipticCurvePrivateKey]:
    """
    Turn candidates into keys, confirmed ones first.

    Order matters: the specification gives the encryption key first, so wire order is
    preserved *within* each group rather than discarded. But a verified candidate outranks
    an unverified one whatever their order, because one of them cannot be wrong and the
    other is a length coincidence away from being exactly that.

    A candidate that will not derive is skipped rather than raised on -- with several on
    offer, one bad one is not a reason to fail.
    """
    ranked = [c for c in candidates if c.verified]
    ranked += [c for c in candidates if not c.verified]

    keys = [_derived(candidate) for candidate in ranked]
    return [key for key in keys if key is not None]


def _derived(candidate: ScalarCandidate) -> ec.EllipticCurvePrivateKey | None:
    """Derive a key from a candidate, or None if it will not derive."""
    try:
        return private_key_from_scalar(candidate.scalar)
    except ServiceKeyError as e:
        logger.debug("Skipping a %d-byte candidate: %s", len(candidate.scalar), e)
        return None


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
    candidates = [c for c in declared if c is not None]

    # Fall back to the wire when the assumed field numbers find nothing, and also when
    # what they found is unverified -- a length match is a guess, and the wire may hold a
    # blob that proves itself. Preferring an unchecked match over a checked one because it
    # came from the expected field is exactly the mistake this ranking exists to prevent.
    if not any(c.verified for c in candidates):
        positional = _candidates_in(payload)
        if positional:
            logger.debug(
                "Read %d scalar candidate(s) positionally from the v2 payload (%d verified)",
                len(positional),
                sum(c.verified for c in positional),
            )
            candidates = positional or candidates

    usable = _keys_from_candidates(candidates)

    if not usable:
        msg = (
            f"A v2 private key structure's {len(payload)}-byte payload carries no usable"
            " private key. A key blob is taken as a point followed by its scalar when the"
            " two check each other, or as a bare scalar by its length, and neither held."
            f" Its wire structure is: {describe_wire(payload)}"
        )
        raise ServiceKeyError(msg)

    return ServiceKeys(
        encryption_key=usable[0],
        signing_key=usable[1] if len(usable) > 1 else None,
    )


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
