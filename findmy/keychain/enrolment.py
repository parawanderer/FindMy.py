"""
Enrolling an escrow record, so that an identity can be recovered later.

Implements Stage 3 §4.5 of the Find My key-export protocol specification: the two-request
exchange that makes a new peer's material recoverable with a passcode.

**This is the write that makes a join survivable.** A bottle sent in `joinWithVoucher`
whose entropy was never enrolled produces a peer that is in the trust circle and can never
be recovered from -- permanent, invisible in every Apple interface, and exactly the residue
the specification's rules exist to prevent. Enrol before joining, not after.

Nothing here sends anything by itself except :func:`enrol_record`, which is the one
function in this module that writes. Everything else builds bytes and can be exercised
offline, which is deliberate: the blob is the part that is easy to get wrong and impossible
to inspect once sent.

.. warning::
    **The certificate the blob is encrypted to is fetched from the service that will store
    it.** Accepting it unverified hands the user's escrowed material to whoever supplied
    the certificate, so :func:`verify_club_certificate` runs *before* anything is encrypted
    to that key, and a chain that does not verify is a refusal rather than a warning. There
    is deliberately no fall-back to the system trust store: that store holds Apple's public
    roots, and these are not those.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import plistlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import srp._pysrp as srp
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing_extensions import override

from findmy.errors import UnhandledProtocolError

from .escrow import (
    ESCROW_LABEL_ICDP,
    KeyVaultSection,
    build_keyvault_message,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from .escrow import AsyncEscrowProxy

logger = logging.getLogger(__name__)


class EnrolmentError(UnhandledProtocolError):
    """Raised when a record cannot be enrolled, or should not be."""


# --------------------------------------------------------------------------------------
# The three digests, which are three because none of them is derivable from the others
# --------------------------------------------------------------------------------------

# The blob is *announced* with SHA-1: `blobDigest` is the SHA-1 of the bytes sent as
# `blob`. Not SHA-256. This is a wire format Apple's service checks, not a security choice
# this library gets to make, and "modernising" it to SHA-256 produces a request the service
# rejects.
_BLOB_DIGEST = "sha1"

# RSA-OAEP to the club certificate uses SHA-1 as **both** the OAEP digest and the MGF1
# digest. `cryptography` takes those as two separate arguments, and passing SHA-256 for
# either -- which looks like an obvious cleanup, since SHA-1 is obsolete everywhere else --
# produces a blob Apple cannot decrypt, with nothing local to catch it. The failure would
# surface as an unrecoverable escrow record, discovered whenever the user next needed it.
_OAEP_DIGEST = hashes.SHA1

# The two integrity hashes *inside* the blob are SHA-256: the digest of the certificate's
# public key and the digest of the inner message. Named separately from the two SHA-1 uses
# above so that one shared binding cannot quietly cover all three.
_INTEGRITY_DIGEST = "sha256"


# --------------------------------------------------------------------------------------
# Pinned roots
# --------------------------------------------------------------------------------------

PINNED_ROOT_FINGERPRINTS: Mapping[int, bytes] = {
    101: bytes.fromhex("5644C142208DD4BF7AD770902F70D6730B8571164FD874D9AE5168807B32F766"),
    102: bytes.fromhex("D4EAA88170B8AEE18FCEFF68698310D4C2AB4CEB48179D99206A53AC73E8A4EB"),
    103: bytes.fromhex("FDBA6F3365D617B9EB799D2F48851B1A85C62CF366C36797E539B3C4C2C3BDC6"),
    500: bytes.fromhex("654BFB656D80A715559034C7FE08E637B335E770C84EC05CD90475E8BBC59EB0"),
}
"""
SHA-256 of each escrow root certificate, by version.

**The fingerprints are the useful half of a pinning set.** The certificates themselves are
not carried here -- they have to be obtained from Apple -- and a root obtained by any route
is only trustworthy once it matches one of these. A set assembled without checking is
pinned to whatever arrived.

The version is the certificate's **serial number**, which is why :func:`load_pinned_roots`
can cross-check the two: a certificate whose fingerprint says 103 and whose serial says 102
is two independent statements of identity disagreeing, and that is a refusal.

Note that 500 expires in 2032 while the three older roots run to 2049.
"""


@dataclass(frozen=True)
class PinnedRoots:
    """
    The escrow roots a client will accept, each checked against its fingerprint.

    Build one with :meth:`load`. Constructing it directly from certificates that were not
    fingerprint-checked defeats the point of the type existing.
    """

    by_version: Mapping[int, x509.Certificate] = field(default_factory=dict)

    @classmethod
    def load(cls, certificates: Iterable[bytes]) -> PinnedRoots:
        """
        Check certificates against :data:`PINNED_ROOT_FINGERPRINTS` and keep the matches.

        Each is accepted only if its SHA-256 matches a known version, its serial number
        agrees with that version, and it is self-signed -- the three things a root
        certificate asserts about itself, all checkable offline.

        :param certificates: DER or PEM encodings, in any order.
        :raises EnrolmentError: If any certificate is not one of the pinned roots. This is
            deliberately not a skip: a caller that supplied an unrecognised root meant it
            to be trusted, and silently dropping it would leave a pinning set narrower than
            the caller believes.
        """
        found: dict[int, x509.Certificate] = {}

        for encoded in certificates:
            certificate = _load_certificate(encoded)
            digest = certificate.fingerprint(hashes.SHA256())

            version = next(
                (v for v, f in PINNED_ROOT_FINGERPRINTS.items() if f == digest),
                None,
            )
            if version is None:
                msg = (
                    f"A supplied root has SHA-256 {digest.hex()}, which is not one of the"
                    " pinned escrow roots. Pinning to a certificate that was not checked"
                    " against a fingerprint is pinning to whatever arrived."
                )
                raise EnrolmentError(msg)

            if certificate.serial_number != version:
                msg = (
                    f"A root fingerprinted as version {version} carries serial number"
                    f" {certificate.serial_number}. The version *is* the serial number, so"
                    " these are two statements of identity disagreeing."
                )
                raise EnrolmentError(msg)

            if certificate.subject != certificate.issuer:
                msg = f"Escrow root {version} is not self-signed, so it is not a root"
                raise EnrolmentError(msg)
            _verify_signed_by(certificate, certificate, description=f"escrow root {version}")

            found[version] = certificate

        missing = sorted(set(PINNED_ROOT_FINGERPRINTS) - set(found))
        if missing:
            # Not an error: a client may legitimately carry fewer. But a club certificate
            # issued by one of the absent roots will be refused, and "the certificate did
            # not verify" is a confusing way to learn that the root was never loaded.
            logger.info(
                "Escrow root(s) %s were not supplied. A club certificate issued by one of"
                " them will be refused rather than verified against the system store.",
                ", ".join(str(version) for version in missing),
            )

        return cls(by_version=found)

    def __bool__(self) -> bool:
        """Whether any root was loaded at all."""
        return bool(self.by_version)

    def issuers_of(self, certificate: x509.Certificate) -> list[x509.Certificate]:
        """Every pinned root whose subject matches this certificate's issuer."""
        return [
            root for root in self.by_version.values() if root.subject == certificate.issuer
        ]


def _load_certificate(encoded: bytes) -> x509.Certificate:
    """Parse a certificate in either encoding, since a caller's source decides which."""
    try:
        if encoded.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(encoded)
        return x509.load_der_x509_certificate(encoded)
    except ValueError as e:
        msg = f"Could not parse a certificate: {e}"
        raise EnrolmentError(msg) from None


def _verify_signed_by(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    *,
    description: str,
) -> None:
    """Check one certificate's signature under another's public key."""
    public_key = issuer.public_key()
    algorithm = certificate.signature_hash_algorithm
    if algorithm is None:
        # Ed25519 and Ed448 have no separate hash. Neither is used here, and guessing at
        # one would be worse than saying the certificate is not one this can check.
        msg = f"{description} is signed with an algorithm that carries no digest"
        raise EnrolmentError(msg)
    parameters = certificate.signature_algorithm_parameters
    signature, signed = certificate.signature, certificate.tbs_certificate_bytes

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if not isinstance(parameters, (asym_padding.PKCS1v15, asym_padding.PSS)):
                msg = f"{description} is RSA-signed with unrecognised padding"
                raise EnrolmentError(msg)
            public_key.verify(signature, signed, parameters, algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if not isinstance(parameters, ec.ECDSA):
                msg = f"{description} is EC-signed with unrecognised parameters"
                raise EnrolmentError(msg)
            public_key.verify(signature, signed, parameters)
        else:
            msg = f"{description} is signed with an unsupported key type"
            raise EnrolmentError(msg)
    except InvalidSignature:
        msg = f"The signature on {description} does not verify"
        raise EnrolmentError(msg) from None
    except (UnsupportedAlgorithm, TypeError) as e:
        msg = f"The signature on {description} could not be checked: {e}"
        raise EnrolmentError(msg) from None


def verify_club_certificate(
    encoded: bytes,
    roots: PinnedRoots,
    *,
    now: datetime | None = None,
) -> x509.Certificate:
    """
    Verify the club certificate against the pinned roots, before anything is encrypted.

    **A failure here is a refusal, not a warning.** The certificate is the key the user's
    escrow blob is encrypted to; accepting an unverified one hands the material to whoever
    supplied it. Nothing falls back to the system trust store, because that store holds
    Apple's *public* roots and these are not those -- a fall-back would turn pinning into
    ordinary web PKI without saying so.

    :param encoded: The certificate, DER or PEM, from `get_club_cert`.
    :param roots: The pinned roots, from :meth:`PinnedRoots.load`.
    :param now: The moment to judge validity at. Defaults to now, and exists so that a
        test does not expire.
    :raises EnrolmentError: If it does not verify, is expired, or was issued by something
        that is not a pinned root.
    """
    if not roots:
        msg = (
            "No pinned escrow roots were supplied, so the club certificate cannot be"
            " verified. Enrolment is refused rather than encrypting the user's escrowed"
            " material to an unverified key."
        )
        raise EnrolmentError(msg)

    certificate = _load_certificate(encoded)
    moment = now or datetime.now(timezone.utc)

    candidates = roots.issuers_of(certificate)
    if not candidates:
        msg = (
            f"The club certificate names {certificate.issuer.rfc4514_string()} as its"
            " issuer, which is not among the pinned escrow roots. Refusing, rather than"
            " falling back to the system trust store."
        )
        raise EnrolmentError(msg)

    failures: list[str] = []
    for root in candidates:
        version = next(v for v, c in roots.by_version.items() if c == root)
        try:
            _verify_signed_by(certificate, root, description="the club certificate")
        except EnrolmentError as e:
            failures.append(f"root {version}: {e}")
            continue

        _require_current(root, moment, f"escrow root {version}")
        _require_current(certificate, moment, "the club certificate")

        logger.info("The club certificate verifies against pinned escrow root %d", version)
        return certificate

    msg = "The club certificate did not verify against any pinned root: " + "; ".join(failures)
    raise EnrolmentError(msg)


def _require_current(certificate: x509.Certificate, moment: datetime, description: str) -> None:
    """Insist a certificate is inside its validity window."""
    if moment < certificate.not_valid_before_utc:
        msg = f"{description} is not valid until {certificate.not_valid_before_utc:%Y-%m-%d}"
        raise EnrolmentError(msg)
    if moment > certificate.not_valid_after_utc:
        msg = (
            f"{description} expired on {certificate.not_valid_after_utc:%Y-%m-%d}. Note"
            " that escrow root 500 expires in 2032 while the older three run to 2049, so"
            " an expiry is more likely to be a root that needs replacing than a fault."
        )
        raise EnrolmentError(msg)


# --------------------------------------------------------------------------------------
# The blob
# --------------------------------------------------------------------------------------

# §4.5.1's inner header: four 32-bit values, of which the third is the PBKDF2 iteration
# count §6.5 reads back out of it. The other three are unexplained constants.
INNER_HEADER = (160, 0, 10000, 10)
PBKDF2_ITERATIONS = INNER_HEADER[2]
PBKDF2_KEY_LENGTH = 16

# §4.5.1's outer header: five 32-bit values, all unexplained. Not to be confused with the
# outer blob of §6.4, which travels in the other direction and is framed differently.
OUTER_HEADER = (161, 1, 0, 0, 10)

SALT_LENGTH = 64
"""The inner salt, which is both the PBKDF2 salt and, in its first 16 bytes, the CBC IV."""

AES_IV_LENGTH = 16
AES_BLOCK_BITS = 128
OUTER_KEY_LENGTH = 32

# §4.5.1's fixed section footprints. A footprint is the *whole* section including its
# four-byte length prefix, and the padding is appended after the data -- see
# `KeyVaultSection`, where getting this wrong produces a message that parses and is wrong.
DSID_FOOTPRINT = 16
LABEL_FOOTPRINT = 80
TIMESTAMP_FOOTPRINT = 24

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
"""
A space rather than a `T`, and no zone.

The same string goes in three places -- the blob's sixth section, the metadata's
`timestamp`, and its `SecureBackupMetadataTimestamp` -- which is why it is computed once
and passed around rather than formatted at each site.
"""

SRP_MODULUS_BYTES = 256
"""
The width the SRP verifier is padded to.

**[unverified]** §4.5.1 does not say how the verifier is encoded, and the natural
big-endian encoding of an integer is one byte shorter about one time in 256. Apple's own
values are padded to the group size -- the server's `B` arrives as exactly 256 bytes -- so
that is what is done here. The consequence of guessing wrong is not a failure now: it is a
record that enrols fine and fails to recover later, for one user in 256, in a way
indistinguishable from a wrong passcode.
"""

ENTROPY_FIELD = "BottledPeerEntropy"
"""The field a recovered record must carry for anything downstream to be able to use it."""


def escrow_timestamp(when: datetime | None = None) -> str:
    """
    Format the one timestamp an enrolment uses, in all three of the places it appears.

    :param when: Defaults to now, in UTC.
    """
    moment = when or datetime.now(timezone.utc)
    return moment.strftime(TIMESTAMP_FORMAT)


def srp_verifier(identity: str, password: str, salt: bytes) -> bytes:
    """
    Compute the SRP verifier the escrow service will later authenticate a recovery against.

    Standard SRP-6a with SHA-256 and the 2048-bit group: `x = H(salt ‖ H(identity ‖ ":" ‖
    password))` and `v = g^x mod N`. The identity is the **dsid**, as §6.3 uses when
    proving against this verifier.

    The derivation is written out rather than taken from the SRP library because the
    library carries "is the identity in the private-key hash" as a **process-global** which
    :mod:`findmy.reports.account` sets the other way at import time. A verifier computed
    under the wrong setting is accepted by the service and then fails every future
    recovery, so this does not depend on which way that flag happens to be pointing.

    :param identity: The dsid, as a string.
    :param password: The passcode this record will be recoverable with. Not retained.
    :param salt: The 64-byte salt, which is also the PBKDF2 salt of the encrypted record.
    """
    inner = hashlib.sha256(identity.encode() + b":" + password.encode()).digest()
    x = int.from_bytes(hashlib.sha256(salt + inner).digest(), "big")
    modulus, generator = srp.get_ng(srp.NG_2048, None, None)

    return pow(generator, x, modulus).to_bytes(SRP_MODULUS_BYTES, "big")


def build_inner_message(  # noqa: PLR0913 -- the six inputs the inner message frames
    *,
    dsid: str,
    label: str,
    timestamp: str,
    password: str,
    record: bytes,
    salt: bytes | None = None,
) -> bytes:
    """
    Build §4.5.1's inner message: the record itself, sealed under the passcode.

    Six sections, and two of them are derived from the **same** password and the **same**
    salt by two different constructions -- the SRP verifier, which makes a future recovery
    authenticate, and the encrypted record, which is what that recovery then decrypts.
    Reusing one derivation for the other yields a record that enrols and never opens.

    :param dsid: The numeric account id, which is also the SRP identity.
    :param label: This record's full label, from :func:`record_label`.
    :param timestamp: From :func:`escrow_timestamp`. The same value the metadata carries.
    :param password: The passcode the record will be recoverable with. Not retained.
    :param record: The material to escrow. §4.5 does not say what it must contain;
        **[observed]** what recovery expects is a property list carrying
        :data:`ENTROPY_FIELD`, and a record without it recovers successfully and yields
        nothing usable -- so this warns rather than accepting silently.
    :param salt: The 64-byte salt. Generated if not supplied; a parameter so that a test
        can produce the same bytes twice.
    """
    if not password:
        msg = "A record enrolled under an empty passcode could be recovered by anyone"
        raise EnrolmentError(msg)

    _warn_if_record_is_unusable(record)

    salt = salt if salt is not None else secrets.token_bytes(SALT_LENGTH)
    if len(salt) != SALT_LENGTH:
        msg = f"The escrow salt is {SALT_LENGTH} bytes, not {len(salt)}"
        raise EnrolmentError(msg)

    derived = hashlib.pbkdf2_hmac(
        _INTEGRITY_DIGEST,
        password.encode(),
        salt,
        PBKDF2_ITERATIONS,
        PBKDF2_KEY_LENGTH,
    )
    padder = padding.PKCS7(AES_BLOCK_BITS).padder()
    encryptor = Cipher(
        algorithms.AES(derived),
        modes.CBC(salt[:AES_IV_LENGTH]),
    ).encryptor()
    encrypted = encryptor.update(padder.update(record) + padder.finalize()) + encryptor.finalize()

    header = b"".join(value.to_bytes(4, "big") for value in INNER_HEADER)

    return build_keyvault_message(
        header,
        [
            KeyVaultSection(dsid.encode("ascii"), footprint=DSID_FOOTPRINT),
            salt,
            srp_verifier(dsid, password, salt),
            encrypted,
            KeyVaultSection(label.encode("ascii"), footprint=LABEL_FOOTPRINT),
            KeyVaultSection(timestamp.encode("ascii"), footprint=TIMESTAMP_FOOTPRINT),
        ],
    )


def _warn_if_record_is_unusable(record: bytes) -> None:
    """Say so if the material being escrowed is not what a recovery would look for."""
    try:
        fields = plistlib.loads(record)
    except (plistlib.InvalidFileException, ValueError, EOFError):
        logger.debug("The material being escrowed is not a property list; enrolling it as-is")
        return

    if isinstance(fields, dict) and ENTROPY_FIELD not in fields:
        logger.warning(
            "The material being escrowed carries no %s, so recovering this record would"
            " succeed and yield nothing usable. An escrow record cannot be corrected"
            " afterwards -- it can only be deleted and replaced.",
            ENTROPY_FIELD,
        )


def seal_to_club(inner: bytes, certificate: x509.Certificate) -> bytes:
    """
    Build §4.5.1's outer message: the inner one, encrypted to the club certificate.

    Five sections, of which three are digests and **none of the three algorithms is
    derivable from the others** -- see the constants at the top of this module. The blob is
    announced with SHA-1 and padded with SHA-1; the two hashes inside it are SHA-256.

    :param inner: From :func:`build_inner_message`.
    :param certificate: The club certificate, **already verified** by
        :func:`verify_club_certificate`. This function cannot check that for the caller,
        which is why :func:`build_escrow_blob` takes the roots instead.
    """
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        msg = "The club certificate does not carry an RSA key, so the blob cannot be sealed"
        raise EnrolmentError(msg)

    aes_key = secrets.token_bytes(OUTER_KEY_LENGTH)
    hmac_key = secrets.token_bytes(OUTER_KEY_LENGTH)
    iv = secrets.token_bytes(AES_IV_LENGTH)

    padder = padding.PKCS7(AES_BLOCK_BITS).padder()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    body = iv + encryptor.update(padder.update(inner) + padder.finalize()) + encryptor.finalize()

    # The HMAC covers the whole of section 2 -- the IV as well as the ciphertext -- rather
    # than the ciphertext alone.
    authentication = hmac.new(hmac_key, body, _INTEGRITY_DIGEST).digest()

    wrapped = public_key.encrypt(
        aes_key + hmac_key,
        asym_padding.OAEP(
            # Both digests are SHA-1, and they are separate arguments precisely because
            # they need not agree. Here they must: see _OAEP_DIGEST.
            mgf=asym_padding.MGF1(algorithm=_OAEP_DIGEST()),
            algorithm=_OAEP_DIGEST(),
            label=None,
        ),
    )

    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        # PKCS#1, which is the bare RSA key -- not SubjectPublicKeyInfo, which would carry
        # an algorithm identifier around it and hash to something else entirely.
        serialization.PublicFormat.PKCS1,
    )

    header = b"".join(value.to_bytes(4, "big") for value in OUTER_HEADER)

    return build_keyvault_message(
        header,
        [
            authentication,
            body,
            wrapped,
            hashlib.new(_INTEGRITY_DIGEST, spki).digest(),
            hashlib.new(_INTEGRITY_DIGEST, inner).digest(),
        ],
    )


def blob_digest(blob: bytes) -> str:
    """
    Compute the `blobDigest` field: **SHA-1** of the blob, base64.

    Not SHA-256. This is the announcement Apple's service checks against the bytes it
    received, so the algorithm is a wire format rather than a security decision -- the two
    hashes *inside* the blob are SHA-256 and that difference is load-bearing.
    """
    return base64.b64encode(hashlib.new(_BLOB_DIGEST, blob).digest()).decode()


@dataclass(frozen=True)
class EscrowBlob:
    """A built escrow blob and the digest that announces it."""

    blob: bytes
    salt: bytes
    """The inner salt. Kept so a caller can reproduce the blob; not sent anywhere."""

    @property
    def digest(self) -> str:
        """The `blobDigest` field, base64 of the blob's SHA-1."""
        return blob_digest(self.blob)

    @override
    def __repr__(self) -> str:
        """Describe the blob without printing any of it."""
        return f"EscrowBlob({len(self.blob)} bytes, digest {self.digest})"


def build_escrow_blob(  # noqa: PLR0913 -- the blob's inputs, and there are six
    *,
    dsid: str,
    label: str,
    timestamp: str,
    password: str,
    record: bytes,
    certificate: x509.Certificate,
    salt: bytes | None = None,
) -> EscrowBlob:
    """
    Build both layers of §4.5.1's blob.

    :param certificate: The club certificate, already verified against the pinned roots.
    """
    salt = salt if salt is not None else secrets.token_bytes(SALT_LENGTH)
    inner = build_inner_message(
        dsid=dsid,
        label=label,
        timestamp=timestamp,
        password=password,
        record=record,
        salt=salt,
    )
    return EscrowBlob(blob=seal_to_club(inner, certificate), salt=salt)


# --------------------------------------------------------------------------------------
# The metadata
# --------------------------------------------------------------------------------------

PASSCODE_GENERATION = 13
"""**[observed]** What a real client sends. Not derived from anything."""


@dataclass(frozen=True)
class DeviceDescription:
    """
    What §4.5.2's metadata says about the client enrolling, which is all a user ever sees.

    Escrow records appear in no Apple interface, so a listing built by this library is the
    only place these fields are read -- and a record with an empty device name is one the
    user cannot identify later when deciding what to delete. Worth filling honestly, and
    the README's labelling rules apply: this is a name a person will read.
    """

    name: str
    model: str
    serial: str
    build: str

    model_version: str = ""
    model_class: str = ""
    platform: str = ""
    machine_id: str = ""


def build_metadata(
    device: DeviceDescription,
    *,
    timestamp: str,
    bottle_id: str,
    escrowed_spki: bytes,
    password: str,
) -> bytes:
    """
    Build §4.5.2's metadata, as the binary property list the `metadata` field carries.

    :param timestamp: From :func:`escrow_timestamp`. **The same string** as the blob's
        sixth section -- one value in three places.
    :param bottle_id: The bottle's UUID. Not the label; see §4.4 on why those are not
        interchangeable.
    :param escrowed_spki: The escrowed **signing** public key, as sent in the bottle.
    :param password: Used only to classify the passcode, and not stored. Note that
        publishing its length is what Apple's own clients do -- a recovery interface asks
        for "a 6-digit passcode" -- but it is a disclosure, and this is where it happens.
    """
    numeric = bool(password) and all(character in "0123456789" for character in password)

    client: dict[str, Any] = {
        "device_name": device.name,
        "device_model": device.model,
        "device_model_version": device.model_version,
        "device_model_class": device.model_class,
        "device_platform": device.platform,
        "device_mid": device.machine_id,
        "SecureBackupMetadataTimestamp": timestamp,
        "SecureBackupUsesNumericPassphrase": numeric,
        "SecureBackupNumericPassphraseLength": len(password) if numeric else 0,
        "SecureBackupUsesComplexPassphrase": 1,
    }

    return plistlib.dumps(
        {
            "serial": device.serial,
            "build": device.build,
            "timestamp": timestamp,
            "bottleID": bottle_id,
            "passcodeGeneration": PASSCODE_GENERATION,
            "escrowedSPKI": escrowed_spki,
            "multipleICSC": True,
            "clientMetadata": client,
        },
        fmt=plistlib.FMT_BINARY,
    )


def record_label(peer_id: str) -> str:
    """
    Build the label that addresses one specific record.

    :param peer_id: The peer the record belongs to -- a `SHA256:`-prefixed digest, from
        :func:`~findmy.keychain.peers.peer_identifier`.
    :raises EnrolmentError: If it does not look like a peer identifier. A `bottleID` is a
        UUID and addresses nothing at the escrow proxy, and substituting one for the other
        is the specific confusion §4.4 warns about.
    """
    if not peer_id.startswith("SHA256:"):
        msg = (
            f"{peer_id!r} is not a peer identifier, which is a SHA256:-prefixed digest. A"
            " bottleID is a UUID and addresses nothing at the escrow proxy."
        )
        raise EnrolmentError(msg)
    return f"{ESCROW_LABEL_ICDP}.{peer_id}"


# --------------------------------------------------------------------------------------
# The exchange
# --------------------------------------------------------------------------------------


async def fetch_club_certificate(
    proxy: AsyncEscrowProxy,
    roots: PinnedRoots,
    transaction_id: str,
    *,
    now: datetime | None = None,
) -> x509.Certificate:
    """
    Fetch the club certificate and verify it, in that order and never the other way.

    Read-only: `get_club_cert` creates nothing. It is separate from :func:`enrol_record` so
    that a caller can check the pinning works before anything writes.

    :param transaction_id: Shared with the `enroll` that follows.
    :raises EnrolmentError: If the certificate is missing, or does not verify.
    """
    response = await proxy.get_club_cert(transaction_id)

    encoded = response.get("clubCert")
    if not encoded:
        msg = "get_club_cert returned no clubCert, so there is no key to seal a blob to"
        raise EnrolmentError(msg)

    raw = base64.b64decode(encoded) if isinstance(encoded, str) else bytes(encoded)
    return verify_club_certificate(raw, roots, now=now)


async def enrol_record(  # noqa: PLR0913 -- everything an escrow record is made of
    proxy: AsyncEscrowProxy,
    roots: PinnedRoots,
    *,
    peer_id: str,
    dsid: str,
    password: str,
    record: bytes,
    device: DeviceDescription,
    bottle_id: str,
    escrowed_spki: bytes,
    when: datetime | None = None,
    user_action_label: str = "FindMy.py enrolling an escrow record",
) -> str:
    """
    Enrol an escrow record: two requests, one transaction, and one permanent artefact.

    **This writes, and nothing removes what it leaves.** An escrow record outlives the
    device that made it and appears in no Apple interface, so a record enrolled by mistake
    is invisible residue until someone lists it with this library and deletes it
    deliberately. Enrol once, with a description a user will recognise.

    The order is not incidental: the certificate is fetched and **verified before** the
    blob is built, because the blob is encrypted to it.

    :param peer_id: The new identity, whose label the record takes.
    :param dsid: The numeric account id -- also the SRP identity of a future recovery.
    :param password: The passcode this record will be recoverable with. Used inside this
        call and not retained; callers should hold it no longer.
    :param record: The material to escrow. See :func:`build_inner_message`.
    :param bottle_id: The bottle's UUID.
    :param escrowed_spki: The escrowed signing public key.
    :param when: The moment to stamp. Defaults to now.
    :returns: The label the record was enrolled under.
    """
    label = record_label(peer_id)
    transaction_id = str(uuid.uuid4()).upper()

    certificate = await fetch_club_certificate(proxy, roots, transaction_id, now=when)

    timestamp = escrow_timestamp(when)
    blob = build_escrow_blob(
        dsid=dsid,
        label=label,
        timestamp=timestamp,
        password=password,
        record=record,
        certificate=certificate,
    )
    metadata = build_metadata(
        device,
        timestamp=timestamp,
        bottle_id=bottle_id,
        escrowed_spki=escrowed_spki,
        password=password,
    )

    logger.warning(
        "Enrolling escrow record %s for %s. This is permanent: nothing but a deliberate"
        " deletion removes an escrow record, and no Apple interface shows one.",
        label,
        device.name or "an unnamed device",
    )

    await proxy.enroll(
        label,
        blob=blob.blob,
        blob_digest=blob.digest,
        metadata=metadata,
        dsid=dsid,
        transaction_id=transaction_id,
        user_action_label=user_action_label,
    )

    return label


__all__ = [
    "PINNED_ROOT_FINGERPRINTS",
    "DeviceDescription",
    "EnrolmentError",
    "EscrowBlob",
    "PinnedRoots",
    "blob_digest",
    "build_escrow_blob",
    "build_inner_message",
    "build_metadata",
    "enrol_record",
    "escrow_timestamp",
    "fetch_club_certificate",
    "record_label",
    "seal_to_club",
    "srp_verifier",
    "verify_club_certificate",
]
