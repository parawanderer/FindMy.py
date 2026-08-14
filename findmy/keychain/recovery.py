"""
Recovering a bottled peer from an escrow record, using a device passcode.

Implements Stage 3 §6.1 to §6.5 of the Find My key-export protocol specification: the SRP
exchange in which the passcode is the password, and the two layers of blob it unwraps.

What comes out is **not the keychain**. It is a bottled peer -- the sealed identity of a
device that was already in the user's trust circle -- which :mod:`findmy.keychain.bottle`
turns into keys and which is then used to vouch for a new identity of our own. This module
stops at the sealed material.

.. warning::
    **The passcode is the most sensitive value this library touches.** It is the key to
    the user's entire keychain, and unlike an Apple ID password it cannot be rotated
    without physical access to the device. It is read, used twice, and discarded: nothing
    here stores it, logs it, or keeps it past the call it was passed to. Callers should
    hold it no longer.

    Nothing in this module writes to the account. Recovery reads escrowed material; it is
    *joining* that creates a peer and an escrow record, and that is elsewhere.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import secrets
import textwrap
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import srp._pysrp as srp
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from findmy.errors import UnhandledProtocolError

from .escrow import (
    EscrowError,
    KeyVaultSection,
    build_keyvault_message,
    parse_keyvault_message,
    split_keyvault_message,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .escrow import AsyncEscrowProxy, EscrowRecord

logger = logging.getLogger(__name__)

# §6.2: the header of an srp_init reply is two 32-bit values then a 16-byte request id.
SRP_INIT_HEADER_LENGTH = 24
SRP_INIT_SECTIONS = 3

# §6.3: the two values rewritten into that header before it is sent back.
RECOVERY_MAGIC = 165
RECOVERY_CLUB_TYPE = 1

# §6.3: the exchange token goes back in a section that occupies twenty bytes -- its
# four-byte length prefix, its eight bytes, and eight zeros. Why twenty is not
# established; the service expects it.
EXCHANGE_TOKEN_FOOTPRINT = 20

# §6.4: the reply header is longer when a club type is in play.
RECOVER_HEADER_LENGTH = 24
RECOVER_HEADER_LENGTH_CLUB = 40
RECOVER_SECTIONS = 3

# §6.5: the innermost blob.
INNER_HEADER_LENGTH = 16
INNER_SECTIONS = 6
INNER_KEY_LENGTH = 16
INNER_IV_LENGTH = 16

# §6.4's cipher table.
BLOB_VERSION_CBC = 0
BLOB_VERSION_UNKNOWN = 1
BLOB_VERSION_GCM = 2
GCM_NONCE_LENGTH = 16
GCM_TAG_LENGTH = 16

# §6.2: a 32-byte client secret. pysrp wants exactly 256 bytes and reads them as an
# integer, so the value is left-padded rather than lengthened.
CLIENT_SECRET_LENGTH = 32
_PYSRP_SECRET_LENGTH = 256


class RecoveryError(UnhandledProtocolError):
    """Raised when a recovery cannot be completed."""


def _blob_bytes(value: object, name: str) -> bytes:
    """
    Read a blob from a property-list response.

    The escrow proxy carries these as **base64 in a string**, not as plist `data`, which
    is the same encoding the request uses in the other direction. Raw bytes are accepted
    too, so that a response using `data` would not need a second code path.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return base64.b64decode(value)
        except (ValueError, binascii.Error) as e:
            msg = f"{name} is a string but not valid base64: {e}"
            raise RecoveryError(msg) from None

    msg = f"{name} is a {type(value).__name__}, which is neither bytes nor base64 text"
    raise RecoveryError(msg)


@contextmanager
def _identity_in_private_key() -> Iterator[None]:
    """
    Include the identity in SRP's private-key hash, for as long as this is held.

    Recovery is **standard SRP-6a**, unlike Grand Slam authentication, which omits the
    identity from that hash. The distinction matters and is invisible when wrong: a client
    that gets it backwards fails to authenticate in a way indistinguishable from a wrong
    passcode.

    The awkward part is that the SRP library carries this as a **process-global**, and
    :mod:`findmy.reports.account` sets it the other way at import time. So it is flipped
    for the duration and put back afterwards, including on failure. Two SRP exchanges of
    different kinds running concurrently in one process would interfere; that does not
    happen here, and this is the narrowest place to contain it.
    """
    previous = srp._no_username_in_x  # noqa: SLF001
    srp.no_username_in_x(False)
    try:
        yield
    finally:
        srp.no_username_in_x(previous)


@dataclass(frozen=True)
class RecoveryChallenge:
    """What the escrow proxy answers `srp_init` with."""

    label: str
    """The record being recovered, by its own label."""

    transaction_id: str
    """Shared with the `recover` call that completes the exchange."""

    prefix: bytes
    """
    The four leading bytes of the reply's framing: its own total length.

    Kept for diagnosis only. A reply computes its own rather than echoing this one.
    """

    header: bytes
    """The reply's 24-byte header, rewritten and sent back in the proof."""

    exchange_token: bytes
    """
    Section 0, and the value re-sent as a section in the proof.

    **Not** the transaction id, which is the sixteen bytes inside the header and travels
    back there untouched. The reply carries two identifiers and only this one is re-sent
    as a section of its own.
    """

    salt: bytes
    server_public: bytes

    dsid: str
    """The SRP identity. Not the Apple ID, and not the `adsid` from authentication."""

    club_type_id: int | None


def parse_challenge(response: dict[str, Any], label: str, transaction_id: str) -> RecoveryChallenge:
    """Read an `srp_init` reply."""
    blob = response.get("respBlob")
    if not blob:
        msg = "srp_init returned no respBlob"
        raise RecoveryError(msg)

    dsid = response.get("dsid")
    if not dsid:
        msg = "srp_init returned no dsid, which is the SRP identity"
        raise RecoveryError(msg)

    prefix, header, sections = split_keyvault_message(
        _blob_bytes(blob, "srp_init's respBlob"),
        SRP_INIT_HEADER_LENGTH,
        SRP_INIT_SECTIONS,
    )
    logger.debug(
        "srp_init framing: prefix %s, header %s, section lengths %s",
        prefix.hex(),
        header.hex(),
        [len(section) for section in sections],
    )

    return RecoveryChallenge(
        label=label,
        transaction_id=transaction_id,
        prefix=prefix,
        header=header,
        exchange_token=sections[0],
        salt=sections[1],
        server_public=sections[2],
        dsid=str(dsid),
        club_type_id=response.get("clubTypeID"),
    )


def build_recovery_proof(challenge: RecoveryChallenge, proof: bytes) -> bytes:
    """
    Frame an SRP proof the way the `recover` command expects it.

    Two sections and no others: the exchange token from section 0, then the proof.

    The token's section occupies twenty bytes while declaring the eight it holds -- zeros
    are appended after the data, and the offsets account for the larger footprint. Padding
    the data itself to twenty and declaring twenty produces a message that parses and is
    rejected.

    The header's sixteen-byte transaction id is a different value and travels back inside
    the header, untouched.
    """
    header = bytearray(challenge.header)
    header[0:4] = RECOVERY_MAGIC.to_bytes(4, "big")
    header[4:8] = (2 if challenge.club_type_id == RECOVERY_CLUB_TYPE else 0).to_bytes(4, "big")

    token = KeyVaultSection(challenge.exchange_token, footprint=EXCHANGE_TOKEN_FOOTPRINT)

    return build_keyvault_message(bytes(header), [token, proof])


def unwrap_outer_blob(blob: bytes, session_key: bytes, *, club_type_id: int | None) -> bytes:
    """
    Decrypt the outer blob a successful `recover` returns.

    Its header length depends on the club type, and a version field four bytes into that
    header selects the cipher.

    :returns: The inner blob, still wrapped -- see :func:`unwrap_inner_blob`.
    :raises RecoveryError: If the version is one this specification does not describe.
    """
    header_length = (
        RECOVER_HEADER_LENGTH_CLUB if club_type_id == RECOVERY_CLUB_TYPE else RECOVER_HEADER_LENGTH
    )
    header, sections = parse_keyvault_message(blob, header_length, RECOVER_SECTIONS)

    version = int.from_bytes(header[4:8], "big")
    iv, ciphertext = sections[1], sections[2]

    if version == BLOB_VERSION_CBC:
        decryptor = Cipher(algorithms.AES(session_key), modes.CBC(iv)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return _strip_padding(plaintext)

    if version == BLOB_VERSION_GCM:
        # A 16-byte nonce, not GCM's usual 12. The tag's position is not stated; it is
        # taken from the end of the ciphertext, which is where every other construction in
        # this protocol puts it.
        if len(iv) != GCM_NONCE_LENGTH:
            logger.warning(
                "Expected a %d-byte GCM nonce, got %d",
                GCM_NONCE_LENGTH,
                len(iv),
            )
        body, tag = ciphertext[:-GCM_TAG_LENGTH], ciphertext[-GCM_TAG_LENGTH:]
        decryptor = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag)).decryptor()
        try:
            return decryptor.update(body) + decryptor.finalize()
        except InvalidTag:
            msg = "Outer blob failed to authenticate under the SRP session key"
            raise RecoveryError(msg) from None

    if version == BLOB_VERSION_UNKNOWN:
        msg = (
            "The outer blob announces version 1, which this specification does not"
            " describe. Refusing rather than guessing at a cipher."
        )
        raise RecoveryError(msg)

    msg = f"The outer blob announces unknown version {version}"
    raise RecoveryError(msg)


def _strip_padding(plaintext: bytes) -> bytes:
    """Remove PKCS#7 padding if it is there, and leave the data alone if it is not."""
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(plaintext) + unpadder.finalize()
    except ValueError:
        # The padding scheme is not stated. Returning the plaintext unaltered is better
        # than failing, since the next layer will reject it if this was wrong.
        logger.debug("Outer blob plaintext is not PKCS#7 padded; using it as-is")
        return plaintext


def unwrap_inner_blob(blob: bytes, passcode: str) -> bytes:
    """
    Decrypt the innermost blob, which is where the passcode is spent a second time.

    Note that one section serves as **both** the PBKDF2 salt and, in its first sixteen
    bytes, the CBC initialisation vector -- and that the iteration count is carried in the
    blob's own header rather than being fixed.

    :param blob: The plaintext from :func:`unwrap_outer_blob`.
    :param passcode: The device passcode. Not retained.
    :returns: The bottled peer, sealed.
    """
    header, sections = parse_keyvault_message(blob, INNER_HEADER_LENGTH, INNER_SECTIONS)

    iterations = int.from_bytes(header[8:12], "big")
    if iterations <= 0:
        msg = f"The inner blob asks for {iterations} PBKDF2 iterations, which cannot be right"
        raise RecoveryError(msg)

    salt = sections[1]
    derived = hashlib.pbkdf2_hmac("sha256", passcode.encode(), salt, iterations, INNER_KEY_LENGTH)

    decryptor = Cipher(algorithms.AES(derived), modes.CBC(salt[:INNER_IV_LENGTH])).decryptor()
    plaintext = decryptor.update(sections[3]) + decryptor.finalize()

    return _strip_padding(plaintext)


# **[observed] This call fails intermittently, and the same passcode succeeds on a retry.**
# Seen as HTTP 409 with `status` -6015 and a `message` beginning `CLUBH ERROR:`, on an
# account where the recovery had worked before and worked again immediately after.
#
# That reorders the advice. The specification's point -- that a wrong passcode and a
# mis-parameterised exchange fail identically -- is still true and still worth saying, but
# it is no longer the first thing to suspect, and leading with it sends somebody to check
# a passcode that was right.
TRANSIENT_STATUS = "-6015"

_ADVICE = (
    "Try again first: this call fails intermittently and the same passcode then works.",
    "If it keeps failing, note that a wrong passcode and a mis-parameterised exchange"
    " are indistinguishable here by design, so this says which half is at fault and not"
    " which fault. srp_init was answered, so the record, the label and the transport are"
    " right; only the proof or the passcode is in question.",
    "Attempts may be a limited resource. Apple's escrow services generally cap them, and"
    " what this one allows is not established here -- so prefer being sure of a passcode"
    " over trying variations of one.",
)


def _rejected(error: EscrowError) -> RecoveryError:
    """
    Explain a rejection the service reported, in the order worth acting on.

    Not in the order of likelihood-of-being-interesting: the intermittent case goes first
    because it is both the most common and the cheapest to rule out, and because the
    alternative -- leading with the passcode -- sends somebody to re-examine something
    that was already right.
    """
    lines = "\n".join(
        textwrap.fill(
            f"{index}. {advice}",
            width=78,
            initial_indent="  ",
            subsequent_indent="     ",
        )
        for index, advice in enumerate(_ADVICE, start=1)
    )
    return RecoveryError(f"{error}\n\n{lines}")


async def recover_bottled_peer(
    proxy: AsyncEscrowProxy,
    record: EscrowRecord,
    passcode: str,
) -> bytes:
    """
    Recover the sealed material an escrow record holds.

    The passcode is used twice and neither use substitutes for the other: once as the SRP
    password, and again as a PBKDF2 input to unwrap the innermost blob. It is not stored,
    logged or retained past this call.

    Nothing here writes to the account.

    :param proxy: An escrow-proxy client.
    :param record: The record to recover from, from a listing. It must carry a bottle.
    :param passcode: The screen-lock passcode of the device that made the record.
    :returns: The bottled peer, still sealed -- :mod:`findmy.keychain.bottle` opens it.
    :raises RecoveryError: If the exchange fails. Note that a wrong passcode and a
        mis-parameterised SRP exchange fail identically, so a failure here is not proof
        the passcode was wrong.
    """
    if not record.is_recovery_candidate:
        msg = (
            f"{record.label} carries no bottle, so there is nothing to recover from it."
            " It is a different kind of record, not a broken one."
        )
        raise RecoveryError(msg)
    if not passcode:
        msg = "A passcode is required; the escrowed material is encrypted under it"
        raise RecoveryError(msg)

    transaction_id = str(uuid.uuid4()).upper()

    with _identity_in_private_key():
        # A 32-byte secret, left-padded because the library wants 256 bytes and reads
        # them as an integer.
        secret = secrets.token_bytes(CLIENT_SECRET_LENGTH).rjust(_PYSRP_SECRET_LENGTH, b"\x00")
        user = srp.User(
            "",  # replaced below: the identity is only known once srp_init has answered
            passcode,
            hash_alg=srp.SHA256,
            ng_type=srp.NG_2048,
            bytes_a=secret,
        )
        _, client_public = user.start_authentication()

        logger.info("Beginning escrow recovery for %s", record.label)
        challenge = parse_challenge(
            await proxy.srp_init(record.label, client_public, transaction_id),
            record.label,
            transaction_id,
        )

        # The identity is the dsid the reply carried, which is why it is set here rather
        # than at construction. The library accepts either a string or bytes and encodes
        # as needed; the annotation says otherwise.
        user.I = challenge.dsid  # pyright: ignore [reportAttributeAccessIssue]

        proof = user.process_challenge(challenge.salt, challenge.server_public)
        if proof is None:
            msg = "Could not compute an SRP proof from the challenge"
            raise RecoveryError(msg)

        try:
            response = await proxy.recover(
                record.label,
                build_recovery_proof(challenge, proof),
                transaction_id,
                dsid=challenge.dsid,
            )
        except EscrowError as e:
            raise _rejected(e) from None

        blob = _blob_bytes(response.get("respBlob"), "recover's respBlob")

        header_length = (
            RECOVER_HEADER_LENGTH_CLUB
            if challenge.club_type_id == RECOVERY_CLUB_TYPE
            else RECOVER_HEADER_LENGTH
        )
        _, _, sections = split_keyvault_message(blob, header_length, RECOVER_SECTIONS)

        # Verify the server before decrypting anything with the session key it implies.
        user.verify_session(sections[0])
        if not user.authenticated():
            msg = (
                "The escrow proxy's proof did not verify. Either the passcode is wrong or"
                " this exchange is mis-parameterised; the two are indistinguishable here."
            )
            raise RecoveryError(msg)

        session_key = user.get_session_key()
        if session_key is None:
            msg = "SRP produced no session key"
            raise RecoveryError(msg)

    outer = unwrap_outer_blob(blob, session_key, club_type_id=challenge.club_type_id)
    material = unwrap_inner_blob(outer, passcode)

    logger.info("Recovered %d bytes of sealed material from %s", len(material), record.label)
    return material


__all__ = [
    "RecoveryChallenge",
    "RecoveryError",
    "build_recovery_proof",
    "parse_challenge",
    "recover_bottled_peer",
    "unwrap_inner_blob",
    "unwrap_outer_blob",
]
