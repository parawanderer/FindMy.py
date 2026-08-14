"""
Key shares: the last thing between a recovered peer and the keychain's view keys.

Implements Stage 3 §6.7.0 of the Find My key-export protocol specification.

**Why this matters more than its size suggests.** A share is wrapped to the *receiving*
peer's encryption key, and escrow recovery yields exactly that key. So a client holding a
recovered bottle can unwrap the shares that peer was entitled to -- without being in the
trust circle, and therefore **without creating a peer, signing a voucher, or enrolling an
escrow record**. If the keys these yield satisfy what Stage 5 needs, every write in this
flow disappears and the whole feature becomes read-only apart from signing in.

Two things here are encodings used nowhere else in the protocol: a wrapped key is base64
of an `NSKeyedArchiver` archive, and what that expands to is an ECIES ciphertext.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import logging
import plistlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from google.protobuf.message import DecodeError

from findmy.cloudkit.constants import CUTTLEFISH_SERVICE
from findmy.cloudkit.proto import cloudkit_pb2 as ck
from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.cloudkit.records import describe_wire, named_fields
from findmy.errors import UnhandledProtocolError

from .items import VIEW_MANATEE, VIEW_PROTECTED_CLOUD_STORAGE

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from findmy.cloudkit.client import AsyncCloudKitClient

    from .peers import Peer, PeerDirectory

logger = logging.getLogger(__name__)

NEEDED_VIEWS = (VIEW_MANATEE, VIEW_PROTECTED_CLOUD_STORAGE)
"""The keychain views this project reads. A share for any other is not its concern."""

METHOD_FETCH_RECOVERABLE_TLK_SHARES = "fetchRecoverableTLKShares"

# Apple's ECIES puts an ephemeral public key in front of an AES-GCM ciphertext. For P-384
# that point is 97 bytes uncompressed; the tag is the trailing 16.
_EPHEMERAL_POINT_LENGTH = 97
_GCM_TAG_LENGTH = 16


class ShareError(UnhandledProtocolError):
    """Raised when a key share cannot be read."""


def _decode_base64(value: str) -> bytes:
    """
    Take a field from base64 text to bytes, or its own bytes if it is not base64.

    **Validated on purpose.** `b64decode` defaults to discarding characters outside the
    alphabet, so a string that is not base64 at all decodes to garbage rather than
    failing -- and the fallback that exists for exactly that case never runs.
    """
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return value.encode()


# --------------------------------------------------------------------------------------
# NSKeyedArchiver
# --------------------------------------------------------------------------------------


def unarchive(data: bytes) -> Any:  # noqa: ANN401
    """
    Read an `NSKeyedArchiver` archive far enough to get the bytes out of it.

    An archive is a property list holding a flat `$objects` table and a `$top` map into
    it, with references stored as `plistlib.UID`. This resolves those references and
    returns plain Python values -- it is not a general unarchiver and knows nothing about
    classes, which is all that is needed for a payload that is ultimately a blob.

    :raises ShareError: If the data is not an archive.
    """
    try:
        archive = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, EOFError) as e:
        msg = f"Not a property list, so not an archive: {e}"
        raise ShareError(msg) from None

    if not isinstance(archive, dict) or "$objects" not in archive:
        msg = "A property list, but not an NSKeyedArchiver archive"
        raise ShareError(msg)

    objects = archive["$objects"]

    def resolve(value: Any, depth: int = 0) -> Any:  # noqa: ANN401
        if depth > 32:  # a cycle, or an archive deeper than anything here should be
            return None
        if isinstance(value, plistlib.UID):
            index = int(value)
            if not 0 <= index < len(objects):
                return None
            return resolve(objects[index], depth + 1)
        if isinstance(value, dict):
            return {k: resolve(v, depth + 1) for k, v in value.items() if k != "$class"}
        if isinstance(value, list):
            return [resolve(v, depth + 1) for v in value]
        return value

    return resolve(archive.get("$top", {}))


def archived_blobs(data: bytes) -> list[bytes]:
    """
    Pull every byte string out of an archive, longest first.

    An archive may carry more than one, and which is the payload is not stated -- so
    rather than assume the largest, all are returned and the caller decides. For a wrapped
    key the caller is ECIES, whose authentication tag makes that decision free.

    :raises ShareError: If the archive holds no byte string.
    """
    found: list[bytes] = []

    def walk(value: Any, depth: int = 0) -> None:  # noqa: ANN401
        if depth > 32:
            return
        if isinstance(value, bytes):
            found.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                walk(item, depth + 1)

    walk(unarchive(data))

    if not found:
        msg = "This archive carries no byte string to unwrap"
        raise ShareError(msg)

    return sorted(found, key=len, reverse=True)


def archived_bytes(data: bytes) -> bytes:
    """Pull the largest byte string out of an archive."""
    return archived_blobs(data)[0]


def describe_archive(data: bytes) -> str:
    """
    Describe what an archive holds, by member name and size.

    An archive that "expands to an ECIES ciphertext structure" holds its parts separately
    rather than as one blob, and which member is which is not stated. Naming them is what
    turns a failed decrypt into something actionable.
    """
    try:
        resolved = unarchive(data)
    except ShareError as e:
        return f"<not an archive: {e}>"

    parts: list[str] = []

    def walk(value: object, path: str, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(value, bytes):
            parts.append(f"{path}={len(value)}B")
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}" if path else str(key), depth + 1)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]", depth + 1)
        elif value is not None:
            parts.append(f"{path}={value!r}"[:60])

    walk(resolved, "")
    return ", ".join(parts) or "<empty>"


def archived_members(data: bytes) -> dict[str, bytes]:
    """
    Pull an archive's byte members out with the names the archive gives them.

    Names matter here rather than shapes: the members of an `SFIESCiphertext` say what
    they are, and reading them by name is what stops a reader pairing the wrong two.
    """
    members: dict[str, bytes] = {}

    def walk(value: Any, path: str, depth: int = 0) -> None:  # noqa: ANN401
        if depth > 32:
            return
        if isinstance(value, bytes):
            members[path] = value
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}.{key}" if path else str(key), depth + 1)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]", depth + 1)

    walk(unarchive(data), "")
    return members


# The members of an SFIESCiphertext, matched on a distinctive fragment rather than the
# whole name. Apple's own key for the ephemeral point reads
# `SFEphemeralSenderPublicKeyExternaRepresentation` -- "Externa", missing its final `l` --
# so matching the spelled-out name would find nothing on real data.
_MEMBER_POINT = "EphemeralSenderPublicKey"
_MEMBER_CIPHERTEXT = "SFCiphertext"
_MEMBER_CODE = "AuthenticationCode"


@dataclass(frozen=True)
class SfiesParts:
    """The three members of an `SFIESCiphertext`, with the ciphertext already trimmed."""

    point: bytes
    ciphertext: bytes
    code: bytes


def sfies_parts(archive: bytes) -> SfiesParts:
    """
    Read an `SFIESCiphertext` archive into the three pieces decryption needs.

    **`SFCiphertext` is longer than the ciphertext.** It overruns by exactly the size of
    the other two members -- the ephemeral point plus the authentication code -- and the
    excess is uninitialised heap from Apple's own buffer. It is not padding, not a nonce
    and not part of any construction, so it is trimmed here and never read, logged or
    modelled.

    That overrun is why a correct implementation still fails: the tag check rejects it
    exactly as a wrong key or a wrong cipher parameter would, which sends the search after
    the construction when the construction was right all along.

    The trim is derived from the other two members rather than written as 113, because a
    different curve makes it a different number.

    :raises ShareError: If the archive is not an `SFIESCiphertext`.
    """
    members = archived_members(archive)

    def find(fragment: str) -> bytes | None:
        return next((v for k, v in members.items() if fragment in k), None)

    point = find(_MEMBER_POINT)
    ciphertext = find(_MEMBER_CIPHERTEXT)
    code = find(_MEMBER_CODE)

    if point is None or ciphertext is None or code is None:
        msg = (
            "This archive is not an SFIESCiphertext: it holds"
            f" {describe_archive(archive)}"
        )
        raise ShareError(msg)

    overrun = len(point) + len(code)
    if len(ciphertext) <= overrun:
        msg = (
            f"The ciphertext member is {len(ciphertext)} bytes, which is not longer than"
            f" the {overrun}-byte overrun it is expected to carry"
        )
        raise ShareError(msg)

    return SfiesParts(point=point, ciphertext=ciphertext[:-overrun], code=code)


# --------------------------------------------------------------------------------------
# SFIES
# --------------------------------------------------------------------------------------


def _x963_kdf(shared: bytes, shared_info: bytes, length: int) -> bytes:
    """ANSI X9.63 key derivation with SHA-256, counter starting at one."""
    out = b""
    counter = 1
    while len(out) < length:
        block = shared + counter.to_bytes(4, "big") + shared_info
        out += hashlib.sha256(block).digest()
        counter += 1
    return out[:length]


# 32 bytes of AES-256 key followed by a 16-byte GCM nonce. Sixteen, not the twelve a GCM
# nonce is usually specified as -- and the two authenticate differently, so this is not a
# detail a reader can normalise on the way past.
_SFIES_KEY_LENGTH = 32
_SFIES_NONCE_LENGTH = 16


def sfies_decrypt(
    private_key: ec.EllipticCurvePrivateKey,
    parts: SfiesParts,
) -> bytes:
    """
    Decrypt an `SFIESCiphertext`.

    Plain ECDH -- P-384's cofactor is one, so there is no cofactor variant to consider --
    then ANSI X9.63 with SHA-256, using the ephemeral point **exactly as archived** as the
    shared info. That yields 48 bytes: an AES-256 key and a 16-byte GCM nonce. There is no
    associated data, and the authentication code is the GCM tag.

    :raises ShareError: If it does not authenticate.
    """
    try:
        ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(private_key.curve, parts.point)
    except ValueError as e:
        msg = f"The archived ephemeral key is not a point on {private_key.curve.name}: {e}"
        raise ShareError(msg) from None

    shared = private_key.exchange(ec.ECDH(), ephemeral)
    material = _x963_kdf(shared, parts.point, _SFIES_KEY_LENGTH + _SFIES_NONCE_LENGTH)

    key = material[:_SFIES_KEY_LENGTH]
    nonce = material[_SFIES_KEY_LENGTH:]

    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, parts.code)).decryptor()
    try:
        return decryptor.update(parts.ciphertext) + decryptor.finalize()
    except InvalidTag:
        msg = (
            "The SFIES ciphertext did not authenticate under this key. The key, the"
            " trimming of the ciphertext member, or the shared secret is wrong"
        )
        raise ShareError(msg) from None


def sfies_decrypt_archive(private_key: ec.EllipticCurvePrivateKey, archive: bytes) -> bytes:
    """Read an `SFIESCiphertext` archive and decrypt it."""
    return sfies_decrypt(private_key, sfies_parts(archive))


# --------------------------------------------------------------------------------------
# Shares
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyShare:
    """One key share, and whatever could be made of it."""

    service: str
    """The keychain view this share is for -- `Manatee` is the one Find My needs."""

    key_id: str
    sender: str
    receiver: str

    wrapped_key: bytes
    """The ciphertext, already base64-decoded and unarchived."""

    plaintext: bytes | None = None
    """The unwrapped key material, if it could be decrypted."""

    error: str | None = None
    """Why it could not be, if it could not."""

    view_keys: ViewKeyring = field(default_factory=lambda: ViewKeyring())
    """The view's keys, unwrapped under the key this share yielded."""

    sender_known: bool = False
    """
    Whether the sending peer appears in the trust circle at all.

    A peer genuinely absent from the directory is a reason to **reject** the share, not to
    proceed: unwrapping the user's keychain with material from a party nothing can
    identify is not a small thing to wave through.
    """

    sender_verified: bool = False
    """
    Whether the sending peer's signature over this share verified.

    Separate from :attr:`sender_known` because the two fail differently: an unknown sender
    means nothing identifies who produced the key, while a known sender whose signature
    fails means something claims to be them and is not.
    """


@dataclass(frozen=True)
class ShareRecord:
    """
    A key share, read out of the CloudKit record that carries it.

    The record is of type `tlkshare` and its members are addressed **by name**. Note what
    is *not* on it: no service and no key id. Both live on the message wrapping it, which
    is why a reader looking here for the view name finds nothing.
    """

    sender: str
    receiver: str
    receiver_public_encryption_key: bytes
    wrapped_key: bytes
    signature: bytes
    curve: int
    epoch: int
    poisoned: int
    version: int

    @classmethod
    def from_record(cls, record: ck.Record) -> ShareRecord:
        """Read a `tlkshare` record."""
        fields = named_fields(record)

        def text(name: str) -> str:
            value = fields.get(name)
            return value if isinstance(value, str) else ""

        def number(name: str) -> int:
            value = fields.get(name)
            return int(value) if isinstance(value, (int, float)) else 0

        return cls(
            sender=text("sender"),
            receiver=text("receiver"),
            receiver_public_encryption_key=_as_bytes(fields.get("receiverPublicEncryptionKey")),
            wrapped_key=_as_bytes(fields.get("wrappedkey")),
            signature=_as_bytes(fields.get("signature")),
            curve=number("curve"),
            epoch=number("epoch"),
            poisoned=number("poisoned"),
            version=number("version"),
        )


@dataclass(frozen=True)
class ViewKey:
    """One of a view's keys, from a `synckey` record."""

    key_class: str
    wrapped_key: bytes
    upload_version: int

    uuid: str = ""
    """
    The key's own UUID -- its record identifier.

    This is what a keychain item's `parentkeyref` names, so it is the only thing that
    matches an item to the key that unwraps it. The class *name* does not: `parentkeyref`
    holds a UUID, and matching on `classA`/`classB` instead finds nothing.
    """

    slot: str = ""
    """
    Which member of the view key set this came from: `tlk`, `classA` or `classB`.

    Kept because the slot decides how the key is obtained and the record's own `class`
    field is not a reliable substitute -- the top-level key is **not wrapped at all**,
    while the class keys are, and unwrapping is not something to get wrong by one field.
    """

    @classmethod
    def from_record(cls, record: ck.Record, slot: str = "") -> ViewKey:
        """Read a `synckey` record."""
        fields = named_fields(record)
        key_class = fields.get("class")
        upload = fields.get("uploadver")

        return cls(
            key_class=key_class if isinstance(key_class, str) else "",
            wrapped_key=_as_bytes(fields.get("wrappedkey")),
            upload_version=int(upload) if isinstance(upload, (int, float)) else 0,
            uuid=record.record_identifier.value.name,
            slot=slot,
        )


def _as_bytes(value: object) -> bytes:
    """Take a record field to bytes, whether it arrived as text or as bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return _decode_base64(value)
    return b""


def _record_in(wrapper: cf.RecordWrapper) -> ck.Record | None:
    """Pull the CloudKit record out of a wrapper, or None if there is not one."""
    if not wrapper.record:
        return None

    record = ck.Record()
    try:
        record.ParseFromString(wrapper.record)
    except DecodeError:
        logger.warning("A share wrapper's payload did not decode as a CloudKit record")
        return None
    return record


def _little_endian(value: int, width: int) -> bytes:
    """
    Render an integer little-endian in a fixed width, whatever its sign.

    These fields are declared `int64` and real records **do** carry negative values, so an
    unsigned rendering is not merely stricter -- it raises, and a raise here aborts every
    remaining share rather than failing the one it could not read. Masking into the width
    reproduces two's complement for a negative and truncates an oversized positive, which
    is what the value's own encoding does.
    """
    return (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little")


SIGNED_INTEGER_WIDTH = 8
"""
**All four integers are eight bytes**, `version` and `poisoned` included.

They are not eight bytes anywhere else: the §6.9 message declares those two as `uint32`
and the CloudKit record carries its own integer type. The signed form is neither.

This started as four, from an earlier revision of the table, and it is the wrong that costs
most: both fields are zero on real shares, so a four-byte rendering leaves the digest four
zero bytes short, the check fails, and the share is **skipped**. The symptom is a peer that
appears to have no shares to give -- not a verification error, and not anything that points
here.
"""


def share_signed_data(share: ShareRecord) -> bytes:
    """
    Assemble the bytes a key share's signature covers.

    Seven fields in a fixed order, all seven always present, and **the integers are
    little-endian** -- which is the trap. Everything else in this protocol is big-endian:
    CloudKit's protobuf, the KeyVault framing, the PCS structures. This one construction is
    not, and getting it wrong produces a signature that will not verify with nothing to say
    why.

    None of the seven may be skipped. A share that omits `poisoned` and `version` on the
    wire still signs them, as zero -- so building this by walking the populated fields
    produces a five-part digest that verifies nowhere.
    """
    return b"".join(
        (
            _little_endian(share.version, SIGNED_INTEGER_WIDTH),
            share.receiver.encode("utf-8"),
            share.sender.encode("utf-8"),
            share.wrapped_key,
            _little_endian(share.curve, SIGNED_INTEGER_WIDTH),
            _little_endian(share.epoch, SIGNED_INTEGER_WIDTH),
            _little_endian(share.poisoned, SIGNED_INTEGER_WIDTH),
        ),
    )


def verify_share_signature(share: ShareRecord, sender: Peer) -> bool:
    """
    Check a share against the peer that sent it.

    ECDSA over SHA-256, against the signing key the trust circle reports for that peer.

    :returns: Whether the signature verified. False also when the sender's key cannot be
        read or the share cannot be rendered, since an unverifiable share is not a
        verified one -- and since a verification that *raises* takes down the whole
        listing, which is a far worse outcome than one share reported as unverified.
    """
    public_key = sender.signing_public_key()
    if public_key is None:
        logger.warning("Peer %s has a signing key this cannot read", sender.hash)
        return False

    if not share.signature:
        return False

    try:
        public_key.verify(share.signature, share_signed_data(share), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    except Exception:  # noqa: BLE001 -- one malformed share must not abort the listing
        logger.warning(
            "The share from %s could not be checked at all, so it counts as unverified",
            sender.hash,
            exc_info=True,
        )
        return False
    return True


@dataclass(frozen=True)
class ShareEntry:
    """One view's share, together with that view's keys."""

    view: str
    """The keychain view. It lives on the wrapping message, not on the record."""

    share: ShareRecord
    view_keys: list[ViewKey]


def decode_share_entry(data: bytes) -> ShareEntry | None:
    """
    Read one entry of a share listing.

    An entry names a **view**, carries that view's keys, and carries the share handing
    them out. Both the share and each key arrive as a CloudKit record inside a wrapper.

    :returns: The entry, or None if it carries no readable share.
    :raises ShareError: If the entry is not shaped like a share listing at all.
    """
    entry = cf.RecoverableTlkShare()
    try:
        entry.ParseFromString(data)
    except DecodeError:
        msg = f"A share entry did not decode. Its top-level fields are: {describe_wire(data)}"
        raise ShareError(msg) from None

    if not entry.service and not entry.HasField("share"):
        msg = (
            "A share entry carries neither a view name nor a share."
            f" Its top-level fields are: {describe_wire(data)}"
        )
        raise ShareError(msg)

    record = _record_in(entry.share)
    if record is None:
        # Whether this matters depends entirely on which view it is. An account's trust
        # circle lists shares for every keychain view it syncs -- around twenty -- and
        # this project reads exactly two of them. A share it cannot open for a view it
        # never looks at costs nothing, and warning about it buries the case that does.
        needed = entry.service in NEEDED_VIEWS
        logger.log(
            logging.WARNING if needed else logging.INFO,
            "Entry for %s carries no readable share record%s",
            entry.service,
            (
                ", and that view is one this needs, so key recovery will come up short"
                if needed
                else ". Nothing here reads that view, so this affects nothing."
            ),
        )
        return None

    return ShareEntry(
        view=entry.service,
        share=ShareRecord.from_record(record),
        view_keys=read_view_keys(entry.viewkeys),
    )


def read_view_keys(keys: cf.ViewKeySet) -> list[ViewKey]:
    """
    Read a view's keys out of their wrappers, remembering which slot each came from.

    The slot is not decoration: the top-level key and the class keys are obtained by
    different means, and only the position distinguishes them reliably.
    """
    found: list[ViewKey] = []
    for slot, wrapper in (("tlk", keys.tlk), ("classA", keys.class_a), ("classB", keys.class_b)):
        record = _record_in(wrapper)
        if record is not None:
            found.append(ViewKey.from_record(record, slot))
    return found


async def fetch_recoverable_shares(
    client: AsyncCloudKitClient,
    peer_id: str,
) -> list[ShareEntry]:
    """
    Ask which key shares a peer is entitled to receive.

    Read-only, and needs no membership: the question is what *that* peer can receive, and
    the answer is wrapped to a key escrow recovery already yielded.

    :param client: A CloudKit client on the keychain container.
    :param peer_id: The recovered peer's identifier, which its escrow record's label
        already carries.
    """
    request = cf.FetchRecoverableTlkSharesRequest(for_peer=peer_id)

    serialized = await client.function_invoke(
        CUTTLEFISH_SERVICE,
        METHOD_FETCH_RECOVERABLE_TLK_SHARES,
        request.SerializeToString(),
    )

    response = cf.FetchRecoverableTlkSharesResponse()
    try:
        response.ParseFromString(serialized)
    except DecodeError as e:
        msg = (
            f"CloudKit accepted the call but its result did not decode as a"
            f" {METHOD_FETCH_RECOVERABLE_TLK_SHARES} response ({e})."
            f" Its top-level fields are: {describe_wire(serialized)}"
        )
        raise ShareError(msg) from None

    logger.info("Peer %s is entitled to %d share(s)", peer_id, len(response.shares))

    # The wire shape settled this message's schema once, and is worth keeping for the next
    # response that does not decode. Two things keep it from being a wall:
    #
    # DEBUG, because a working run does not need it and printing it every time buries the
    # count above, which a working run does need.
    #
    # Top level only. At depth 2 this is five kilobytes of the same nested shape repeated
    # once per share -- and when an individual entry really is the problem,
    # `decode_share_entry` describes that one entry on the way to raising. So the depth is
    # duplicated where it is useful and noise where it is not.
    logger.debug("Share response fields: %s", describe_wire(serialized, depth=0))

    entries: list[ShareEntry] = []
    for index, raw in enumerate(response.shares):
        try:
            entry = decode_share_entry(raw)
        except ShareError as e:
            logger.warning("Entry %d could not be read: %s", index, e)
            continue
        if entry is not None:
            entries.append(entry)

    views = sorted({entry.view for entry in entries if entry.view})
    logger.info("Read %d share(s) across views: %s", len(entries), ", ".join(views))
    return entries


def unwrap_share(
    entry: ShareEntry,
    encryption_key: ec.EllipticCurvePrivateKey,
    directory: PeerDirectory | None = None,
    *,
    alternates: Mapping[str, ec.EllipticCurvePrivateKey] | None = None,
    expected_receiver: str | None = None,
) -> KeyShare:
    """
    Unwrap one share with the recovered peer's encryption key.

    Failures are recorded on the returned share rather than raised: a listing legitimately
    contains views this client has no interest in, and one unreadable share should not
    hide the readable ones.

    :param directory: The trust circle's peers. Supplying a populated one means a share
        whose sender is not in the circle is **refused** rather than unwrapped. An *empty*
        directory is treated as no directory at all rather than as "every sender is
        unknown" -- refusing every share because the circle could not be read reports a
        verification failure where the real problem is nothing to verify against.
    :param alternates: Other keys recovery yielded, tried if the encryption key does not
        work and named in the diagnostic. Which of a peer's two keys a share is wrapped to
        is a question the share itself answers, and trying both costs nothing.
    :param expected_receiver: The recovered peer's identifier. Comparing it against the
        share's `receiver` is the same evidence as the declared key, for free and without
        depending on that field being populated -- and it is worth having independently,
        because if the receiver does not match then no cipher parameter was ever going to
        help and the ECIES failure says nothing about the construction.
    """
    share = entry.share
    candidates: dict[str, ec.EllipticCurvePrivateKey] = {"encryption": encryption_key}
    candidates.update(alternates or {})

    sender = directory.get(share.sender) if directory is not None else None
    sender_known = sender is not None
    sender_verified = verify_share_signature(share, sender) if sender is not None else False

    def failed(reason: str, wrapped: bytes = b"") -> KeyShare:
        return KeyShare(
            service=entry.view,
            key_id="",
            sender=share.sender,
            receiver=share.receiver,
            wrapped_key=wrapped,
            sender_known=sender_known,
            sender_verified=sender_verified,
            error=reason,
        )

    if directory is not None and len(directory) and not sender_known:
        return failed(
            f"the sending peer {share.sender!r} is not in the trust circle, so nothing"
            " identifies who produced this key",
        )

    if not share.wrapped_key:
        return failed("this share carries no wrapped key")

    # A share names the key it was wrapped to, so "wrong key" and "wrong construction"
    # are distinguishable from the data rather than guessed at afterwards. They fail
    # identically -- an authentication tag that does not check -- and lead in opposite
    # directions: one back to how the key was recovered, the other to the ECIES
    # parameters. This verdict is reported whether or not anything decrypts, because a
    # failure that cannot say which of the two it is sends the next hour the wrong way.
    verdict = describe_receiver_key(share, candidates)

    if expected_receiver is not None and share.receiver != expected_receiver:
        return failed(
            f"this share is for peer {share.receiver!r}, not the recovered peer"
            f" {expected_receiver!r}, so no key we hold was ever going to open it",
            share.wrapped_key,
        )

    # If the share names one of our keys, that is the key -- otherwise every key we hold
    # is worth trying, since a wrong one costs microseconds and only a tag check.
    named = matching_candidate(share.receiver_public_encryption_key, candidates)
    order = [named] if named is not None else list(candidates)

    plaintext = None
    for name in order:
        with contextlib.suppress(ShareError):
            plaintext = sfies_decrypt_archive(candidates[name], share.wrapped_key)
        if plaintext is not None:
            if name != "encryption":
                logger.warning(
                    "This share unwrapped under the %s key, not the encryption key",
                    name,
                )
            break

    if plaintext is None:
        return failed(
            f"nothing authenticated as an ECIES ciphertext under {' or '.join(order)}."
            f" The share says {verdict}. The archive holds:"
            f" {describe_archive(share.wrapped_key)}",
            share.wrapped_key,
        )

    wrapped = share.wrapped_key

    return KeyShare(
        service=entry.view,
        key_id="",
        sender=share.sender,
        receiver=share.receiver,
        wrapped_key=wrapped,
        sender_known=sender_known,
        sender_verified=sender_verified,
        plaintext=plaintext,
        view_keys=unwrap_view_keys(entry.view_keys, plaintext),
    )


def matching_candidate(
    declared: bytes,
    candidates: Mapping[str, ec.EllipticCurvePrivateKey],
) -> str | None:
    """
    Find which of our keys a share names as its receiver, if any.

    Compares by meaning rather than by bytes: a key named as a SubjectPublicKeyInfo and
    the same key as a bare point are the same key.
    """
    wanted = _load_point(declared) or declared

    for name, key in candidates.items():
        if public_point(key) == wanted:
            return name
    return None


def describe_receiver_key(
    share: ShareRecord,
    candidates: Mapping[str, ec.EllipticCurvePrivateKey],
) -> str:
    """
    Say what the share's declared receiver key establishes about our keys.

    This exists because a wrong key and a wrong cipher construction **fail identically**
    -- an authentication tag that does not check -- and lead in opposite directions. The
    share names the key it was wrapped to, so the question is already answered in the
    data; not asking it is what turns a settled fact into a search.

    Note that "the share names no key" and "the share names ours" are very different
    findings and must not collapse into one silence: the first establishes nothing, the
    second establishes that the key is right and the construction is what remains.
    """
    declared = share.receiver_public_encryption_key
    if not declared:
        return "it names no receiver key, so nothing here confirms the key is right"

    match = matching_candidate(declared, candidates)
    if match is not None:
        return (
            f"it is addressed to our {match} key, so that key is right and the"
            " construction is what remains"
        )

    ours = ", ".join(f"{name} {public_point(key)[:6].hex()}…" for name, key in candidates.items())
    return (
        f"it is addressed to {declared[:6].hex()}… ({len(declared)} bytes), which is"
        f" none of ours ({ours}) -- so the recovery is what to look at, not the cipher"
    )


def _load_point(data: bytes) -> bytes | None:
    """Read a public key however it is written, and render its uncompressed point."""
    from findmy.keychain.peers import load_public_key  # noqa: PLC0415 -- avoids a cycle

    key = load_public_key(data)
    if key is None:
        return None
    return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def parse_key_material(plaintext: bytes) -> cf.TlkKeyMaterial:
    """
    Read what a decrypted share expands to.

    Four members, and **field 4 is the view's top-level key itself** -- symmetric key
    bytes, not a container holding a key and not an EC private key. Reading it as an EC
    scalar fails on every share, because the bytes were never that.

    :raises ShareError: If the plaintext is not a key message.
    """
    material = cf.TlkKeyMaterial()
    try:
        material.ParseFromString(plaintext)
    except DecodeError:
        msg = (
            "A share decrypted but its plaintext is not a key message. Its top-level"
            f" fields are: {describe_wire(plaintext)}"
        )
        raise ShareError(msg) from None

    if not material.key:
        msg = (
            "A share decrypted to a key message carrying no key at field 4. Its"
            f" top-level fields are: {describe_wire(plaintext)}"
        )
        raise ShareError(msg)

    return material


def unwrap_class_key(wrapped: bytes, top_level_key: bytes) -> bytes:
    """
    Unwrap a class key with the view's top-level key.

    **This is not the ECIES that opened the share.** It is AES-SIV (RFC 5297) with CMAC,
    keyed with the top-level key, and with **no associated data at all** -- an empty
    *vector* of headers, which is not the same thing as a vector holding one empty header.
    The two produce different results, and the wrong one fails as an authentication
    failure with nothing to say it was the header count.

    :raises ShareError: If it does not authenticate.
    """
    try:
        # None is the empty vector. Passing [b""] would be one empty header instead.
        return AESSIV(top_level_key).decrypt(wrapped, None)
    except InvalidTag:
        msg = "The class key did not authenticate under the view's top-level key"
        raise ShareError(msg) from None
    except ValueError as e:
        msg = f"The top-level key is not a usable AES-SIV key ({len(top_level_key)} bytes): {e}"
        raise ShareError(msg) from None


@dataclass(frozen=True)
class ViewKeyring:
    """
    A view's keys, addressable both ways.

    Two indexes because two things need them and they ask differently: a person reads
    `tlk`/`classA`/`classB`, while a keychain item's `parentkeyref` names a **UUID**.
    Keeping only the names is what makes an item unmatchable.
    """

    by_uuid: dict[str, bytes] = field(default_factory=dict)
    by_slot: dict[str, bytes] = field(default_factory=dict)

    def get(self, uuid: str) -> bytes | None:
        """Look up the key an item's `parentkeyref` names."""
        return self.by_uuid.get(uuid)

    def __len__(self) -> int:
        """How many keys this holds."""
        return len(self.by_slot)

    def __bool__(self) -> bool:
        """Whether it holds any key."""
        return bool(self.by_slot)

    def describe(self) -> str:
        """Name the keys and their sizes, for a caller reporting to a person."""
        return ", ".join(f"{n}: {len(k)} bytes" for n, k in sorted(self.by_slot.items()))


def unwrap_view_keys(keys: list[ViewKey], share_plaintext: bytes) -> ViewKeyring:
    """
    Assemble a view's three keys.

    **Three, not four.** The top-level key is not wrapped anywhere -- it *is* what the
    share decrypted to, so looking for a fourth thing to unwrap finds a `tlk` record whose
    contents were already in hand. Only `classA` and `classB` are wrapped, and under that
    top-level key rather than under any peer key.

    Keep all three: the top-level key alone is not what a record's protection structure is
    matched against, so discarding the class keys leaves the interesting records
    undecryptable for a reason nothing would explain.

    Failures are logged rather than raised, since a class key this client cannot read is
    not a reason to discard the top-level key it already has.
    """
    try:
        material = parse_key_material(share_plaintext)
    except ShareError as e:
        logger.warning("%s", e)
        return ViewKeyring()

    by_uuid = {material.uuid: material.key} if material.uuid else {}
    by_slot = {"tlk": material.key}

    for key in keys:
        if key.slot == "tlk":
            # Already held: this record carries the key the share itself decrypted to.
            # Note its UUID is still worth taking, since the message and the record are
            # two sources for the same identifier and either may be the one an item names.
            if key.uuid:
                by_uuid[key.uuid] = material.key
            continue
        if not key.wrapped_key:
            continue

        name = key.slot or key.key_class
        try:
            unwrapped = unwrap_class_key(key.wrapped_key, material.key)
        except ShareError as e:
            logger.warning("View key %r did not unwrap: %s", name, e)
            continue

        by_slot[name] = unwrapped
        if key.uuid:
            by_uuid[key.uuid] = unwrapped

    return ViewKeyring(by_uuid=by_uuid, by_slot=by_slot)


def summarise(shares: Sequence[KeyShare]) -> str:
    """Describe what a set of shares yielded, for a caller reporting to a person."""
    readable = [s for s in shares if s.plaintext is not None]
    services = sorted({s.service for s in shares if s.service})

    parts = [f"{len(readable)}/{len(shares)} unwrapped"]
    if services:
        parts.append(f"views: {', '.join(services)}")
    return "; ".join(parts)


def public_point(key: ec.EllipticCurvePrivateKey) -> bytes:
    """Render a key's uncompressed public point, to compare against a share's receiver."""
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


# --------------------------------------------------------------------------------------
# Creating a share (§6.9.2)
# --------------------------------------------------------------------------------------

SHARE_CURVE_P384 = 4
"""What `curve` names for P-384. The rest of the enumeration is unspecified."""

SHARE_EPOCH = 1
"""What `epoch` carries on a share this client creates."""

# Apple's own key for the ephemeral point, spelled as Apple spells it: `Externa`, with no
# final `l`. A reader can match the fragment and forgive it; a writer cannot. The correctly
# spelled name is one Apple's unarchiver will not find the ephemeral key under, and the
# failure arrives as a share that authenticates against nothing.
MEMBER_POINT = "SFEphemeralSenderPublicKeyExternaRepresentation"
MEMBER_CIPHERTEXT = "SFCiphertext"
MEMBER_CODE = "SFIESAuthenticationCode"


def sfies_encrypt(
    receiver_public: ec.EllipticCurvePublicKey,
    plaintext: bytes,
    ephemeral: ec.EllipticCurvePrivateKey | None = None,
) -> SfiesParts:
    """
    Encrypt to a peer's public key, the inverse of :func:`sfies_decrypt`.

    A fresh ephemeral key pair each time -- its uncompressed point is both what gets
    archived and the shared info the derivation is bound to, so the two cannot disagree.

    :param receiver_public: The receiving peer's encryption key.
    :param plaintext: The serialised key material.
    :param ephemeral: The ephemeral key. Generated if not supplied; a parameter so a test
        can produce the same ciphertext twice.
    :returns: The three parts, with the ciphertext at its true length -- the overrun that
        §6.9.2 requires is added when archiving, since it is a property of the archived
        member rather than of the ciphertext.
    """
    ephemeral = ephemeral or ec.generate_private_key(receiver_public.curve)
    point = public_point(ephemeral)

    shared = ephemeral.exchange(ec.ECDH(), receiver_public)
    material = _x963_kdf(shared, point, _SFIES_KEY_LENGTH + _SFIES_NONCE_LENGTH)

    encryptor = Cipher(
        algorithms.AES(material[:_SFIES_KEY_LENGTH]),
        modes.GCM(material[_SFIES_KEY_LENGTH:]),
    ).encryptor()
    body = encryptor.update(plaintext) + encryptor.finalize()

    return SfiesParts(point=point, ciphertext=body, code=encryptor.tag)


def archive_sfies(parts: SfiesParts) -> bytes:
    """
    Write the three parts as the keyed archive a share carries.

    Two things here are not what a fresh implementation would produce, and both are the
    format rather than a quirk to tidy:

    **The ciphertext member is longer than the ciphertext.** Apple's writer sizes that
    buffer for all three parts and archives it untrimmed, and Apple's reader subtracts that
    much unconditionally -- so a tightly-sized ciphertext arrives with its last bytes cut
    off and fails authentication. The pad is derived from the other two members rather than
    written as 113, because a different curve makes it a different number. **Zeros**, not
    the uninitialised heap Apple leaks there: the overrun has to exist, its contents do not
    have to be anybody's memory.

    **The ephemeral point's member name is misspelled**, and that spelling is the wire
    format -- see :data:`MEMBER_POINT`.

    The envelope is a plain dictionary. Nothing declares `$class` naming `SFIESCiphertext`
    or reconstructs its hierarchy, because Apple's side finds the members by name; the one
    class that matters is the `NSMutableData` on the point, which is a property of that
    member rather than of the envelope.
    """
    overrun = len(parts.point) + len(parts.code)

    archive = {
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
        "$top": {"root": plistlib.UID(1)},
        "$objects": [
            "$null",
            {
                MEMBER_CIPHERTEXT: plistlib.UID(2),
                MEMBER_CODE: plistlib.UID(3),
                MEMBER_POINT: plistlib.UID(4),
            },
            parts.ciphertext + bytes(overrun),
            parts.code,
            {"NS.data": parts.point, "$class": plistlib.UID(5)},
            {"$classes": ["NSMutableData", "NSData", "NSObject"], "$classname": "NSMutableData"},
        ],
    }

    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


def make_share(
    plaintext: bytes,
    *,
    peer_id: str,
    encryption_key: ec.EllipticCurvePublicKey,
    signing_key: ec.EllipticCurvePrivateKey,
) -> cf.TlkShare:
    """
    Build one `TlkShare`: a view key, re-addressed to the joining peer.

    **A joining peer shares to itself.** Both `sender` and `receiver` are the new peer's
    identifier and the wrapping key is its own encryption key, which reads like a no-op and
    is not: the keys were recovered from a *different* peer's shares, and Cuttlefish only
    recognises a peer as holding a view key when a share addressed to that peer says so.
    The join is where the keys are re-addressed from the recovered identity to this one.

    `service` and `keyId` come from the key material itself rather than from the share --
    the CloudKit record form carries neither, which is a fact about reading one.

    :param plaintext: The serialised `TlkKeyMaterial`, as recovered.
    :param peer_id: The new peer's identifier, which is both ends of this share.
    :param encryption_key: The new peer's public encryption key.
    :param signing_key: The new peer's signing key, for the share's own signature.
    """
    material = parse_key_material(plaintext)
    if not material.zone_name or not material.uuid:
        msg = (
            "This key material names no zone or no uuid, so a share built from it would"
            f" carry no service or key id: {material}"
        )
        raise ShareError(msg)

    wrapped = archive_sfies(sfies_encrypt(encryption_key, plaintext))

    # Rendered through the same type the reader verifies, so the signature is built by the
    # one function that knows the field order, the widths and the endianness.
    signed = share_signed_data(
        ShareRecord(
            sender=peer_id,
            receiver=peer_id,
            receiver_public_encryption_key=encryption_key.public_bytes(
                Encoding.X962,
                PublicFormat.UncompressedPoint,
            ),
            wrapped_key=wrapped,
            signature=b"",
            curve=SHARE_CURVE_P384,
            epoch=SHARE_EPOCH,
            # Omitted from the message and signed as zero. Both, always.
            poisoned=0,
            version=0,
        ),
    )

    return cf.TlkShare(
        service=material.zone_name,
        key_id=material.uuid,
        curve=SHARE_CURVE_P384,
        epoch=SHARE_EPOCH,
        receiver=peer_id,
        sender=peer_id,
        # base64 of the uncompressed point, not the SPKI -- the one place in this stage
        # where a public key does not travel as DER.
        receiver_public_encryption_key=base64.b64encode(
            encryption_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
        ).decode(),
        wrapped_key=base64.b64encode(wrapped).decode(),
        signature=base64.b64encode(
            signing_key.sign(signed, ec.ECDSA(hashes.SHA256())),
        ).decode(),
    )
