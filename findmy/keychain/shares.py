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
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from google.protobuf.message import DecodeError

from findmy.cloudkit.constants import CUTTLEFISH_SERVICE
from findmy.cloudkit.proto import cloudkit_pb2 as ck
from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.cloudkit.records import named_fields
from findmy.errors import UnhandledProtocolError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from findmy.cloudkit.client import AsyncCloudKitClient

    from .peers import Peer, PeerDirectory

logger = logging.getLogger(__name__)

METHOD_FETCH_RECOVERABLE_TLK_SHARES = "fetchRecoverableTLKShares"

# Apple's ECIES puts an ephemeral public key in front of an AES-GCM ciphertext. For P-384
# that point is 97 bytes uncompressed; the tag is the trailing 16.
_EPHEMERAL_POINT_LENGTH = 97
_GCM_TAG_LENGTH = 16


class ShareError(UnhandledProtocolError):
    """Raised when a key share cannot be read."""


def _decode_base64(value: str) -> bytes:
    """
    Take a share field from base64 text to bytes.

    `TlkShare` declares its binary members as strings, so everything binary arrives this
    way. A value that is not base64 is returned as its own bytes rather than lost.
    """
    try:
        return base64.b64decode(value)
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


def ecies_parts(blobs: list[bytes], point_length: int) -> list[tuple[bytes, bytes, bytes]]:
    """
    Assemble candidate (point, body, tag) triples from an archive's members.

    The parts may arrive concatenated in one member or split across several, and which
    member is which is not stated -- so both readings are offered and GCM's tag decides.
    A point is recognised by its length and leading byte, a tag by being sixteen bytes.
    """
    points = [b for b in blobs if len(b) == point_length and b[:1] == b"\x04"]
    tags = [b for b in blobs if len(b) == _GCM_TAG_LENGTH]
    bodies = [b for b in blobs if len(b) not in (point_length, _GCM_TAG_LENGTH)]

    triples = [(point, body, tag) for point in points for body in bodies for tag in tags]

    # A member that already carries all three, concatenated.
    triples.extend(
        (blob[:point_length], blob[point_length:-_GCM_TAG_LENGTH], blob[-_GCM_TAG_LENGTH:])
        for blob in blobs
        if len(blob) > point_length + _GCM_TAG_LENGTH and blob[:1] == b"\x04"
    )

    return triples


# --------------------------------------------------------------------------------------
# ECIES
# --------------------------------------------------------------------------------------


def _x963_kdf(shared: bytes, shared_info: bytes, length: int, digest: str = "sha256") -> bytes:
    """
    ANSI X9.63 key derivation, as Apple's ECIES uses it.

    :param digest: Which hash. Not fixed at SHA-256: a construction for a P-384 key may
        pair the curve with SHA-384, and the two are indistinguishable without trying.
    """
    out = b""
    counter = 1
    while len(out) < length:
        block = shared + counter.to_bytes(4, "big") + shared_info
        out += hashlib.new(digest, block).digest()
        counter += 1
    return out[:length]


@dataclass(frozen=True)
class EciesVariant:
    """
    One way of turning a shared secret into an AES-GCM key, IV and AAD.

    The specification names the construction -- ephemeral point, X9.63 KDF, AES-GCM -- but
    not the parameters that a reader cannot infer and a wrong choice does not announce.
    Every combination below decrypts in microseconds and fails on the tag, so trying them
    all costs nothing; guessing one and shipping it costs a round trip against a real
    account for every guess. The name of whichever authenticates is reported, so the
    specification can record the answer rather than the search.
    """

    digest: str
    key_length: int
    iv_length: int
    derived_iv: bool
    shared_info_is_point: bool
    aad_is_point: bool

    @property
    def name(self) -> str:
        """A short label naming what this variant chose, for reporting a match."""
        iv = f"{'derived' if self.derived_iv else 'zero'}-iv{self.iv_length}"
        return (
            f"{self.digest}/aes{self.key_length * 8}-gcm/{iv}"
            f"/info={'point' if self.shared_info_is_point else 'empty'}"
            f"/aad={'point' if self.aad_is_point else 'empty'}"
        )


def _ecies_variants() -> list[EciesVariant]:
    """Every parameter combination worth trying, cheapest-first is irrelevant here."""
    return [
        EciesVariant(digest, key_length, iv_length, derived_iv, info_point, aad_point)
        for digest in ("sha256", "sha384")
        for key_length in (16, 32)
        # A GCM nonce is twelve bytes by specification, but Apple's ECIES has been seen
        # with a sixteen-byte all-zero one, and the two authenticate differently.
        for iv_length in (12, 16)
        for derived_iv in (False, True)
        for info_point in (True, False)
        for aad_point in (True, False)
    ]


def ecies_decrypt(private_key: ec.EllipticCurvePrivateKey, ciphertext: bytes) -> bytes:
    """
    Decrypt an Apple ECIES ciphertext held in one blob.

    Kept for a payload that arrives already concatenated; a share's arrives inside an
    archive, for which :func:`ecies_decrypt_archive` is the entry point.
    """
    point_length = 1 + 2 * ((private_key.curve.key_size + 7) // 8)

    starts = [i for i, byte in enumerate(ciphertext) if byte == 0x04]
    starts = [i for i in starts if len(ciphertext) - i > point_length + _GCM_TAG_LENGTH][:8]

    if not starts:
        msg = (
            f"No uncompressed point begins anywhere in these {len(ciphertext)} bytes, so"
            f" this is not an ECIES ciphertext for a {private_key.curve.name} key."
            f" It starts {ciphertext[:16].hex()}"
        )
        raise ShareError(msg)

    for start in starts:
        result = _try_ecies(private_key, ciphertext, start, point_length)
        if result is not None:
            return result

    msg = (
        "None of the ECIES variants authenticated at any plausible offset. Either this"
        " key does not receive this share, or the construction differs from the ones"
        " tried."
    )
    raise ShareError(msg)


def ecies_decrypt_archive(private_key: ec.EllipticCurvePrivateKey, archive: bytes) -> bytes:
    """
    Decrypt an ECIES ciphertext that arrives as an archived structure.

    The archive holds the ephemeral point, the ciphertext and the tag as **separate
    members**, not as one blob -- which is what "expands to an ECIES ciphertext structure"
    means and what a reader expecting a single payload gets wrong. Which member is which
    is not stated, so they are recognised by shape and every combination is tried; the
    authentication tag makes a wrong pairing free to reject.

    :raises ShareError: If nothing in the archive authenticates.
    """
    blobs = archived_blobs(archive)
    point_length = 1 + 2 * ((private_key.curve.key_size + 7) // 8)

    for point, body, tag in ecies_parts(blobs, point_length):
        result = _decrypt_ecies_parts(private_key, point, body, tag)
        if result is not None:
            return result

    msg = (
        "Nothing in this archive authenticated as an ECIES ciphertext for a"
        f" {private_key.curve.name} key. It holds: {describe_archive(archive)}"
    )
    raise ShareError(msg)


def _try_ecies(
    private_key: ec.EllipticCurvePrivateKey,
    ciphertext: bytes,
    start: int,
    point_length: int,
) -> bytes | None:
    """Try one starting offset, across the key-derivation variants."""
    return _decrypt_ecies_parts(
        private_key,
        ciphertext[start : start + point_length],
        ciphertext[start + point_length : -_GCM_TAG_LENGTH],
        ciphertext[-_GCM_TAG_LENGTH:],
    )


def _decrypt_ecies_parts(
    private_key: ec.EllipticCurvePrivateKey,
    point: bytes,
    body: bytes,
    tag: bytes,
) -> bytes | None:
    """Try one (point, body, tag) triple across the key-derivation variants."""
    try:
        ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(private_key.curve, point)
    except ValueError:
        return None

    shared = private_key.exchange(ec.ECDH(), ephemeral)

    for variant in _ecies_variants():
        shared_info = point if variant.shared_info_is_point else b""
        length = variant.key_length + (variant.iv_length if variant.derived_iv else 0)
        material = _x963_kdf(shared, shared_info, length, variant.digest)

        key = material[: variant.key_length]
        iv = material[variant.key_length :] if variant.derived_iv else bytes(variant.iv_length)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        if variant.aad_is_point:
            decryptor.authenticate_additional_data(point)
        try:
            plaintext = decryptor.update(body) + decryptor.finalize()
        except InvalidTag:
            continue

        logger.info("ECIES variant %s decrypted a share", variant.name)
        return plaintext

    return None


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

    view_keys: list[bytes] = field(default_factory=list)
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


def describe_wire(data: bytes) -> str:
    """
    Describe a protobuf payload's top-level fields without knowing its schema.

    Used when a message does not decode as expected. Naming the field numbers, wire types
    and sizes that actually arrived turns "it did not parse" into something someone can
    act on, which is worth more than any guess about why.
    """
    from findmy.cloudkit.records import iter_wire_fields  # noqa: PLC0415

    kinds = {0: "varint", 1: "fixed64", 2: "bytes", 5: "fixed32"}
    parts = []
    try:
        for number, wire, payload in iter_wire_fields(data):
            size = f" {len(payload)}B" if wire == 2 else ""
            parts.append(f"{number}:{kinds.get(wire, wire)}{size}")
    except Exception:  # noqa: BLE001 -- a malformed payload is exactly what this describes
        parts.append("<unparseable>")

    return ", ".join(parts) or "<empty>"


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

    @classmethod
    def from_record(cls, record: ck.Record) -> ViewKey:
        """Read a `synckey` record."""
        fields = named_fields(record)
        key_class = fields.get("class")
        upload = fields.get("uploadver")

        return cls(
            key_class=key_class if isinstance(key_class, str) else "",
            wrapped_key=_as_bytes(fields.get("wrappedkey")),
            upload_version=int(upload) if isinstance(upload, (int, float)) else 0,
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


def share_signed_data(share: ShareRecord) -> bytes:
    """
    Assemble the bytes a key share's signature covers.

    Seven fields in a fixed order, and **the integers are little-endian** -- which is the
    trap. Everything else in this protocol is big-endian: CloudKit's protobuf, the
    KeyVault framing, the PCS structures. This one construction is not, and getting it
    wrong produces a signature that will not verify with nothing to say why.
    """
    return b"".join(
        (
            _little_endian(share.version, 4),
            share.receiver.encode("utf-8"),
            share.sender.encode("utf-8"),
            share.wrapped_key,
            _little_endian(share.curve, 8),
            _little_endian(share.epoch, 8),
            _little_endian(share.poisoned, 4),
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
        logger.warning("Entry for %s carries no readable share record", entry.service)
        return None

    return ShareEntry(
        view=entry.service,
        share=ShareRecord.from_record(record),
        view_keys=read_view_keys(entry.viewkeys),
    )


def read_view_keys(keys: cf.ViewKeySet) -> list[ViewKey]:
    """
    Read a view's keys out of their wrappers.

    Their field numbers are assumed rather than stated, and a wrong one yields no key
    rather than an error -- so the count is worth reporting instead of trusting.
    """
    found: list[ViewKey] = []
    for wrapper in (keys.tlk, keys.class_a, keys.class_b):
        record = _record_in(wrapper)
        if record is not None:
            found.append(ViewKey.from_record(record))
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

    logger.info(
        "Peer %s is entitled to %d share(s); response fields: %s",
        peer_id,
        len(response.shares),
        describe_wire(serialized),
    )

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
    """
    share = entry.share

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
    # are distinguishable before decrypting rather than guessed at afterwards. They fail
    # identically -- an authentication tag that does not check -- and the two lead in
    # opposite directions: one back to how the encryption key was recovered, the other to
    # the ECIES parameters. Saying which is why this check is worth its few lines.
    mismatch = _receiver_key_mismatch(share, encryption_key)
    if mismatch is not None:
        return failed(mismatch, share.wrapped_key)

    try:
        plaintext = ecies_decrypt_archive(encryption_key, share.wrapped_key)
    except ShareError as e:
        return failed(str(e), share.wrapped_key)

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


def _receiver_key_mismatch(
    share: ShareRecord,
    encryption_key: ec.EllipticCurvePrivateKey,
) -> str | None:
    """
    Check that this key is the one the share was wrapped to.

    :returns: A description of the mismatch, or None if the keys agree -- or if the share
        does not say, which is not a mismatch and must not be reported as one.
    """
    declared = share.receiver_public_encryption_key
    if not declared:
        return None

    ours = public_point(encryption_key)
    if declared == ours:
        return None

    # A key can be named as a bare point or wrapped in a SubjectPublicKeyInfo, so compare
    # what they mean rather than how they are written.
    loaded = _load_point(declared)
    if loaded is not None and loaded == ours:
        return None

    return (
        f"this share is wrapped to a different key than the one recovered: it names"
        f" {declared[:8].hex()}… ({len(declared)} bytes) and the recovered encryption key"
        f" is {ours[:8].hex()}…. The recovery is what to look at, not the cipher"
    )


def _load_point(data: bytes) -> bytes | None:
    """Read a public key however it is written, and render its uncompressed point."""
    from findmy.keychain.peers import load_public_key  # noqa: PLC0415 -- avoids a cycle

    key = load_public_key(data)
    if key is None:
        return None
    return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def unwrap_view_keys(keys: list[ViewKey], share_plaintext: bytes) -> list[bytes]:
    """
    Unwrap a view's keys with the key the share yielded.

    **These are wrapped under the share's key, not under a peer key** -- a different key
    from the one that opened the share, and the same ECIES construction. Keep all of them:
    the top key alone is not what a record's protection structure is matched against, so
    discarding the class keys leaves the interesting records undecryptable for a reason
    nothing would explain.

    Failures are logged rather than raised, since a view key this client cannot read is
    not a reason to discard the share key it already has.
    """
    recovered: list[bytes] = []

    private_key = _share_key_as_private(share_plaintext)
    if private_key is None:
        if keys:
            logger.warning(
                "A share yielded %d bytes that are not an EC private key, so its %d view"
                " key(s) cannot be unwrapped",
                len(share_plaintext),
                len(keys),
            )
        return recovered

    for key in keys:
        if not key.wrapped_key:
            continue
        try:
            recovered.append(ecies_decrypt_archive(private_key, key.wrapped_key))
        except ShareError as e:
            logger.warning("View key %r did not unwrap: %s", key.key_class or "?", e)

    return recovered


def _share_key_as_private(plaintext: bytes) -> ec.EllipticCurvePrivateKey | None:
    """
    Read a share's plaintext as an EC private key.

    The plaintext is a key message -- a UUID, a zone name, a key class and the key bytes --
    and it is the key bytes that unwrap the view keys. Both the whole plaintext and any
    scalar-sized run inside it are tried, since which part is the key is not stated.
    """
    for candidate in _key_candidates(plaintext):
        for curve in (ec.SECP384R1(), ec.SECP256R1()):
            if len(candidate) != (curve.key_size + 7) // 8:
                continue
            try:
                return ec.derive_private_key(int.from_bytes(candidate, "big"), curve)
            except ValueError:
                continue
    return None


def _key_candidates(plaintext: bytes) -> list[bytes]:
    """List the byte runs of a share plaintext that might be the key itself."""
    from findmy.cloudkit.records import iter_wire_fields  # noqa: PLC0415

    candidates = [plaintext]
    with contextlib.suppress(Exception):
        # A plaintext that is not a message is still a candidate in its own right.
        candidates.extend(
            payload for _, wire, payload in iter_wire_fields(plaintext) if wire == 2 and payload
        )
    return candidates


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
