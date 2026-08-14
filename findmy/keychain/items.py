"""
Keychain items: the step from a view's keys to the key Stage 5 actually decrypts with.

Implements Stage 3 §6.8.1 of the Find My key-export protocol specification.

**This is the join that was missing.** A 64-byte AES-SIV view key never becomes an EC
private key, and no derivation turns one into the other. The view key decrypts an *item*;
the item's `v_Data` **contains** the EC private key. Two different things, one step apart --
and the type signatures make it concrete, since :mod:`findmy.cloudkit.pcs` takes
`EllipticCurvePrivateKey` and §6.7.0 produces symmetric bytes.

Note the container: the same one Cuttlefish uses, but addressed to a **different bundle**.
Reusing the Cuttlefish client here asks the wrong service.
"""

from __future__ import annotations

import base64
import binascii
import logging
import plistlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from google.protobuf.message import DecodeError

from findmy.cloudkit.client import AsyncCloudKitClient
from findmy.cloudkit.constants import KEYCHAIN_CONTAINER, ValueType
from findmy.cloudkit.proto import cloudkit_pb2 as ck
from findmy.cloudkit.records import CloudKitRecord, records_from_changes, reference_name
from findmy.errors import UnhandledProtocolError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from findmy.reports.account import AsyncAppleAccount

    from .shares import ViewKeyring

logger = logging.getLogger(__name__)

# Same container as Cuttlefish, different bundle. A client that reuses the Cuttlefish
# client here is asking the wrong service, and the failure is a CloudKit error rather than
# anything that names the bundle.
SECURITYD_BUNDLE = "com.apple.securityd"

RECORD_TYPE_ITEM = "item"
RECORD_TYPE_CURRENT_ITEM = "currentitem"

# The `currentitem` pointer naming this project's key. Its own record identifier is the
# tag, so finding the service key is a lookup rather than a scan of the whole view.
SERVICE_KEY_TAG = "com.apple.ProtectedCloudStorage-com.apple.icloud.searchparty"

# The keychain views Stage 5 needs synced.
VIEW_MANATEE = "Manatee"
VIEW_PROTECTED_CLOUD_STORAGE = "ProtectedCloudStorage"

# An item's plaintext is padded to a multiple of this, terminated by PADDING_MARKER with
# zeros after it.
PADDING_BLOCK = 20
PADDING_MARKER = 0x80

# The item's `data` field opens with its initialisation vector.
IV_LENGTH = 16

# `encver` 1 passes exactly four additional-data entries; anything else passes those plus
# the optional PCS fields plus every other field on the record.
ENCVER_MINIMAL = 1

# Names already accounted for in the additional data, which therefore do not join it a
# second time under their own name.
RESERVED_FIELD_NAMES = frozenset(
    {
        "gen",
        "pcspublickey",
        "UUID",
        "data",
        "pcsservice",
        "pcspublicidentity",
        "parentkeyref",
        "uploadver",
        "wrappedkey",
        "encver",
    },
)

# Server-set fields never join the additional data.
SERVER_FIELD_PREFIX = "server_"

# Apple's frameworks count seconds from 2001-01-01, not from the Unix epoch.
APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


class ItemError(UnhandledProtocolError):
    """Raised when a keychain item cannot be read."""


def make_securityd_client(account: AsyncAppleAccount) -> AsyncCloudKitClient:
    """
    Build a CloudKit client for keychain item zones.

    The same container as Cuttlefish and a **different bundle**, which is the whole of the
    difference and the easiest thing here to get wrong.
    """
    return AsyncCloudKitClient(
        account,
        container=KEYCHAIN_CONTAINER,
        bundle=SECURITYD_BUNDLE,
    )


# --------------------------------------------------------------------------------------
# Rendering values for the additional data
# --------------------------------------------------------------------------------------


def _little_endian(value: int, width: int = 8) -> bytes:
    """
    Render an integer little-endian, whatever its sign.

    Little-endian again, as in §6.7.0's signature and against everything else in this
    protocol. Masking rather than requiring an unsigned value, for the reason §6.7.0's
    signature needed it: a real record carries negatives, and raising here would take down
    a whole view rather than one item.
    """
    return (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little")


def _apple_date(seconds: float) -> str:
    """
    Render a CloudKit date as RFC 3339, whole seconds, `Z`.

    The epoch is Apple's rather than Unix's. Stage 5 §8 records that this is **not
    settled** for accessory records, and it is not settled here either -- but no item field
    observed so far is a date, so nothing has exercised it. A caller that hits one gets a
    warning rather than a silent guess.
    """
    stamp = APPLE_EPOCH.timestamp() + seconds
    return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_value(value: ck.Record.Value, name: str = "") -> bytes:
    """
    Render one field's value as the additional data carries it.

    :raises ItemError: If the value is of a type with no stated rendering, since guessing
        one produces an authentication failure that says nothing about which field.
    """
    if value.HasField("string_value"):
        return value.string_value.encode("utf-8")
    if value.HasField("bytes_value"):
        return value.bytes_value
    if value.HasField("signed_value"):
        return _little_endian(value.signed_value)
    if value.HasField("double_value"):
        # Cast to an integer first, then render as one. Not the double's own bytes.
        return _little_endian(int(value.double_value))
    if value.HasField("date_value"):
        date = ck.Date()
        try:
            date.ParseFromString(value.date_value)
        except DecodeError:
            msg = f"Field {name!r} is a date whose payload does not decode"
            raise ItemError(msg) from None
        logger.warning(
            "Field %r is a date, whose epoch this protocol has not settled; if this item"
            " fails to authenticate, that is the first thing to doubt",
            name,
        )
        return _apple_date(date.time).encode("ascii")

    msg = (
        f"Field {name!r} has no rendering for the additional data (type"
        f" {value.type}), and guessing one fails authentication with no diagnostic"
    )
    raise ItemError(msg)


def additional_data(record: CloudKitRecord, parent_uuid: str) -> list[bytes]:
    """
    Assemble the additional data an item's decryption authenticates against.

    A sorted map of name to bytes, of which **only the values are passed**. Three things
    here fail silently and each has cost someone an afternoon:

    - **The sort is the only thing ordering the values.** The names are discarded, so a map
      that preserves insertion order instead yields a wrong order that is stable,
      repeatable, and wrong on every item.
    - **The `wrappedkey` entry is the parent key's UUID**, not the `wrappedkey` field's
      value. The name means two different things one line apart.
    - **`encver` decides how many entries there are**: four for version 1, and for anything
      else those four plus the optional PCS fields plus every other field on the record.

    :param parent_uuid: The UUID `parentkeyref` names -- the `wrappedkey` entry's value.
    """
    fields = record.fields

    def value_of(name: str) -> ck.Record.Value | None:
        entry = fields.get(name)
        return entry.value if entry is not None else None

    encver_value = value_of("encver")
    encver = encver_value.signed_value if encver_value is not None else 0

    gen_value = value_of("gen")
    gen = gen_value.signed_value if gen_value is not None else 0

    entries: dict[str, bytes] = {
        "UUID": record.name.encode("utf-8"),
        "encver": _little_endian(encver),
        "gen": _little_endian(gen),
        # Not the wrappedkey field. The identifier parentkeyref points at.
        "wrappedkey": parent_uuid.encode("utf-8"),
    }

    if encver != ENCVER_MINIMAL:
        for name in ("pcsservice", "pcspublicidentity", "pcspublickey"):
            value = value_of(name)
            if value is not None:
                entries[name] = render_value(value, name)

        for name, entry in fields.items():
            if name in RESERVED_FIELD_NAMES or name.startswith(SERVER_FIELD_PREFIX):
                continue
            entries[name] = render_value(entry.value, name)

    # Sorted by name, then the names dropped. This line is the whole ordering.
    return [entries[name] for name in sorted(entries)]


# --------------------------------------------------------------------------------------
# Decrypting an item
# --------------------------------------------------------------------------------------


def strip_padding(plaintext: bytes) -> bytes:
    """
    Remove an item plaintext's padding.

    Padded to a multiple of twenty bytes, terminated by `0x80` with zeros after it, so this
    walks back over the zeros to that marker and truncates there. The marker is not data.

    :raises ItemError: If anything but a zero is met before the marker, which means the
        decryption is wrong rather than the padding unusual.
    """
    for index in range(len(plaintext) - 1, -1, -1):
        byte = plaintext[index]
        if byte == PADDING_MARKER:
            return plaintext[:index]
        if byte != 0:
            msg = (
                f"The plaintext's padding ends in {byte:#04x} rather than"
                f" {PADDING_MARKER:#04x}, so this did not decrypt correctly"
            )
            raise ItemError(msg)

    msg = "The plaintext is entirely zeros, so it carries no padding marker"
    raise ItemError(msg)


def _decode_base64(value: str) -> bytes:
    """Take a field from base64 text to bytes, or its own bytes if it is not base64."""
    try:
        return base64.b64decode(value)
    except (ValueError, binascii.Error):
        return value.encode()


def _bytes_of(record: CloudKitRecord, name: str) -> bytes:
    """Read a field as bytes, whether it arrived as text or as bytes."""
    entry = record.fields.get(name)
    if entry is None:
        return b""

    value = entry.value
    if value.HasField("bytes_value"):
        return value.bytes_value
    if value.HasField("string_value"):
        return _decode_base64(value.string_value)
    return b""


def parent_key_uuid(record: CloudKitRecord) -> str:
    """
    Read which key unwraps this item.

    `parentkeyref` is a reference whose record identifier is a key **UUID**, matched
    against the UUIDs §6.7.0's keys carry. It is not a class name, so matching on
    `classA`/`classB` finds nothing.
    """
    entry = record.fields.get("parentkeyref")
    if entry is None:
        return ""
    return reference_name(entry.value)


def decrypt_item(record: CloudKitRecord, keyring: ViewKeyring) -> dict[str, Any]:
    """
    Decrypt one keychain item into its dictionary.

    Two AES-SIV operations, which is worth being explicit about because they use different
    keys and only the second takes headers: the view key named by `parentkeyref` unwraps
    the item's own 64-byte key, and *that* decrypts `data`.

    :raises ItemError: If the key is not held, or anything fails to authenticate.
    """
    uuid = parent_key_uuid(record)
    item_key = _item_key(record, keyring, uuid)

    data = _bytes_of(record, "data")
    if len(data) <= IV_LENGTH:
        msg = f"Item {record.name} carries {len(data)} bytes of data, too few to hold an IV"
        raise ItemError(msg)

    iv, ciphertext = data[:IV_LENGTH], data[IV_LENGTH:]

    # The headers are the IV first, then the additional data values in their sorted order.
    headers = [iv, *additional_data(record, uuid)]

    try:
        padded = AESSIV(item_key).decrypt(ciphertext, headers)
    except InvalidTag:
        msg = (
            f"Item {record.name} did not authenticate. Its own key unwrapped correctly, so"
            f" the additional data is what to doubt -- {len(headers) - 1} value(s) after"
            " the IV, and their order comes from sorting their names"
        )
        raise ItemError(msg) from None
    except ValueError as e:
        msg = f"The item key is not a usable AES-SIV key ({len(item_key)} bytes): {e}"
        raise ItemError(msg) from None

    return _as_dictionary(record.name, strip_padding(padded))


def _item_key(record: CloudKitRecord, keyring: ViewKeyring, uuid: str) -> bytes:
    """Unwrap an item's own key with the view key its `parentkeyref` names."""
    if not uuid:
        msg = f"Item {record.name} names no parent key, so nothing says what unwraps it"
        raise ItemError(msg)

    parent = keyring.get(uuid)
    if parent is None:
        msg = (
            f"Item {record.name} is wrapped under key {uuid}, which this client does not"
            f" hold. It holds {len(keyring)}: {keyring.describe()}"
        )
        raise ItemError(msg)

    wrapped = _bytes_of(record, "wrappedkey")
    if not wrapped:
        msg = f"Item {record.name} carries no wrapped key"
        raise ItemError(msg)

    try:
        return AESSIV(parent).decrypt(wrapped, None)
    except InvalidTag:
        msg = (
            f"Item {record.name}'s own key did not unwrap under {uuid}. The key matched by"
            " UUID but did not authenticate, so the view key itself is suspect"
        )
        raise ItemError(msg) from None
    except ValueError as e:
        msg = f"The parent key is not a usable AES-SIV key ({len(parent)} bytes): {e}"
        raise ItemError(msg) from None


def _as_dictionary(name: str, plaintext: bytes) -> dict[str, Any]:
    """Read an item's decrypted plaintext as the property list it is."""
    try:
        parsed = plistlib.loads(plaintext)
    except (plistlib.InvalidFileException, ValueError, EOFError) as e:
        msg = f"Item {name} decrypted but is not a property list: {e}"
        raise ItemError(msg) from None

    if not isinstance(parsed, dict):
        msg = f"Item {name} decrypted to a {type(parsed).__name__}, not a dictionary"
        raise ItemError(msg)

    return parsed


# --------------------------------------------------------------------------------------
# Finding an item
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ViewContents:
    """The records of one keychain view's zone, split by the two types that matter."""

    items: dict[str, CloudKitRecord] = field(default_factory=dict)
    """`item` records, by their own identifier."""

    pointers: dict[str, str] = field(default_factory=dict)
    """`currentitem` tags to the item identifier each names."""

    def follow(self, tag: str) -> CloudKitRecord | None:
        """Resolve a pointer's tag to the item it names."""
        target = self.pointers.get(tag)
        return self.items.get(target) if target is not None else None


def split_view_records(records: Iterable[CloudKitRecord]) -> ViewContents:
    """Sort a view's records into items and pointers, ignoring the other types."""
    items: dict[str, CloudKitRecord] = {}
    pointers: dict[str, str] = {}

    for record in records:
        if record.record_type == RECORD_TYPE_ITEM:
            items[record.name] = record
        elif record.record_type == RECORD_TYPE_CURRENT_ITEM:
            # The pointer's own identifier is the tag; its single field names the item.
            entry = record.fields.get(RECORD_TYPE_ITEM)
            target = reference_name(entry.value) if entry is not None else ""
            if target:
                pointers[record.name] = target
            else:
                logger.warning("Pointer %s names no item", record.name)

    logger.info("View holds %d item(s) and %d pointer(s)", len(items), len(pointers))
    return ViewContents(items=items, pointers=pointers)


def find_by_account(contents: ViewContents, keyring: ViewKeyring, account: bytes) -> dict[str, Any]:
    """
    Find an item by its `acct` attribute, decrypting as it searches.

    This is the other way in, used when a record's protection structure names a key and the
    item holding it must be found. It is a scan and it costs a decryption per item, which
    is why the pointer lookup is preferred where a tag is known -- but the two fail
    differently and both are worth having.

    :param account: Base64 of a compressed public key, as `acct` holds it.
    :raises ItemError: If no item carries that account.
    """
    for name, record in contents.items.items():
        try:
            item = decrypt_item(record, keyring)
        except ItemError as e:
            logger.debug("Item %s did not decrypt while searching: %s", name, e)
            continue
        if _account_bytes(item.get("acct")) == account:
            return item

    msg = (
        f"No item in this view carries acct {account[:12]!r}. Searched"
        f" {len(contents.items)} item(s)"
    )
    raise ItemError(msg)


def _account_bytes(value: object) -> bytes:
    """Read an `acct` attribute as bytes, however the plist stored it."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    return b""


def describe_item(item: dict[str, Any]) -> str:
    """Describe an item's attributes without printing its payload."""
    interesting = ("class", "acct", "agrp", "vwht", "labl", "srvr", "atyp", "pdmn")
    parts = [f"{name}={item[name]!r}" for name in interesting if name in item]

    payload = item.get("v_Data")
    if isinstance(payload, bytes):
        parts.append(f"v_Data={len(payload)} bytes")

    return ", ".join(parts)


async def fetch_view(
    client: AsyncCloudKitClient,
    view: str,
    *,
    continuation_token: bytes | None = None,
) -> ViewContents:
    """
    Enumerate a keychain view's zone.

    **The zone is the view name.** `Manatee` is literally a private zone in the keychain
    container, read with the same paging as any other.

    :param client: A client from :func:`make_securityd_client` -- *not* a Cuttlefish one.
    :param view: The view, e.g. `Manatee`.
    :param continuation_token: Resume an earlier fetch. Keep one per zone.
    """
    changes = [
        change
        async for change in client.iter_records(view, continuation_token=continuation_token)
    ]
    return split_view_records(records_from_changes(changes, view))


def service_key_item(contents: ViewContents, keyring: ViewKeyring) -> dict[str, Any]:
    """
    Read the Find My service key's item, by following its pointer.

    A direct lookup rather than a scan: the `currentitem` whose own identifier is
    :data:`SERVICE_KEY_TAG` names the item holding this project's key.

    :raises ItemError: If the pointer or the item it names is absent.
    """
    record = contents.follow(SERVICE_KEY_TAG)
    if record is None:
        target = contents.pointers.get(SERVICE_KEY_TAG)
        if target is None:
            msg = (
                f"This view has no pointer tagged {SERVICE_KEY_TAG}. It has"
                f" {len(contents.pointers)}: {', '.join(sorted(contents.pointers))}"
            )
        else:
            msg = (
                f"The pointer tagged {SERVICE_KEY_TAG} names item {target}, which is not"
                " in this view"
            )
        raise ItemError(msg)

    item = decrypt_item(record, keyring)
    logger.info("Service key item: %s", describe_item(item))
    return item


def payload_of(item: dict[str, Any]) -> bytes:
    """
    Read an item's `v_Data`, which is where the key lives.

    :raises ItemError: If it is absent or not bytes.
    """
    payload = item.get("v_Data")
    if not isinstance(payload, bytes) or not payload:
        msg = (
            "This item carries no v_Data, so it holds no key. Its attributes are:"
            f" {describe_item(item)}"
        )
        raise ItemError(msg)
    return payload


def unencrypted_types() -> Sequence[int]:
    """
    Which value types an item record's fields arrive as.

    Kept as a function rather than inlined to make the point that **an item's own fields
    are not PCS-encrypted**: the item's payload is, by the two AES-SIV steps above. A
    reader expecting Stage 4's `is_encrypted` fields here finds none.
    """
    return (ValueType.BYTES_TYPE, ValueType.STRING_TYPE, ValueType.INT64_TYPE)
