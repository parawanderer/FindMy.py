"""
Reading Find My accessory keys directly from a user's iCloud account.

Apple keeps the key material for a user's AirTags and other Find My accessories in a
private CloudKit container, encrypted under keys held in their iCloud Keychain. This
package speaks enough of that protocol to fetch those records and decrypt them, which
means an accessory can be located without ever exporting anything from a Mac.

The flow has three parts, and only two of them live here:

* **Fetching** (:mod:`~findmy.cloudkit.client`) opens the container and reads the records.
  It needs nothing but a logged-in account, and has no side effects.
* **Decrypting** (:mod:`~findmy.cloudkit.pcs`) turns those records into plaintext, given
  keys from the `Manatee` view of the user's iCloud Keychain.
* **Obtaining those keys** means joining the keychain trust circle by escrow recovery,
  which needs the screen-lock passcode of a device already in the circle. That is
  **not implemented**; see :mod:`findmy.keychain` for how far it goes.

So today this package can retrieve every record in the account and can decrypt them once
somebody hands it the keys, but cannot yet obtain the keys itself.

.. warning::
    Fetching has been exercised against a real account; **decryption has not**. Every
    construction in :mod:`~findmy.cloudkit.pcs` is implemented exactly as specified rather
    than guessed at, but exact is not the same as verified.
"""

from .beacons import (
    AsyncBeaconStore,
    BeaconExportError,
    DecryptedRecord,
    DecryptedRecords,
    RecordGroup,
    accessories_from_records,
    accessory_from_record,
    can_be_located,
    decrypt_record,
    decrypt_records,
    group_records,
    to_beacon_naming_plist,
    to_key_alignment_plist,
    to_owned_beacon_plist,
)
from .client import (
    AsyncCloudKitClient,
    CloudKitContainerInfo,
    CloudKitError,
    RecordSyncPage,
)
from .constants import (
    BEACON_STORE_ZONE,
    SEARCHPARTY_BUNDLE,
    SEARCHPARTY_CONTAINER,
    ClientErrorCode,
    OperationType,
    RecordType,
    ResultCode,
    ValueType,
)
from .pcs import (
    FieldContext,
    MissingKeyError,
    ObjectSignature,
    PCSError,
    ShareProtection,
    UnwrappedProtection,
    compress_public_key,
    decrypt_field,
    describe_protection_signature,
    parse_keychain_private_key,
    unwrap_protection,
    verify_protection_hmac,
    verify_protection_signature,
)
from .records import CloudKitRecord, RecordField, records_from_changes

__all__ = (
    "BEACON_STORE_ZONE",
    "SEARCHPARTY_BUNDLE",
    "SEARCHPARTY_CONTAINER",
    "AsyncBeaconStore",
    "AsyncCloudKitClient",
    "BeaconExportError",
    "ClientErrorCode",
    "CloudKitContainerInfo",
    "CloudKitError",
    "CloudKitRecord",
    "DecryptedRecord",
    "DecryptedRecords",
    "FieldContext",
    "MissingKeyError",
    "ObjectSignature",
    "OperationType",
    "PCSError",
    "RecordField",
    "RecordGroup",
    "RecordSyncPage",
    "RecordType",
    "ResultCode",
    "ShareProtection",
    "UnwrappedProtection",
    "ValueType",
    "accessories_from_records",
    "accessory_from_record",
    "can_be_located",
    "compress_public_key",
    "decrypt_field",
    "decrypt_record",
    "decrypt_records",
    "describe_protection_signature",
    "group_records",
    "parse_keychain_private_key",
    "records_from_changes",
    "to_beacon_naming_plist",
    "to_key_alignment_plist",
    "to_owned_beacon_plist",
    "unwrap_protection",
    "verify_protection_hmac",
    "verify_protection_signature",
)
