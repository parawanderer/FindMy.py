"""
Constants for CloudKit's client protocol.

Values whose enumeration the protocol specification admits is incomplete live here rather
than in the .proto schema, because a proto2 enum silently discards a value it does not
know about: an unrecognised error code would decode as absent rather than as itself.
"""

from __future__ import annotations

from enum import IntEnum

# The private container holding Find My accessory data. "Search party" is Apple's internal
# name for the Find My network -- the same service the searchPartyToken belongs to.
SEARCHPARTY_CONTAINER = "com.apple.icloud.searchparty"
SEARCHPARTY_BUNDLE = "com.apple.icloud.searchpartyd"

# The zone within that container that accessory records live in. The container also holds
# CloudKit's empty `_defaultZone`.
BEACON_STORE_ZONE = "BeaconStore"

# Opening a container. Note this is addressed to the gateway, unlike record operations,
# which are addressed to the URL this call hands back.
CK_APP_INIT_URL = "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit"

# Paths beneath a service's base URL. The "changes" operations are called sync, which is
# not obvious from their message names.
PATH_ZONE_RETRIEVE = "/api/client/zone/retrieve"
PATH_ZONE_SYNC = "/api/client/zone/sync"
PATH_RECORD_RETRIEVE = "/api/client/record/retrieve"
PATH_RECORD_SYNC = "/api/client/record/sync"
PATH_RECORD_SAVE = "/api/client/record/save"

# Server-side function invocation, beneath the code gateway rather than the database one.
PATH_CODE_INVOKE = "/api/client/code/invoke"

# The container Cuttlefish -- the keychain trust circle -- is reached through. A different
# container from the accessory one, opened the same way.
KEYCHAIN_CONTAINER = "com.apple.security.keychain"
CUTTLEFISH_BUNDLE = "com.apple.security.cuttlefish"
CUTTLEFISH_SERVICE = "Cuttlefish"

# The content type record operations are sent as. The `desc` parameter declares which
# schema the payload conforms to; it is not fetchable, and is sent because Apple's own
# clients send it rather than because anything reads it back.
PROTOBUF_CONTENT_TYPE = (
    "application/x-protobuf; "
    'desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; '
    "messageType=RequestOperation; delimited=true"
)


class SaveSemantics(IntEnum):
    """Whether a save may create a record, update one, or either."""

    CREATE = 2
    UPDATE = 3


class OperationType(IntEnum):
    """
    Which operation a request is.

    The number is also the field of RequestOperation that carries the operation's own
    request message, and the two must agree. Only the read operations are implemented;
    the rest are named so that a response naming one can be reported legibly.
    """

    ZONE_SAVE_TYPE = 200
    ZONE_RETRIEVE_TYPE = 201
    ZONE_DELETE_TYPE = 202
    RECORD_ZONE_RETRIEVE_CHANGES_TYPE = 203
    RECORD_SAVE_TYPE = 210
    RECORD_RETRIEVE_TYPE = 211
    RECORD_RETRIEVE_CHANGES_TYPE = 213
    RECORD_DELETE_TYPE = 214
    QUERY_RETRIEVE_TYPE = 220
    FUNCTION_INVOKE_TYPE = 1101


class ResultCode(IntEnum):
    """
    Whether an operation succeeded.

    PARTIAL exists: a batched request can half-succeed, so treating anything that is not
    SUCCESS as total failure discards good results.
    """

    SUCCESS = 1
    PARTIAL = 2
    FAILURE = 3
    INDETERMINATE = 4


class ClientErrorCode(IntEnum):
    """
    Client-fault codes, as far as they are known.

    Incomplete: the wire field is an int32 precisely so that a code missing from this list
    still reaches the caller.
    """

    BAD_SYNTAX = 4
    FORBIDDEN = 5
    THROTTLED = 6
    NOT_SUPPORTED = 8
    EXISTS = 9
    BAD_AUTH_TOKEN = 11
    NEEDS_AUTHENTICATION = 12


SYNC_STATUS_COMPLETE = 3
"""
The value of a record-sync response's `status` that means the zone is fully synced.

Paging loops on this rather than on a page coming back empty, because **a response can
carry this status and still contain changes**. Other values are unobserved.
"""


class ValueType(IntEnum):
    """
    What a record field's plaintext is.

    This describes the plaintext, not what is on the wire: an encrypted field carries its
    ciphertext in `bytes_value` while declaring the type its plaintext will have. The
    enumeration runs from 1 to 22; only the values the specification names are here.
    """

    BYTES_TYPE = 1
    DATE_TYPE = 2
    STRING_TYPE = 3
    INT64_TYPE = 7
    DOUBLE_TYPE = 8
    STRING_LIST_TYPE = 15
    ENCRYPTED_BYTES_TYPE = 20


class RecordType:
    """
    The record types the BeaconStore zone holds.

    A plain namespace rather than an enum: these are wire strings, and a type not listed
    here must still pass through rather than being rejected.
    """

    MASTER_BEACON = "MasterBeaconRecord"
    BEACON_NAMING = "BeaconNamingRecord"
    KEY_ALIGNMENT = "KeyAlignmentRecord"
    OWNED_DEVICE_KEY = "OwnedDeviceKeyRecord"
    SHARING_CIRCLE_SECRET = "SharingCircleSecret"  # noqa: S105 -- a record type name
    OWNER_SHARING_CIRCLE = "OwnerSharingCircle"
    OWNER_PEER_TRUST = "OwnerPeerTrust"
    SAFE_LOCATION = "SafeLocation"
    LEASH = "LeashRecord"


# Record types this library refuses to hand out or persist, whatever else it does with a
# fetch. SafeLocation holds the user's home and work coordinates: it arrives whether it is
# wanted or not, it decrypts with the same keys as everything else, and nothing here has
# any use for it. Discarding it must be a decision rather than an omission.
PRIVACY_SENSITIVE_RECORD_TYPES = frozenset({RecordType.SAFE_LOCATION})
