from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FetchViableBottlesRequest(_message.Message):
    __slots__ = ("filter", "metrics")
    FILTER_FIELD_NUMBER: _ClassVar[int]
    METRICS_FIELD_NUMBER: _ClassVar[int]
    filter: int
    metrics: bytes
    def __init__(self, filter: _Optional[int] = ..., metrics: _Optional[bytes] = ...) -> None: ...

class FetchViableBottlesResponse(_message.Message):
    __slots__ = ("valid", "partial")
    VALID_FIELD_NUMBER: _ClassVar[int]
    PARTIAL_FIELD_NUMBER: _ClassVar[int]
    valid: _containers.RepeatedCompositeFieldContainer[EscrowData]
    partial: _containers.RepeatedCompositeFieldContainer[EscrowMeta]
    def __init__(self, valid: _Optional[_Iterable[_Union[EscrowData, _Mapping]]] = ..., partial: _Optional[_Iterable[_Union[EscrowMeta, _Mapping]]] = ...) -> None: ...

class EscrowData(_message.Message):
    __slots__ = ("id", "bottle", "meta")
    ID_FIELD_NUMBER: _ClassVar[int]
    BOTTLE_FIELD_NUMBER: _ClassVar[int]
    META_FIELD_NUMBER: _ClassVar[int]
    id: str
    bottle: Bottle
    meta: EscrowMeta
    def __init__(self, id: _Optional[str] = ..., bottle: _Optional[_Union[Bottle, _Mapping]] = ..., meta: _Optional[_Union[EscrowMeta, _Mapping]] = ...) -> None: ...

class EscrowMeta(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class FetchChangesRequest(_message.Message):
    __slots__ = ("sync_token",)
    SYNC_TOKEN_FIELD_NUMBER: _ClassVar[int]
    sync_token: str
    def __init__(self, sync_token: _Optional[str] = ...) -> None: ...

class FetchChangesResponse(_message.Message):
    __slots__ = ("changes",)
    CHANGES_FIELD_NUMBER: _ClassVar[int]
    changes: CuttlefishChanges
    def __init__(self, changes: _Optional[_Union[CuttlefishChanges, _Mapping]] = ...) -> None: ...

class CuttlefishChanges(_message.Message):
    __slots__ = ("sync_token", "changes")
    SYNC_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CHANGES_FIELD_NUMBER: _ClassVar[int]
    sync_token: str
    changes: _containers.RepeatedCompositeFieldContainer[CuttlefishChange]
    def __init__(self, sync_token: _Optional[str] = ..., changes: _Optional[_Iterable[_Union[CuttlefishChange, _Mapping]]] = ...) -> None: ...

class CuttlefishChange(_message.Message):
    __slots__ = ("add",)
    ADD_FIELD_NUMBER: _ClassVar[int]
    add: CuttlefishPeer
    def __init__(self, add: _Optional[_Union[CuttlefishPeer, _Mapping]] = ...) -> None: ...

class FetchRecoverableTlkSharesRequest(_message.Message):
    __slots__ = ("for_peer",)
    FOR_PEER_FIELD_NUMBER: _ClassVar[int]
    for_peer: str
    def __init__(self, for_peer: _Optional[str] = ...) -> None: ...

class FetchRecoverableTlkSharesResponse(_message.Message):
    __slots__ = ("shares",)
    SHARES_FIELD_NUMBER: _ClassVar[int]
    shares: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, shares: _Optional[_Iterable[bytes]] = ...) -> None: ...

class RecoverableTlkShare(_message.Message):
    __slots__ = ("service", "viewkeys", "share")
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    VIEWKEYS_FIELD_NUMBER: _ClassVar[int]
    SHARE_FIELD_NUMBER: _ClassVar[int]
    service: str
    viewkeys: ViewKeySet
    share: RecordWrapper
    def __init__(self, service: _Optional[str] = ..., viewkeys: _Optional[_Union[ViewKeySet, _Mapping]] = ..., share: _Optional[_Union[RecordWrapper, _Mapping]] = ...) -> None: ...

class ViewKeySet(_message.Message):
    __slots__ = ("tlk", "class_a", "class_b")
    TLK_FIELD_NUMBER: _ClassVar[int]
    CLASS_A_FIELD_NUMBER: _ClassVar[int]
    CLASS_B_FIELD_NUMBER: _ClassVar[int]
    tlk: RecordWrapper
    class_a: RecordWrapper
    class_b: RecordWrapper
    def __init__(self, tlk: _Optional[_Union[RecordWrapper, _Mapping]] = ..., class_a: _Optional[_Union[RecordWrapper, _Mapping]] = ..., class_b: _Optional[_Union[RecordWrapper, _Mapping]] = ...) -> None: ...

class TlkKeyMaterial(_message.Message):
    __slots__ = ("uuid", "zone_name", "key_class", "key")
    UUID_FIELD_NUMBER: _ClassVar[int]
    ZONE_NAME_FIELD_NUMBER: _ClassVar[int]
    KEY_CLASS_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    uuid: str
    zone_name: str
    key_class: str
    key: bytes
    def __init__(self, uuid: _Optional[str] = ..., zone_name: _Optional[str] = ..., key_class: _Optional[str] = ..., key: _Optional[bytes] = ...) -> None: ...

class RecordWrapper(_message.Message):
    __slots__ = ("record",)
    RECORD_FIELD_NUMBER: _ClassVar[int]
    record: bytes
    def __init__(self, record: _Optional[bytes] = ...) -> None: ...

class CuttlefishJoinWithVoucherRequest(_message.Message):
    __slots__ = ("restore_point", "peer", "bottle", "shares", "keys")
    RESTORE_POINT_FIELD_NUMBER: _ClassVar[int]
    PEER_FIELD_NUMBER: _ClassVar[int]
    BOTTLE_FIELD_NUMBER: _ClassVar[int]
    SHARES_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    restore_point: str
    peer: CuttlefishPeer
    bottle: Bottle
    shares: _containers.RepeatedCompositeFieldContainer[TlkShare]
    keys: _containers.RepeatedCompositeFieldContainer[ViewKeys]
    def __init__(self, restore_point: _Optional[str] = ..., peer: _Optional[_Union[CuttlefishPeer, _Mapping]] = ..., bottle: _Optional[_Union[Bottle, _Mapping]] = ..., shares: _Optional[_Iterable[_Union[TlkShare, _Mapping]]] = ..., keys: _Optional[_Iterable[_Union[ViewKeys, _Mapping]]] = ...) -> None: ...

class CuttlefishJoinWithVoucherResponse(_message.Message):
    __slots__ = ("changes",)
    CHANGES_FIELD_NUMBER: _ClassVar[int]
    changes: CuttlefishChanges
    def __init__(self, changes: _Optional[_Union[CuttlefishChanges, _Mapping]] = ...) -> None: ...

class CuttlefishUpdateTrustRequest(_message.Message):
    __slots__ = ("restore_point", "peer_id", "stable_info", "dynamic_info", "tlkshares", "view_keys")
    RESTORE_POINT_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    STABLE_INFO_FIELD_NUMBER: _ClassVar[int]
    DYNAMIC_INFO_FIELD_NUMBER: _ClassVar[int]
    TLKSHARES_FIELD_NUMBER: _ClassVar[int]
    VIEW_KEYS_FIELD_NUMBER: _ClassVar[int]
    restore_point: str
    peer_id: str
    stable_info: SignedInfo
    dynamic_info: SignedInfo
    tlkshares: _containers.RepeatedCompositeFieldContainer[TlkShare]
    view_keys: _containers.RepeatedCompositeFieldContainer[ViewKeys]
    def __init__(self, restore_point: _Optional[str] = ..., peer_id: _Optional[str] = ..., stable_info: _Optional[_Union[SignedInfo, _Mapping]] = ..., dynamic_info: _Optional[_Union[SignedInfo, _Mapping]] = ..., tlkshares: _Optional[_Iterable[_Union[TlkShare, _Mapping]]] = ..., view_keys: _Optional[_Iterable[_Union[ViewKeys, _Mapping]]] = ...) -> None: ...

class CuttlefishUpdateTrustResponse(_message.Message):
    __slots__ = ("changes",)
    CHANGES_FIELD_NUMBER: _ClassVar[int]
    changes: CuttlefishChanges
    def __init__(self, changes: _Optional[_Union[CuttlefishChanges, _Mapping]] = ...) -> None: ...

class CuttlefishPeer(_message.Message):
    __slots__ = ("hash", "permanent_info", "stable_info", "dynamic_info", "voucher")
    HASH_FIELD_NUMBER: _ClassVar[int]
    PERMANENT_INFO_FIELD_NUMBER: _ClassVar[int]
    STABLE_INFO_FIELD_NUMBER: _ClassVar[int]
    DYNAMIC_INFO_FIELD_NUMBER: _ClassVar[int]
    VOUCHER_FIELD_NUMBER: _ClassVar[int]
    hash: str
    permanent_info: SignedInfo
    stable_info: SignedInfo
    dynamic_info: SignedInfo
    voucher: SignedInfo
    def __init__(self, hash: _Optional[str] = ..., permanent_info: _Optional[_Union[SignedInfo, _Mapping]] = ..., stable_info: _Optional[_Union[SignedInfo, _Mapping]] = ..., dynamic_info: _Optional[_Union[SignedInfo, _Mapping]] = ..., voucher: _Optional[_Union[SignedInfo, _Mapping]] = ...) -> None: ...

class SignedInfo(_message.Message):
    __slots__ = ("info", "signature")
    INFO_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    info: bytes
    signature: bytes
    def __init__(self, info: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class PeerPermanentInfo(_message.Message):
    __slots__ = ("epoch", "signing_key", "encryption_key", "machine_id", "model_id", "creation_time")
    EPOCH_FIELD_NUMBER: _ClassVar[int]
    SIGNING_KEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTION_KEY_FIELD_NUMBER: _ClassVar[int]
    MACHINE_ID_FIELD_NUMBER: _ClassVar[int]
    MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    CREATION_TIME_FIELD_NUMBER: _ClassVar[int]
    epoch: int
    signing_key: bytes
    encryption_key: bytes
    machine_id: str
    model_id: str
    creation_time: int
    def __init__(self, epoch: _Optional[int] = ..., signing_key: _Optional[bytes] = ..., encryption_key: _Optional[bytes] = ..., machine_id: _Optional[str] = ..., model_id: _Optional[str] = ..., creation_time: _Optional[int] = ...) -> None: ...

class PeerStableInfo(_message.Message):
    __slots__ = ("clock", "frozen_policy_version", "frozen_policy_hash", "secrets", "os_version", "device_name", "recovery_signing_public_key", "recovery_encryption_public_key", "serial_number", "flexible_policy_version", "flexible_policy_hash", "user_controllable_view_status", "custodian_recovery_keys", "secure_element_identity", "walrus", "web_access", "is_inherited_account")
    CLOCK_FIELD_NUMBER: _ClassVar[int]
    FROZEN_POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    FROZEN_POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    SECRETS_FIELD_NUMBER: _ClassVar[int]
    OS_VERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICE_NAME_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_SIGNING_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_ENCRYPTION_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    SERIAL_NUMBER_FIELD_NUMBER: _ClassVar[int]
    FLEXIBLE_POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    FLEXIBLE_POLICY_HASH_FIELD_NUMBER: _ClassVar[int]
    USER_CONTROLLABLE_VIEW_STATUS_FIELD_NUMBER: _ClassVar[int]
    CUSTODIAN_RECOVERY_KEYS_FIELD_NUMBER: _ClassVar[int]
    SECURE_ELEMENT_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    WALRUS_FIELD_NUMBER: _ClassVar[int]
    WEB_ACCESS_FIELD_NUMBER: _ClassVar[int]
    IS_INHERITED_ACCOUNT_FIELD_NUMBER: _ClassVar[int]
    clock: int
    frozen_policy_version: int
    frozen_policy_hash: bytes
    secrets: _containers.RepeatedScalarFieldContainer[bytes]
    os_version: str
    device_name: str
    recovery_signing_public_key: bytes
    recovery_encryption_public_key: bytes
    serial_number: str
    flexible_policy_version: int
    flexible_policy_hash: bytes
    user_controllable_view_status: int
    custodian_recovery_keys: _containers.RepeatedScalarFieldContainer[bytes]
    secure_element_identity: bytes
    walrus: int
    web_access: int
    is_inherited_account: bool
    def __init__(self, clock: _Optional[int] = ..., frozen_policy_version: _Optional[int] = ..., frozen_policy_hash: _Optional[bytes] = ..., secrets: _Optional[_Iterable[bytes]] = ..., os_version: _Optional[str] = ..., device_name: _Optional[str] = ..., recovery_signing_public_key: _Optional[bytes] = ..., recovery_encryption_public_key: _Optional[bytes] = ..., serial_number: _Optional[str] = ..., flexible_policy_version: _Optional[int] = ..., flexible_policy_hash: _Optional[bytes] = ..., user_controllable_view_status: _Optional[int] = ..., custodian_recovery_keys: _Optional[_Iterable[bytes]] = ..., secure_element_identity: _Optional[bytes] = ..., walrus: _Optional[int] = ..., web_access: _Optional[int] = ..., is_inherited_account: bool = ...) -> None: ...

class PeerDynamicInfo(_message.Message):
    __slots__ = ("clock", "includeds", "excludeds", "dispositions", "preapprovals")
    CLOCK_FIELD_NUMBER: _ClassVar[int]
    INCLUDEDS_FIELD_NUMBER: _ClassVar[int]
    EXCLUDEDS_FIELD_NUMBER: _ClassVar[int]
    DISPOSITIONS_FIELD_NUMBER: _ClassVar[int]
    PREAPPROVALS_FIELD_NUMBER: _ClassVar[int]
    clock: int
    includeds: _containers.RepeatedScalarFieldContainer[str]
    excludeds: _containers.RepeatedScalarFieldContainer[str]
    dispositions: _containers.RepeatedCompositeFieldContainer[PeerDisposition]
    preapprovals: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, clock: _Optional[int] = ..., includeds: _Optional[_Iterable[str]] = ..., excludeds: _Optional[_Iterable[str]] = ..., dispositions: _Optional[_Iterable[_Union[PeerDisposition, _Mapping]]] = ..., preapprovals: _Optional[_Iterable[str]] = ...) -> None: ...

class PeerDisposition(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class Voucher(_message.Message):
    __slots__ = ("reason", "beneficiary", "sponsor")
    REASON_FIELD_NUMBER: _ClassVar[int]
    BENEFICIARY_FIELD_NUMBER: _ClassVar[int]
    SPONSOR_FIELD_NUMBER: _ClassVar[int]
    reason: int
    beneficiary: str
    sponsor: str
    def __init__(self, reason: _Optional[int] = ..., beneficiary: _Optional[str] = ..., sponsor: _Optional[str] = ...) -> None: ...

class Bottle(_message.Message):
    __slots__ = ("bottle", "escrowed_signing_key", "escrowed_key_signature", "peer_key_signature", "peer_id", "bottle_id")
    BOTTLE_FIELD_NUMBER: _ClassVar[int]
    ESCROWED_SIGNING_KEY_FIELD_NUMBER: _ClassVar[int]
    ESCROWED_KEY_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    PEER_KEY_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    BOTTLE_ID_FIELD_NUMBER: _ClassVar[int]
    bottle: bytes
    escrowed_signing_key: bytes
    escrowed_key_signature: bytes
    peer_key_signature: bytes
    peer_id: str
    bottle_id: str
    def __init__(self, bottle: _Optional[bytes] = ..., escrowed_signing_key: _Optional[bytes] = ..., escrowed_key_signature: _Optional[bytes] = ..., peer_key_signature: _Optional[bytes] = ..., peer_id: _Optional[str] = ..., bottle_id: _Optional[str] = ...) -> None: ...

class OTBottle(_message.Message):
    __slots__ = ("peer_id", "bottle_id", "escrowed_signing_key", "escrowed_encryption_key", "peer_signing_key", "peer_encryption_key", "ciphertext")
    PEER_ID_FIELD_NUMBER: _ClassVar[int]
    BOTTLE_ID_FIELD_NUMBER: _ClassVar[int]
    ESCROWED_SIGNING_KEY_FIELD_NUMBER: _ClassVar[int]
    ESCROWED_ENCRYPTION_KEY_FIELD_NUMBER: _ClassVar[int]
    PEER_SIGNING_KEY_FIELD_NUMBER: _ClassVar[int]
    PEER_ENCRYPTION_KEY_FIELD_NUMBER: _ClassVar[int]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    peer_id: str
    bottle_id: str
    escrowed_signing_key: bytes
    escrowed_encryption_key: bytes
    peer_signing_key: bytes
    peer_encryption_key: bytes
    ciphertext: OTAuthenticatedCiphertext
    def __init__(self, peer_id: _Optional[str] = ..., bottle_id: _Optional[str] = ..., escrowed_signing_key: _Optional[bytes] = ..., escrowed_encryption_key: _Optional[bytes] = ..., peer_signing_key: _Optional[bytes] = ..., peer_encryption_key: _Optional[bytes] = ..., ciphertext: _Optional[_Union[OTAuthenticatedCiphertext, _Mapping]] = ...) -> None: ...

class OTAuthenticatedCiphertext(_message.Message):
    __slots__ = ("ciphertext", "authentication_code", "initialization_vector")
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATION_CODE_FIELD_NUMBER: _ClassVar[int]
    INITIALIZATION_VECTOR_FIELD_NUMBER: _ClassVar[int]
    ciphertext: bytes
    authentication_code: bytes
    initialization_vector: bytes
    def __init__(self, ciphertext: _Optional[bytes] = ..., authentication_code: _Optional[bytes] = ..., initialization_vector: _Optional[bytes] = ...) -> None: ...

class OTInternalBottle(_message.Message):
    __slots__ = ("signing_key", "encryption_key")
    SIGNING_KEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTION_KEY_FIELD_NUMBER: _ClassVar[int]
    signing_key: OTPrivateKey
    encryption_key: OTPrivateKey
    def __init__(self, signing_key: _Optional[_Union[OTPrivateKey, _Mapping]] = ..., encryption_key: _Optional[_Union[OTPrivateKey, _Mapping]] = ...) -> None: ...

class OTPrivateKey(_message.Message):
    __slots__ = ("key_type", "key_data")
    KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    KEY_DATA_FIELD_NUMBER: _ClassVar[int]
    key_type: int
    key_data: bytes
    def __init__(self, key_type: _Optional[int] = ..., key_data: _Optional[bytes] = ...) -> None: ...

class TlkShare(_message.Message):
    __slots__ = ("service", "curve", "epoch", "key_id", "poisoned", "receiver", "receiver_public_encryption_key", "sender", "signature", "version", "wrapped_key")
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    CURVE_FIELD_NUMBER: _ClassVar[int]
    EPOCH_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    POISONED_FIELD_NUMBER: _ClassVar[int]
    RECEIVER_FIELD_NUMBER: _ClassVar[int]
    RECEIVER_PUBLIC_ENCRYPTION_KEY_FIELD_NUMBER: _ClassVar[int]
    SENDER_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    WRAPPED_KEY_FIELD_NUMBER: _ClassVar[int]
    service: str
    curve: int
    epoch: int
    key_id: str
    poisoned: int
    receiver: str
    receiver_public_encryption_key: str
    sender: str
    signature: str
    version: int
    wrapped_key: str
    def __init__(self, service: _Optional[str] = ..., curve: _Optional[int] = ..., epoch: _Optional[int] = ..., key_id: _Optional[str] = ..., poisoned: _Optional[int] = ..., receiver: _Optional[str] = ..., receiver_public_encryption_key: _Optional[str] = ..., sender: _Optional[str] = ..., signature: _Optional[str] = ..., version: _Optional[int] = ..., wrapped_key: _Optional[str] = ...) -> None: ...

class ViewKeys(_message.Message):
    __slots__ = ("service", "top_level_key", "class_a", "class_c", "old_top_level_key")
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    TOP_LEVEL_KEY_FIELD_NUMBER: _ClassVar[int]
    CLASS_A_FIELD_NUMBER: _ClassVar[int]
    CLASS_C_FIELD_NUMBER: _ClassVar[int]
    OLD_TOP_LEVEL_KEY_FIELD_NUMBER: _ClassVar[int]
    service: str
    top_level_key: ViewKey
    class_a: ViewKey
    class_c: ViewKey
    old_top_level_key: ViewKey
    def __init__(self, service: _Optional[str] = ..., top_level_key: _Optional[_Union[ViewKey, _Mapping]] = ..., class_a: _Optional[_Union[ViewKey, _Mapping]] = ..., class_c: _Optional[_Union[ViewKey, _Mapping]] = ..., old_top_level_key: _Optional[_Union[ViewKey, _Mapping]] = ...) -> None: ...

class ViewKey(_message.Message):
    __slots__ = ("key_id", "top_level_key_id", "key_number", "key", "field_5")
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    TOP_LEVEL_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_NUMBER_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    FIELD_5_FIELD_NUMBER: _ClassVar[int]
    key_id: str
    top_level_key_id: str
    key_number: int
    key: bytes
    field_5: bytes
    def __init__(self, key_id: _Optional[str] = ..., top_level_key_id: _Optional[str] = ..., key_number: _Optional[int] = ..., key: _Optional[bytes] = ..., field_5: _Optional[bytes] = ...) -> None: ...

class PcsServiceKeys(_message.Message):
    __slots__ = ("encryption_key", "signing_key")
    ENCRYPTION_KEY_FIELD_NUMBER: _ClassVar[int]
    SIGNING_KEY_FIELD_NUMBER: _ClassVar[int]
    encryption_key: PcsPrivateKey
    signing_key: PcsPrivateKey
    def __init__(self, encryption_key: _Optional[_Union[PcsPrivateKey, _Mapping]] = ..., signing_key: _Optional[_Union[PcsPrivateKey, _Mapping]] = ...) -> None: ...

class PcsPrivateKey(_message.Message):
    __slots__ = ("key", "public_structure")
    KEY_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_STRUCTURE_FIELD_NUMBER: _ClassVar[int]
    key: bytes
    public_structure: bytes
    def __init__(self, key: _Optional[bytes] = ..., public_structure: _Optional[bytes] = ...) -> None: ...
