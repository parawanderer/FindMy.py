from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ContainerEnvironment(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PRODUCTION: _ClassVar[ContainerEnvironment]
    SANDBOX: _ClassVar[ContainerEnvironment]

class Database(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PRIVATE_DB: _ClassVar[Database]
    PUBLIC_DB: _ClassVar[Database]
    SHARED_DB: _ClassVar[Database]

class IsolationLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ZONE: _ClassVar[IsolationLevel]
    OPERATION: _ClassVar[IsolationLevel]
PRODUCTION: ContainerEnvironment
SANDBOX: ContainerEnvironment
PRIVATE_DB: Database
PUBLIC_DB: Database
SHARED_DB: Database
ZONE: IsolationLevel
OPERATION: IsolationLevel

class Identifier(_message.Message):
    __slots__ = ("name", "type")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        RECORD: _ClassVar[Identifier.Type]
        DEVICE: _ClassVar[Identifier.Type]
        SUBSCRIPTION: _ClassVar[Identifier.Type]
        SHARE: _ClassVar[Identifier.Type]
        COMMENT: _ClassVar[Identifier.Type]
        RECORD_ZONE: _ClassVar[Identifier.Type]
        USER: _ClassVar[Identifier.Type]
    RECORD: Identifier.Type
    DEVICE: Identifier.Type
    SUBSCRIPTION: Identifier.Type
    SHARE: Identifier.Type
    COMMENT: Identifier.Type
    RECORD_ZONE: Identifier.Type
    USER: Identifier.Type
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    name: str
    type: Identifier.Type
    def __init__(self, name: _Optional[str] = ..., type: _Optional[_Union[Identifier.Type, str]] = ...) -> None: ...

class RecordZoneIdentifier(_message.Message):
    __slots__ = ("value", "owner_identifier", "environment")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    OWNER_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    value: Identifier
    owner_identifier: Identifier
    environment: ContainerEnvironment
    def __init__(self, value: _Optional[_Union[Identifier, _Mapping]] = ..., owner_identifier: _Optional[_Union[Identifier, _Mapping]] = ..., environment: _Optional[_Union[ContainerEnvironment, str]] = ...) -> None: ...

class RecordIdentifier(_message.Message):
    __slots__ = ("value", "zone_identifier")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    ZONE_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    value: Identifier
    zone_identifier: RecordZoneIdentifier
    def __init__(self, value: _Optional[_Union[Identifier, _Mapping]] = ..., zone_identifier: _Optional[_Union[RecordZoneIdentifier, _Mapping]] = ...) -> None: ...

class Operation(_message.Message):
    __slots__ = ("operation_uuid", "type", "synchronous_mode", "last")
    OPERATION_UUID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SYNCHRONOUS_MODE_FIELD_NUMBER: _ClassVar[int]
    LAST_FIELD_NUMBER: _ClassVar[int]
    operation_uuid: str
    type: int
    synchronous_mode: bool
    last: bool
    def __init__(self, operation_uuid: _Optional[str] = ..., type: _Optional[int] = ..., synchronous_mode: bool = ..., last: bool = ...) -> None: ...

class RequestOperation(_message.Message):
    __slots__ = ("header", "request", "zone_retrieve_request", "retrieve_zone_changes_request", "retrieve_changes_request", "function_invoke_request")
    class Header(_message.Message):
        __slots__ = ("user_token", "application_container", "application_bundle", "application_version", "device_identifier", "device_software_version", "device_hardware_version", "device_library_name", "device_library_version", "device_protocol_version", "mmcs_protocol_version", "application_container_environment", "device_assigned_name", "device_hardware_id", "target_database", "isolation_level", "group", "device_serial", "unknown_29", "unknown_34", "unknown_35")
        USER_TOKEN_FIELD_NUMBER: _ClassVar[int]
        APPLICATION_CONTAINER_FIELD_NUMBER: _ClassVar[int]
        APPLICATION_BUNDLE_FIELD_NUMBER: _ClassVar[int]
        APPLICATION_VERSION_FIELD_NUMBER: _ClassVar[int]
        DEVICE_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
        DEVICE_SOFTWARE_VERSION_FIELD_NUMBER: _ClassVar[int]
        DEVICE_HARDWARE_VERSION_FIELD_NUMBER: _ClassVar[int]
        DEVICE_LIBRARY_NAME_FIELD_NUMBER: _ClassVar[int]
        DEVICE_LIBRARY_VERSION_FIELD_NUMBER: _ClassVar[int]
        DEVICE_PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
        MMCS_PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
        APPLICATION_CONTAINER_ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
        DEVICE_ASSIGNED_NAME_FIELD_NUMBER: _ClassVar[int]
        DEVICE_HARDWARE_ID_FIELD_NUMBER: _ClassVar[int]
        TARGET_DATABASE_FIELD_NUMBER: _ClassVar[int]
        ISOLATION_LEVEL_FIELD_NUMBER: _ClassVar[int]
        GROUP_FIELD_NUMBER: _ClassVar[int]
        DEVICE_SERIAL_FIELD_NUMBER: _ClassVar[int]
        UNKNOWN_29_FIELD_NUMBER: _ClassVar[int]
        UNKNOWN_34_FIELD_NUMBER: _ClassVar[int]
        UNKNOWN_35_FIELD_NUMBER: _ClassVar[int]
        user_token: str
        application_container: str
        application_bundle: str
        application_version: str
        device_identifier: Identifier
        device_software_version: str
        device_hardware_version: str
        device_library_name: str
        device_library_version: str
        device_protocol_version: str
        mmcs_protocol_version: str
        application_container_environment: ContainerEnvironment
        device_assigned_name: str
        device_hardware_id: str
        target_database: Database
        isolation_level: IsolationLevel
        group: str
        device_serial: str
        unknown_29: int
        unknown_34: int
        unknown_35: int
        def __init__(self, user_token: _Optional[str] = ..., application_container: _Optional[str] = ..., application_bundle: _Optional[str] = ..., application_version: _Optional[str] = ..., device_identifier: _Optional[_Union[Identifier, _Mapping]] = ..., device_software_version: _Optional[str] = ..., device_hardware_version: _Optional[str] = ..., device_library_name: _Optional[str] = ..., device_library_version: _Optional[str] = ..., device_protocol_version: _Optional[str] = ..., mmcs_protocol_version: _Optional[str] = ..., application_container_environment: _Optional[_Union[ContainerEnvironment, str]] = ..., device_assigned_name: _Optional[str] = ..., device_hardware_id: _Optional[str] = ..., target_database: _Optional[_Union[Database, str]] = ..., isolation_level: _Optional[_Union[IsolationLevel, str]] = ..., group: _Optional[str] = ..., device_serial: _Optional[str] = ..., unknown_29: _Optional[int] = ..., unknown_34: _Optional[int] = ..., unknown_35: _Optional[int] = ...) -> None: ...
    HEADER_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    ZONE_RETRIEVE_REQUEST_FIELD_NUMBER: _ClassVar[int]
    RETRIEVE_ZONE_CHANGES_REQUEST_FIELD_NUMBER: _ClassVar[int]
    RETRIEVE_CHANGES_REQUEST_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_INVOKE_REQUEST_FIELD_NUMBER: _ClassVar[int]
    header: RequestOperation.Header
    request: Operation
    zone_retrieve_request: ZoneRetrieveRequest
    retrieve_zone_changes_request: RetrieveZoneChangesRequest
    retrieve_changes_request: RetrieveChangesRequest
    function_invoke_request: FunctionInvokeRequest
    def __init__(self, header: _Optional[_Union[RequestOperation.Header, _Mapping]] = ..., request: _Optional[_Union[Operation, _Mapping]] = ..., zone_retrieve_request: _Optional[_Union[ZoneRetrieveRequest, _Mapping]] = ..., retrieve_zone_changes_request: _Optional[_Union[RetrieveZoneChangesRequest, _Mapping]] = ..., retrieve_changes_request: _Optional[_Union[RetrieveChangesRequest, _Mapping]] = ..., function_invoke_request: _Optional[_Union[FunctionInvokeRequest, _Mapping]] = ...) -> None: ...

class FunctionInvokeRequest(_message.Message):
    __slots__ = ("service", "name", "parameters")
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    service: str
    name: str
    parameters: bytes
    def __init__(self, service: _Optional[str] = ..., name: _Optional[str] = ..., parameters: _Optional[bytes] = ...) -> None: ...

class FunctionInvokeResponse(_message.Message):
    __slots__ = ("serialized_result",)
    SERIALIZED_RESULT_FIELD_NUMBER: _ClassVar[int]
    serialized_result: bytes
    def __init__(self, serialized_result: _Optional[bytes] = ...) -> None: ...

class ResponseOperation(_message.Message):
    __slots__ = ("operation_cost", "response", "result", "bundled", "zone_retrieve_response", "retrieve_zone_changes_response", "retrieve_changes_response", "function_invoke_response")
    OPERATION_COST_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    BUNDLED_FIELD_NUMBER: _ClassVar[int]
    ZONE_RETRIEVE_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    RETRIEVE_ZONE_CHANGES_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    RETRIEVE_CHANGES_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_INVOKE_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    operation_cost: int
    response: Operation
    result: Result
    bundled: _containers.RepeatedScalarFieldContainer[bytes]
    zone_retrieve_response: ZoneRetrieveResponse
    retrieve_zone_changes_response: RetrieveZoneChangesResponse
    retrieve_changes_response: RetrieveChangesResponse
    function_invoke_response: FunctionInvokeResponse
    def __init__(self, operation_cost: _Optional[int] = ..., response: _Optional[_Union[Operation, _Mapping]] = ..., result: _Optional[_Union[Result, _Mapping]] = ..., bundled: _Optional[_Iterable[bytes]] = ..., zone_retrieve_response: _Optional[_Union[ZoneRetrieveResponse, _Mapping]] = ..., retrieve_zone_changes_response: _Optional[_Union[RetrieveZoneChangesResponse, _Mapping]] = ..., retrieve_changes_response: _Optional[_Union[RetrieveChangesResponse, _Mapping]] = ..., function_invoke_response: _Optional[_Union[FunctionInvokeResponse, _Mapping]] = ...) -> None: ...

class Result(_message.Message):
    __slots__ = ("code", "error")
    CODE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    code: int
    error: Error
    def __init__(self, code: _Optional[int] = ..., error: _Optional[_Union[Error, _Mapping]] = ...) -> None: ...

class Error(_message.Message):
    __slots__ = ("client_error", "server_error", "retry_after_seconds", "error_description", "error_key", "error_internal", "extension_error")
    class ClientError(_message.Message):
        __slots__ = ("code",)
        CODE_FIELD_NUMBER: _ClassVar[int]
        code: int
        def __init__(self, code: _Optional[int] = ...) -> None: ...
    class ServerError(_message.Message):
        __slots__ = ("code",)
        CODE_FIELD_NUMBER: _ClassVar[int]
        code: int
        def __init__(self, code: _Optional[int] = ...) -> None: ...
    CLIENT_ERROR_FIELD_NUMBER: _ClassVar[int]
    SERVER_ERROR_FIELD_NUMBER: _ClassVar[int]
    RETRY_AFTER_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ERROR_DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    ERROR_KEY_FIELD_NUMBER: _ClassVar[int]
    ERROR_INTERNAL_FIELD_NUMBER: _ClassVar[int]
    EXTENSION_ERROR_FIELD_NUMBER: _ClassVar[int]
    client_error: Error.ClientError
    server_error: Error.ServerError
    retry_after_seconds: int
    error_description: str
    error_key: str
    error_internal: str
    extension_error: ExtensionError
    def __init__(self, client_error: _Optional[_Union[Error.ClientError, _Mapping]] = ..., server_error: _Optional[_Union[Error.ServerError, _Mapping]] = ..., retry_after_seconds: _Optional[int] = ..., error_description: _Optional[str] = ..., error_key: _Optional[str] = ..., error_internal: _Optional[str] = ..., extension_error: _Optional[_Union[ExtensionError, _Mapping]] = ...) -> None: ...

class ExtensionError(_message.Message):
    __slots__ = ("extension_name", "type_code", "extension_payload")
    EXTENSION_NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_CODE_FIELD_NUMBER: _ClassVar[int]
    EXTENSION_PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    extension_name: str
    type_code: int
    extension_payload: bytes
    def __init__(self, extension_name: _Optional[str] = ..., type_code: _Optional[int] = ..., extension_payload: _Optional[bytes] = ...) -> None: ...

class ProtectionInfo(_message.Message):
    __slots__ = ("protection_info", "protection_info_tag")
    PROTECTION_INFO_FIELD_NUMBER: _ClassVar[int]
    PROTECTION_INFO_TAG_FIELD_NUMBER: _ClassVar[int]
    protection_info: bytes
    protection_info_tag: str
    def __init__(self, protection_info: _Optional[bytes] = ..., protection_info_tag: _Optional[str] = ...) -> None: ...

class Zone(_message.Message):
    __slots__ = ("zone_identifier", "etag", "protection_info", "record_protection_info")
    ZONE_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    ETAG_FIELD_NUMBER: _ClassVar[int]
    PROTECTION_INFO_FIELD_NUMBER: _ClassVar[int]
    RECORD_PROTECTION_INFO_FIELD_NUMBER: _ClassVar[int]
    zone_identifier: RecordZoneIdentifier
    etag: str
    protection_info: ProtectionInfo
    record_protection_info: ProtectionInfo
    def __init__(self, zone_identifier: _Optional[_Union[RecordZoneIdentifier, _Mapping]] = ..., etag: _Optional[str] = ..., protection_info: _Optional[_Union[ProtectionInfo, _Mapping]] = ..., record_protection_info: _Optional[_Union[ProtectionInfo, _Mapping]] = ...) -> None: ...

class ZoneRetrieveRequest(_message.Message):
    __slots__ = ("zone_identifier",)
    ZONE_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    zone_identifier: RecordZoneIdentifier
    def __init__(self, zone_identifier: _Optional[_Union[RecordZoneIdentifier, _Mapping]] = ...) -> None: ...

class ZoneRetrieveResponse(_message.Message):
    __slots__ = ("zone_summary",)
    ZONE_SUMMARY_FIELD_NUMBER: _ClassVar[int]
    zone_summary: _containers.RepeatedCompositeFieldContainer[ZoneSummary]
    def __init__(self, zone_summary: _Optional[_Iterable[_Union[ZoneSummary, _Mapping]]] = ...) -> None: ...

class ZoneSummary(_message.Message):
    __slots__ = ("target_zone", "current_server_continuation_token", "client_change_token", "device_count", "asset_quota_usage", "metadata_quota_usage")
    TARGET_ZONE_FIELD_NUMBER: _ClassVar[int]
    CURRENT_SERVER_CONTINUATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CLIENT_CHANGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    DEVICE_COUNT_FIELD_NUMBER: _ClassVar[int]
    ASSET_QUOTA_USAGE_FIELD_NUMBER: _ClassVar[int]
    METADATA_QUOTA_USAGE_FIELD_NUMBER: _ClassVar[int]
    target_zone: Zone
    current_server_continuation_token: bytes
    client_change_token: bytes
    device_count: int
    asset_quota_usage: int
    metadata_quota_usage: int
    def __init__(self, target_zone: _Optional[_Union[Zone, _Mapping]] = ..., current_server_continuation_token: _Optional[bytes] = ..., client_change_token: _Optional[bytes] = ..., device_count: _Optional[int] = ..., asset_quota_usage: _Optional[int] = ..., metadata_quota_usage: _Optional[int] = ...) -> None: ...

class RetrieveZoneChangesRequest(_message.Message):
    __slots__ = ("sync_continuation_token", "max_changed_zones")
    SYNC_CONTINUATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    MAX_CHANGED_ZONES_FIELD_NUMBER: _ClassVar[int]
    sync_continuation_token: bytes
    max_changed_zones: int
    def __init__(self, sync_continuation_token: _Optional[bytes] = ..., max_changed_zones: _Optional[int] = ...) -> None: ...

class ChangedZone(_message.Message):
    __slots__ = ("identifier", "change_type", "delete_type")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    CHANGE_TYPE_FIELD_NUMBER: _ClassVar[int]
    DELETE_TYPE_FIELD_NUMBER: _ClassVar[int]
    identifier: RecordZoneIdentifier
    change_type: int
    delete_type: int
    def __init__(self, identifier: _Optional[_Union[RecordZoneIdentifier, _Mapping]] = ..., change_type: _Optional[int] = ..., delete_type: _Optional[int] = ...) -> None: ...

class RetrieveZoneChangesResponse(_message.Message):
    __slots__ = ("changed_zone", "sync_continuation_token", "status")
    CHANGED_ZONE_FIELD_NUMBER: _ClassVar[int]
    SYNC_CONTINUATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    changed_zone: _containers.RepeatedCompositeFieldContainer[ChangedZone]
    sync_continuation_token: bytes
    status: int
    def __init__(self, changed_zone: _Optional[_Iterable[_Union[ChangedZone, _Mapping]]] = ..., sync_continuation_token: _Optional[bytes] = ..., status: _Optional[int] = ...) -> None: ...

class RetrieveChangesRequest(_message.Message):
    __slots__ = ("sync_continuation_token", "zone_identifier", "requested_fields", "max_changes", "requested_changes_types", "newest_first", "ignore_calling_device_changes", "include_mergeable_deltas")
    SYNC_CONTINUATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ZONE_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_FIELDS_FIELD_NUMBER: _ClassVar[int]
    MAX_CHANGES_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_CHANGES_TYPES_FIELD_NUMBER: _ClassVar[int]
    NEWEST_FIRST_FIELD_NUMBER: _ClassVar[int]
    IGNORE_CALLING_DEVICE_CHANGES_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_MERGEABLE_DELTAS_FIELD_NUMBER: _ClassVar[int]
    sync_continuation_token: bytes
    zone_identifier: RecordZoneIdentifier
    requested_fields: _containers.RepeatedScalarFieldContainer[str]
    max_changes: int
    requested_changes_types: _containers.RepeatedScalarFieldContainer[int]
    newest_first: bool
    ignore_calling_device_changes: bool
    include_mergeable_deltas: bool
    def __init__(self, sync_continuation_token: _Optional[bytes] = ..., zone_identifier: _Optional[_Union[RecordZoneIdentifier, _Mapping]] = ..., requested_fields: _Optional[_Iterable[str]] = ..., max_changes: _Optional[int] = ..., requested_changes_types: _Optional[_Iterable[int]] = ..., newest_first: bool = ..., ignore_calling_device_changes: bool = ..., include_mergeable_deltas: bool = ...) -> None: ...

class RecordChange(_message.Message):
    __slots__ = ("identifier", "etag", "record_type", "type", "record")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    ETAG_FIELD_NUMBER: _ClassVar[int]
    RECORD_TYPE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    RECORD_FIELD_NUMBER: _ClassVar[int]
    identifier: RecordIdentifier
    etag: str
    record_type: NameWrapper
    type: int
    record: Record
    def __init__(self, identifier: _Optional[_Union[RecordIdentifier, _Mapping]] = ..., etag: _Optional[str] = ..., record_type: _Optional[_Union[NameWrapper, _Mapping]] = ..., type: _Optional[int] = ..., record: _Optional[_Union[Record, _Mapping]] = ...) -> None: ...

class RetrieveChangesResponse(_message.Message):
    __slots__ = ("record_change", "sync_continuation_token", "client_change_token", "status", "changed_shares", "pending_archived_records", "changed_deltas", "sync_obligations", "zone_attributes_changes")
    RECORD_CHANGE_FIELD_NUMBER: _ClassVar[int]
    SYNC_CONTINUATION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CLIENT_CHANGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CHANGED_SHARES_FIELD_NUMBER: _ClassVar[int]
    PENDING_ARCHIVED_RECORDS_FIELD_NUMBER: _ClassVar[int]
    CHANGED_DELTAS_FIELD_NUMBER: _ClassVar[int]
    SYNC_OBLIGATIONS_FIELD_NUMBER: _ClassVar[int]
    ZONE_ATTRIBUTES_CHANGES_FIELD_NUMBER: _ClassVar[int]
    record_change: _containers.RepeatedCompositeFieldContainer[RecordChange]
    sync_continuation_token: bytes
    client_change_token: bytes
    status: int
    changed_shares: _containers.RepeatedScalarFieldContainer[bytes]
    pending_archived_records: _containers.RepeatedScalarFieldContainer[bytes]
    changed_deltas: _containers.RepeatedScalarFieldContainer[bytes]
    sync_obligations: bytes
    zone_attributes_changes: bytes
    def __init__(self, record_change: _Optional[_Iterable[_Union[RecordChange, _Mapping]]] = ..., sync_continuation_token: _Optional[bytes] = ..., client_change_token: _Optional[bytes] = ..., status: _Optional[int] = ..., changed_shares: _Optional[_Iterable[bytes]] = ..., pending_archived_records: _Optional[_Iterable[bytes]] = ..., changed_deltas: _Optional[_Iterable[bytes]] = ..., sync_obligations: _Optional[bytes] = ..., zone_attributes_changes: _Optional[bytes] = ...) -> None: ...

class NameWrapper(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class Record(_message.Message):
    __slots__ = ("etag", "record_identifier", "type", "created_by", "time_statistics", "record_field", "modified_by", "protection_info", "permission", "pcs_key")
    class Value(_message.Message):
        __slots__ = ("type", "bytes_value", "signed_value", "double_value", "date_value", "string_value", "location_value", "reference_value", "asset_value", "list_values", "is_encrypted")
        TYPE_FIELD_NUMBER: _ClassVar[int]
        BYTES_VALUE_FIELD_NUMBER: _ClassVar[int]
        SIGNED_VALUE_FIELD_NUMBER: _ClassVar[int]
        DOUBLE_VALUE_FIELD_NUMBER: _ClassVar[int]
        DATE_VALUE_FIELD_NUMBER: _ClassVar[int]
        STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
        LOCATION_VALUE_FIELD_NUMBER: _ClassVar[int]
        REFERENCE_VALUE_FIELD_NUMBER: _ClassVar[int]
        ASSET_VALUE_FIELD_NUMBER: _ClassVar[int]
        LIST_VALUES_FIELD_NUMBER: _ClassVar[int]
        IS_ENCRYPTED_FIELD_NUMBER: _ClassVar[int]
        type: int
        bytes_value: bytes
        signed_value: int
        double_value: float
        date_value: bytes
        string_value: str
        location_value: bytes
        reference_value: bytes
        asset_value: bytes
        list_values: _containers.RepeatedCompositeFieldContainer[Record.Value]
        is_encrypted: bool
        def __init__(self, type: _Optional[int] = ..., bytes_value: _Optional[bytes] = ..., signed_value: _Optional[int] = ..., double_value: _Optional[float] = ..., date_value: _Optional[bytes] = ..., string_value: _Optional[str] = ..., location_value: _Optional[bytes] = ..., reference_value: _Optional[bytes] = ..., asset_value: _Optional[bytes] = ..., list_values: _Optional[_Iterable[_Union[Record.Value, _Mapping]]] = ..., is_encrypted: bool = ...) -> None: ...
    class Field(_message.Message):
        __slots__ = ("identifier", "value")
        IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        identifier: NameWrapper
        value: Record.Value
        def __init__(self, identifier: _Optional[_Union[NameWrapper, _Mapping]] = ..., value: _Optional[_Union[Record.Value, _Mapping]] = ...) -> None: ...
    ETAG_FIELD_NUMBER: _ClassVar[int]
    RECORD_IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    TIME_STATISTICS_FIELD_NUMBER: _ClassVar[int]
    RECORD_FIELD_FIELD_NUMBER: _ClassVar[int]
    MODIFIED_BY_FIELD_NUMBER: _ClassVar[int]
    PROTECTION_INFO_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_FIELD_NUMBER: _ClassVar[int]
    PCS_KEY_FIELD_NUMBER: _ClassVar[int]
    etag: str
    record_identifier: RecordIdentifier
    type: NameWrapper
    created_by: Identifier
    time_statistics: TimeStatistics
    record_field: _containers.RepeatedCompositeFieldContainer[Record.Field]
    modified_by: Identifier
    protection_info: ProtectionInfo
    permission: int
    pcs_key: bytes
    def __init__(self, etag: _Optional[str] = ..., record_identifier: _Optional[_Union[RecordIdentifier, _Mapping]] = ..., type: _Optional[_Union[NameWrapper, _Mapping]] = ..., created_by: _Optional[_Union[Identifier, _Mapping]] = ..., time_statistics: _Optional[_Union[TimeStatistics, _Mapping]] = ..., record_field: _Optional[_Iterable[_Union[Record.Field, _Mapping]]] = ..., modified_by: _Optional[_Union[Identifier, _Mapping]] = ..., protection_info: _Optional[_Union[ProtectionInfo, _Mapping]] = ..., permission: _Optional[int] = ..., pcs_key: _Optional[bytes] = ...) -> None: ...

class TimeStatistics(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EncryptedValue(_message.Message):
    __slots__ = ("signed_value", "date_value", "string_value")
    SIGNED_VALUE_FIELD_NUMBER: _ClassVar[int]
    DATE_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    signed_value: int
    date_value: Date
    string_value: str
    def __init__(self, signed_value: _Optional[int] = ..., date_value: _Optional[_Union[Date, _Mapping]] = ..., string_value: _Optional[str] = ...) -> None: ...

class Date(_message.Message):
    __slots__ = ("time",)
    TIME_FIELD_NUMBER: _ClassVar[int]
    time: float
    def __init__(self, time: _Optional[float] = ...) -> None: ...
