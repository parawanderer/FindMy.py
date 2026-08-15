"""Tests for the CloudKit transport and record layer (Stage 4)."""

from __future__ import annotations

import gzip
import json
import uuid

import pytest

from findmy.cloudkit.client import (
    AsyncCloudKitClient,
    _decode_varint,
    _encode_varint,
    CloudKitContainerInfo,
    CloudKitError,
    _check_result,
    _ClientIdentity,
    decode_delimited,
    encode_delimited,
)
from findmy.cloudkit.constants import (
    BEACON_STORE_ZONE,
    SYNC_STATUS_COMPLETE,
    ClientErrorCode,
    OperationType,
    ResultCode,
)
from findmy.cloudkit.proto import cloudkit_pb2 as ck
from findmy.cloudkit.records import CloudKitRecord, records_from_changes
from findmy.errors import UnauthorizedError, UnhandledProtocolError

FINDMY_CLIENT_INFO = (
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
)
DEVICE_UUID = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"


class FakeResponse:
    """Stands in for findmy.util.http.HttpResponse."""

    def __init__(self, status_code: int, content: bytes) -> None:
        self.status_code = status_code
        self._content = content

    @property
    def ok(self) -> bool:
        return str(self.status_code).startswith("2")

    @property
    def content(self) -> bytes:
        return self._content

    def text(self) -> str:
        return self._content.decode("utf-8", errors="replace")

    def json(self) -> dict:
        return json.loads(self.text())


class FakeHttp:
    """Records what was sent and replays a queue of prepared responses."""

    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def post(self, url, **kwargs):  # noqa: ANN001, ANN003, ANN202
        self.calls.append({"url": url, **kwargs})
        if not self._responses:
            msg = f"No prepared response for {url}"
            raise AssertionError(msg)
        return self._responses.pop(0)

    async def close(self) -> None:
        return


class FakeAccount:
    """The slice of AsyncAppleAccount that the CloudKit client actually uses."""

    def __init__(self) -> None:
        self.client_info = FINDMY_CLIENT_INFO
        # The CloudKit client takes its serial from the account rather than keeping a
        # second copy, so this fake has to carry one too.
        self.serial = "0FINDMYPY001"
        self.device_uuid = DEVICE_UUID
        self.dsid = "1234567890"
        self.service_tokens = {
            "mmeAuthToken": "mme-token",
            "cloudKitToken": "ck-token",
            "searchPartyToken": "sp-token",
        }

    async def get_anisette_headers(self) -> dict[str, str]:
        return {"X-Apple-I-MD": "otp", "X-Mme-Device-Id": DEVICE_UUID.upper()}


def make_client(responses: list[FakeResponse] | None = None) -> AsyncCloudKitClient:
    client = AsyncCloudKitClient(FakeAccount())  # pyright: ignore [reportArgumentType]
    client._http = FakeHttp(responses or [])  # noqa: SLF001
    return client


def app_init_response(partition: str = "24") -> FakeResponse:
    return FakeResponse(
        200,
        json.dumps(
            {
                "cloudKitUserId": "_" + "a" * 32,
                "cloudKitDatabaseUrl": f"https://p{partition}-ckdatabase.icloud.com",
                "cloudKitDatabaseGatewayUrl": "https://gateway.icloud.com/ckdatabase",
                "cloudKitCodeGatewayUrl": "https://gateway.icloud.com/ckcoderouter",
                "cloudKitShareGatewayUrl": "https://gateway.icloud.com/ckshare",
                "values": [],
            },
        ).encode(),
    )


def operation_response(
    *,
    result_code: int = ResultCode.SUCCESS,
    changes: list[ck.RecordChange] | None = None,
    token: bytes | None = None,
    status: int | None = None,
) -> FakeResponse:
    response = ck.ResponseOperation(result=ck.Result(code=result_code))
    if changes is not None:
        response.retrieve_changes_response.record_change.extend(changes)
    if token is not None:
        response.retrieve_changes_response.sync_continuation_token = token
    if status is not None:
        response.retrieve_changes_response.status = status

    # Responses are length-delimited, same as requests.
    payload = response.SerializeToString()
    return FakeResponse(200, _encode_varint(len(payload)) + payload)


# --------------------------------------------------------------------------------------
# Length-delimited framing
# --------------------------------------------------------------------------------------


def unframe(body: bytes) -> bytes:
    """Strip the varint length prefix from a length-delimited frame."""
    length, offset = _decode_varint(body, 0)
    assert len(body) - offset == length
    return body[offset : offset + length]


def test_delimited_roundtrip() -> None:
    request = ck.RequestOperation(request=ck.Operation(type=201))
    framed = encode_delimited(request)

    # The frame is a varint length followed by exactly that many bytes.
    assert unframe(framed) == request.SerializeToString()

    (decoded,) = list(decode_delimited(framed))
    assert decoded is not None


def test_decode_delimited_reads_a_stream_of_messages() -> None:
    first = ck.ResponseOperation(result=ck.Result(code=ResultCode.SUCCESS))
    second = ck.ResponseOperation(result=ck.Result(code=ResultCode.FAILURE))

    body = b""
    for message in (first, second):
        payload = message.SerializeToString()
        body += _encode_varint(len(payload)) + payload

    decoded = list(decode_delimited(body))
    assert [d.result.code for d in decoded] == [ResultCode.SUCCESS, ResultCode.FAILURE]


def test_decode_delimited_rejects_a_truncated_body() -> None:
    with pytest.raises(UnhandledProtocolError):
        list(decode_delimited(b"\x20\x01\x02"))


def test_encode_varint_is_base128_little_endian() -> None:
    assert _encode_varint(0) == b"\x00"
    assert _encode_varint(127) == b"\x7f"
    assert _encode_varint(128) == b"\x80\x01"
    assert _encode_varint(300) == b"\xac\x02"


# --------------------------------------------------------------------------------------
# Client identity
# --------------------------------------------------------------------------------------


def test_client_identity_parses_model_and_os() -> None:
    identity = _ClientIdentity.parse(FINDMY_CLIENT_INFO)

    assert identity.model == "MacBookPro18,3"
    assert identity.os_version == "13.4.1"


def test_cloudkit_client_info_keeps_the_device_and_swaps_the_bundle() -> None:
    identity = _ClientIdentity.parse(FINDMY_CLIENT_INFO)
    client_info = identity.cloudkit_client_info

    assert client_info.startswith("<MacBookPro18,3> <Mac OS X;13.4.1;22F8> ")
    assert "cloudd" in client_info
    assert "Xcode" not in client_info


def test_client_identity_survives_an_unparseable_string() -> None:
    identity = _ClientIdentity.parse("nonsense")

    assert identity.model == ""
    assert identity.cloudkit_client_info.startswith("<com.apple.cloudkit")


# --------------------------------------------------------------------------------------
# The request envelope
# --------------------------------------------------------------------------------------


def test_header_sends_its_three_constants_including_the_zeros() -> None:
    # proto3 would drop a field set to zero, which is why the schema is proto2. If this
    # test fails, two of the three constants have silently stopped being sent.
    header = make_client()._build_header()  # noqa: SLF001
    roundtripped = ck.RequestOperation.Header.FromString(header.SerializeToString())

    assert roundtripped.HasField("unknown_29")
    assert roundtripped.HasField("unknown_34")
    assert roundtripped.unknown_29 == 0
    assert roundtripped.unknown_34 == 0
    assert roundtripped.unknown_35 == 1


def test_header_carries_the_required_device_hardware_id() -> None:
    # Omitting this is rejected with BAD_SYNTAX even for a read.
    header = make_client()._build_header()  # noqa: SLF001

    assert header.device_hardware_id == uuid.UUID(DEVICE_UUID).hex.upper()
    assert len(header.device_hardware_id) == 32
    assert set(header.device_hardware_id) <= set("0123456789ABCDEF")


def test_header_leaves_the_user_token_unset() -> None:
    # Operations authenticate by HTTP header; a token here does nothing.
    assert not make_client()._build_header().HasField("user_token")  # noqa: SLF001


def test_header_sets_enums_explicitly_because_none_of_them_use_zero() -> None:
    header = make_client()._build_header()  # noqa: SLF001

    assert header.application_container_environment == ck.PRODUCTION
    assert header.target_database == ck.PRIVATE_DB
    assert header.isolation_level == ck.ZONE


def test_operation_type_is_encoded_at_field_two() -> None:
    # Field 1 is a string. A varint there is met with an empty HTTP 500 and no diagnostic.
    raw = ck.Operation(type=int(OperationType.ZONE_RETRIEVE_TYPE)).SerializeToString()

    assert raw[0] >> 3 == 2
    assert raw[0] & 0x07 == 0  # varint


def test_request_declares_its_operation_in_both_places() -> None:
    client = make_client()
    request = client._build_request(OperationType.RECORD_RETRIEVE_CHANGES_TYPE)  # noqa: SLF001
    request.retrieve_changes_request.SetInParent()

    assert request.request.type == 213
    assert request.HasField("retrieve_changes_request")


# --------------------------------------------------------------------------------------
# Results and errors
# --------------------------------------------------------------------------------------


def test_check_result_accepts_success() -> None:
    _check_result(ck.Result(code=ResultCode.SUCCESS))


def test_check_result_lets_a_partial_result_through() -> None:
    # A batched request can half-succeed, and discarding the good half loses records.
    _check_result(ck.Result(code=ResultCode.PARTIAL))


def test_check_result_raises_and_names_the_client_error() -> None:
    result = ck.Result(
        code=ResultCode.FAILURE,
        error=ck.Error(
            client_error=ck.Error.ClientError(code=ClientErrorCode.BAD_SYNTAX),
            error_description="deviceHardwareID is required field",
            error_key="ABCD1234",
        ),
    )

    with pytest.raises(CloudKitError) as excinfo:
        _check_result(result)

    assert "BAD_SYNTAX" in str(excinfo.value)
    assert "deviceHardwareID" in str(excinfo.value)
    assert "ABCD1234" in str(excinfo.value)
    assert excinfo.value.client_error == ClientErrorCode.BAD_SYNTAX


def test_check_result_reports_an_unknown_client_error_code_rather_than_hiding_it() -> None:
    result = ck.Result(
        code=ResultCode.FAILURE,
        error=ck.Error(client_error=ck.Error.ClientError(code=9999)),
    )

    with pytest.raises(CloudKitError) as excinfo:
        _check_result(result)

    assert "9999" in str(excinfo.value)


# --------------------------------------------------------------------------------------
# Opening the container
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_open_container_returns_the_user_id_and_urls() -> None:
    client = make_client([app_init_response()])
    info = await client.open_container()

    assert info.user_id.startswith("_")
    assert info.database_gateway_url == "https://gateway.icloud.com/ckdatabase"


@pytest.mark.asyncio
async def test_open_container_authenticates_with_the_mobileme_token_not_the_cloudkit_one() -> None:
    client = make_client([app_init_response()])
    await client.open_container()

    call = client._http.calls[0]  # noqa: SLF001
    assert call["auth"] == ("1234567890", "mme-token")
    assert "container=com.apple.icloud.searchparty" in call["url"]


@pytest.mark.asyncio
async def test_open_container_is_cached() -> None:
    client = make_client([app_init_response()])

    first = await client.open_container()
    second = await client.open_container()

    assert first is second
    assert len(client._http.calls) == 1  # noqa: SLF001


@pytest.mark.asyncio
async def test_open_container_reports_an_expired_token_as_unauthorized() -> None:
    client = make_client([FakeResponse(401, b"")])

    with pytest.raises(UnauthorizedError):
        await client.open_container()


@pytest.mark.asyncio
async def test_open_container_rejects_a_response_without_a_user_id() -> None:
    client = make_client([FakeResponse(200, b"{}")])

    with pytest.raises(UnhandledProtocolError):
        await client.open_container()


def test_partition_is_read_off_the_direct_database_url() -> None:
    # Every per-account service is named p<N>-<service>.icloud.com, so this is how the
    # escrow host is derived in Stage 3.
    info = CloudKitContainerInfo(
        user_id="_x",
        database_url="https://p24-ckdatabase.icloud.com",
        database_gateway_url=None,
        code_gateway_url=None,
        share_gateway_url=None,
        raw={},
    )

    assert info.partition == "24"


def test_partition_is_none_when_no_partitioned_url_came_back() -> None:
    info = CloudKitContainerInfo(
        user_id="_x",
        database_url="https://gateway.icloud.com/ckdatabase",
        database_gateway_url=None,
        code_gateway_url=None,
        share_gateway_url=None,
        raw={},
    )

    assert info.partition is None


# --------------------------------------------------------------------------------------
# Operations
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_operations_go_to_the_gateway_url_and_authenticate_by_header() -> None:
    client = make_client([app_init_response(), operation_response(changes=[])])
    await client.record_sync(BEACON_STORE_ZONE)

    call = client._http.calls[1]  # noqa: SLF001
    assert call["url"] == "https://gateway.icloud.com/ckdatabase/api/client/record/sync"
    assert call["headers"]["x-cloudkit-authtoken"] == "ck-token"
    assert call["headers"]["x-cloudkit-userid"].startswith("_")
    assert "auth" not in call


@pytest.mark.asyncio
async def test_operation_bodies_are_gzipped_and_length_delimited() -> None:
    client = make_client([app_init_response(), operation_response(changes=[])])
    await client.record_sync(BEACON_STORE_ZONE)

    call = client._http.calls[1]  # noqa: SLF001
    assert call["headers"]["content-encoding"] == "gzip"
    assert "delimited=true" in call["headers"]["content-type"]

    body = gzip.decompress(call["data"])
    assert unframe(body)  # a well-formed frame, whatever its length


@pytest.mark.asyncio
async def test_record_sync_names_the_zone_by_name_and_owner() -> None:
    client = make_client([app_init_response(), operation_response(changes=[])])
    await client.record_sync(BEACON_STORE_ZONE)

    body = gzip.decompress(client._http.calls[1]["data"])  # noqa: SLF001
    request = ck.RequestOperation.FromString(unframe(body))
    zone = request.retrieve_changes_request.zone_identifier

    assert zone.value.name == "BeaconStore"
    assert zone.value.type == ck.Identifier.RECORD_ZONE
    assert zone.owner_identifier.name.startswith("_")
    assert zone.owner_identifier.type == ck.Identifier.USER


@pytest.mark.asyncio
async def test_record_sync_returns_the_continuation_token() -> None:
    client = make_client([app_init_response(), operation_response(changes=[], token=b"tok")])
    page = await client.record_sync(BEACON_STORE_ZONE)

    assert page.continuation_token == b"tok"


@pytest.mark.asyncio
async def test_an_empty_500_is_reported_as_a_request_that_did_not_parse() -> None:
    client = make_client([app_init_response(), FakeResponse(500, b"")])

    with pytest.raises(UnhandledProtocolError, match="did not.*parse"):
        await client.record_sync(BEACON_STORE_ZONE)


@pytest.mark.asyncio
async def test_a_throttled_operation_is_not_reported_as_a_generic_failure() -> None:
    client = make_client([app_init_response(), FakeResponse(429, b"")])

    with pytest.raises(UnhandledProtocolError, match="throttl"):
        await client.record_sync(BEACON_STORE_ZONE)


@pytest.mark.asyncio
async def test_iter_records_stops_when_the_zone_reports_itself_synced() -> None:
    # And note the page carrying that status still carries changes: emptiness is not the
    # signal, which is why the loop reads the status instead.
    change = ck.RecordChange(record=ck.Record(etag="e"))
    client = make_client(
        [
            app_init_response(),
            operation_response(changes=[change], token=b"a"),
            operation_response(changes=[change], token=b"b", status=SYNC_STATUS_COMPLETE),
        ],
    )

    seen = [c async for c in client.iter_records(BEACON_STORE_ZONE)]

    assert len(seen) == 2
    assert len(client._http.calls) == 3  # noqa: SLF001 -- open, then two pages, and no more


@pytest.mark.asyncio
async def test_a_synced_page_that_still_carries_changes_does_not_lose_them() -> None:
    change = ck.RecordChange(record=ck.Record(etag="e"))
    client = make_client(
        [
            app_init_response(),
            operation_response(changes=[change, change], token=b"a", status=SYNC_STATUS_COMPLETE),
        ],
    )

    assert len([c async for c in client.iter_records(BEACON_STORE_ZONE)]) == 2


@pytest.mark.asyncio
async def test_iter_records_stops_and_warns_if_it_can_neither_finish_nor_continue() -> None:
    change = ck.RecordChange(record=ck.Record(etag="e"))
    client = make_client(
        [
            app_init_response(),
            operation_response(changes=[change], token=b"a"),
            operation_response(changes=[change], token=b"a"),
        ],
    )

    seen = [c async for c in client.iter_records(BEACON_STORE_ZONE)]
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_a_page_reports_whether_the_zone_is_synced() -> None:
    client = make_client([app_init_response(), operation_response(changes=[], status=3)])

    page = await client.record_sync(BEACON_STORE_ZONE)

    assert page.status == SYNC_STATUS_COMPLETE
    assert page.complete is True


# --------------------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------------------


def make_record(
    name: str = "REC-1",
    record_type: str = "MasterBeaconRecord",
    fields: dict[str, tuple[int, bytes]] | None = None,
) -> ck.Record:
    record = ck.Record(
        etag="etag-1",
        record_identifier=ck.RecordIdentifier(value=ck.Identifier(name=name)),
        type=ck.NameWrapper(name=record_type),
        protection_info=ck.ProtectionInfo(protection_info=b"\x30\x00"),
    )
    for field_name, (value_type, payload) in (fields or {}).items():
        record.record_field.append(
            ck.Record.Field(
                identifier=ck.NameWrapper(name=field_name),
                value=ck.Record.Value(
                    type=value_type,
                    bytes_value=payload,
                    is_encrypted=True,
                ),
            ),
        )
    return record


def test_record_is_indexed_by_field_name() -> None:
    record = CloudKitRecord.from_proto(
        make_record(fields={"privateKey": (20, b"cipher"), "model": (3, b"cipher2")}),
        "BeaconStore",
    )

    assert record.name == "REC-1"
    assert record.zone_name == "BeaconStore"
    assert record.record_type == "MasterBeaconRecord"
    assert set(record.fields) == {"privateKey", "model"}
    assert record.protection_info == b"\x30\x00"


def test_a_fields_declared_type_describes_its_plaintext_not_its_ciphertext() -> None:
    # Every field in this zone arrives encrypted while declaring the type its plaintext
    # will have. Branching on type alone reads ciphertext as a string.
    record = CloudKitRecord.from_proto(
        make_record(fields={"model": (3, b"not-a-string")}),
        "BeaconStore",
    )
    field = record.fields["model"]

    assert field.is_encrypted
    assert field.type_name == "STRING_TYPE"
    assert field.raw == b"not-a-string"


def test_records_from_changes_skips_a_change_that_carries_no_record() -> None:
    # A deletion carries no record; assuming one is present fails on an ordinary zone.
    changes = [
        ck.RecordChange(record=make_record()),
        ck.RecordChange(identifier=ck.RecordIdentifier(value=ck.Identifier(name="gone"))),
    ]

    records = records_from_changes(changes)
    assert len(records) == 1
    assert records[0].name == "REC-1"


def test_records_from_changes_falls_back_to_the_type_on_the_change() -> None:
    record = make_record()
    record.ClearField("type")
    change = ck.RecordChange(
        record=record,
        record_type=ck.NameWrapper(name="BeaconNamingRecord"),
    )

    (parsed,) = records_from_changes([change])
    assert parsed.record_type == "BeaconNamingRecord"


# --------------------------------------------------------------------------------------
# Server-side function invocation (how the keychain trust circle is reached)
# --------------------------------------------------------------------------------------


def function_invoke_response(payload: bytes) -> FakeResponse:
    response = ck.ResponseOperation(result=ck.Result(code=ResultCode.SUCCESS))
    response.function_invoke_response.serialized_result = payload

    serialized = response.SerializeToString()
    return FakeResponse(200, _encode_varint(len(serialized)) + serialized)


@pytest.mark.asyncio
async def test_function_invoke_goes_to_the_code_gateway_not_the_database_one() -> None:
    client = make_client([app_init_response(), function_invoke_response(b"result")])

    await client.function_invoke("Cuttlefish", "fetchViableBottles", b"params")

    call = client._http.calls[1]  # noqa: SLF001
    assert call["url"] == "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke"


@pytest.mark.asyncio
async def test_function_invoke_carries_the_inner_message_untouched() -> None:
    client = make_client([app_init_response(), function_invoke_response(b"result")])

    result = await client.function_invoke("Cuttlefish", "fetchViableBottles", b"params")

    body = gzip.decompress(client._http.calls[1]["data"])  # noqa: SLF001
    request = ck.RequestOperation.FromString(unframe(body))

    assert request.request.type == 1101
    assert request.function_invoke_request.service == "Cuttlefish"
    assert request.function_invoke_request.name == "fetchViableBottles"
    assert request.function_invoke_request.parameters == b"params"
    assert result == b"result"


@pytest.mark.asyncio
async def test_viable_bottles_are_read_out_of_the_inner_message() -> None:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415
    from findmy.keychain.cuttlefish import fetch_viable_bottles  # noqa: PLC0415

    inner = cf.FetchViableBottlesResponse(
        valid=[cf.EscrowData(id="BOTTLE-1"), cf.EscrowData(id="BOTTLE-2")],
        partial=[cf.EscrowMeta()],
    )
    client = make_client(
        [app_init_response(), function_invoke_response(inner.SerializeToString())],
    )

    bottles = await fetch_viable_bottles(client)

    assert bottles.valid == ["BOTTLE-1", "BOTTLE-2"]
    assert bottles.partial_count == 1


@pytest.mark.asyncio
async def test_an_undecodable_inner_message_is_not_reported_as_a_cloudkit_error() -> None:
    # CloudKit neither parses nor validates the inner payload, so a malformed one gives a
    # *successful* operation carrying a result that will not decode.
    from findmy.keychain.cuttlefish import CuttlefishError, fetch_viable_bottles  # noqa: PLC0415

    client = make_client([app_init_response(), function_invoke_response(b"\xff\xff\xff\xff")])

    with pytest.raises(CuttlefishError, match="inner message"):
        await fetch_viable_bottles(client)


def test_the_modelled_response_fields_leave_nothing_unknown() -> None:
    # The fields the first live run reported as unmodelled are now declared, so an
    # unknown field from here on means something genuinely new.
    from findmy.cloudkit.client import describe_unknown_fields  # noqa: PLC0415

    payload = ck.RetrieveChangesResponse(
        record_change=[ck.RecordChange(etag="e")],
        sync_continuation_token=b"tok",
        status=3,
        zone_attributes_changes=b"\x0a\x02hi",
    )
    roundtripped = ck.RetrieveChangesResponse.FromString(payload.SerializeToString())

    assert describe_unknown_fields(roundtripped) == []
