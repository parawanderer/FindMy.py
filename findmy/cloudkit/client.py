"""
Reaching a private CloudKit container, and reading records out of it.

Implements Stage 4 of the Find My key-export protocol specification. What comes back is
ciphertext: every interesting field of every record in the accessory zone is encrypted
under keys CloudKit never sees. Turning that into plaintext is :mod:`findmy.cloudkit.pcs`.
"""

from __future__ import annotations

import gzip
import logging
import secrets
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NamedTuple
from urllib.parse import quote

from typing_extensions import override

from findmy.errors import UnauthorizedError, UnhandledProtocolError
from findmy.util.abc import Closable
from findmy.util.http import HttpSession

from .constants import (
    CK_APP_INIT_URL,
    PATH_CODE_INVOKE,
    PATH_RECORD_SAVE,
    PATH_RECORD_SYNC,
    PATH_ZONE_RETRIEVE,
    PROTOBUF_CONTENT_TYPE,
    SEARCHPARTY_BUNDLE,
    SEARCHPARTY_CONTAINER,
    SYNC_STATUS_COMPLETE,
    ClientErrorCode,
    OperationType,
    ResultCode,
    SaveSemantics,
)
from .proto import cloudkit_pb2 as ck

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

    from findmy.reports.account import AsyncAppleAccount

logger = logging.getLogger(__name__)

# CloudKit's own client library, as this client claims to be it.
_CLOUDKIT_LIBRARY_NAME = "com.apple.cloudkit.CloudKitDaemon"
_CLOUDKIT_LIBRARY_VERSION = "1970"
_CLOUDKIT_USER_AGENT = "CloudKit/1970 (19H384)"
_CLOUDKIT_CLIENT_INFO_BUNDLE = "com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)"
_MMCS_PROTOCOL_VERSION = "5.0"


def _random_operation_id() -> str:
    """
    Generate one of the correlation identifiers CloudKit deduplicates requests by.

    Fresh per request rather than constant: a client that sends the same operation id
    repeatedly is describing a retry of one operation, which is not what is meant.
    """
    return secrets.token_hex(16).upper()


def _random_request_uuid() -> str:
    """Generate the per-request v4 UUID, uppercase as CloudKit expects."""
    return str(uuid.uuid4()).upper()


class _ClientIdentity(NamedTuple):
    """The device this client claims to be, parsed out of its `X-Mme-Client-Info`."""

    model: str
    os_version: str
    prefix: str

    @classmethod
    def parse(cls, client_info: str) -> _ClientIdentity:
        """
        Pull the hardware and OS identity out of a client-info string.

        The format is `<MODEL> <OS;VERSION;BUILD> <BUNDLE>`. Only the first two groups are
        wanted here; the bundle is replaced, because CloudKit is addressed as CloudKit's
        own daemon rather than as whatever the account authenticated as.

        Falls back to empty values rather than raising: these fields identify the caller
        and are not known to be validated, so a client-info string in an unexpected shape
        should not stop a fetch.
        """
        groups = [part for part in client_info.split("<") if ">" in part]
        parsed = [part.split(">", 1)[0] for part in groups]

        model = parsed[0] if parsed else ""
        os_version = ""
        if len(parsed) > 1:
            os_parts = parsed[1].split(";")
            os_version = os_parts[1] if len(os_parts) > 1 else ""

        prefix = "".join(f"<{part}> " for part in parsed[:2])
        if not prefix:
            logger.warning(
                "Could not parse client info %r; sending the CloudKit bundle alone",
                client_info,
            )

        return cls(model=model, os_version=os_version, prefix=prefix)

    @property
    def cloudkit_client_info(self) -> str:
        """The client-info string to send with CloudKit requests."""
        return f"{self.prefix}<{_CLOUDKIT_CLIENT_INFO_BUNDLE}>"


@dataclass(frozen=True)
class CloudKitContainerInfo:
    """
    Where CloudKit lives for this account, as returned by opening a container.

    iCloud partitions accounts across numbered service hosts, so none of these URLs is
    safe to hardcode: the one that works for one account is meaningless for another.
    """

    user_id: str
    """This account's CloudKit user identifier. Required to name a private record zone."""

    database_url: str | None
    """The account's own partition, addressed directly."""

    database_gateway_url: str | None
    """The gateway-routed form. Record operations go here, not to the direct form."""

    code_gateway_url: str | None
    """Server-side function invocation -- how the keychain trust circle is reached."""

    share_gateway_url: str | None
    """Sharing operations. Relevant only if shared accessories are ever in scope."""

    raw: dict[str, Any]
    """The whole response, so that a key not modelled here is still reachable."""

    @property
    def partition(self) -> str | None:
        """
        The account's iCloud partition, as the bare number of a `p<N>-` host prefix.

        Other per-account services are named `p<N>-<service>.icloud.com`, so this is how
        their hosts are derived. Returns None if no partitioned URL was returned.
        """
        for url in (self.database_url, self.raw.get("cloudKitShareUrl")):
            if not url:
                continue
            host = url.split("://", 1)[-1].split("/", 1)[0]
            if host.startswith("p") and "-" in host:
                candidate = host[1:].split("-", 1)[0]
                if candidate.isdigit():
                    return candidate
        return None


class CloudKitError(UnhandledProtocolError):
    """Raised when CloudKit rejects an operation."""

    def __init__(self, message: str, result: ck.Result) -> None:
        """Initialize from the failing result, keeping it for callers that want detail."""
        super().__init__(message)

        self.result: ck.Result = result
        self.code: int = result.code
        self.client_error: int | None = (
            result.error.client_error.code if result.error.HasField("client_error") else None
        )
        self.server_error: int | None = (
            result.error.server_error.code if result.error.HasField("server_error") else None
        )
        self.retry_after: int | None = (
            result.error.retry_after_seconds
            if result.error.HasField("retry_after_seconds")
            else None
        )
        self.error_key: str = result.error.error_key


class RecordSyncPage(NamedTuple):
    """One page of record changes, the token that continues from it, and its status."""

    changes: list[ck.RecordChange]
    continuation_token: bytes | None

    status: int | None
    """
    Whether the zone is fully synced. `SYNC_STATUS_COMPLETE` means it is.

    This is what says a fetch is finished. A page carrying changes may still be the last
    one, so an empty page is not the signal -- see :attr:`complete`.
    """

    @property
    def complete(self) -> bool:
        """Whether this page finished the zone."""
        return self.status == SYNC_STATUS_COMPLETE


def _encode_varint(value: int) -> bytes:
    """Encode an unsigned integer in protobuf's base-128 varint form."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a varint, returning its value and the offset just past it."""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            msg = "Truncated varint in CloudKit response"
            raise UnhandledProtocolError(msg)
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def encode_delimited(message: ck.RequestOperation) -> bytes:
    """
    Frame a request the way CloudKit's content type declares: length-delimited.

    Several operations may be batched into one request, so a body is a stream of messages
    rather than a single one, each preceded by its length.
    """
    payload = message.SerializeToString()
    return _encode_varint(len(payload)) + payload


def decode_delimited(data: bytes) -> Iterator[ck.ResponseOperation]:
    """Split a length-delimited response body back into its messages."""
    offset = 0
    while offset < len(data):
        length, offset = _decode_varint(data, offset)
        chunk = data[offset : offset + length]
        if len(chunk) != length:
            msg = f"Truncated CloudKit response: wanted {length} bytes, got {len(chunk)}"
            raise UnhandledProtocolError(msg)
        offset += length

        response = ck.ResponseOperation()
        response.ParseFromString(chunk)
        yield response


class AsyncCloudKitClient(Closable):
    """
    A client for one private CloudKit container.

    Opening the container is cheap, has no side effects, and proves rather a lot at once:
    that the account's iCloud tokens are accepted by CloudKit, that this client's invented
    identity passes its checks, and that the container may be opened at all. Nothing after
    it is worth attempting if it fails.
    """

    def __init__(  # noqa: PLR0913 -- all keyword-only, and each names one wire value
        self,
        account: AsyncAppleAccount,
        *,
        container: str = SEARCHPARTY_CONTAINER,
        bundle: str = SEARCHPARTY_BUNDLE,
        environment: str = "Production",
        database_scope: str = "PRIVATE",
        device_name: str = "FindMy.py",
        device_serial: str = "0",
    ) -> None:
        """
        Initialize the client.

        :param account: A logged-in account. Its iCloud service tokens are what
            authenticates every call made here.
        :param container: The CloudKit container id. Defaults to the Find My one.
        :param bundle: The bundle id that owns the container.
        :param device_name: Name this client reports itself by.
        :param device_serial: Serial this client reports itself by. Defaults to matching
            what the account already sends as its Anisette serial.
        """
        super().__init__()

        self._account = account
        self._container = container
        self._bundle = bundle
        self._environment = environment
        self._database_scope = database_scope
        self._device_name = device_name
        self._device_serial = device_serial

        self._identity = _ClientIdentity.parse(account.client_info)
        self._info: CloudKitContainerInfo | None = None
        self._http: HttpSession = HttpSession()

    @property
    def container_info(self) -> CloudKitContainerInfo | None:
        """What opening the container returned, or None if it has not been opened yet."""
        return self._info

    @property
    def _device_hardware_id(self) -> str:
        """
        The 32-hex-character device identifier CloudKit requires, even for a read.

        Derived from the account's own persisted device UUID rather than generated, so
        that it is stable for the life of the installation without introducing a second
        piece of identity state that could drift from the first.
        """
        return uuid.UUID(self._account.device_uuid).hex.upper()

    @override
    async def close(self) -> None:
        """Close the underlying HTTP session. Does not close the account."""
        await self._http.close()

    async def _cloudkit_headers(self) -> dict[str, str]:
        """Build the header set every request in this stage carries."""
        headers = {
            "x-cloudkit-containerid": self._container,
            "x-cloudkit-bundleid": self._bundle,
            "x-cloudkit-databasescope": self._database_scope,
            "x-cloudkit-environment": self._environment,
            "x-cloudkit-duetpreclearedmode": "None",
            "x-apple-operation-group-id": _random_operation_id(),
            "x-apple-operation-id": _random_operation_id(),
            "x-apple-request-uuid": _random_request_uuid(),
            "x-apple-c2-metric-triggers": "0",
            "user-agent": _CLOUDKIT_USER_AGENT,
            "x-mme-client-info": self._identity.cloudkit_client_info,
            "accept": "application/x-protobuf",
            "accept-encoding": "gzip",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-transform",
        }
        headers.update(await self._account.get_anisette_headers())
        return headers

    async def open_container(self, *, refresh: bool = False) -> CloudKitContainerInfo:
        """
        Open the container, learning this account's CloudKit user id and service URLs.

        Authenticated with the general iCloud credential over HTTP Basic -- not with the
        CloudKit token, despite this being CloudKit. The CloudKit token authenticates
        every operation afterwards; the two are not interchangeable.

        :param refresh: Re-open even if the container has been opened already.
        """
        if self._info is not None and not refresh:
            return self._info

        logger.info("Opening CloudKit container %s", self._container)

        url = f"{CK_APP_INIT_URL}?container={quote(self._container)}"
        auth = (self._account.dsid, self._account.service_tokens["mmeAuthToken"])

        resp = await self._http.post(
            url,
            auth=auth,
            headers=await self._cloudkit_headers(),
        )
        if resp.status_code == 401:
            msg = (
                "CloudKit rejected the iCloud token. It has most likely expired;"
                " logging in again will obtain a fresh one."
            )
            raise UnauthorizedError(msg)
        if not resp.ok:
            msg = f"Failed to open CloudKit container: HTTP {resp.status_code}"
            raise UnhandledProtocolError(msg)

        data = resp.json()
        user_id = data.get("cloudKitUserId")
        if not user_id:
            msg = "CloudKit did not return a user id; cannot address any private zone"
            raise UnhandledProtocolError(msg)

        self._info = CloudKitContainerInfo(
            user_id=user_id,
            database_url=data.get("cloudKitDatabaseUrl"),
            database_gateway_url=data.get("cloudKitDatabaseGatewayUrl"),
            code_gateway_url=data.get("cloudKitCodeGatewayUrl"),
            share_gateway_url=data.get("cloudKitShareGatewayUrl"),
            raw=data,
        )

        logger.debug(
            "Container open: user %s, partition %s",
            user_id,
            self._info.partition,
        )
        return self._info

    def _build_header(self) -> ck.RequestOperation.Header:
        """
        Build the request header identifying this client.

        `user_token` is deliberately left unset: operations are authenticated by HTTP
        header. The three unnamed fields are sent as the constants the protocol expects;
        a server that wants them will not say so.
        """
        return ck.RequestOperation.Header(
            application_container=self._container,
            application_bundle=self._bundle,
            device_identifier=ck.Identifier(
                name=self._account.device_uuid.upper(),
                type=ck.Identifier.DEVICE,
            ),
            device_software_version=self._identity.os_version,
            device_hardware_version=self._identity.model,
            device_library_name=_CLOUDKIT_LIBRARY_NAME,
            device_library_version=_CLOUDKIT_LIBRARY_VERSION,
            mmcs_protocol_version=_MMCS_PROTOCOL_VERSION,
            application_container_environment=ck.PRODUCTION,
            device_assigned_name=self._device_name,
            device_hardware_id=self._device_hardware_id,
            target_database=ck.PRIVATE_DB,
            isolation_level=ck.ZONE,
            group=_random_operation_id(),
            device_serial=self._device_serial,
            unknown_29=0,
            unknown_34=0,
            unknown_35=1,
        )

    def _build_request(self, operation: OperationType) -> ck.RequestOperation:
        """Build a request envelope for one operation, declaring its type both ways."""
        return ck.RequestOperation(
            header=self._build_header(),
            request=ck.Operation(
                operation_uuid=_random_request_uuid(),
                type=int(operation),
                synchronous_mode=False,
                last=True,
            ),
        )

    def _zone_identifier(self, zone_name: str) -> ck.RecordZoneIdentifier:
        """Name a private zone: the zone's own name, plus this account as its owner."""
        if self._info is None:
            msg = "Container has not been opened; call open_container() first"
            raise UnhandledProtocolError(msg)

        return ck.RecordZoneIdentifier(
            value=ck.Identifier(name=zone_name, type=ck.Identifier.RECORD_ZONE),
            owner_identifier=ck.Identifier(
                name=self._info.user_id,
                type=ck.Identifier.USER,
            ),
            environment=ck.PRODUCTION,
        )

    async def _post_operation(
        self,
        path: str,
        request: ck.RequestOperation,
        *,
        base_url: str | None = None,
    ) -> ck.ResponseOperation:
        """
        Send one operation and return its response, having checked the result.

        Operations are addressed to the gateway-routed URL rather than to the account's
        own partition host, and are authenticated by header rather than by anything in
        the protobuf envelope.
        """
        info = await self.open_container()
        base = base_url or info.database_gateway_url
        if not base:
            msg = "Container did not return a database gateway URL"
            raise UnhandledProtocolError(msg)

        headers = await self._cloudkit_headers()
        headers.update(
            {
                "content-type": PROTOBUF_CONTENT_TYPE,
                "content-encoding": "gzip",
                "x-cloudkit-userid": info.user_id,
                "x-cloudkit-authtoken": self._account.service_tokens["cloudKitToken"],
            },
        )

        body = gzip.compress(encode_delimited(request))

        resp = await self._http.post(
            base.rstrip("/") + path,
            headers=headers,
            data=body,
        )

        if resp.status_code == 401:
            msg = "CloudKit rejected the token for this operation; log in again"
            raise UnauthorizedError(msg)
        if resp.status_code == 429:
            msg = "CloudKit is throttling this account"
            raise UnhandledProtocolError(msg)
        if resp.status_code == 500 and not resp.text().strip():
            # An empty 500 is this API's answer to a request that did not parse. There is
            # no protobuf error to decode and no hint as to the cause; the field numbering
            # is the first thing to suspect.
            msg = (
                "CloudKit returned an empty HTTP 500, which means the request did not"
                " parse. This indicates the protobuf schema does not match what the"
                " server expects."
            )
            raise UnhandledProtocolError(msg)
        if not resp.ok:
            msg = f"CloudKit operation failed: HTTP {resp.status_code}"
            raise UnhandledProtocolError(msg)

        responses = list(decode_delimited(resp.content))
        if not responses:
            msg = "CloudKit returned no operations in its response"
            raise UnhandledProtocolError(msg)

        response = responses[0]
        _check_result(response.result)
        return response

    async def zone_retrieve(self) -> list[ck.ZoneSummary]:
        """
        List the zones this container holds.

        The simplest operation there is, and a good first thing to try: it needs no
        keychain state and answers what the container actually contains.
        """
        request = self._build_request(OperationType.ZONE_RETRIEVE_TYPE)
        request.zone_retrieve_request.SetInParent()

        response = await self._post_operation(PATH_ZONE_RETRIEVE, request)
        return list(response.zone_retrieve_response.zone_summary)

    async def record_sync(
        self,
        zone_name: str,
        *,
        continuation_token: bytes | None = None,
        max_changes: int | None = None,
    ) -> RecordSyncPage:
        """
        Fetch one page of record changes from a zone.

        This is a changes operation rather than a listing, because CloudKit's model is
        incremental sync. Persist the returned token: it is both how a later run avoids
        refetching everything and how it notices a newly-paired accessory.

        :param zone_name: The zone to read.
        :param continuation_token: Omit on a first run; everything is returned.
        :param max_changes: Page size. Omit to let the server decide.
        """
        # Naming a private zone needs the CloudKit user id, which only opening the
        # container supplies -- so that has to happen before the request is built, not
        # merely before it is sent.
        await self.open_container()

        request = self._build_request(OperationType.RECORD_RETRIEVE_CHANGES_TYPE)
        changes = request.retrieve_changes_request
        changes.zone_identifier.CopyFrom(self._zone_identifier(zone_name))
        if continuation_token is not None:
            changes.sync_continuation_token = continuation_token
        if max_changes is not None:
            changes.max_changes = max_changes

        response = await self._post_operation(PATH_RECORD_SYNC, request)
        payload = response.retrieve_changes_response

        record_changes = list(payload.record_change)

        token = None
        if payload.HasField("sync_continuation_token"):
            token = payload.sync_continuation_token

        # Only suspicious if the response yielded nothing at all. A page that carries
        # records or a token has proved its field numbers right, and an unmodelled field
        # alongside them is simply part of the protocol this schema does not describe.
        _log_unknown_fields(
            payload,
            "RetrieveChangesResponse",
            suspicious=not record_changes and token is None,
        )

        status = payload.status if payload.HasField("status") else None
        return RecordSyncPage(
            changes=record_changes,
            continuation_token=token,
            status=status,
        )

    async def record_save(
        self,
        record: ck.Record,
        *,
        record_protection_info_tag: str,
        zone_protection_info_tag: str = "",
        semantics: SaveSemantics = SaveSemantics.UPDATE,
    ) -> ck.Record:
        """
        Save a record, and return it as the server now holds it.

        **The one write in this library.** Everything else here reads, and the record
        types it may be pointed at are deliberately restricted a level up -- see
        :meth:`findmy.cloudkit.beacons.AsyncBeaconStore.save_naming_record`.

        `merge` is always set, so fields the record does not carry are kept rather than
        dropped. That is a safety net rather than a plan: send the whole record, because
        a save that omits `associatedBeacon` and is not merged removes the join key that
        makes a naming record findable at all.

        .. warning::
            **A success response is not proof the write took effect**, and this cannot
            check it. Elsewhere in this protocol a service reports success for a deletion
            that addressed nothing, and the value returned here is the server echoing what
            it was sent. Re-fetch and decrypt to confirm -- and even that only proves this
            implementation agrees with itself, never that Apple can read what was written.

        :param record: The whole record, with any changed field already encrypted.
        :param record_protection_info_tag: The tag the record **currently** carries. The
            save checks it and replaces it, so this is what serialises concurrent writes.
        :param zone_protection_info_tag: The zone's tag, where one is held.
        :param semantics: Update by default. Creating is not something this library has a
            use for, and the two are one integer apart.
        :raises UnhandledProtocolError: If the save fails, including on a stale tag.
        :returns: The record as the server now holds it.
        """
        await self.open_container()

        request = self._build_request(OperationType.RECORD_SAVE_TYPE)
        save = request.record_save_request
        save.record.CopyFrom(record)
        save.merge = True
        save.save_semantics = int(semantics)
        save.record_protection_info_tag = record_protection_info_tag
        if zone_protection_info_tag:
            save.zone_protection_info_tag = zone_protection_info_tag

        logger.info(
            "Saving record %s, presenting protection tag %s",
            record.record_identifier.value.name or "<unnamed>",
            record_protection_info_tag or "<none>",
        )

        response = await self._post_operation(PATH_RECORD_SAVE, request)
        saved = response.record_save_response.server_fields

        if not saved.record_identifier.value.name:
            # The operation succeeded and returned no record. Reported rather than
            # returned empty, because the next thing a caller does is read a tag off it
            # and store an empty string as the tag its next write must present.
            msg = (
                "The save reported success but returned no record, so there is no new"
                " protection tag to carry forward. Re-fetch before writing again."
            )
            raise UnhandledProtocolError(msg)

        return saved

    async def function_invoke(self, service: str, name: str, parameters: bytes) -> bytes:
        """
        Call a server-side function, and return its serialised result.

        This is how services that are not CloudKit -- Cuttlefish, the keychain trust
        circle -- are reached: through a CloudKit container, at a different base URL from
        record operations.

        Note that the payload crossing this call is a second layer of protobuf that
        CloudKit neither parses nor validates. A malformed inner message produces a
        *successful* CloudKit operation carrying a result that will not decode, so a
        caller must not read "the operation succeeded" as "the call worked".

        :param service: The target service, e.g. `Cuttlefish`.
        :param name: The method to call.
        :param parameters: The method's own request message, already serialised.
        :returns: The method's own response message, still serialised.
        """
        info = await self.open_container()
        if not info.code_gateway_url:
            msg = "Container did not return a code gateway URL; cannot invoke functions"
            raise UnhandledProtocolError(msg)

        request = self._build_request(OperationType.FUNCTION_INVOKE_TYPE)
        request.function_invoke_request.service = service
        request.function_invoke_request.name = name
        request.function_invoke_request.parameters = parameters

        response = await self._post_operation(
            PATH_CODE_INVOKE,
            request,
            base_url=info.code_gateway_url,
        )
        return response.function_invoke_response.serialized_result

    async def iter_records(
        self,
        zone_name: str,
        *,
        continuation_token: bytes | None = None,
        max_pages: int = 100,
    ) -> AsyncIterator[ck.RecordChange]:
        """
        Page through every record change in a zone.

        :param zone_name: The zone to read.
        :param continuation_token: Where to resume from, if resuming.
        :param max_pages: A backstop against a server that never stops handing back
            tokens. Reaching it is logged rather than passed over silently.
        """
        token = continuation_token
        for page_num in range(max_pages):
            page = await self.record_sync(zone_name, continuation_token=token)
            for change in page.changes:
                yield change

            # The status is what says the zone is synced, not an empty page: a response
            # can report completion and still carry changes, so stopping on emptiness
            # both pages once more than necessary and relies on a coincidence.
            if page.complete:
                logger.debug("Zone %s fully synced after page %d", zone_name, page_num + 1)
                return

            if page.continuation_token is None or page.continuation_token == token:
                logger.warning(
                    "Zone %s did not report itself synced but offered no way to continue;"
                    " some records may be missing",
                    zone_name,
                )
                return

            token = page.continuation_token
            logger.debug("Fetched page %d of zone %s", page_num + 1, zone_name)

        logger.warning(
            "Stopped paging %s after %d pages; some records may not have been fetched",
            zone_name,
            max_pages,
        )


def _check_result(result: ck.Result) -> None:
    """
    Raise unless an operation's result says it worked.

    PARTIAL is not a failure: a batched request can half-succeed, and discarding the good
    half would lose records that were fetched perfectly well.
    """
    if result.code == ResultCode.SUCCESS:
        return

    if result.code == ResultCode.PARTIAL:
        logger.warning(
            "CloudKit reported a partial result: %s",
            result.error.error_description or "no description",
        )
        return

    error = result.error
    client_code: int | None = error.client_error.code if error.HasField("client_error") else None

    name = ""
    if client_code is not None:
        try:
            name = f" ({ClientErrorCode(client_code).name})"
        except ValueError:
            name = f" (client error {client_code})"

    description = error.error_description or "no description given"
    msg = f"CloudKit operation failed{name}: {description}"
    if error.error_key:
        msg = f"{msg} [{error.error_key}]"

    raise CloudKitError(msg, result)


_WIRE_TYPE_NAMES = {0: "varint", 1: "fixed64", 2: "bytes", 3: "group", 4: "endgroup", 5: "fixed32"}


def describe_unknown_fields(message: object) -> list[str]:
    """
    Describe the fields a response carried that this schema does not model.

    Several field numbers in this protocol are inferred rather than observed. When one is
    wrong protobuf does not complain: the data lands in the unknown-field set and the
    caller sees an empty result. Reporting the number, the wire type and the value of what
    actually arrived is what turns that into something someone can act on -- and, when the
    schema is right, is how a field the specification never mentioned gets identified.
    """
    try:
        from google.protobuf.unknown_fields import UnknownFieldSet  # noqa: PLC0415

        unknown = UnknownFieldSet(message)  # pyright: ignore [reportArgumentType]
    except (ImportError, TypeError, AttributeError):  # pragma: no cover - protobuf build
        return []

    described: list[str] = []
    for field_info in unknown:
        wire = _WIRE_TYPE_NAMES.get(field_info.wire_type, str(field_info.wire_type))
        data = field_info.data

        if isinstance(data, bytes):
            shown = f"{len(data)} bytes: {data[:32].hex()}" + ("..." if len(data) > 32 else "")
        else:
            shown = str(data)

        described.append(f"field {field_info.field_number} ({wire}) = {shown}")

    return described


def _log_unknown_fields(message: object, name: str, *, suspicious: bool) -> None:
    """Log unmodelled fields, loudly only when the response yielded nothing usable."""
    described = describe_unknown_fields(message)
    if not described:
        return

    if suspicious:
        logger.warning(
            "%s yielded neither records nor a token, and carried unmodelled %s."
            " The schema's assumed field numbers are likely wrong.",
            name,
            "; ".join(described),
        )
    else:
        logger.info(
            "%s carried unmodelled %s. The schema is working; this is a field the"
            " specification does not describe.",
            name,
            "; ".join(described),
        )
