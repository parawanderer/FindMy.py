"""Tests for the escrow proxy listing and its KeyVault framing (Stage 3, read-only)."""

from __future__ import annotations

import base64
import plistlib
from datetime import datetime, timezone

import pytest

from findmy.keychain.escrow import (
    COMMAND_SPELLINGS,
    AsyncEscrowProxy,
    EscrowError,
    EscrowListing,
    EscrowRecord,
    build_keyvault_message,
    escrow_host,
    join_recovery_options,
    parse_keyvault_message,
)

FINDMY_CLIENT_INFO = (
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
)


class FakeResponse:
    def __init__(self, status_code: int, content: bytes) -> None:
        self.status_code = status_code
        self._content = content

    @property
    def ok(self) -> bool:
        return str(self.status_code).startswith("2")

    @property
    def content(self) -> bytes:
        # The real HttpResponse exposes this, and the failure path reads it. A fake
        # missing a method the code under test calls does not fail loudly -- it fails as
        # an empty string somewhere downstream.
        return self._content

    def plist(self) -> dict:
        return plistlib.loads(self._content)


class FakeHttp:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def post(self, url, **kwargs):  # noqa: ANN001, ANN003, ANN202
        self.calls.append({"url": url, **kwargs})
        return self._responses.pop(0)

    async def close(self) -> None:
        return


class FakeAccount:
    def __init__(self) -> None:
        self.client_info = FINDMY_CLIENT_INFO
        self.account_name = "someone@example.com"

    async def get_anisette_headers(self) -> dict[str, str]:
        return {"X-Apple-I-MD": "otp"}


def make_proxy(responses: list[FakeResponse]) -> AsyncEscrowProxy:
    proxy = AsyncEscrowProxy(FakeAccount(), escrow_host("24"), "the-pet")  # pyright: ignore [reportArgumentType]
    proxy._http = FakeHttp(responses)  # noqa: SLF001
    return proxy


def device_metadata(
    *,
    name: str = "Someone's iMac Pro",
    serial: str = "C02XYZ123456",
    bottle_id: str | None = "BOTTLE-1",
) -> str:
    metadata: dict = {
        "ClientMetadata": {
            "device_name": name,
            "device_model": "iMacPro1,1",
            "device_model_class": "iMac",
        },
        "serial": serial,
        "build": "22F8",
        "com.apple.securebackup.timestamp": datetime(2023, 5, 1, tzinfo=timezone.utc),
    }
    if bottle_id is not None:
        metadata["bottleID"] = bottle_id
    return base64.b64encode(plistlib.dumps(metadata)).decode()


def listing_response(entries: list[dict]) -> FakeResponse:
    return FakeResponse(
        200,
        plistlib.dumps({"status": 0, "message": "ok", "dsid": "1", "metadataList": entries}),
    )


# --------------------------------------------------------------------------------------
# Host derivation
# --------------------------------------------------------------------------------------


def test_the_escrow_host_is_derived_from_the_account_partition() -> None:
    # Hardcoding a partition works only for accounts that happen to live on it.
    assert escrow_host("24") == "https://p24-escrowproxy.icloud.com:443"
    assert escrow_host("97") == "https://p97-escrowproxy.icloud.com:443"


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------


def test_the_two_command_spellings_are_not_derivable_from_each_other() -> None:
    # Sending the path spelling in the body is rejected with "Wrong command sent".
    assert COMMAND_SPELLINGS["get_records"] == "GETRECORDS"  # loses its separator
    assert COMMAND_SPELLINGS["get_club_cert"] == "GETCLUB"  # loses a whole word
    assert COMMAND_SPELLINGS["srp_init"] == "SRP_INIT"  # keeps its separator

    for path, body in COMMAND_SPELLINGS.items():
        if path != "srp_init":
            assert body != path.upper().replace("_", "_") or path in {"recover", "enroll", "delete"}


@pytest.mark.asyncio
async def test_a_listing_sends_the_body_spelling_not_the_path_spelling() -> None:
    proxy = make_proxy([listing_response([])])
    await proxy.list_records()

    call = proxy._http.calls[0]  # noqa: SLF001
    body = plistlib.loads(call["data"])

    assert call["url"].endswith("/escrowproxy/api/get_records")
    assert body["command"] == "GETRECORDS"
    assert body["label"] == "com.apple.securebackup.record"
    assert body["version"] == 1


@pytest.mark.asyncio
async def test_a_listing_authenticates_with_the_pet_and_the_account_email() -> None:
    proxy = make_proxy([listing_response([])])
    await proxy.list_records()

    assert proxy._http.calls[0]["auth"] == ("someone@example.com", "the-pet")  # noqa: SLF001


@pytest.mark.asyncio
async def test_the_content_type_is_the_unusual_apple_one() -> None:
    proxy = make_proxy([listing_response([])])
    await proxy.list_records()

    headers = proxy._http.calls[0]["headers"]  # noqa: SLF001
    assert headers["Content-Type"] == "application/x-apple-plst"
    assert "sbd" in headers["X-Mme-Client-Info"]


def test_an_empty_pet_is_refused_up_front() -> None:
    with pytest.raises(EscrowError, match="PET"):
        AsyncEscrowProxy(FakeAccount(), escrow_host("24"), "")  # pyright: ignore [reportArgumentType]


@pytest.mark.asyncio
async def test_a_service_error_is_surfaced_verbatim() -> None:
    # The messages are specific and worth showing as-is.
    response = FakeResponse(
        200,
        plistlib.dumps(
            {"success": False, "errorCode": 3, "errorMessage": "Wrong command sent: get_records"},
        ),
    )
    proxy = make_proxy([response])

    with pytest.raises(EscrowError, match="Wrong command sent: get_records"):
        await proxy.list_records()


# --------------------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_records_are_decoded_into_the_fields_a_user_can_recognise() -> None:
    proxy = make_proxy([listing_response([{"label": "BOTTLE-1", "metadata": device_metadata()}])])
    listing = await proxy.list_records()

    (record,) = listing.records
    assert record.device_name == "Someone's iMac Pro"
    assert record.device_model == "iMacPro1,1"
    assert record.serial == "C02XYZ123456"
    assert record.escrowed_at == datetime(2023, 5, 1, tzinfo=timezone.utc)
    assert "C02XYZ123456" in record.describe()


@pytest.mark.asyncio
async def test_a_record_of_another_shape_is_kept_rather_than_treated_as_broken() -> None:
    # Of twelve records on one account, one had no serial, build or bottle id at all.
    other_shape = base64.b64encode(
        plistlib.dumps({"BackupKeybagDigest": b"\x01\x02", "ClientMetadata": {}}),
    ).decode()
    proxy = make_proxy([listing_response([{"label": "ODD-1", "metadata": other_shape}])])

    listing = await proxy.list_records()

    (record,) = listing.records
    assert record.serial is None
    assert record.is_recovery_candidate is False
    assert listing.recovery_candidates == []
    assert "BackupKeybagDigest" in record.metadata


@pytest.mark.asyncio
async def test_metadata_that_cannot_be_decoded_is_reported_not_dropped() -> None:
    entries = [
        {"label": "GOOD", "metadata": device_metadata()},
        {"label": "BAD", "metadata": "not-base64-plist!!"},
    ]
    proxy = make_proxy([listing_response(entries)])

    listing = await proxy.list_records()

    assert [r.label for r in listing.records] == ["GOOD"]
    assert listing.unreadable == ["BAD"]


@pytest.mark.asyncio
async def test_only_records_with_a_bottle_id_are_recovery_candidates() -> None:
    entries = [
        {"label": "WITH", "metadata": device_metadata(bottle_id="BOTTLE-1")},
        {"label": "WITHOUT", "metadata": device_metadata(bottle_id=None)},
    ]
    proxy = make_proxy([listing_response(entries)])

    listing = await proxy.list_records()

    assert len(listing.records) == 2
    assert [r.label for r in listing.recovery_candidates] == ["WITH"]


def test_the_module_offers_no_way_to_delete_a_record() -> None:
    # Deliberate: the protocol needs nothing but a label to destroy any record on the
    # account, and there is no server-side check. Deletion without the confirmation
    # interface that makes it safe does not belong in a library.
    import findmy.keychain.escrow as module  # noqa: PLC0415

    assert not [name for name in dir(module) if "delete" in name.lower()]


# --------------------------------------------------------------------------------------
# KeyVault framing
# --------------------------------------------------------------------------------------


def test_keyvault_framing_roundtrips() -> None:
    header = bytes(range(24))
    sections = [b"request-id", b"salt-bytes", b"server-public-value"]

    framed = build_keyvault_message(header, sections)
    parsed_header, parsed_sections = parse_keyvault_message(framed, 24, 3)

    assert parsed_header == header
    assert parsed_sections == sections


def test_keyvault_offsets_are_one_more_than_the_sections() -> None:
    # Computing the base from the section count rather than count-plus-one puts every
    # section four bytes out and produces what looks like a decryption failure.
    header = bytes(range(16))
    sections = [b"a" * 4, b"b" * 8]
    framed = build_keyvault_message(header, sections)

    # 4 length + 16 header + (2 + 1) offsets * 4 = 32 bytes before any section data.
    assert len(framed) == 4 + 16 + 12 + (4 + 4) + (4 + 8)


def test_the_leading_four_bytes_are_the_messages_own_total_length() -> None:
    # Not padding, and not something to echo from the message being replied to. The
    # service checks it, and a mismatch is rejected with an internal error naming nothing.
    for sections in ([b"a"], [b"x" * 8, b"y" * 64, b"z" * 256], [b"", b""]):
        framed = build_keyvault_message(bytes(24), sections)

        assert int.from_bytes(framed[:4], "big") == len(framed)


def test_a_message_declaring_the_wrong_length_still_parses_but_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    framed = bytearray(build_keyvault_message(bytes(24), [b"one", b"two"]))
    framed[:4] = (999).to_bytes(4, "big")

    _, sections = parse_keyvault_message(bytes(framed), 24, 2)

    assert sections == [b"one", b"two"]
    assert "declares 999 bytes" in caplog.text


def test_keyvault_parses_the_header_lengths_the_recovery_flow_uses() -> None:
    # srp_init replies use H=24, S=3; the inner blob uses H=16, S=6.
    for header_length, section_count in ((24, 3), (40, 3), (16, 6)):
        header = bytes(range(header_length))
        sections = [bytes([i]) * (i + 1) for i in range(section_count)]

        framed = build_keyvault_message(header, sections)
        parsed_header, parsed_sections = parse_keyvault_message(framed, header_length, section_count)

        assert parsed_header == header
        assert parsed_sections == sections


def test_a_truncated_keyvault_message_is_rejected() -> None:
    with pytest.raises(EscrowError):
        parse_keyvault_message(b"\x00" * 8, 24, 3)


def test_a_keyvault_section_pointing_past_the_end_is_rejected() -> None:
    framed = bytearray(build_keyvault_message(bytes(24), [b"x", b"y", b"z"]))
    framed[28:32] = (0xFFFF).to_bytes(4, "big")

    with pytest.raises(EscrowError, match="past the end"):
        parse_keyvault_message(bytes(framed), 24, 3)


# --------------------------------------------------------------------------------------
# Joining escrow metadata against Cuttlefish's viable bottles
# --------------------------------------------------------------------------------------


def make_listing(records: list) -> EscrowListing:
    return EscrowListing(records=records, unreadable=[], status=0, message="ok")


def make_record(label: str, bottle_id: str | None) -> EscrowRecord:
    return EscrowRecord(
        label=label,
        device_name="An iPhone",
        device_model="iPhone15,2",
        device_model_class="iPhone",
        serial="F2LXYZ0123",
        build="21E219",
        escrowed_at=None,
        bottle_id=bottle_id,
        passcode_generation=None,
        metadata={},
    )


LABEL = "com.apple.icdp.record.PEER-1"
BOTTLE_UUID = "0B4E28BA-2FA1-11D2-883F-0016D3CCA427"


def test_a_record_that_is_both_described_and_viable_is_recoverable() -> None:
    listing = make_listing([make_record(LABEL, BOTTLE_UUID)])

    options = join_recovery_options(listing, [LABEL])

    assert [r.label for r in options.recoverable] == [LABEL]
    assert options.described_but_not_viable == []
    assert options.viable_but_undescribed == []


def test_the_join_is_on_the_label_not_the_bottle_id() -> None:
    # They are different strings of different shapes and never coincide: the label
    # addresses the record, the bottle id names the bottle inside it. Matching on the
    # bottle id would be forgiving of a confusion that should be caught.
    listing = make_listing([make_record(LABEL, BOTTLE_UUID)])

    options = join_recovery_options(listing, [BOTTLE_UUID])

    assert options.recoverable == []
    assert [r.label for r in options.described_but_not_viable] == [LABEL]
    assert options.viable_but_undescribed == [BOTTLE_UUID]


def test_metadata_without_a_viable_bottle_is_reported_not_dropped() -> None:
    # It cannot be recovered from, and saying so is the signal that this model has
    # drifted from what Apple returns.
    listing = make_listing([make_record(LABEL, BOTTLE_UUID)])

    options = join_recovery_options(listing, [])

    assert options.recoverable == []
    assert [r.label for r in options.described_but_not_viable] == [LABEL]


def test_a_viable_bottle_without_metadata_is_reported_not_dropped() -> None:
    # It cannot be described to a user, so it cannot be offered as a choice.
    options = join_recovery_options(make_listing([]), ["ORPHAN-1"])

    assert options.recoverable == []
    assert options.viable_but_undescribed == ["ORPHAN-1"]


def test_a_record_with_no_bottle_id_is_not_counted_as_a_mismatch() -> None:
    # A different kind of record, not a broken one.
    listing = make_listing([make_record("com.apple.icdp.record.ODD", None)])

    options = join_recovery_options(listing, [])

    assert options.recoverable == []
    assert options.described_but_not_viable == []
    assert options.viable_but_undescribed == []


def test_the_join_summarises_itself_for_reporting() -> None:
    listing = make_listing([make_record("A", BOTTLE_UUID), make_record("B", BOTTLE_UUID)])

    options = join_recovery_options(listing, ["A", "C"])

    assert "1 recoverable" in options.describe()
    assert "not viable" in options.describe()
    assert "undescribed" in options.describe()


def test_a_companion_record_is_recognised_by_its_suffix() -> None:
    # Nothing in enrolment creates one, so a record this client makes will have none --
    # but a deletion must still issue both calls, or a first-party record's companion is
    # orphaned.
    parent = make_record("com.apple.icdp.record.PEER-1", BOTTLE_UUID)
    companion = make_record("com.apple.icdp.record.PEER-1.double", BOTTLE_UUID)

    assert parent.is_companion is False
    assert companion.is_companion is True
    assert companion.companion_of == parent.label


def test_devices_are_counted_by_serial_not_by_record() -> None:
    # One device can hold several records, each under its own peer identity, if it
    # enrolled more than once. Counting records overstates how many devices there are.
    def with_serial(label: str, serial: str) -> EscrowRecord:
        base = make_record(label, BOTTLE_UUID)
        return EscrowRecord(
            label=base.label,
            device_name=base.device_name,
            device_model=base.device_model,
            device_model_class=base.device_model_class,
            serial=serial,
            build=base.build,
            escrowed_at=None,
            bottle_id=base.bottle_id,
            passcode_generation=None,
            metadata={},
        )

    listing = make_listing(
        [
            with_serial("com.apple.icdp.record.A", "SAME"),
            with_serial("com.apple.icdp.record.B", "SAME"),
            with_serial("com.apple.icdp.record.C", "OTHER"),
        ],
    )

    options = join_recovery_options(listing, [])

    assert len(options.described_but_not_viable) == 3
    assert options.device_count == 2


def test_the_peer_id_is_read_out_of_the_label() -> None:
    # The same value a peer carries as its hash, so a listing already names the peer a
    # voucher would have to name as its sponsor.
    digest = "SHA256:OSUs+amZS4S6iLyzPPjrHGQJrB12JugpVSFAQ4Qe5lU="
    record = make_record(f"com.apple.icdp.record.{digest}", BOTTLE_UUID)

    assert record.peer_id == digest


def test_a_companions_peer_id_is_its_parents() -> None:
    digest = "SHA256:abc="
    companion = make_record(f"com.apple.icdp.record.{digest}.double", BOTTLE_UUID)

    assert companion.peer_id == digest


def test_a_label_without_the_expected_prefix_is_not_guessed_at() -> None:
    record = make_record("something.else.entirely", BOTTLE_UUID)

    assert record.peer_id == "something.else.entirely"


# --------------------------------------------------------------------------------------
# Deletion
#
# Each guard is tested on its own. A single "deleting works" test would pass with any one
# of them silently not firing, and each covers a different way of destroying a real
# device's ability to recover its keychain.
# --------------------------------------------------------------------------------------


def deletable_record(label: str = "com.apple.icdp.record.JUNK", serial: str = "C02JUNK1") -> EscrowRecord:
    return EscrowRecord(
        label=label,
        device_name="sb's iMac Pro",
        device_model="iMacPro1,1",
        device_model_class="iMac",
        serial=serial,
        build="22F8",
        escrowed_at=None,
        bottle_id=BOTTLE_UUID,
        passcode_generation=None,
        metadata={},
    )


def ok_response() -> FakeResponse:
    return FakeResponse(200, plistlib.dumps({"status": 0, "message": "ok"}))


VIABLE = deletable_record(label="com.apple.icdp.record.LIVE", serial="C02LIVE1")


def options_with(*records: EscrowRecord):  # noqa: ANN201
    """
    Join a listing that also contains one genuinely viable record.

    Every test below isolates one guard, and without a viable record present they would
    all trip the "no usable bottle at all" check instead of the guard under test.
    """
    return join_recovery_options(make_listing([VIABLE, *records]), [VIABLE.label])


async def delete(
    record: EscrowRecord,
    options,  # noqa: ANN001
    responses: list[FakeResponse] | None = None,
    **kwargs,  # noqa: ANN003
) -> AsyncEscrowProxy:
    proxy = make_proxy(responses if responses is not None else [ok_response(), ok_response()])
    await proxy.delete_record(record, options, **kwargs)
    return proxy


@pytest.mark.asyncio
async def test_deleting_a_non_viable_record_issues_both_calls_companion_first() -> None:
    record = deletable_record()
    options = options_with(record)

    proxy = await delete(record, options, confirm="C02JUNK1")

    labels = [plistlib.loads(call["data"])["label"] for call in proxy._http.calls]  # noqa: SLF001
    assert labels == [record.label + ".double", record.label]
    assert all(plistlib.loads(c["data"])["command"] == "DELETE" for c in proxy._http.calls)  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_missing_companion_does_not_stop_the_record_being_deleted() -> None:
    # A record this client created has no companion, so that call addresses nothing.
    record = deletable_record()
    options = options_with(record)
    missing = FakeResponse(
        200,
        plistlib.dumps({"success": False, "errorCode": 4, "errorMessage": "No such record"}),
    )

    proxy = await delete(record, options, [missing, ok_response()], confirm="C02JUNK1")

    assert len(proxy._http.calls) == 2  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_viable_record_is_refused() -> None:
    # Deleting it destroys a real device's ability to recover its keychain, and its owner
    # would not find out until after a wipe.
    record = deletable_record()
    options = join_recovery_options(make_listing([record]), [record.label])

    with pytest.raises(EscrowError, match="live recovery path"):
        await delete(record, options, [], confirm="C02JUNK1")


@pytest.mark.asyncio
async def test_a_viable_record_can_be_deleted_only_deliberately() -> None:
    record = deletable_record()
    options = join_recovery_options(make_listing([record]), [record.label])

    proxy = await delete(record, options, confirm="C02JUNK1", allow_viable=True)

    assert len(proxy._http.calls) == 2  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_record_outside_the_listing_cannot_be_deleted() -> None:
    # Without a listing there is no viability, and every record looks alike.
    record = deletable_record()
    without_it = options_with()

    with pytest.raises(EscrowError, match="viability"):
        await delete(record, without_it, [], confirm="C02JUNK1")


@pytest.mark.asyncio
async def test_the_wrong_serial_is_refused() -> None:
    record = deletable_record()
    options = options_with(record)

    with pytest.raises(EscrowError, match="confirmation"):
        await delete(record, options, [], confirm="C02OTHER1")


@pytest.mark.asyncio
async def test_a_record_with_no_serial_confirms_against_its_label() -> None:
    record = EscrowRecord(
        label="com.apple.icdp.record.ODD",
        device_name=None,
        device_model=None,
        device_model_class=None,
        serial=None,
        build=None,
        escrowed_at=None,
        bottle_id=BOTTLE_UUID,
        passcode_generation=None,
        metadata={},
    )
    options = options_with(record)

    with pytest.raises(EscrowError, match="confirmation"):
        await delete(record, options, [], confirm="")

    proxy = await delete(record, options, confirm=record.label)
    assert len(proxy._http.calls) == 2  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_companion_is_not_deleted_directly() -> None:
    # Deleting the record it belongs to removes both.
    companion = deletable_record(label="com.apple.icdp.record.JUNK.double")
    options = options_with(companion)

    with pytest.raises(EscrowError, match="companion"):
        await delete(companion, options, [], confirm="C02JUNK1")


def test_the_safe_and_unsafe_lists_are_the_viability_split() -> None:
    junk = deletable_record(label="com.apple.icdp.record.JUNK", serial="C02JUNK1")
    real = deletable_record(label="com.apple.icdp.record.REAL", serial="C02REAL1")
    options = join_recovery_options(make_listing([junk, real]), [real.label])

    assert [r.label for r in options.safe_to_delete] == [junk.label]
    assert [r.label for r in options.unsafe_to_delete] == [real.label]


@pytest.mark.asyncio
async def test_nothing_is_deletable_when_no_bottle_is_reported_viable_at_all() -> None:
    # Viability is the deletion guard, so a transiently non-viable bottle is dangerous:
    # an outage would make live recovery paths look like debris. A client cannot tell an
    # outage from a bottle that is genuinely gone -- but "every record became unusable at
    # once" is a far better description of a bad day than of an account.
    record = deletable_record()
    options = join_recovery_options(make_listing([record]), [])

    assert options.viability_is_trustworthy is False
    assert options.safe_to_delete == []

    with pytest.raises(EscrowError, match="no usable bottle at all"):
        await delete(record, options, [], confirm="C02JUNK1")


@pytest.mark.asyncio
async def test_deletion_resumes_once_some_bottle_is_viable_again() -> None:
    junk = deletable_record(label="com.apple.icdp.record.JUNK", serial="C02JUNK1")
    real = deletable_record(label="com.apple.icdp.record.REAL", serial="C02REAL1")
    options = join_recovery_options(make_listing([junk, real]), [real.label])

    assert options.viability_is_trustworthy is True
    assert [r.label for r in options.safe_to_delete] == [junk.label]

    proxy = await delete(junk, options, confirm="C02JUNK1")
    assert len(proxy._http.calls) == 2  # noqa: SLF001


@pytest.mark.asyncio
async def test_recovery_commands_declare_the_pinned_certificate_versions() -> None:
    # Omitting them leaves the club handler with nothing to select, and it fails with an
    # internal error rather than naming what is missing.
    from findmy.keychain.escrow import ROOT_CERT_VERSIONS  # noqa: PLC0415

    proxy = make_proxy([ok_response(), ok_response()])
    await proxy.srp_init("com.apple.icdp.record.PEER", b"A", "TX")
    await proxy.recover("com.apple.icdp.record.PEER", b"M1", "TX")

    for call in proxy._http.calls:  # noqa: SLF001
        body = plistlib.loads(call["data"])
        assert body["baseRootCertVersions"] == list(ROOT_CERT_VERSIONS)
        assert body["trustedRootCertVersions"] == list(ROOT_CERT_VERSIONS)


@pytest.mark.asyncio
async def test_srp_init_and_recover_share_one_transaction_id() -> None:
    proxy = make_proxy([ok_response(), ok_response()])
    await proxy.srp_init("com.apple.icdp.record.PEER", b"A", "SHARED-TX")
    await proxy.recover("com.apple.icdp.record.PEER", b"M1", "SHARED-TX")

    ids = {plistlib.loads(c["data"])["transactionUUID"] for c in proxy._http.calls}  # noqa: SLF001
    assert ids == {"SHARED-TX"}


def test_a_rejection_is_read_as_a_plist_rather_than_dumped_as_text() -> None:
    # **[observed]** A rejected `recover` comes back as HTTP 409 carrying a complete reply:
    # status, message, respBlob and version. Reading it as text throws away the two fields
    # that say what happened and leaves a truncated XML dump in the exception.
    from findmy.keychain.escrow import _failure  # noqa: PLC0415

    body = plistlib.dumps(
        {
            "version": 1,
            "status": "-6015",
            "respBlob": "c3RyaXBwZWQ=",
            "message": "CLUBH ERROR: Credentials did not verify",
        },
    )
    error = _failure("recover", FakeResponse(409, body))

    assert "status -6015" in str(error)
    assert "CLUBH ERROR: Credentials did not verify" in str(error)
    # Status first and short, message second and whole: the status is what a reader
    # searches for, the message is what they read.
    assert str(error).index("status") < str(error).index("CLUBH")
    # The service described this, rather than the request failing in transport.
    assert error.reported


def test_a_rejection_that_is_not_a_plist_still_reports_what_arrived() -> None:
    from findmy.keychain.escrow import _failure  # noqa: PLC0415

    error = _failure("enroll", FakeResponse(503, b"<html>upstream is unwell</html>"))

    assert "HTTP 503" in str(error)
    assert "upstream is unwell" in str(error)
    # Nothing described this, so it must not take the delete-and-re-enrol path.
    assert not error.reported
