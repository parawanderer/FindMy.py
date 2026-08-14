"""Tests for the keychain session facade."""

from __future__ import annotations

import plistlib

import pytest

from findmy.keychain.escrow import EscrowListing, EscrowRecord, join_recovery_options
from findmy.keychain.session import AsyncKeychainSession, KeychainSessionError, RecoveredPeer

BOTTLE_UUID = "0B4E28BA-2FA1-11D2-883F-0016D3CCA427"
LABEL = "com.apple.icdp.record.SHA256:abc="


def a_record(label: str = LABEL, serial: str = "C02JUNK1") -> EscrowRecord:
    return EscrowRecord(
        label=label,
        device_name="A Mac",
        device_model="Mac16,12",
        device_model_class="Mac",
        serial=serial,
        build="22F8",
        escrowed_at=None,
        bottle_id=BOTTLE_UUID,
        passcode_generation=None,
        metadata={},
    )


class FakeProxy:
    def __init__(self, records: list[EscrowRecord]) -> None:
        self.records = records
        self.pets: list[str] = []
        self.deleted: list[str] = []
        self.listings = 0

    def replace_pet(self, pet: str) -> None:
        self.pets.append(pet)

    async def list_records(self) -> EscrowListing:
        self.listings += 1
        return EscrowListing(records=self.records, unreadable=[], status=0, message="ok")

    async def delete_record(self, record, options, *, confirm, allow_viable=False):  # noqa: ANN001, ANN003, ANN202, ARG002
        self.deleted.append(record.label)

    async def close(self) -> None:
        return


class FakeClient:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class FakeAccount:
    def __init__(self) -> None:
        self.adsid = "the-adsid"
        self.dsid = "the-dsid"
        self.pets_issued = 0

    async def request_pet(self) -> str:
        self.pets_issued += 1
        return f"pet-{self.pets_issued}"


def make_session(records: list[EscrowRecord], viable: list[str]) -> AsyncKeychainSession:
    """Build a session over fakes, with the viability answer pre-seeded."""
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415
    from findmy.keychain.cuttlefish import ViableBottles  # noqa: PLC0415

    session = AsyncKeychainSession(
        FakeAccount(),  # pyright: ignore [reportArgumentType]
        FakeClient(),  # pyright: ignore [reportArgumentType]
        FakeClient(),  # pyright: ignore [reportArgumentType]
        FakeClient(),  # pyright: ignore [reportArgumentType]
        FakeProxy(records),  # pyright: ignore [reportArgumentType]
    )

    bottles = ViableBottles(
        valid=viable,
        partial_count=0,
        entries=[cf.EscrowData(id=label) for label in viable],
    )

    async def fake_fetch(_: object) -> ViableBottles:
        return bottles

    import findmy.keychain.session as module  # noqa: PLC0415

    module.fetch_viable_bottles = fake_fetch  # pyright: ignore [reportAttributeAccessIssue]
    return session


@pytest.mark.asyncio
async def test_recovery_options_joins_both_services() -> None:
    record = a_record()
    session = make_session([record], [LABEL])

    options = await session.recovery_options()

    assert [r.label for r in options.recoverable] == [LABEL]


@pytest.mark.asyncio
async def test_recovery_options_are_cached_until_refreshed() -> None:
    # Two services and a token renewal per call is not free, and a caller listing before
    # acting would otherwise pay for it twice.
    session = make_session([a_record()], [LABEL])

    await session.recovery_options()
    await session.recovery_options()
    assert session._proxy.listings == 1  # noqa: SLF001

    await session.recovery_options(refresh=True)
    assert session._proxy.listings == 2  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_deletion_invalidates_the_cache() -> None:
    # The service reports success for a deletion that removed nothing, so the only proof
    # is asking again -- which a stale cache would prevent.
    record = a_record()
    session = make_session([record, a_record("other", "C02OTHER")], ["other"])

    await session.recovery_options()
    await session.delete_record(record, confirm="C02JUNK1")

    assert session._options is None  # noqa: SLF001


@pytest.mark.asyncio
async def test_recovering_from_an_unusable_record_is_refused_before_any_passcode() -> None:
    # Asking a user for a passcode that cannot possibly work is worse than saying so.
    record = a_record()
    session = make_session([record], [])

    with pytest.raises(KeychainSessionError, match="not among the records"):
        await session.recover(record, "123456")


@pytest.mark.asyncio
async def test_the_token_is_renewed_once_it_is_stale() -> None:
    # A PET lasts about five minutes, and an expiry landing mid-exchange would waste a
    # passcode the user has already typed.
    import findmy.keychain.session as module  # noqa: PLC0415

    session = make_session([a_record()], [LABEL])
    await session.recovery_options()
    assert session._proxy.pets == []  # noqa: SLF001

    session._pet_obtained_at -= module.PET_LIFETIME_SECONDS + 1  # noqa: SLF001
    await session.recovery_options(refresh=True)

    assert session._proxy.pets == ["pet-1"]  # noqa: SLF001


@pytest.mark.asyncio
async def test_closing_closes_everything_it_opened() -> None:
    session = make_session([a_record()], [LABEL])

    async with session:
        pass

    assert session._cloudkit.closed  # noqa: SLF001
    assert session._cuttlefish.closed  # noqa: SLF001


def test_a_recovered_peer_names_the_peer_a_voucher_would_sponsor() -> None:
    peer = RecoveredPeer(
        record=a_record(),
        fields={},
        salt="the-adsid",
        keys=None,  # pyright: ignore [reportArgumentType]
        bottle=None,  # pyright: ignore [reportArgumentType]
    )

    assert peer.peer_id == "SHA256:abc="


@pytest.mark.asyncio
async def test_material_that_is_not_a_plist_does_not_blame_the_passcode() -> None:
    # A wrong passcode and a misread exchange fail identically, so the error must not
    # claim to know which.
    import findmy.keychain.session as module  # noqa: PLC0415

    record = a_record()
    session = make_session([record], [LABEL])

    async def fake_recover(*_: object) -> bytes:
        return b"not a plist at all"

    module.recover_bottled_peer = fake_recover  # pyright: ignore [reportAttributeAccessIssue]

    with pytest.raises(KeychainSessionError, match="does not prove which"):
        await session.recover(record, "123456")


@pytest.mark.asyncio
async def test_material_without_entropy_names_the_field_it_wanted() -> None:
    import findmy.keychain.session as module  # noqa: PLC0415

    record = a_record()
    session = make_session([record], [LABEL])

    async def fake_recover(*_: object) -> bytes:
        return plistlib.dumps({"SomethingElse": b"x"})

    module.recover_bottled_peer = fake_recover  # pyright: ignore [reportAttributeAccessIssue]

    with pytest.raises(KeychainSessionError, match="BottledPeerEntropy"):
        await session.recover(record, "123456")
