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


@pytest.mark.asyncio
async def test_recovering_service_keys_is_one_call_from_a_record_and_a_passcode() -> None:
    # The pair is always used together now, so a caller assembling it by hand is a caller
    # who can get the order wrong for no benefit.
    session = make_session([a_record()], viable=[LABEL])

    recovered: list[object] = []

    async def fake_recover(record, passcode):  # noqa: ANN001, ANN202
        recovered.append((record.serial, passcode))
        return "the-peer"

    async def fake_service_keys(peer, *, view, shares=None):  # noqa: ANN001, ANN202, ARG001
        recovered.append((peer, view))
        return "the-keys"

    session.recover = fake_recover  # type: ignore[method-assign]
    session.service_keys = fake_service_keys  # type: ignore[method-assign]

    options = await session.recovery_options()
    keys = await session.recover_service_keys(options.recoverable[0], "1234")

    assert keys == "the-keys"
    assert recovered == [("C02JUNK1", "1234"), ("the-peer", "Manatee")]


@pytest.mark.asyncio
async def test_recovering_service_keys_reads_a_named_view() -> None:
    session = make_session([a_record()], viable=[LABEL])
    seen: list[str] = []

    async def fake_recover(record, passcode):  # noqa: ANN001, ANN202, ARG001
        return "the-peer"

    async def fake_service_keys(peer, *, view, shares=None):  # noqa: ANN001, ANN202, ARG001
        seen.append(view)
        return "the-keys"

    session.recover = fake_recover  # type: ignore[method-assign]
    session.service_keys = fake_service_keys  # type: ignore[method-assign]

    options = await session.recovery_options()
    await session.recover_service_keys(
        options.recoverable[0],
        "1234",
        view="ProtectedCloudStorage",
    )

    assert seen == ["ProtectedCloudStorage"]


# --------------------------------------------------------------------------------------
# The join sequence (§6.9.4)
# --------------------------------------------------------------------------------------


class JoinProxy:
    """An escrow proxy that records the order it was called in."""

    def __init__(self, calls: list[str], *, refuse_first_enrol: bool = False) -> None:
        self.calls = calls
        self.refuse_first_enrol = refuse_first_enrol
        self.deleted: list[str] = []
        self.enrolled: list[str] = []

    async def get_club_cert(self, transaction_id: str, **_: object) -> dict:
        import base64  # noqa: PLC0415

        self.calls.append("get_club_cert")
        return {"clubCert": base64.b64encode(_CLUB[1]).decode(), "transactionUUID": transaction_id}

    async def enroll(self, label: str, **_: object) -> dict:
        from findmy.keychain.escrow import EscrowError  # noqa: PLC0415

        self.calls.append("enroll")
        if self.refuse_first_enrol and self.calls.count("enroll") == 1:
            msg = "Escrow proxy rejected enroll: a record already exists (code 42)"
            raise EscrowError(msg, reported=True)
        self.enrolled.append(label)
        return {}

    async def delete_label(self, label: str, **_: object) -> None:
        self.calls.append("delete_label")
        self.deleted.append(label)

    async def close(self) -> None:
        return


class JoinCuttlefish:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls
        self.payload = b""

    async def function_invoke(self, service: str, method: str, payload: bytes) -> bytes:
        self.calls.append(method)
        self.payload = payload
        return b"the-changes"

    async def close(self) -> None:
        return


class JoinAccount(FakeAccount):
    async def get_anisette_headers(self, **_: object) -> dict[str, str]:
        return {"X-Apple-I-MD-M": "the-machine-id"}


_CLUB: tuple = ()


def _prepare_club(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand a club certificate and its root in for the bundled ones."""
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415

    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    from findmy.keychain.enrolment import PinnedRoots  # noqa: PLC0415

    now = datetime.now(timezone.utc)

    def name(common: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = (
        x509.CertificateBuilder()
        .subject_name(name("Escrow Service Root CA"))
        .issuer_name(name("Escrow Service Root CA"))
        .public_key(root_key.public_key())
        .serial_number(103)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(root_key, hashes.SHA256())
    )
    club_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    club = (
        x509.CertificateBuilder()
        .subject_name(name("Escrow Club"))
        .issuer_name(root.subject)
        .public_key(club_key.public_key())
        .serial_number(7)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(root_key, hashes.SHA256())
    )

    global _CLUB  # noqa: PLW0603
    _CLUB = (club_key, club.public_bytes(serialization.Encoding.DER))

    monkeypatch.setattr(
        "findmy.keychain.enrolment.PINNED_ROOT_FINGERPRINTS",
        {103: root.fingerprint(hashes.SHA256())},
    )
    monkeypatch.setattr(
        PinnedRoots,
        "bundled",
        classmethod(lambda cls: cls.load([root.public_bytes(serialization.Encoding.DER)])),
    )


def _a_joinable_session(monkeypatch: pytest.MonkeyPatch, **proxy_options: bool):
    """A session whose circle, shares and club certificate are all stood in for."""
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415
    from findmy.keychain.join import public_spki  # noqa: PLC0415
    from findmy.keychain.peers import Peer, PeerDirectory  # noqa: PLC0415
    from findmy.keychain.shares import KeyShare  # noqa: PLC0415

    _prepare_club(monkeypatch)

    calls: list[str] = []
    cuttlefish = JoinCuttlefish(calls)
    session = AsyncKeychainSession(
        JoinAccount(),  # pyright: ignore [reportArgumentType]
        FakeClient(),  # pyright: ignore [reportArgumentType]
        cuttlefish,  # pyright: ignore [reportArgumentType]
        FakeClient(),  # pyright: ignore [reportArgumentType]
        JoinProxy(calls, **proxy_options),  # pyright: ignore [reportArgumentType]
    )

    sponsor_key = ec.generate_private_key(ec.SECP384R1())
    sponsor = Peer(
        hash="SHA256:sponsor",
        signing_key=public_spki(sponsor_key.public_key()),
        encryption_key=b"",
        machine_id="",
        model_id="",
        stable_clock=3,
        dynamic_clock=4,
        includeds=("SHA256:sponsor",),
    )

    async def directory(_: object) -> PeerDirectory:
        return PeerDirectory(peers={sponsor.hash: sponsor})

    monkeypatch.setattr("findmy.keychain.session.fetch_peer_directory", directory)

    material = cf.TlkKeyMaterial(
        uuid="7F0A2C1E-0000-4000-8000-000000000001",
        zone_name="Manatee",
        key_class="tlk",
        key=b"\x11" * 32,
    ).SerializeToString()

    async def shares(self: object, peer: object) -> list[KeyShare]:  # noqa: ARG001
        calls.append("key_shares")
        return [
            KeyShare(
                service="Manatee",
                key_id="7F0A2C1E-0000-4000-8000-000000000001",
                sender="SHA256:sponsor",
                receiver="SHA256:sponsor",
                wrapped_key=b"",
                plaintext=material,
            ),
        ]

    monkeypatch.setattr(AsyncKeychainSession, "key_shares", shares)

    class Recovered:
        peer_id = "SHA256:sponsor"

        def signing_key(self):  # noqa: ANN202
            return sponsor_key

    return session, Recovered(), calls, cuttlefish


def _a_device():
    from findmy.keychain.enrolment import DeviceDescription  # noqa: PLC0415

    return DeviceDescription(name="A Linux box", model="LinuxPC1,1", serial="X0X0", build="24A335")


@pytest.mark.asyncio
async def test_the_record_is_enrolled_before_the_join_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The ordering §6.9.4 exists for. A join that lands with no record leaves a peer
    # nobody can ever recover, invisible to every listing; a record with no join is
    # listed and deletable. One is permanent, the other is tidy-up.
    session, recovered, calls, _ = _a_joinable_session(monkeypatch)

    await session.join(recovered, passcode="123456", device=_a_device(), os_version="6.1")

    assert calls.index("enroll") < calls.index("joinWithVoucher")


@pytest.mark.asyncio
async def test_the_join_carries_the_peer_its_bottle_and_its_shares(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    session, recovered, _, cuttlefish = _a_joinable_session(monkeypatch)

    outcome = await session.join(
        recovered,
        passcode="123456",
        device=_a_device(),
        os_version="6.1",
    )

    request = cf.CuttlefishJoinWithVoucherRequest()
    request.ParseFromString(cuttlefish.payload)

    assert request.peer.hash == outcome.identity.peer_id
    assert request.bottle.peer_id == outcome.identity.peer_id
    assert len(request.shares) == 1
    # Never sent: this project receives view keys, it does not establish them.
    assert list(request.keys) == []
    assert outcome.response == b"the-changes"


@pytest.mark.asyncio
async def test_the_joining_peer_asserts_its_sponsors_trust_plus_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    session, recovered, _, cuttlefish = _a_joinable_session(monkeypatch)

    outcome = await session.join(
        recovered,
        passcode="123456",
        device=_a_device(),
        os_version="6.1",
    )

    request = cf.CuttlefishJoinWithVoucherRequest()
    request.ParseFromString(cuttlefish.payload)
    dynamic = cf.PeerDynamicInfo()
    dynamic.ParseFromString(request.peer.dynamic_info.info)

    assert list(dynamic.includeds) == ["SHA256:sponsor", outcome.identity.peer_id]
    assert dynamic.clock == 5


@pytest.mark.asyncio
async def test_the_bottle_and_the_record_come_from_one_derivation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    session, recovered, _, cuttlefish = _a_joinable_session(monkeypatch)

    outcome = await session.join(
        recovered,
        passcode="123456",
        device=_a_device(),
        os_version="6.1",
    )

    request = cf.CuttlefishJoinWithVoucherRequest()
    request.ParseFromString(cuttlefish.payload)
    inner = cf.OTBottle()
    inner.ParseFromString(request.bottle.bottle)

    assert outcome.bottle.escrowed_spki == inner.escrowed_signing_key
    assert outcome.label.endswith(outcome.identity.peer_id)


@pytest.mark.asyncio
async def test_a_taken_label_is_cleared_and_enrolled_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, recovered, calls, _ = _a_joinable_session(monkeypatch, refuse_first_enrol=True)

    outcome = await session.join(
        recovered,
        passcode="123456",
        device=_a_device(),
        os_version="6.1",
    )

    assert calls.count("enroll") == 2
    assert calls.index("delete_label") < calls.index("joinWithVoucher")
    assert session._proxy.deleted == [outcome.label]  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_transport_failure_does_not_delete_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Only a failure the service *reported* establishes that something is at that label.
    # Deleting on a transport error would remove a record this client never saw.
    from findmy.keychain.escrow import EscrowError  # noqa: PLC0415

    session, recovered, calls, _ = _a_joinable_session(monkeypatch)

    async def refuse(label: str, **_: object) -> dict:
        calls.append("enroll")
        msg = "Escrow proxy returned HTTP 503 for enroll"
        raise EscrowError(msg)

    session._proxy.enroll = refuse  # noqa: SLF001  # pyright: ignore [reportAttributeAccessIssue]

    with pytest.raises(EscrowError, match="503"):
        await session.join(recovered, passcode="123456", device=_a_device(), os_version="6.1")

    assert "delete_label" not in calls
    assert "joinWithVoucher" not in calls


@pytest.mark.asyncio
async def test_joining_without_usable_shares_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from findmy.keychain.shares import KeyShare  # noqa: PLC0415

    session, recovered, calls, _ = _a_joinable_session(monkeypatch)

    async def nothing(self: object, peer: object) -> list[KeyShare]:  # noqa: ARG001
        return [
            KeyShare(
                service="Manatee",
                key_id="k",
                sender="x",
                receiver="y",
                wrapped_key=b"",
                error="would not unwrap",
            ),
        ]

    monkeypatch.setattr(AsyncKeychainSession, "key_shares", nothing)

    with pytest.raises(KeychainSessionError, match="yield nothing"):
        await session.join(recovered, passcode="123456", device=_a_device(), os_version="6.1")

    assert calls == []
