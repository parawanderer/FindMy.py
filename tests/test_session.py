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


def a_peer(record: EscrowRecord | None = None, cuttlefish_peer_id: str | None = None):  # noqa: ANN201
    """Build a recovered peer without recovering: only its identifier is under test."""
    return RecoveredPeer(
        record=record or a_record(),
        fields={},
        salt="the-adsid",
        keys=None,  # pyright: ignore [reportArgumentType]
        bottle=None,  # pyright: ignore [reportArgumentType]
        cuttlefish_peer_id=cuttlefish_peer_id,
    )


def test_a_recovered_peer_names_the_peer_a_voucher_would_sponsor() -> None:
    # The **agreeing** case, and the one every working account takes: this label's suffix
    # already is the hash the circle knows. Kept exactly as it was, because a fix that
    # only ever returned the bottle's id would break these accounts and pass every other
    # test here. See the divergent case below.
    assert a_peer().peer_id == "SHA256:abc="


def test_a_peer_the_circle_names_differently_is_addressed_the_circle_s_way() -> None:
    # Issue #140. The escrow label's suffix is not always the peer hash Cuttlefish knows,
    # and asking for shares under the wrong one returns every view's key set and *no
    # shares* -- no error, so it reads as an account problem rather than a wrong id.
    peer = a_peer(
        record=a_record(label="com.apple.icdp.record.CBEEDA4C-0000-4000-8000-000000000000"),
        cuttlefish_peer_id="SHA256:realpeerhash=",
    )

    assert peer.peer_id == "SHA256:realpeerhash="
    assert peer.record.peer_id == "CBEEDA4C-0000-4000-8000-000000000000"


def test_the_label_is_still_the_fallback_when_the_bottle_offers_nothing() -> None:
    # A bottle carrying no peer id at all leaves the label as the only thing to go on,
    # which is what accounts did before this existed.
    assert a_peer(cuttlefish_peer_id=None).peer_id == "SHA256:abc="
    assert a_peer(cuttlefish_peer_id="").peer_id == "SHA256:abc="


def test_every_place_a_peer_is_named_uses_the_one_property() -> None:
    """Test that no call site reads the escrow label directly."""
    # There are three, and the third is a **write**: `join` builds a voucher naming this
    # peer as sponsor, permanently. Fixing only the fetch leaves shares retrieved and then
    # rejected as addressed to someone else; fixing only those two leaves a voucher naming
    # a sponsor Cuttlefish does not know.
    import inspect  # noqa: PLC0415

    from findmy.keychain import session  # noqa: PLC0415

    source = inspect.getsource(session.AsyncKeychainSession)

    assert "peer.record.peer_id" not in source
    for site in ("fetch_recoverable_shares(self._cuttlefish, peer.peer_id)",
                 "expected_receiver=peer.peer_id",
                 "make_voucher(identity.peer_id, peer.peer_id"):
        assert site in source, site


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
        from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

        self.calls.append(method)
        self.payload = payload
        return cf.CuttlefishJoinWithVoucherResponse(
            changes=cf.CuttlefishChanges(sync_token="tok-after-join"),
        ).SerializeToString()

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


@pytest.mark.asyncio
async def test_the_reply_is_decoded_and_its_token_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The response carries the same CuttlefishChanges fetchChanges returns, so it goes
    # through the path that already exists -- and the token it brings is what makes every
    # later sync incremental. Discarding the reply drops both.
    session, recovered, _, _ = _a_joinable_session(monkeypatch)

    outcome = await session.join(
        recovered,
        passcode="123456",
        device=_a_device(),
        os_version="6.1",
    )

    assert outcome.sync_token == "tok-after-join"
    assert outcome.directory.sync_token == "tok-after-join"
    assert session._peers is outcome.directory  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_first_join_sends_no_restore_point(monkeypatch: pytest.MonkeyPatch) -> None:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    session, recovered, _, cuttlefish = _a_joinable_session(monkeypatch)

    await session.join(recovered, passcode="123456", device=_a_device(), os_version="6.1")

    request = cf.CuttlefishJoinWithVoucherRequest()
    request.ParseFromString(cuttlefish.payload)

    assert not request.HasField("restore_point")


@pytest.mark.asyncio
async def test_a_held_token_is_sent_back_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    # A string at both ends. Nothing to encode, nothing to guess.
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415
    from findmy.keychain.peers import PeerDirectory  # noqa: PLC0415

    session, recovered, _, cuttlefish = _a_joinable_session(monkeypatch)

    held = await session.peer_directory()
    import dataclasses  # noqa: PLC0415

    async def with_token(_: object) -> PeerDirectory:
        return dataclasses.replace(held, sync_token="tok-before")

    monkeypatch.setattr("findmy.keychain.session.fetch_peer_directory", with_token)

    await session.join(recovered, passcode="123456", device=_a_device(), os_version="6.1")

    request = cf.CuttlefishJoinWithVoucherRequest()
    request.ParseFromString(cuttlefish.payload)

    assert request.restore_point == "tok-before"


@pytest.mark.asyncio
async def test_a_reply_that_does_not_decode_says_the_join_still_happened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The instinct on a decode failure is to retry the call. Retrying this one would try
    # to join twice.
    session, recovered, _, cuttlefish = _a_joinable_session(monkeypatch)

    async def rubbish(service: str, method: str, payload: bytes) -> bytes:
        cuttlefish.calls.append(method)
        return b"\xff\xff\xff\xff"

    cuttlefish.function_invoke = rubbish  # pyright: ignore [reportAttributeAccessIssue]

    with pytest.raises(KeychainSessionError, match="peer is in the circle"):
        await session.join(recovered, passcode="123456", device=_a_device(), os_version="6.1")


@pytest.mark.asyncio
async def test_a_failure_after_sending_says_not_to_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A timeout does not establish that no response was sent, and the reflex on a failed
    # call is to repeat it. Repeating this one leaves a second peer, a second bottle and
    # a second escrow record, all permanent.
    session, recovered, _, cuttlefish = _a_joinable_session(monkeypatch)

    async def times_out(service: str, method: str, payload: bytes) -> bytes:
        raise TimeoutError

    cuttlefish.function_invoke = times_out  # pyright: ignore [reportAttributeAccessIssue]

    with pytest.raises(KeychainSessionError, match="Do not retry"):
        await session.join(recovered, passcode="123456", device=_a_device(), os_version="6.1")


@pytest.mark.asyncio
async def test_the_undecodable_reply_says_the_same_thing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session, recovered, _, cuttlefish = _a_joinable_session(monkeypatch)

    async def rubbish(service: str, method: str, payload: bytes) -> bytes:
        return b"\xff\xff\xff\xff"

    cuttlefish.function_invoke = rubbish  # pyright: ignore [reportAttributeAccessIssue]

    with pytest.raises(KeychainSessionError, match="Do not retry"):
        await session.join(recovered, passcode="123456", device=_a_device(), os_version="6.1")


@pytest.mark.asyncio
async def test_the_club_certificate_can_be_checked_without_joining(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Read-only, and the point of it: the pinning either works on this account or it does
    # not, and finding out here costs nothing -- while finding out mid-join happens after
    # a passcode has been asked for.
    session, _, calls, _ = _a_joinable_session(monkeypatch)

    certificate = await session.club_certificate()

    assert certificate.subject.rfc4514_string() == "CN=Escrow Club"
    assert calls == ["get_club_cert"]


# --------------------------------------------------------------------------------------
# Which of a bottle's ids the circle answers to (issue #140)
# --------------------------------------------------------------------------------------


def a_directory(*hashes: str):  # noqa: ANN201
    """Build a peer directory containing peers by name and nothing else."""
    from findmy.keychain.peers import Peer, PeerDirectory  # noqa: PLC0415

    return PeerDirectory(
        peers={
            name: Peer(
                hash=name,
                signing_key=b"",
                encryption_key=b"",
                machine_id="",
                model_id="",
            )
            for name in hashes
        },
    )


def test_the_id_the_circle_lists_wins_over_the_one_it_does_not() -> None:
    from findmy.keychain.session import addressable_peer_id  # noqa: PLC0415

    directory = a_directory("SHA256:known=")

    assert addressable_peer_id(directory, "SHA256:known=", "SHA256:other=") == "SHA256:known="


def test_the_inner_id_is_taken_when_that_is_the_one_the_circle_lists() -> None:
    # The case a fix that always prefers the envelope's id gets wrong. `recover` looks the
    # sponsor up under whichever of the two the directory holds, so addressing the peer by
    # the other one means the signature was checked against a different peer than the
    # shares were requested for.
    from findmy.keychain.session import addressable_peer_id  # noqa: PLC0415

    directory = a_directory("SHA256:inner=")

    assert addressable_peer_id(directory, "SHA256:envelope=", "SHA256:inner=") == "SHA256:inner="


def test_a_peer_the_circle_does_not_hold_still_gets_its_first_id() -> None:
    # Recovering from a record whose device has since left the circle is a thing people
    # do, so an unknown peer is not a refusal -- there is simply nothing better to use.
    from findmy.keychain.session import addressable_peer_id  # noqa: PLC0415

    assert addressable_peer_id(a_directory(), "SHA256:a=", "SHA256:b=") == "SHA256:a="
    assert addressable_peer_id(a_directory(), "", "SHA256:b=") == "SHA256:b="
    assert addressable_peer_id(a_directory(), "", "") is None


@pytest.mark.asyncio
async def test_joining_refuses_a_sponsor_the_circle_does_not_contain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test the guard on the one call that writes."""
    # A voucher naming an unknown sponsor is signed, sent and permanent, and what
    # Cuttlefish does with it is not known from here -- it may refuse, or leave a peer
    # sponsored by nobody. Issue #140 made this reachable, because the sponsor's id came
    # from the escrow label rather than from the circle. Free to check, so it is checked.
    session, _, calls, _ = _a_joinable_session(monkeypatch)

    class Stranger:
        peer_id = "SHA256:not-in-the-circle"

        def signing_key(self):  # noqa: ANN202
            raise AssertionError

    with pytest.raises(KeychainSessionError, match="not in this trust circle"):
        await session.join(
            Stranger(),  # pyright: ignore [reportArgumentType]
            passcode="123456",
            device=_a_device(),
            os_version="13.4.1",
        )

    # And nothing was enrolled or sent on the way to finding out.
    assert calls == []
