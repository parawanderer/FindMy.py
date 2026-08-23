"""
A whole synthetic account, assembled the way a real one is layered.

**What this is for.** Every other fixture here covers one hop. This chains them, so a
question like "does an account shaped *like that* still yield accessories" has somewhere to
be asked: describe the account, run the real pipeline over it, and see what comes out.

    account = an_account([Accessory(name="Backpack"), Accessory(name="Keys", emoji=None)])
    found = await account.store().fetch_accessories(account.service_keys)

**What it is not.** The data is *generated*, not captured. It cannot be captured: every
layer here is encrypted under somebody's keys, so a real account's bytes are both
unreadable without their private keys and not ours to commit. So this proves the pipeline
handles a shape -- it cannot prove Apple produces that shape. Where a shape is known to be
real, say so with an `[observed]` marker, which is the only thing in this suite that
carries that weight.

The layering, outermost first, because getting one level wrong reads as being locked out:

    keychain service key (P-256, from a keychain item)
      -> zone protection structure     wraps a master key, derives the zone EC key
        -> record protection structure wraps each record's own master key
          -> record fields             encrypted one at a time, each under its own context
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec
from test_beacons import encrypted_value, make_encrypted_record
from test_pcs import build_protection, wrap_master_key

from findmy.cloudkit import beacons, pcs
from findmy.cloudkit.constants import BEACON_STORE_ZONE, RecordType, ValueType
from findmy.cloudkit.proto import cloudkit_pb2 as ck

if TYPE_CHECKING:
    from findmy.accessory import FindMyAccessory
    from findmy.cloudkit.records import CloudKitRecord
    from findmy.keychain.peers import PeerDirectory
    from findmy.keychain.session import AsyncKeychainSession, RecoveredPeer

APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

PAIRED_AT = datetime(2024, 3, 1, 12, 0, tzinfo=timezone.utc)


@dataclass
class Accessory:
    """One accessory as it will be written into the account's records."""

    name: str = "Backpack"
    model: str | None = "AirTag1,1"
    identifier: str = "BEACON-1"
    paired_at: datetime = PAIRED_AT

    emoji: str | None = None
    """Absent on real records unless the owner set one. **[observed]**, see #rename."""

    master_key: bytes = field(default_factory=lambda: bytes(range(16)))
    """What the record's fields are encrypted under. 16 bytes, as PCS uses."""

    private_key: bytes = field(default_factory=lambda: bytes(range(32, 64)))
    shared_secret: bytes = field(default_factory=lambda: bytes(range(64, 96)))
    secondary_secret: bytes = field(default_factory=lambda: bytes(range(96, 128)))

    naming_record: bool = True
    """Whether the account holds the separate record carrying this one's name."""


def _zone_ec_key(master_key: bytes) -> ec.EllipticCurvePrivateKey:
    """Derive the zone key a master key becomes -- §5's one symmetric-to-EC construction."""
    return ec.derive_private_key(pcs.derive_master_ec_private_key(master_key), ec.SECP256R1())


def _protection_for(
    recipient: ec.EllipticCurvePublicKey,
    master_key: bytes,
) -> bytes:
    """Wrap `master_key` so that only the holder of `recipient`'s private half opens it."""
    return build_protection(
        entries=[
            (pcs.compress_public_key(recipient), wrap_master_key(recipient, master_key), None),
        ],
        truncated_key_id=pcs.compute_key_id(master_key)[:4],
        version=5,
        hmac_master_key=master_key,
    )


class FakeCloudKit:
    """A CloudKit client answering for one zone: its protection, and its records."""

    def __init__(self, zone_protection: bytes, records: list[ck.Record]) -> None:
        self._zone_protection = zone_protection
        self._records = records
        self.asked_for: list[str] = []

    async def zone_retrieve(self) -> list[ck.ZoneSummary]:
        return [
            ck.ZoneSummary(
                target_zone=ck.Zone(
                    zone_identifier=ck.RecordZoneIdentifier(
                        value=ck.Identifier(name=BEACON_STORE_ZONE),
                    ),
                    protection_info=ck.ProtectionInfo(protection_info=self._zone_protection),
                ),
            ),
        ]

    async def iter_records(self, zone: str, *, continuation_token: bytes | None = None):  # noqa: ANN201, ARG002
        self.asked_for.append(zone)
        for record in self._records:
            yield ck.RecordChange(record=record)

    async def close(self) -> None:
        return


@dataclass
class FakeAccount:
    """A synthetic account, and the keys that open it."""

    service_keys: list[ec.EllipticCurvePrivateKey]
    """The keychain keys Stage 3 produces -- what `fetch_accessories` is handed."""

    zone_key: ec.EllipticCurvePrivateKey
    client: FakeCloudKit

    def store(self) -> beacons.AsyncBeaconStore:
        """Build the real store, over this account's data."""
        store = object.__new__(beacons.AsyncBeaconStore)
        store._client = self.client  # noqa: SLF001  # pyright: ignore [reportAttributeAccessIssue]
        return store

    async def accessories(self) -> list[FindMyAccessory]:
        """Run the real pipeline: zone, records, decryption, accessories."""
        return await self.store().fetch_accessories(self.service_keys)


def an_account(
    accessories: list[Accessory] | None = None,
    *,
    zone_master_key: bytes = bytes(range(16, 32)),
) -> FakeAccount:
    """
    Assemble an account holding `accessories`, encrypted at every level as a real one is.

    :param zone_master_key: What the zone's protection wraps. The zone's EC key derives
        from it, and every record is protected under that.
    """
    accessories = accessories if accessories is not None else [Accessory()]

    service_key = ec.generate_private_key(ec.SECP256R1())
    zone_key = _zone_ec_key(zone_master_key)

    records: list[ck.Record] = []
    for accessory in accessories:
        records.extend(_records_for(accessory, zone_key))

    return FakeAccount(
        service_keys=[service_key],
        zone_key=zone_key,
        client=FakeCloudKit(
            _protection_for(service_key.public_key(), zone_master_key),
            records,
        ),
    )


def _records_for(accessory: Accessory, zone_key: ec.EllipticCurvePrivateKey) -> list[ck.Record]:
    """Build the master-beacon record, and the naming record beside it if there is one."""
    seconds = (accessory.paired_at - APPLE_EPOCH).total_seconds()

    fields: dict[str, tuple[int, bytes]] = {
        "privateKey": (ValueType.ENCRYPTED_BYTES_TYPE, accessory.private_key),
        "sharedSecret": (ValueType.ENCRYPTED_BYTES_TYPE, accessory.shared_secret),
        "sharedSecret2": (ValueType.ENCRYPTED_BYTES_TYPE, accessory.secondary_secret),
        "pairingDate": (ValueType.DATE_TYPE, encrypted_value(date_value=ck.Date(time=seconds))),
    }
    if accessory.model is not None:
        fields["model"] = (ValueType.STRING_TYPE, encrypted_value(string_value=accessory.model))

    beacon, _ = make_encrypted_record(
        zone_key,
        accessory.master_key,
        fields,
        name=accessory.identifier,
    )
    records = [_proto_of(beacon)]

    if accessory.naming_record:
        naming_fields: dict[str, tuple[int, bytes]] = {
            "name": (ValueType.STRING_TYPE, encrypted_value(string_value=accessory.name)),
            "associatedBeacon": (
                ValueType.STRING_TYPE,
                encrypted_value(string_value=accessory.identifier),
            ),
        }
        if accessory.emoji is not None:
            naming_fields["emoji"] = (
                ValueType.STRING_TYPE,
                encrypted_value(string_value=accessory.emoji),
            )

        naming, _ = make_encrypted_record(
            zone_key,
            accessory.master_key,
            naming_fields,
            record_type=RecordType.BEACON_NAMING,
            name=f"NAMING-{accessory.identifier}",
        )
        records.append(_proto_of(naming))

    return records


def _proto_of(record) -> ck.Record:  # noqa: ANN001
    """Return the wire record a `CloudKitRecord` came from, which is what a fetch yields."""
    assert record.source is not None
    return record.source


# --------------------------------------------------------------------------------------
# The front half: a trust circle, its shares, and the keychain item holding the key
# --------------------------------------------------------------------------------------

VIEW = "Manatee"
TLK_UUID = "11111111-2222-3333-4444-555555555555"
"""The uuid the item names as its parent key. Must be `test_items.PARENT_UUID`: an item
says which key wraps it, and a keyring holding the right *bytes* under the wrong name is
reported as a key this client does not hold."""
SENDER = "SHA256:the-sender="


def _tlk_material(key: bytes) -> bytes:
    """Build the share's plaintext: the view's top-level key, named by its uuid."""
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf

    return cf.TlkKeyMaterial(
        uuid=TLK_UUID,
        zone_name=VIEW,
        key_class="tlk",
        key=key,
    ).SerializeToString()


class FakeCuttlefish:
    """Answers one share listing, and remembers which peer it was asked about."""

    def __init__(self, entry: bytes) -> None:
        self.asked_for: list[str] = []
        self._entry = entry

    async def function_invoke(self, service: str, method: str, payload: bytes) -> bytes:  # noqa: ARG002
        from findmy.cloudkit.proto import cuttlefish_pb2 as cf

        request = cf.FetchRecoverableTlkSharesRequest()
        request.ParseFromString(payload)
        self.asked_for.append(request.for_peer)

        # An id the circle does not know is answered with **no shares and no error**,
        # which is the whole of #140: nothing downstream can tell it apart from an
        # account that simply holds none.
        if request.for_peer != CIRCLE_PEER_ID:
            return cf.FetchRecoverableTlkSharesResponse().SerializeToString()

        return cf.FetchRecoverableTlkSharesResponse(shares=[self._entry]).SerializeToString()

    async def close(self) -> None:
        return


CIRCLE_PEER_ID = "SHA256:the-hash-cuttlefish-knows="
"""How the circle addresses the recovered peer."""

AGREEING_LABEL_SUFFIX = CIRCLE_PEER_ID
"""An account where the escrow label's suffix already is the peer hash."""

DIVERGENT_LABEL_SUFFIX = "CBEEDA4C-0000-4000-8000-000000000000"
"""An account where it is not. **[observed]** by jamorenom on two accounts, #140."""


def _share_entry(receiver: str, peer_key: ec.EllipticCurvePrivateKey, top_level: bytes) -> bytes:
    """One share listing entry, really wrapped to the peer's encryption key."""
    from test_shares import a_record as a_share_record
    from test_shares import sfies_archive

    from findmy.cloudkit.proto import cuttlefish_pb2 as cf

    record = a_share_record(
        sender=SENDER,
        receiver=receiver,
        wrappedkey=sfies_archive(peer_key.public_key(), _tlk_material(top_level)),
        curve=1,
        epoch=1,
        version=1,
    )
    return cf.RecoverableTlkShare(
        service=VIEW,
        share=cf.RecordWrapper(record=record.SerializeToString()),
    ).SerializeToString()


def _keychain_item(top_level: bytes, service_key: ec.EllipticCurvePrivateKey):  # noqa: ANN202
    """Build the keychain item whose `v_Data` is this account's Find My service key."""
    from test_items import a_v2_payload, an_item

    from findmy.cloudkit.pcs import public_key_forms

    scalar = service_key.private_numbers().private_value.to_bytes(32, "big")

    # **`acct` is not decoration.** Items are indexed by it, because §6.8 resolves a key
    # reference by matching on `acct` -- so an item without one is read and then dropped,
    # silently, and the view reports no keys at all.
    record, _ = an_item(
        top_level,
        {
            "v_Data": a_v2_payload(scalar),
            "acct": next(iter(public_key_forms(service_key.public_key()))),
        },
    )
    return record


@dataclass
class FakeCircle:
    """The trust-circle half: a peer, its shares, and the view holding the key."""

    peer: RecoveredPeer
    cuttlefish: FakeCuttlefish
    view_records: list[CloudKitRecord]
    directory: PeerDirectory

    def session(self) -> AsyncKeychainSession:
        """Build a real keychain session over these fakes."""
        from findmy.keychain.session import AsyncKeychainSession

        session = object.__new__(AsyncKeychainSession)
        session._cuttlefish = self.cuttlefish  # noqa: SLF001  # pyright: ignore [reportAttributeAccessIssue]
        session._securityd = None  # noqa: SLF001  # pyright: ignore [reportAttributeAccessIssue]
        session._peers = self.directory  # noqa: SLF001  # pyright: ignore [reportAttributeAccessIssue]
        return session


def a_circle(
    *,
    label_suffix: str = AGREEING_LABEL_SUFFIX,
    service_key: ec.EllipticCurvePrivateKey | None = None,
) -> FakeCircle:
    """
    Build the trust-circle half of an account.

    :param label_suffix: What this peer's escrow record is labelled with. Pass
        :data:`DIVERGENT_LABEL_SUFFIX` for an account where that is not the peer hash the
        circle knows -- the shape of #140, and the reason two variants exist here.
    :param service_key: The keychain key the view's item should hold. Defaults to a fresh
        one; pass an account's to join the two halves.
    """
    from test_session import a_record as an_escrow_record

    from findmy.keychain.peers import Peer, PeerDirectory
    from findmy.keychain.session import RecoveredPeer

    peer_key = ec.generate_private_key(ec.SECP384R1())
    top_level = bytes(range(64))
    service_key = service_key or ec.generate_private_key(ec.SECP256R1())

    class OneKeyBottle:
        def signing(self) -> ec.EllipticCurvePrivateKey:
            return peer_key

        def encryption(self) -> ec.EllipticCurvePrivateKey:
            return peer_key

    peer = RecoveredPeer(
        record=an_escrow_record(label=f"com.apple.icdp.record.{label_suffix}"),
        fields={},
        salt="the-adsid",
        keys=None,  # pyright: ignore [reportArgumentType]
        bottle=OneKeyBottle(),  # pyright: ignore [reportArgumentType]
        cuttlefish_peer_id=CIRCLE_PEER_ID,
    )

    directory = PeerDirectory(
        peers={
            name: Peer(hash=name, signing_key=b"", encryption_key=b"", machine_id="", model_id="")
            for name in (SENDER, CIRCLE_PEER_ID)
        },
    )

    return FakeCircle(
        peer=peer,
        cuttlefish=FakeCuttlefish(_share_entry(CIRCLE_PEER_ID, peer_key, top_level)),
        view_records=[_keychain_item(top_level, service_key)],
        directory=directory,
    )


@dataclass
class WholeAccount:
    """Both halves: the trust circle that yields keychain keys, and what they decrypt."""

    circle: FakeCircle
    data: FakeAccount

    def use_the_view(self, monkeypatch) -> None:  # noqa: ANN001
        """Point the session's keychain read at this account's view."""
        from findmy.keychain.items import split_view_records

        contents = split_view_records(self.circle.view_records)

        async def view(client: object, name: str, **_: object):  # noqa: ANN202, ARG001
            return contents

        monkeypatch.setattr("findmy.keychain.session.fetch_view", view)

    async def keychain_keys(self) -> list[ec.EllipticCurvePrivateKey]:
        """Stage 3: shares to the keychain keys, as `unlock` and `resume` do."""
        return await self.circle.session().pcs_keys(self.circle.peer, views=[VIEW])

    async def accessories(self) -> list[FindMyAccessory]:
        """Stages 4 to 6: the keychain keys to accessories, as `fetch_accessories` does."""
        return await self.data.store().fetch_accessories(await self.keychain_keys())


def a_whole_account(
    accessories: list[Accessory] | None = None,
    *,
    label_suffix: str = AGREEING_LABEL_SUFFIX,
) -> WholeAccount:
    """
    Build an account drivable from a recovered peer all the way to accessories.

    :param label_suffix: Which of the two known account shapes this is. See
        :data:`AGREEING_LABEL_SUFFIX` and :data:`DIVERGENT_LABEL_SUFFIX`.
    """
    data = an_account(accessories)
    circle = a_circle(label_suffix=label_suffix, service_key=data.service_keys[0])
    return WholeAccount(circle=circle, data=data)
