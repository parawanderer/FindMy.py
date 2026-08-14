"""
One object for everything the keychain half of this library does.

The pieces underneath are separate because the protocol is: two unrelated-looking services
joined on an identifier, a token with a five-minute life, a host derived from a URL
belonging to something else entirely. Using them directly means assembling that every
time, and every caller assembles it identically.

This is that assembly, done once. What it wraps is the part that has been **verified
against a real account**: listing escrow records, judging which could be recovered from,
recovering one with a device passcode, opening the bottle it yields, and deleting records
that are no longer good for anything.

What it deliberately does not wrap is joining the trust circle, which is unbuilt and may
turn out to be unnecessary -- so there is no method here that writes a peer or enrolls a
record.

    async with await AsyncKeychainSession.open(account) as session:
        options = await session.recovery_options()
        for record in options.recoverable:
            print(record.describe())

.. warning::
    :meth:`AsyncKeychainSession.recover` needs a device's screen-lock passcode, and
    :meth:`AsyncKeychainSession.delete_record` destroys something irreversibly. Everything
    else here reads.
"""

from __future__ import annotations

import logging
import plistlib
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from typing_extensions import Self, override

from findmy.cloudkit.client import AsyncCloudKitClient
from findmy.cloudkit.pcs import public_key_forms
from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.errors import UnhandledProtocolError
from findmy.util.abc import Closable

from .bottle import BottleKeys, OpenedBottle, find_bottle_keys, open_bottle
from .cuttlefish import ViableBottles, fetch_viable_bottles, make_cuttlefish_client
from .escrow import (
    AsyncEscrowProxy,
    EscrowRecord,
    RecoveryOptions,
    escrow_host,
    join_recovery_options,
)
from .items import (
    VIEW_MANATEE,
    VIEW_PROTECTED_CLOUD_STORAGE,
    ItemError,
    fetch_view,
    make_securityd_client,
    payload_of,
    readable_items,
    service_key_item,
)
from .peers import PeerDirectory, fetch_peer_directory
from .recovery import recover_bottled_peer
from .servicekey import ServiceKeyError, ServiceKeys, service_keys_from_der
from .shares import (
    KeyShare,
    ViewKeyring,
    fetch_recoverable_shares,
    summarise,
    unwrap_share,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cryptography.hazmat.primitives.asymmetric import ec

    from findmy.reports.account import AsyncAppleAccount

logger = logging.getLogger(__name__)

ENTROPY_FIELD = "BottledPeerEntropy"
"""
The field of a recovered record that everything else derives from.

**[observed]** Recovered material also carries `SecureBackupIDMSData`, a
`DoubleEnrollmentPassword` and version, a `BackupBagPassword`, a backup version and a
timestamp. Only this one is needed here.

**None of the others is required when writing one either** -- §4.5.3's record is three
keys, and :func:`findmy.keychain.enrolment.build_record` sends exactly those. They are what
an Apple client happens to include, and reproducing them would be inventing plausible
values for fields nothing reads.
"""

# A PET lasts about five minutes. Renewing a little early costs one authentication and
# avoids an expiry landing in the middle of an exchange that has already asked a user for
# their passcode.
PET_LIFETIME_SECONDS = 240


class KeychainSessionError(UnhandledProtocolError):
    """Raised when a keychain session cannot be established or used."""


def _require_partition(partition: str | None) -> str:
    """Insist on the partition the escrow host is derived from."""
    if partition is None:
        msg = (
            "The container returned no partitioned URL, so the escrow host cannot be"
            " derived. Every per-account iCloud service is named"
            " p<N>-<service>.icloud.com and there is no other source for the N."
        )
        raise KeychainSessionError(msg)
    return partition


@dataclass(frozen=True)
class RecoveredPeer:
    """
    A recovered peer, opened.

    Holding this means holding a device's identity from the user's trust circle -- the
    private keys it signs and receives with. It is the most sensitive thing this library
    produces, and it exists in memory only.
    """

    record: EscrowRecord
    """The escrow record it came from."""

    fields: dict[str, Any]
    """Everything the recovered property list carried, entropy included."""

    salt: str
    """Which account identifier turned out to be the HKDF salt."""

    keys: BottleKeys
    """The three keys the bottle was sealed under."""

    bottle: OpenedBottle
    """The opened bottle: the sponsoring peer's own private keys."""

    @property
    def peer_id(self) -> str:
        """The peer this identity belongs to -- what a voucher would name as sponsor."""
        return self.record.peer_id

    def signing_key(self) -> ec.EllipticCurvePrivateKey:
        """Parse the signing key. This is what would sign a voucher."""
        return self.bottle.signing()

    def encryption_key(self) -> ec.EllipticCurvePrivateKey:
        """Parse the encryption key. A key share would be wrapped to this."""
        return self.bottle.encryption()


class AsyncKeychainSession(Closable):
    """
    A live session against the services that describe an account's escrow records.

    Build one with :meth:`open` rather than by calling the constructor: establishing a
    session needs a CloudKit container opened before the escrow host can even be derived.
    """

    def __init__(
        self,
        account: AsyncAppleAccount,
        cloudkit: AsyncCloudKitClient,
        cuttlefish: AsyncCloudKitClient,
        securityd: AsyncCloudKitClient,
        proxy: AsyncEscrowProxy,
    ) -> None:
        """Use :meth:`open`."""
        super().__init__()

        self._account = account
        self._cloudkit = cloudkit
        self._cuttlefish = cuttlefish
        self._securityd = securityd
        self._proxy = proxy
        self._pet_obtained_at = time.monotonic()

        self._options: RecoveryOptions | None = None
        self._bottles: ViableBottles | None = None
        self._peers: PeerDirectory | None = None

    @classmethod
    async def open(cls, account: AsyncAppleAccount) -> Self:
        """
        Establish a session.

        Opens the container, derives the escrow host from the partition it reports, and
        obtains a token for the escrow proxy -- which costs one authentication, because
        logging in spends the token this service wants.

        :param account: A logged-in account.
        :raises KeychainSessionError: If the escrow host cannot be derived.
        """
        cloudkit = AsyncCloudKitClient(account)
        cuttlefish = make_cuttlefish_client(account)

        # The same container as Cuttlefish, addressed to a different bundle. Keychain item
        # zones answer to securityd, and reusing the Cuttlefish client asks the wrong
        # service -- so the two are separate clients rather than one with a swapped header.
        securityd = make_securityd_client(account)

        try:
            info = await cloudkit.open_container()
            partition = _require_partition(info.partition)
            pet = await account.request_pet()
            proxy = AsyncEscrowProxy(account, escrow_host(partition), pet)
        except Exception:
            await cloudkit.close()
            await cuttlefish.close()
            await securityd.close()
            raise

        logger.info("Keychain session open on partition %s", info.partition)
        return cls(account, cloudkit, cuttlefish, securityd, proxy)

    @override
    async def close(self) -> None:
        """Close everything this session opened. Does not close the account."""
        await self._proxy.close()
        await self._securityd.close()
        await self._cuttlefish.close()
        await self._cloudkit.close()

    async def __aenter__(self) -> Self:
        """Enter a context that closes this session on exit."""
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close the session."""
        await self.close()

    async def _renew_token_if_stale(self) -> None:
        """Replace the escrow token before it expires mid-exchange."""
        if time.monotonic() - self._pet_obtained_at < PET_LIFETIME_SECONDS:
            return

        logger.debug("Escrow token is near expiry; obtaining another")
        self._proxy.replace_pet(await self._account.request_pet())
        self._pet_obtained_at = time.monotonic()

    async def recovery_options(self, *, refresh: bool = False) -> RecoveryOptions:
        """
        Ask both services what this account could be recovered from.

        Read-only, creates nothing, and needs no passcode. Neither service alone answers
        the question: the escrow proxy holds the descriptions and the trust-circle service
        knows which bottles are usable.

        Worth looking at even with nothing to act on. Escrow records outlive the devices
        that made them and no Apple interface enumerates them, so this is the only way a
        user can see what their account is carrying.

        :param refresh: Ask again rather than reusing the previous answer.
        """
        if self._options is not None and not refresh:
            return self._options

        await self._renew_token_if_stale()

        self._bottles = await fetch_viable_bottles(self._cuttlefish)
        listing = await self._proxy.list_records()
        self._options = join_recovery_options(
            listing,
            self._bottles.valid,
            partial_count=self._bottles.partial_count,
        )
        return self._options

    async def peer_directory(self, *, refresh: bool = False) -> PeerDirectory:
        """
        Read who is in the trust circle.

        Read-only. This is a prerequisite rather than an extra: a key share names its
        sender by hash and a bottle names its sponsor by hash, and nothing else in the
        protocol says what those peers' keys are. Syncing trust first is what makes those
        names checkable at all.

        :param refresh: Read again rather than reusing the previous answer.
        """
        if self._peers is not None and not refresh:
            return self._peers

        self._peers = await fetch_peer_directory(self._cuttlefish)

        if not len(self._peers):
            # Worth saying loudly. Everything that verifies against a peer degrades to
            # "unknown sender" when this is empty, which reads as a security failure when
            # the real problem is an empty directory.
            logger.warning(
                "The trust circle came back empty. Nothing can be verified against it,"
                " and every share will report its sender as unknown.",
            )

        return self._peers

    async def recover(self, record: EscrowRecord, passcode: str) -> RecoveredPeer:
        """
        Recover a peer's identity from an escrow record.

        The passcode is the **screen-lock passcode of the device the record belongs to** —
        its PIN or login password, not an Apple ID password. It is used twice inside this
        call and is neither stored nor logged; callers should hold it no longer either.

        Nothing here writes to the account.

        :param record: A record from :meth:`recovery_options`. It must be recoverable.
        :param passcode: That device's passcode.
        :raises KeychainSessionError: If the record is not one this session listed, or the
            recovered material is not shaped as expected.
        """
        options = await self.recovery_options()
        if record not in options.recoverable:
            msg = (
                f"{record.label} is not among the records this session found recoverable."
                " Recovering from a record whose bottle is not usable cannot succeed."
            )
            raise KeychainSessionError(msg)

        await self._renew_token_if_stale()

        material = await recover_bottled_peer(self._proxy, record, passcode)

        try:
            fields = plistlib.loads(material)
        except (plistlib.InvalidFileException, ValueError, EOFError) as e:
            msg = (
                f"The recovered material is not a property list ({e}). A wrong passcode"
                " and a misread exchange fail identically here, so this does not prove"
                " which."
            )
            raise KeychainSessionError(msg) from None

        entropy = fields.get(ENTROPY_FIELD) if isinstance(fields, dict) else None
        if not isinstance(entropy, bytes):
            msg = f"The recovered material carries no {ENTROPY_FIELD}"
            raise KeychainSessionError(msg)

        sealed = self._sealed_bottle(record)
        inner = cf.OTBottle.FromString(sealed.bottle)

        # Who sealed this bottle. Looked up before it is opened, so that key material from
        # a party the circle does not contain is refused rather than used.
        directory = await self.peer_directory()
        sponsor = directory.get(sealed.peer_id) or directory.get(inner.peer_id)

        # The salt is the account's `adsid`, and an account carries more than one
        # identifier of that shape. The check is free and offline, so the candidates are
        # tried rather than one being assumed.
        keys, salt = find_bottle_keys(
            entropy,
            [self._account.adsid or "", self._account.dsid],
            inner.escrowed_signing_key,
            inner.escrowed_encryption_key,
        )

        return RecoveredPeer(
            record=record,
            fields=fields,
            salt=salt,
            keys=keys,
            bottle=open_bottle(sealed, keys, sponsor=sponsor),
        )

    def _sealed_bottle(self, record: EscrowRecord) -> cf.Bottle:
        """Find the sealed bottle the viability listing already returned for a record."""
        entries = self._bottles.entries if self._bottles else []
        sealed = next((entry.bottle for entry in entries if entry.id == record.label), None)

        if sealed is None or not sealed.bottle:
            msg = (
                f"The trust-circle service listed {record.label} as viable but returned"
                " no sealed contents for it, so there is nothing to open."
            )
            raise KeychainSessionError(msg)
        return sealed

    async def key_shares(self, peer: RecoveredPeer) -> list[KeyShare]:
        """
        Fetch and unwrap the key shares a recovered peer is entitled to.

        **This is where the keys arrive, and it happens before anything is written.** A
        share is wrapped to the receiving peer's encryption key, which recovery has
        already yielded -- so no membership of the trust circle is needed to read one, and
        therefore no peer, no voucher and no escrow record.

        Read-only, and needs no passcode beyond the one recovery already spent.

        :param peer: A peer from :meth:`recover`.
        """
        directory = await self.peer_directory()
        entries = await fetch_recoverable_shares(self._cuttlefish, peer.peer_id)
        encryption_key = peer.encryption_key()

        # The signing key is offered as an alternate purely so the failure can say which
        # key a share is addressed to. A share should be wrapped to the encryption key;
        # if one turns out not to be, that is worth learning from the data rather than
        # from a wrong assumption that presents as a cipher that will not authenticate.
        alternates = {"signing": peer.signing_key()}

        shares = [
            unwrap_share(
                entry,
                encryption_key,
                directory,
                alternates=alternates,
                expected_receiver=peer.peer_id,
            )
            for entry in entries
        ]
        logger.info("Shares for %s: %s", peer.peer_id, summarise(shares))
        return shares

    async def service_keys(
        self,
        peer: RecoveredPeer,
        *,
        view: str = VIEW_MANATEE,
        shares: list[KeyShare] | None = None,
    ) -> ServiceKeys:
        """
        Recover the elliptic-curve keys Stage 5 decrypts accessory records with.

        This is the whole path in one call: fetch the shares, unwrap the view's three keys,
        enumerate the view's zone, follow the pointer tagged with this project's service,
        decrypt that item, and read its `v_Data`.

        **Note where the boundary is.** Everything up to the item is symmetric -- view
        keys, item keys, AES-SIV -- and everything after it is elliptic-curve. A view key
        never becomes an EC private key; the item's payload *contains* one.

        Read-only throughout, and needs no passcode beyond the one :meth:`recover` spent.

        :param peer: A peer from :meth:`recover`.
        :param view: The keychain view to read. `Manatee` holds Find My's keys.
        :param shares: Shares already fetched by :meth:`key_shares`, to avoid asking for
            them twice. They are the same for every view, so a caller reading two views
            should fetch once and pass them here.
        :raises KeychainSessionError: If the view yields no keys for this peer.
        :raises ItemError: If the item cannot be found or decrypted.
        :raises ServiceKeyError: If its payload is not a key structure.
        """
        keyring = await self._view_keyring(peer, view, shares)

        contents = await fetch_view(self._securityd, view)
        item = service_key_item(contents, keyring)

        return service_keys_from_der(payload_of(item))

    async def _view_keyring(
        self,
        peer: RecoveredPeer,
        view: str,
        shares: list[KeyShare] | None,
    ) -> ViewKeyring:
        """Find the symmetric keys that open a view's items, fetching shares if needed."""
        if shares is None:
            shares = await self.key_shares(peer)

        keyring = next(
            (s.view_keys for s in shares if s.service == view and s.view_keys),
            None,
        )
        if keyring is None:
            available = sorted({s.service for s in shares if s.view_keys})
            msg = (
                f"No keys were recovered for the {view!r} view, so its items cannot be"
                f" read. Views that did yield keys: {', '.join(available) or 'none'}"
            )
            raise KeychainSessionError(msg)

        logger.info("Reading the %s view with %s", view, keyring.describe())
        return keyring

    async def pcs_keys(
        self,
        peer: RecoveredPeer,
        *,
        views: Sequence[str] = (VIEW_MANATEE, VIEW_PROTECTED_CLOUD_STORAGE),
        shares: list[KeyShare] | None = None,
    ) -> list[ec.EllipticCurvePrivateKey]:
        """
        Every elliptic-curve key a keychain view holds, for Stage 5 to try.

        **Not the same as :meth:`service_keys`, and this is the one a record needs.** That
        method follows the `currentitem` pointer to the view's *current* key for this
        service. A record's protection structure names whichever key protected it, which
        may be an older one or another service's -- §6.8 resolves such a reference by
        matching on an item's `acct`, so the answer is a view-wide lookup rather than one
        pointer.

        Reading them all costs a decryption per item and needs no further round trip: the
        zone was fetched once already.

        :param peer: A peer from :meth:`recover`.
        :param views: The keychain views to read. **Both by default**, because Stage 5 §2
            says both must be synced before decryption can begin -- reading only the one
            that "holds these keys" is a reading of that sentence, and the cheaper mistake
            is to read the other as well.
        :param shares: Shares already fetched, to avoid asking twice.
        """
        if shares is None:
            shares = await self.key_shares(peer)

        keys: list[ec.EllipticCurvePrivateKey] = []
        for view in views:
            # A view that yields no shares is not a reason to skip the other.
            keys.extend(await self._pcs_keys_or_none(peer, view, shares))

        logger.info("%d elliptic-curve key(s) across %s", len(keys), ", ".join(views))
        return keys

    async def _pcs_keys_or_none(
        self,
        peer: RecoveredPeer,
        view: str,
        shares: list[KeyShare],
    ) -> list[ec.EllipticCurvePrivateKey]:
        """Read one view's keys, reporting rather than raising if it cannot be read."""
        try:
            return await self._pcs_keys_in(peer, view, shares)
        except KeychainSessionError as e:
            logger.warning("Could not read the %s view: %s", view, e)
            return []

    async def _pcs_keys_in(
        self,
        peer: RecoveredPeer,
        view: str,
        shares: list[KeyShare],
    ) -> list[ec.EllipticCurvePrivateKey]:
        """Read every elliptic-curve key one view's items hold."""
        keyring = await self._view_keyring(peer, view, shares)
        contents = await fetch_view(self._securityd, view)

        keys: list[ec.EllipticCurvePrivateKey] = []
        for account, item in readable_items(contents, keyring).items():
            try:
                found = service_keys_from_der(payload_of(item))
            except (ItemError, ServiceKeyError) as e:
                logger.debug("Item for acct %s holds no key: %s", account[:8].hex(), e)
                continue

            # An item names the key it holds, so a mismatch here is this client having
            # mis-read the payload rather than the item being for someone else -- worth
            # saying, because it is the difference between a bad reader and a bad key.
            if account not in public_key_forms(found.encryption_key.public_key()):
                logger.warning(
                    "The item for acct %s holds a key whose public half does not match it",
                    account[:8].hex(),
                )

            keys.extend(found.for_pcs())

        logger.info("The %s view holds %d elliptic-curve key(s)", view, len(keys))
        return keys

    async def recover_service_keys(
        self,
        record: EscrowRecord,
        passcode: str,
        *,
        view: str = VIEW_MANATEE,
    ) -> ServiceKeys:
        """
        Go from an escrow record and a device passcode to the keys Stage 5 decrypts with.

        The whole of Stage 3 in one call, and the only one most callers want: recover the
        peer, fetch its key shares, unwrap the view's keys, read the service key's item,
        and return the elliptic-curve keys inside it.

        **Read-only.** Nothing is created, signed or enrolled -- see :meth:`key_shares` for
        why the keys arrive before any write would happen.

        :param record: A recoverable record from :meth:`recovery_options`.
        :param passcode: That device's screen-lock passcode. Used inside this call and not
            retained; see :meth:`recover`.
        :param view: The keychain view to read. `Manatee` holds Find My's keys.
        :raises KeychainSessionError: If the record is not recoverable, or the view yields
            no keys.
        """
        peer = await self.recover(record, passcode)
        return await self.service_keys(peer, view=view)

    async def delete_record(
        self,
        record: EscrowRecord,
        *,
        confirm: str,
        allow_viable: bool = False,
    ) -> None:
        """
        Delete an escrow record, and its companion if it has one.

        **Irreversible, and the protocol offers no protection.** See
        :meth:`findmy.keychain.escrow.AsyncEscrowProxy.delete_record` for the four rules
        that make it safe to offer; this passes the listing through so they apply.

        Note that deleting records does not stop new ones appearing.

        :param record: The record to delete.
        :param confirm: Its serial, typed back in full.
        :param allow_viable: Permit deleting a live recovery path. Almost never right.
        """
        options = await self.recovery_options()
        await self._renew_token_if_stale()

        await self._proxy.delete_record(
            record,
            options,
            confirm=confirm,
            allow_viable=allow_viable,
        )

        # The service reports success for a deletion that addressed nothing, so the only
        # proof is asking again. Dropping the cache forces that on the next call.
        self._options = None
