"""
Find My accessories from an iCloud account, with no Mac involved.

One object over both halves of the flow. They are separate packages because the protocol
is: :mod:`findmy.keychain` recovers key material from the trust circle, and
:mod:`findmy.cloudkit` reads and decrypts the accessory zone. Nothing needs them apart,
and everything that uses them together assembles the same three steps.

    async with await AsyncFindMyClient.open(account) as client:
        options = await client.recovery_options()
        await client.unlock(options.recoverable[0], passcode)

        for accessory in await client.accessories():
            print(accessory.name, accessory.serial_number)

**Read-only except for :meth:`~AsyncFindMyClient.rename`.** Reading leaves no trace: no
peer joins the trust circle, no voucher is signed, no escrow record is enrolled. The keys
arrive before any write would have happened, which is what makes that possible -- see
:meth:`findmy.keychain.AsyncKeychainSession.key_shares`. `rename` is the single
exception, saves one record, and is never called by anything else here.

**The passcode is spent once.** :meth:`unlock` needs the screen-lock passcode of the
device whose escrow record is being recovered from. What it yields can be kept, and
:meth:`use_keys` takes it back on a later run, so ordinary use never asks again.

.. warning::
    The keys this holds decrypt the user's Find My data. It keeps them in memory and
    writes nothing to disk; persisting them is a decision for the caller, and they must be
    stored as carefully as the passcode that produced them.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from typing_extensions import Self, override

from findmy.cloudkit.beacons import AsyncBeaconStore, BeaconExportError
from findmy.keychain.items import VIEW_MANATEE, VIEW_PROTECTED_CLOUD_STORAGE
from findmy.keychain.session import AsyncKeychainSession, KeychainSessionError
from findmy.util.abc import Closable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cryptography.hazmat.primitives.asymmetric import ec

    from findmy.accessory import FindMyAccessory
    from findmy.cloudkit.records import CloudKitRecord
    from findmy.keychain.escrow import EscrowRecord, RecoveryOptions
    from findmy.reports.account import AsyncAppleAccount

logger = logging.getLogger(__name__)


class AsyncFindMyClient(Closable):
    """
    A user's Find My accessories, in their iCloud account.

    **Reads, and renames.** Everything here reads except :meth:`rename`, which is the
    only call that changes anything on the account -- hence a client rather than a
    reader, which is what this was called while it could only read.

    Build one with :meth:`open`. It holds a keychain session and a beacon store, and
    closes both.
    """

    def __init__(
        self,
        account: AsyncAppleAccount,
        session: AsyncKeychainSession,
        store: AsyncBeaconStore,
    ) -> None:
        """Use :meth:`open`."""
        super().__init__()

        self._account = account
        self._session = session
        self._store = store

        self._keychain_keys: list[ec.EllipticCurvePrivateKey] = []
        self._zone_keys: list[ec.EllipticCurvePrivateKey] | None = None

    @classmethod
    async def open(cls, account: AsyncAppleAccount) -> Self:
        """
        Establish a client over a logged-in account.

        :param account: A logged-in account.
        :raises KeychainSessionError: If the keychain session cannot be established.
        """
        session = await AsyncKeychainSession.open(account)
        try:
            store = AsyncBeaconStore(account)
        except Exception:
            await session.close()
            raise

        return cls(account, session, store)

    @override
    async def close(self) -> None:
        """Close everything this opened. Does not close the account."""
        await self._store.close()
        await self._session.close()

    async def __aenter__(self) -> Self:
        """Enter a context that closes this client on exit."""
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close on the way out."""
        await self.close()

    @property
    def session(self) -> AsyncKeychainSession:
        """The keychain session, for callers that want the parts underneath."""
        return self._session

    @property
    def store(self) -> AsyncBeaconStore:
        """The beacon store, likewise."""
        return self._store

    @property
    def keychain_keys(self) -> list[ec.EllipticCurvePrivateKey]:
        """
        The keychain keys held, if any.

        **These open the zone, not a record.** A record's protection structure names a
        *zone* key, and confusing the two is the mistake that costs the most time here --
        it presents as every record being protected for somebody else.
        """
        return list(self._keychain_keys)

    @property
    def unlocked(self) -> bool:
        """Whether keys are held. Fetching records needs none; decrypting them does."""
        return bool(self._keychain_keys)

    async def recovery_options(self, *, refresh: bool = False) -> RecoveryOptions:
        """
        Ask what this account could be recovered from.

        Read-only, and the only way to see escrow records at all -- Apple exposes them in
        no interface, so an account accumulates them invisibly.
        """
        return await self._session.recovery_options(refresh=refresh)

    async def unlock(
        self,
        record: EscrowRecord,
        passcode: str,
        *,
        views: Sequence[str] = (VIEW_MANATEE, VIEW_PROTECTED_CLOUD_STORAGE),
    ) -> list[ec.EllipticCurvePrivateKey]:
        """
        Recover the keychain keys, using a device's screen-lock passcode.

        **The one step that needs the passcode**, and it needs it once. What this returns
        can be kept and handed back to :meth:`use_keys` on a later run.

        :param record: A recoverable record from :meth:`recovery_options`.
        :param passcode: That device's screen-lock passcode -- its PIN or login password,
            not the Apple ID password. Used inside this call and not retained.
        :param views: Which keychain views to read.
        :returns: The keys, which are also kept for :meth:`accessories`.
        """
        peer = await self._session.recover(record, passcode)
        keys = await self._session.pcs_keys(peer, views=views)

        self.use_keys(keys)
        return keys

    def use_keys(self, keys: Sequence[ec.EllipticCurvePrivateKey]) -> None:
        """
        Supply keychain keys obtained earlier, instead of recovering them.

        This is what makes the passcode a one-time cost: keep what :meth:`unlock`
        returned, hand it back here, and a later run never asks.

        **These are the keychain keys, not a record's.** A record is protected by a zone
        key, and the zone is unwrapped with these -- see :meth:`zone_keys`.
        """
        self._keychain_keys = list(keys)
        self._zone_keys = None

    async def zone_keys(self) -> list[ec.EllipticCurvePrivateKey]:
        """
        Unwrap the accessory zone with the keychain keys, yielding the keys its records use.

        Two levels, and this is the first. The keychain keys open the *zone*; the zone
        yields what a record's protection structure names. Cached, since the zone is
        fetched once and its keys do not change between records.

        :raises KeychainSessionError: If no keys are held.
        """
        self._require_keys()

        if self._zone_keys is None:
            self._zone_keys = await self._store.zone_keys(self._keychain_keys)

        return self._zone_keys

    async def records(self, *, continuation_token: bytes | None = None) -> list[CloudKitRecord]:
        """
        Fetch the accessory zone's records, still encrypted.

        **Needs no keys at all** -- not the keychain, not the trust circle, not a passcode.
        Fetching and decrypting are cleanly separable, and this is the half that a later
        run repeats.

        :param continuation_token: Resume from a previous fetch. Persisting this is how a
            later run notices a newly-paired accessory without refetching everything.
        """
        return await self._store.fetch_records(continuation_token=continuation_token)

    async def accessories(
        self,
        *,
        continuation_token: bytes | None = None,
    ) -> list[FindMyAccessory]:
        """
        Fetch, decrypt and assemble the account's accessories.

        What comes back is an ordinary :class:`~findmy.accessory.FindMyAccessory`. There
        is nothing further to learn to use one: locating it is
        :meth:`~findmy.reports.account.AsyncAppleAccount.fetch_location`, the same call
        that locates an accessory read from a plist.

        .. warning::
            **An accessory whose key-alignment record is missing searches its whole
            history when located.** It starts at index zero from its pairing date, which
            for an eighteen-month-old tag is around fifty thousand keys against a service
            that answers a few hundred at a time. That is slow, and enough of it looks
            like abuse of the account rather than like a first sync. The alignment records
            are fetched alongside the beacons and attached where present.

        :param continuation_token: As :meth:`records`.
        :raises KeychainSessionError: If no keys are held -- call :meth:`unlock` or
            :meth:`use_keys` first.
        """
        self._require_keys()

        return await self._store.fetch_accessories(
            self._keychain_keys,
            continuation_token=continuation_token,
        )

    async def rename(
        self,
        accessory: str | CloudKitRecord,
        *,
        name: str | None = None,
        emoji: str | None = None,
    ) -> CloudKitRecord:
        """
        Rename an accessory, by saving its naming record.

        **The only thing here that writes to the account.** Everything else reads, and
        this changes exactly the fields it is given -- the rest of the record is sent back
        unchanged and merged, so nothing else about the accessory moves.

        **Pass an identifier.** `reader.rename(accessory.identifier, name="Keys")` closes
        the loop from :meth:`accessories` to here without the caller ever meeting a
        `CloudKitRecord`, and it costs one fetch, which a rename can afford.

        The naming record itself is also accepted, for a caller that already holds one --
        but **holding one across a write is a trap**. A save checks the record's
        protection tag and replaces it, so a record kept from before a write is stale and
        the *second* rename fails after the first succeeded, which is the worst way round
        to find out. The identifier form has no such lifecycle to manage.

        .. note::
            **[observed] Confirmed against Apple's own Find My**, on a Mac, which showed a
            name written here and kept the accessory's emoji and association intact.

            Worth remembering why that was the check: a success response is the server
            echoing what it was sent, and reading the value back only proves this library
            agrees with itself. Nothing on this side could have caught a wrong layout.

        :param accessory: The accessory's identifier, or its naming record as fetched.
        :param name: The new name, if it is changing.
        :param emoji: The new emoji, if it is changing.
        :raises BeaconExportError: If neither a name nor an emoji was given, if the
            identifier names no accessory in this account, or if the record given is not a
            naming record.
        :raises KeychainSessionError: If no keys are held.
        """
        changes: dict[str, object] = {}
        if name is not None:
            changes["name"] = name
        if emoji is not None:
            changes["emoji"] = emoji

        if not changes:
            msg = "Nothing to change: pass a name, an emoji, or both."
            raise BeaconExportError(msg)

        zone_keys = await self.zone_keys()
        naming = (
            await self._store.find_naming_record(accessory, zone_keys)
            if isinstance(accessory, str)
            else accessory
        )

        return await self._store.save_naming_record(naming, zone_keys, **changes)

    def _require_keys(self) -> None:
        """Insist on keys, naming the two ways to get them."""
        if self._keychain_keys:
            return

        msg = (
            "No keychain keys are held, so nothing can be decrypted. Call unlock() with a"
            " recoverable record and that device's passcode, or use_keys() with keys kept"
            " from an earlier run."
        )
        raise KeychainSessionError(msg)
