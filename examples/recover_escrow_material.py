"""
Recover a peer's identity from an escrow record, and unwrap the keychain keys it holds.

This exercises Stage 3 of the protocol specification end to end: the SRP exchange in which
a device passcode is the password, the bottle that yields, and the key shares that bottle's
identity is entitled to receive.

    cd examples && python3 recover_escrow_material.py

**It does not write to your account.** Every step here reads. A share is wrapped to the
*receiving* peer's encryption key, and recovery yields exactly that key -- so the keys
arrive without this client ever joining the trust circle, which means no peer is created,
no voucher signed and no escrow record enrolled. That is the whole point of stopping here.

What it needs from you is the **screen-lock passcode of the device the record belongs to**
-- that machine's PIN or login password, not your Apple ID password. Only records the
trust-circle service considers usable are offered, and each is shown with its device name,
model and serial so you can tell which passcode to reach for.

The passcode is read with `getpass`, so it is not echoed and does not reach your shell
history. It is used twice inside one call and is not stored, logged or retained.

A wrong passcode and a misread exchange fail identically by design, so if it fails, try
another device's record before concluding the implementation is at fault.
"""

from __future__ import annotations

import asyncio
import getpass
import logging
import sys
from typing import TYPE_CHECKING

from _login import get_account_async  # pyright: ignore [reportMissingImports]

from findmy.errors import UnhandledProtocolError
from findmy.keychain import AsyncKeychainSession, RecoveredPeer
from findmy.keychain.shares import summarise

if TYPE_CHECKING:
    from findmy.keychain.servicekey import ServiceKeys

ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"


def report_recovered(peer: RecoveredPeer) -> None:
    """Report what recovery yielded, without printing any key material."""
    print(f"\nRecovered {len(peer.fields)} field(s) from the escrow record:")
    for key, value in sorted(peer.fields.items()):
        size = f", {len(value)} bytes" if isinstance(value, (bytes, str)) else ""
        print(f"  {key} ({type(value).__name__}{size})")

    print(f"\nThe HKDF salt is the {peer.salt!r} identifier.")
    print(
        "The bottle's escrowed public keys matched the derived ones under"
        f" {peer.bottle.key_encoding} encoding,\nso the passcode, the recovery and the key"
        " derivation are all confirmed correct.",
    )
    print(
        f"\n  sponsor signing key:    {len(peer.bottle.signing_key)} bytes,"
        f" type {peer.bottle.signing_key_type}",
    )
    print(
        f"  sponsor encryption key: {len(peer.bottle.encryption_key)} bytes,"
        f" type {peer.bottle.encryption_key_type}",
    )


def report_shares(shares: list) -> bool:
    """Report what the shares yielded. Returns whether anything unwrapped."""
    print(f"{summarise(shares)}\n")

    for share in shares:
        state = f"{len(share.plaintext)} bytes" if share.plaintext else f"failed: {share.error}"
        sender = f" from {share.sender}" if share.sender else ""
        print(f"  {share.service or '<no view>'}{sender}: {state}")
        for name, key in sorted(share.view_keys.by_slot.items()):
            print(f"      {name}: {len(key)} bytes")

    return any(share.plaintext for share in shares)


def report_service_keys(keys: ServiceKeys) -> None:
    """Report the keys the service key item yielded, without printing any of them."""
    print("\n--- The service key ---")
    print(f"  encryption key: {keys.encryption_key.curve.name}")
    if keys.signing_key is not None:
        print(f"  signing key:    {keys.signing_key.curve.name}")

    print("\nThat is what Stage 5 decrypts accessory records with. Run")
    print("fetch_beacons_from_icloud.py to use it.")


async def main() -> int:
    """Recover one record and unwrap the key shares it entitles us to."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)-8s %(message)s")
    logging.getLogger("findmy.keychain").setLevel(logging.DEBUG)

    account = await get_account_async(ACCOUNT_STORE, ANISETTE_SERVER, ANISETTE_LIBS_PATH)

    try:
        async with await AsyncKeychainSession.open(account) as session:
            options = await session.recovery_options()
            if not options.recoverable:
                print("No record on this account is currently recoverable.")
                return 1

            print(f"\n{len(options.recoverable)} record(s) can be recovered from:\n")
            for record in options.recoverable:
                print(f"  {record.describe()}")

            print("\nEnter the SERIAL of the one to recover from. You will need that")
            print("device's screen-lock passcode -- its PIN or login password.\n")

            typed = input("serial> ").strip()
            chosen = next((r for r in options.recoverable if r.serial == typed), None)
            if chosen is None:
                print("No recoverable record has that serial.")
                return 1

            print(f"\nRecovering from {chosen.describe()}")
            passcode = getpass.getpass("passcode (not echoed)> ")

            try:
                peer = await session.recover(chosen, passcode)
            finally:
                del passcode  # used twice inside the call above and wanted no longer

            report_recovered(peer)

            # The keys arrive here, before anything is written anywhere.
            print("\n--- Key shares ---")

            directory = await session.peer_directory()
            print(f"The trust circle holds {len(directory)} peer(s).")

            shares = await session.key_shares(peer)
            if not shares:
                print("This peer is entitled to no key shares at all, so there is nothing")
                print("to unwrap. Joining would have succeeded and yielded nothing, which")
                print("is exactly the case worth refusing.")
                return 1

            if not report_shares(shares):
                print("\nNothing unwrapped. The construction is specified, so this is not a")
                print("parameter to search for -- the failure above says which part is at")
                print("fault, and the key having been confirmed rules out the recovery.")
                return 1

            print("\nThose are keychain view keys, obtained without joining the circle:")
            print("no peer created, no voucher signed, no escrow record enrolled, nothing")
            print("written to the account. Each view yields three keys -- the top-level")
            print("key and its two class keys -- and Manatee is the one Find My needs.")

            # The last step: a view key is symmetric and Stage 5 needs an EC private key.
            # The view key decrypts an item; the item's v_Data contains the EC key.
            report_service_keys(await session.service_keys(peer, shares=shares))
    except UnhandledProtocolError as e:
        print(f"\nFailed: {e}")
        return 1
    finally:
        await account.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
