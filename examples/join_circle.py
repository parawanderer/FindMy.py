"""
Join the account's keychain trust circle. **This writes, and nothing undoes it.**

    cd examples && python3 preflight_join.py     # first, and it writes nothing
    cd examples && python3 join_circle.py        # this one

A join creates three permanent things: a peer in the circle that protects every password
the account holds, a bottle sealed under a passcode you choose, and an escrow record for
that bottle. Only the record can be removed afterwards, with `delete_escrow_records.py`.
The peer stays.

**Consider whether you need it at all.** `trace_key_recovery.py` and
`fetch_beacons_from_icloud.py` already read the keychain view keys, because a key share is
wrapped to the *receiving* peer's encryption key and recovering an escrow record yields
exactly that key. Joining is not how the keys are obtained -- it is what makes this client
a member in its own right, holding keys addressed to itself and staying current as they
rotate. If you only want to read your AirTags, you do not need this script.

Two passcodes are involved and they are not the same:

  * the **device passcode** of the record you recover from, which is that machine's PIN or
    login password -- exactly as `trace_key_recovery.py` asks for;
  * a passcode **you choose** for the new record this creates, which is what would recover
    *this* client later. Choose it as carefully as the first: it is the only way back.

The preflight check is re-run here and this script refuses to continue unless it passes,
because the identifier derivation it settles is the one thing a join cannot check for
itself.

> **A failure after the join is sent is never a reason to run this again.** A response that
> does not decode is not a call that failed, and a timeout does not establish that no
> response was sent. Running it twice creates a second peer, a second bottle and a second
> escrow record, all permanent. Recover by re-reading the circle, which `preflight_join.py`
> does.
"""

from __future__ import annotations

import asyncio
import getpass
import logging
import sys

from _login import get_account_async  # pyright: ignore [reportMissingImports]

from findmy.errors import UnhandledProtocolError
from findmy.keychain import AsyncKeychainSession, DeviceDescription
from findmy.keychain.peers import check_peer_identifiers

ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"

# How this client describes itself. These reach two places a person reads: the escrow
# record's metadata, which is the only way to recognise it in a listing later, and the
# peer's own name in the account's device list. Worth setting to something you will
# recognise in a year.
DEVICE = DeviceDescription(
    name="FindMy.py",
    model="MacBookPro18,3",
    serial="FINDMYPY0001",
    build="22F8",
    model_class="Mac",
    platform="macOS",
)
OS_VERSION = "13.4.1"


def confirm(prompt: str, expected: str) -> bool:
    """Ask for a word to be typed back in full. Not a y/n."""
    print(f"\n{prompt}")
    return input(f"Type {expected} to continue> ").strip() == expected


async def main() -> int:  # noqa: PLR0911, PLR0915 -- refusals, each with its own reason
    """Recover one record, then join the circle with a new identity it vouches for."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)-8s %(message)s")
    logging.getLogger("findmy.keychain").setLevel(logging.INFO)

    account = await get_account_async(ACCOUNT_STORE, ANISETTE_SERVER, ANISETTE_LIBS_PATH)

    try:
        async with await AsyncKeychainSession.open(account) as session:
            # The same check preflight_join.py makes, re-made here. It is the one thing a
            # join cannot check for itself, and running it in the same session as the join
            # is what makes it a guard rather than a note in an earlier terminal.
            directory = await session.peer_directory(refresh=True)
            check = check_peer_identifiers(directory)
            print(f"Peer identifiers: {check.describe()}")

            if not check.confirmed:
                print("\nThe peer identifier derivation is not confirmed against this")
                print("circle, so a voucher would name a beneficiary that may not exist.")
                print("Refusing to join. Run preflight_join.py to see the detail.")
                return 1

            options = await session.recovery_options()
            if not options.recoverable:
                print("\nNo record on this account can be recovered from, so there is no")
                print("peer available to vouch for a new one.")
                return 1

            print(f"\n{len(options.recoverable)} record(s) can sponsor this join:\n")
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
            passcode = getpass.getpass("that device's passcode (not echoed)> ")
            try:
                peer = await session.recover(chosen, passcode)
            finally:
                del passcode

            print(f"Recovered {peer.peer_id}, which will sponsor the new identity.")

            print("\nNow choose the passcode for the NEW escrow record this creates.")
            print("It is what would recover this client later, and it is the only way")
            print("back. It does not have to match the one you just typed.")

            new_passcode = getpass.getpass("new passcode (not echoed)> ")
            if new_passcode != getpass.getpass("again> "):
                print("Those do not match.")
                return 1
            if not new_passcode:
                print("An empty passcode would leave the record recoverable by anyone.")
                return 1

            print("\nThis creates THREE permanent things on the account:")
            print(f"  a peer in the trust circle of {len(directory)} peer(s) above")
            print("  a bottle sealed under the passcode you just chose")
            print("  an escrow record for it")
            print("\nOnly the record can be removed afterwards. Nothing removes the peer.")

            if not confirm("Proceed?", "JOIN"):
                print("Nothing was done.")
                return 1

            try:
                outcome = await session.join(
                    peer,
                    passcode=new_passcode,
                    device=DEVICE,
                    os_version=OS_VERSION,
                )
            finally:
                del new_passcode

            print("\n--- Joined ---")
            print(f"  peer:   {outcome.identity.peer_id}")
            print(f"  bottle: {outcome.bottle.bottle_id}")
            print(f"  record: {outcome.label}")
            print(f"  keys re-addressed to it: {outcome.shares}")
            print(f"  the circle now holds {len(outcome.directory)} peer(s)")
            if outcome.sync_token:
                print(f"  sync token: {outcome.sync_token}")

            print("\n**Keep the record label above.** It is what delete_escrow_records.py")
            print("needs to remove this record if you decide you did not want it, and no")
            print("Apple interface will show it to you.")
    except UnhandledProtocolError as e:
        print(f"\nFailed: {e}")
        print("\nIf that failure happened after the join was sent, the peer and the")
        print("record exist regardless. Do NOT run this again to find out -- run")
        print("preflight_join.py, which reads the circle and shows what is there.")
        return 1
    finally:
        await account.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
