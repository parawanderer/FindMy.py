"""
Remove escrow records from an Apple account.

An escrow record is a sealed copy of a device's keychain, recoverable with that device's
passcode. They accumulate: **removing a device from an account does not remove its escrow
record**, and Apple exposes them in no interface at all, so an account can carry records
for hardware that was sold or wiped years ago without anyone being able to see them.

    cd examples && python3 delete_escrow_records.py

**This deletes things, and nothing undoes it.** The protocol offers no protection
whatsoever -- any client holding a valid token can destroy any escrow record on the
account, and nothing server-side will refuse. Every safeguard is in the client:

  * Only records with **no usable bottle** are offered. Those take away no capability
    anyone had. A record that *is* usable is a live recovery path for a real device, and
    destroying it means its owner discovers the loss after a wipe, with no undo. This
    script will not delete one; it will not even list them as options.
  * Nothing is offered at all unless a full listing was obtained, because viability is
    what separates debris from danger.
  * Each deletion requires the record's **serial typed back in full**. Not a number from a
    menu: every record looks structurally alike, and the list will contain devices you no
    longer recognise.

Deleting records does not stop new ones being created. If something is still signing in
and enrolling with a fresh identity each run, it will keep leaving them behind.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from _login import get_account_async  # pyright: ignore [reportMissingImports]

from findmy.errors import UnhandledProtocolError
from findmy.keychain import AsyncKeychainSession, EscrowError
from findmy.keychain.escrow import DELETION_DOES_NOT_STOP_THE_SOURCE

ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"


async def main() -> int:
    """List what is safe to remove, then remove what the user confirms."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)-8s %(message)s")

    account = await get_account_async(ACCOUNT_STORE, ANISETTE_SERVER, ANISETTE_LIBS_PATH)

    try:
        async with await AsyncKeychainSession.open(account) as session:
            options = await session.recovery_options()

            print(
                f"\n{options.device_count} device(s) across"
                f" {len(options.recoverable) + len(options.described_but_not_viable)} record(s).",
            )
            print(f"{len(options.unsafe_to_delete)} are live recovery paths and are not offered")
            print("here. Deleting one would destroy that device's ability to recover its")
            print("keychain, and it would not be discovered until after a wipe.\n")

            for record in options.unsafe_to_delete:
                print(f"  keeping: {record.describe()}")

            removable = options.safe_to_delete
            if not removable:
                print("\nNothing to remove.")
                return 0

            print(f"\n{len(removable)} record(s) have no usable bottle and can be removed:\n")
            for record in removable:
                print(f"  {record.describe()}")

            print("\nEnter the SERIAL of a record to delete it, or press enter to stop.")
            print("The serial, not a number -- every record looks alike, and the list")
            print("contains devices you may no longer recognise.\n")

            deleted = 0
            remaining = list(removable)
            while remaining:
                typed = input("serial> ").strip()
                if not typed:
                    break

                match = next((r for r in remaining if r.serial == typed), None)
                if match is None:
                    print("  No record offered here has that serial. Nothing deleted.")
                    continue

                print(f"  Deleting {match.describe()}")
                try:
                    await session.delete_record(match, confirm=typed)
                except EscrowError as e:
                    print(f"  Refused: {e}")
                    continue

                remaining.remove(match)
                deleted += 1
                print("  Deleted.")

            if not deleted:
                print("\nNothing deleted.")
                return 0

            # Re-list rather than trusting the calls: the service reports success for a
            # deletion that addressed nothing, so the only proof is asking again.
            after = await session.recovery_options(refresh=True)
            still_here = len(after.recoverable) + len(after.described_but_not_viable)
            print(f"\nDeleted {deleted} record(s); {still_here} remain.")
            print(f"\n{DELETION_DOES_NOT_STOP_THE_SOURCE}")
    except UnhandledProtocolError as e:
        print(f"\nFailed: {e}")
        return 1
    finally:
        await account.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
