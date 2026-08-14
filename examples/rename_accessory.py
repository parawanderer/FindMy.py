"""
Rename one of your own AirTags, from a machine that is not a Mac.

**This one writes.** `fetch_beacons_from_icloud.py` reads an account and changes nothing;
this changes a record in it. Everything up to the confirmation is read-only, and typing
anything but the number of an accessory leaves the account exactly as it was.

    cd examples && python3 rename_accessory.py

Stage 4 §4 and Stage 5 §6.1. An accessory's name lives in a `BeaconNamingRecord` beside
it, encrypted under the same key that everything else in the zone is, so renaming one is
a save of that record -- no new key material, nothing to recover that reading did not
already need.

**Your own account only.** Holding an accessory's keys from an export is not a right to
modify someone else's iCloud records, and nothing in this can tell the two apart.

**[observed] This works.** A name written by this script showed up correctly in Apple's
own Find My on a Mac, with the accessory's emoji and its association intact. That check
mattered more than it sounds: the field layout puts the GCM tag *before* the ciphertext,
and a writer and a reader that both got that wrong would agree with each other perfectly
while producing something no Apple device could read. Nothing on this side could have
caught it, which is why the script still ends by asking you to go and look.

Renaming back is a rename like any other, so a wrong name is not a trap.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import TYPE_CHECKING

from _login import get_account_async  # pyright: ignore [reportMissingImports]

from findmy.errors import UnhandledProtocolError
from findmy.icloud import AsyncFindMyClient

if TYPE_CHECKING:
    from findmy.accessory import FindMyAccessory

ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"


async def unlock(client: AsyncFindMyClient) -> bool:
    """Recover the keys, asking for a device passcode. Returns whether it worked."""
    import getpass  # noqa: PLC0415

    options = await client.recovery_options()
    if not options.recoverable:
        print("\nNo record on this account is currently recoverable, so there are no")
        print("keys to decrypt or re-encrypt anything with.")
        return False

    print("\nWhich device's passcode can you provide?\n")
    for record in options.recoverable:
        print(f"  {record.describe()}")

    typed = input("\nserial> ").strip()
    chosen = next((r for r in options.recoverable if r.serial == typed), None)
    if chosen is None:
        print("No recoverable record has that serial.")
        return False

    passcode = getpass.getpass("passcode (not echoed)> ")
    try:
        await client.unlock(chosen, passcode)
    finally:
        del passcode

    return True


def choose(accessories: list[FindMyAccessory]) -> FindMyAccessory | None:
    """
    Show what can be renamed and ask which. Returns None to stop.

    Anything that is not one of the numbers stops, rather than being taken as a default.
    The one destructive step should need a deliberate answer, not a plausible typo.
    """
    # An accessory with no identifier cannot be looked up, so there is nothing to rename
    # and offering it would fail at the one step that writes.
    renameable = [a for a in accessories if a.identifier]

    count = len(renameable)
    print(f"\n{count} accessor{'y' if count == 1 else 'ies'} can be renamed:\n")
    for number, accessory in enumerate(renameable, start=1):
        print(f"  {number}. {accessory.name or '<unnamed>'} ({accessory.model})")

    if len(renameable) != len(accessories):
        print(f"\n  ({len(accessories) - count} more carry no identifier to look up.)")

    typed = input("\nWhich one? Number, or anything else to cancel> ").strip()
    if not typed.isdigit() or not 1 <= int(typed) <= count:
        return None

    return renameable[int(typed) - 1]


def confirm(old: str, new: str) -> bool:
    """Ask before the one call that changes anything."""
    print(f"\n  {old or '<unnamed>'}  ->  {new}")
    print("\nThis writes to your iCloud account. Renaming back later is another rename,")
    print("so this is reversible -- but nothing has been sent yet.\n")

    return input("Type RENAME to go ahead> ").strip() == "RENAME"


async def main() -> int:  # noqa: PLR0911
    """Pick an accessory, rename it, and say what would actually verify the write."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(name)s: %(message)s")

    account = await get_account_async(ACCOUNT_STORE, ANISETTE_SERVER, ANISETTE_LIBS_PATH)

    try:
        async with await AsyncFindMyClient.open(account) as client:
            if not await unlock(client):
                return 1

            # Ordinary accessories, exactly as any other example gets them. Nothing here
            # meets a CloudKit record: renaming takes the identifier this already carries.
            accessories = await client.accessories()
            if not accessories:
                print("\nNo accessories came back, so there is nothing to rename.")
                return 1

            chosen = choose(accessories)
            if chosen is None:
                print("\nCancelled. Nothing was sent.")
                return 0

            # Where the accessory stops being an object and becomes the one thing rename
            # needs. choose() already skips accessories without one; this is the boundary
            # that makes that guarantee visible rather than assumed.
            identifier = chosen.identifier
            if not identifier:
                print("\nThat accessory carries no identifier, so it cannot be looked up.")
                return 1

            old = chosen.name or ""
            new = input("\nNew name> ").strip()
            if not new:
                print("\nAn empty name would leave the accessory unlabelled. Cancelled.")
                return 0

            if not confirm(old, new):
                print("\nCancelled. Nothing was sent, and your account is unchanged.")
                return 0

            await client.rename(identifier, name=new)

            # Reading it back proves the two halves of THIS library agree, and nothing
            # more. It is worth doing because a failure here is decisive, but a success
            # is not -- which is what the closing message is for.
            after = {a.identifier: a for a in await client.accessories()}
            readback = (after[identifier].name or "") if identifier in after else ""

            print(f"\nSaved. Reading it back gives: {readback!r}")
            if readback != new:
                print("Which is not what was written, so the write did not take effect.")
                return 1

            print("Done.")
    except UnhandledProtocolError as e:
        print(f"\nFailed: {e}")
        return 1
    finally:
        await account.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
