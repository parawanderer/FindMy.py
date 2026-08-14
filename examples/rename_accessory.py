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

from _login import get_account_async  # pyright: ignore [reportMissingImports]

from findmy.cloudkit.beacons import decrypt_records
from findmy.cloudkit.constants import RecordType
from findmy.errors import UnhandledProtocolError
from findmy.icloud import AsyncFindMyClient

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


def choose(named: list[tuple[object, str]]) -> int:
    """
    Show what can be renamed and ask which. Returns an index, or -1 to stop.

    Anything that is not one of the numbers stops, rather than being taken as a default.
    The one destructive step should need a deliberate answer, not a plausible typo.
    """
    print(f"\n{len(named)} accessor{'y' if len(named) == 1 else 'ies'} can be renamed:\n")
    for number, (_, name) in enumerate(named, start=1):
        print(f"  {number}. {name or '<unnamed>'}")

    typed = input("\nWhich one? Number, or anything else to cancel> ").strip()
    if not typed.isdigit() or not 1 <= int(typed) <= len(named):
        return -1

    return int(typed) - 1


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

            records = await client.records()
            decrypted = {d.name: d for d in decrypt_records(records, await client.zone_keys())}

            # The naming records, paired with the name each currently holds. Renaming
            # saves one of these -- the master beacon beside it is never written.
            named = [
                (record, str(decrypted[record.name].values.get("name", "")))
                for record in records
                if record.record_type == RecordType.BEACON_NAMING and record.name in decrypted
            ]
            if not named:
                print("\nNo naming records came back, so there is nothing to rename.")
                return 1

            index = choose(named)
            if index < 0:
                print("\nCancelled. Nothing was sent.")
                return 0

            record, old = named[index]
            new = input("\nNew name> ").strip()
            if not new:
                print("\nAn empty name would leave the accessory unlabelled. Cancelled.")
                return 0

            if not confirm(old, new):
                print("\nCancelled. Nothing was sent, and your account is unchanged.")
                return 0

            await client.rename(record, name=new)  # pyright: ignore [reportArgumentType]

            # Reading it back proves the two halves of THIS library agree, and nothing
            # more. It is worth doing because a failure here is decisive, but a success
            # is not -- which is what the closing message is for.
            fresh = await client.records()
            again = {d.name: d for d in decrypt_records(fresh, await client.zone_keys())}
            readback = str(again.get(record.name, decrypted[record.name]).values.get("name", ""))

            print(f"\nSaved. Reading it back gives: {readback!r}")
            if readback != new:
                print("Which is not what was written, so the write did not take effect.")
                return 1

            print("\nThat only proves this library can read what this library wrote, so")
            print("it is worth looking at the accessory on an iPhone, iPad or Mac too.")
            print("This path has been confirmed that way once -- a name written here")
            print("showed up correctly in Find My on a Mac -- but nothing on this side")
            print("can detect a layout Apple would reject, so a blank or garbled name")
            print("there is still the more valuable result and worth reporting.")
    except UnhandledProtocolError as e:
        print(f"\nFailed: {e}")
        return 1
    finally:
        await account.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
