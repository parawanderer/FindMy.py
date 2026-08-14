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
from findmy.keychain import AsyncKeychainSession, DeviceDescription, RecoveryOptions
from findmy.keychain.peers import check_peer_identifiers

ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"

# How this client describes itself. These reach two places a person reads: the escrow
# record's metadata, which is the only way to recognise it in a listing later, and the
# peer's name in the account's device list.
#
# The name and the serial are honest -- deliberately synthetic, so that a listing a year
# from now says what made the record. **The model and OS string are not.** They claim to be
# a Mac, and this client is not one; they are here because nobody has tested whether
# Cuttlefish accepts a `modelId` outside the set it knows, and a join is not the run to
# find that out on. If that turns out to be permitted, these should become truthful.
#
# Note what a constant serial means: §5.2's rule is that records count runs and serials
# count devices, so two joins on one account read as **one device that enrolled twice**.
# That is accurate for one installation and wrong for two people running this, and the
# listing will not tell those apart.
DEVICE = DeviceDescription(
    name="FindMy.py",
    model="MacBookPro18,3",
    serial="FINDMYPY0001",
    # The build that goes with the OS version below. They were inconsistent here at first,
    # which nothing checks today and which would be wrong the moment something does.
    build="22F82",
    model_class="Mac",
    platform="macOS",
)
OS_VERSION = "13.4.1"


def confirm(prompt: str, expected: str) -> bool:
    """Ask for a word to be typed back in full. Not a y/n."""
    print(f"\n{prompt}")
    return input(f"Type {expected} to continue> ").strip() == expected


def choose_sponsor(options: RecoveryOptions):  # noqa: ANN201
    """Offer the records that could sponsor a join, and take one by serial."""
    print(f"\n{len(options.recoverable)} record(s) can sponsor this join:\n")
    for record in options.recoverable:
        print(f"  {record.describe()}")

    print("\nEnter the SERIAL of the one to recover from. You will need that")
    print("device's screen-lock passcode -- its PIN or login password.\n")

    typed = input("serial> ").strip()
    return next((r for r in options.recoverable if r.serial == typed), None)


def ask_new_passcode() -> str:
    """Ask for the passcode the new record will be recoverable with, twice."""
    print("\nNow choose the passcode for the NEW escrow record this creates.")
    print("It is what would recover this client later, and it is the only way")
    print("back. It does not have to match the one you just typed.")

    passcode = getpass.getpass("new passcode (not echoed)> ")
    if passcode != getpass.getpass("again> "):
        print("Those do not match.")
        return ""
    if not passcode:
        print("An empty passcode would leave the record recoverable by anyone.")
    return passcode


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

            chosen = choose_sponsor(options)
            if chosen is None:
                print("No recoverable record has that serial.")
                return 1

            print(f"\nRecovering from {chosen.describe()}")
            passcode = getpass.getpass("that device's passcode (not echoed)> ")
            try:
                peer = await session.recover(chosen, passcode)
            finally:
                # A gesture, and worth knowing as one: this drops the name so the string
                # can be collected. It scrubs nothing, and the value has already been
                # copied through the SRP exchange.
                del passcode

            print(f"Recovered {peer.peer_id}, which will sponsor the new identity.")

            new_passcode = ask_new_passcode()
            if not new_passcode:
                return 1

            print("\nThis creates THREE permanent things on the account:")
            print(f"  a peer in the trust circle of {len(directory)} peer(s) above")
            print("  a bottle sealed under the passcode you just chose")
            print("  an escrow record for it")
            print("\nOnly the record can be removed afterwards. Nothing removes the peer.")

            if not confirm("Proceed?", "JOIN"):
                print("Nothing was done.")
                return 1

            # BaseException, not Exception: a Ctrl-C or a cancellation during the join is
            # exactly the case that invites running it again, and it is the case where
            # nothing else would print this. A timeout does not establish that no request
            # was sent -- so anything at all coming out of this call has to carry the
            # warning, not just the failures the library models.
            try:
                outcome = await session.join(
                    peer,
                    passcode=new_passcode,
                    device=DEVICE,
                    os_version=OS_VERSION,
                )
            except BaseException:
                print("\n*** The join may already have happened. ***")
                print("The peer and the escrow record may exist even though this failed,")
                print("and a timeout or an interrupt does not establish otherwise.")
                print("Do NOT run this script again to find out: that would create a")
                print("second peer, a second bottle and a second record, all permanent.")
                print("Run preflight_join.py, which reads the circle and shows what is")
                print("there.")
                raise
            finally:
                # Drops the name so the string becomes collectable. It does not scrub
                # anything, and the passcode has already been copied through the SRP
                # computation -- this is the most Python offers, not a guarantee.
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
        # Failures before the join reach here and are safe to retry. One that happened
        # *during* the join has already printed its own warning above and re-raised, so
        # this deliberately does not repeat it -- two messages about the same failure,
        # one hedged and one definite, is worse than either alone.
        print(f"\nFailed: {e}")
        return 1
    finally:
        await account.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
