"""
Read Find My accessories straight out of an iCloud account, with no Mac involved.

The read-only probe for this whole flow. Run it against a real account to exercise
everything that can be exercised without writing anything to that account.

    cd examples && python3 fetch_beacons_from_icloud.py

Four parts, in increasing order of what they need:

  1. **Fetch** the accessory records. Needs only a logged-in account.
  2. **Ask what the account could be recovered from** -- the escrow records Apple shows
     nowhere in its own interfaces, joined against the bottles the trust-circle service
     considers usable. Needs a fresh PET, which means one extra authentication.
  3. **Decrypt.** The keys come from the `Manatee` keychain view, and this recovers them
     itself -- which needs the screen-lock passcode of one of the account's devices.
  4. **Locate.** Ask the Find My network where each accessory was last seen -- with
     `fetch_location`, exactly as `airtag.py` does for an accessory read from a plist.
     What this produces is an ordinary accessory, so nothing new is needed to use one.

**Nothing here writes to the account.** No escrow record is created and no peer joins the
trust circle. Recovering the keys is entirely read-only: a share is wrapped to the
receiving peer's encryption key, and escrow recovery yields exactly that key.

The passcode is read with `getpass`, used inside one call, and not stored, logged or
retained. **No key material is written to disk** -- the keys live in memory for this run
only, which is why this asks each time rather than caching.

The flow itself is :class:`findmy.icloud.AsyncFindMyReader`; what is here is the reporting
around it. Logging is turned up deliberately, because the interesting output is usually a
warning rather than a result: an unmodelled protobuf field, a mismatch between the escrow
proxy and the trust-circle service, or a signature that did not verify.
"""

from __future__ import annotations

import asyncio
import getpass
import logging
import sys

from _login import get_account_async  # pyright: ignore [reportMissingImports]

from findmy.cloudkit.pcs import ShareProtection, bare_x
from findmy.errors import UnhandledProtocolError
from findmy.icloud import AsyncFindMyReader

ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"


async def report_zones(reader: AsyncFindMyReader) -> None:
    """Report the container and its zones, before anything needs a key."""
    info = await reader.store.client.open_container()
    print(f"\nContainer open. CloudKit user {info.user_id}, partition {info.partition}")
    print(f"  database gateway: {info.database_gateway_url}")

    zones = await reader.store.client.zone_retrieve()
    print(f"\n{len(zones)} zone(s):")
    for zone in zones:
        name = zone.target_zone.zone_identifier.value.name or "<unnamed>"
        protected = zone.target_zone.HasField("protection_info")
        print(f"  {name}: {zone.device_count} device(s), protected={protected}")


def report_records(records: list) -> bool:
    """
    Report what came back, and whether it is worth going on.

    Everything here is what decryption depends on and what fetching alone does not prove:
    that a record's fields decoded at all, that they are marked encrypted, and that each
    carries the protection structure decryption starts from.
    """
    print(f"\n{len(records)} record(s) fetched. By type:")
    by_type: dict[str, int] = {}
    for record in records:
        by_type[record.record_type] = by_type.get(record.record_type, 0) + 1
    for record_type, count in sorted(by_type.items()):
        print(f"  {record_type or '<untyped>'}: {count}")

    if not records:
        print("\nNo records came back. If the zone is not empty, the schema's assumed")
        print("field numbers are wrong -- check the WARNING above for which numbers")
        print("actually arrived, and see docs GAPS.md section C.")
        return False

    with_protection = sum(1 for r in records if r.protection_info is not None)
    with_fields = sum(1 for r in records if r.fields)
    print(f"\n{with_protection}/{len(records)} carry protection info")
    print(f"{with_fields}/{len(records)} decoded any fields at all")

    if with_fields == 0:
        print("\nRecords decoded but carry no fields, so Record.recordField (7) or the")
        print("field-identifier wrapper is wrong. Decryption cannot proceed. See GAPS.md C.")
        return False

    sample = next((r for r in records if r.record_type == "MasterBeaconRecord"), records[0])
    print(f"\nFields of one {sample.record_type}:")
    for field_name, value in sorted(sample.fields.items()):
        size = len(value.raw) if value.raw is not None else 0
        print(f"  {field_name:<30} {value.type_name:<22} encrypted={value.is_encrypted} {size}B")

    return True


def report_key_sources(records: list, *, keychain_keys: list, zone_keys: list) -> None:
    """
    Say where the key a record asks for could possibly have come from.

    Kept after the bug it was written for, because the three answers point in different
    directions where a count of failures points nowhere: a key among the *keychain* keys
    means the wrong level was compared, among the zone keys means a broken comparison, and
    in neither means no better reading of either source would have found it.
    """
    named: dict[bytes, set[str]] = {}
    for record in records:
        if not record.protection_info:
            continue
        try:
            protection = ShareProtection.from_der(record.protection_info)
        except Exception:  # noqa: BLE001, S112 -- a probe reporting, not a library deciding
            continue
        for entry in protection.keys:
            named.setdefault(entry.public_key, set()).add(record.record_type or "<untyped>")

    if not named:
        return

    ours = {bare_x(k.public_key()) for k in keychain_keys}
    theirs = {bare_x(k.public_key()) for k in zone_keys}

    print(f"\n{len(records)} record(s) name {len(named)} distinct key(s):")
    for key, types in sorted(named.items()):
        where = "keychain" if key in ours else "zone" if key in theirs else "neither"
        print(f"  {key[:8].hex()} -> {where}   ({', '.join(sorted(types))})")


async def unlock(reader: AsyncFindMyReader) -> bool:
    """
    Recover the keys, asking for a device passcode. Returns whether it worked.

    Read-only from end to end: the shares are wrapped to a key escrow recovery yields, so
    nothing is created, signed or enrolled.
    """
    print("\n--- What this account could be recovered from ---")

    options = await reader.recovery_options()
    for record in options.recoverable:
        print(f"  {record.describe()}")

    stale = len(options.described_but_not_viable) + len(options.viable_but_undescribed)
    if stale:
        print(f"  ({stale} more that cannot be recovered from; see delete_escrow_records.py)")

    if not options.recoverable:
        print("  No record on this account is currently recoverable.")
        if not options.viability_is_trustworthy:
            print("  Nothing was reported viable, which reads as a service having a bad day")
            print("  rather than an account with no usable bottle. Worth trying again later.")
        return False

    print("\nEnter the SERIAL of the record to recover from, or nothing to skip.")
    print("You will need that device's screen-lock passcode.\n")

    typed = input("serial> ").strip()
    if not typed:
        return False

    chosen = next((r for r in options.recoverable if r.serial == typed), None)
    if chosen is None:
        print("No recoverable record has that serial.")
        return False

    passcode = getpass.getpass("passcode (not echoed)> ")
    try:
        keys = await reader.unlock(chosen, passcode)
    finally:
        del passcode  # used inside the call above and wanted no longer

    print(f"\nRecovered {len(keys)} keychain key(s).")
    return True


async def locate(account, accessories: list) -> dict:  # noqa: ANN001
    """
    Locate each accessory in turn, saying whose search is running.

    One at a time rather than in a batch, and only here: `fetch_location` queries a
    rolling-key accessory separately anyway, so this costs nothing and makes the log
    attributable. An accessory with no key-alignment record searches its whole history --
    tens of thousands of indices, several minutes of `Fetched 0 new reports` -- and
    without a name in front of it there is no way to tell which one is doing that.
    """
    located = {}
    for accessory in accessories:
        print(f"  {accessory.name or '<unnamed>'}...", flush=True)
        located[accessory] = await account.fetch_location(accessory)

    return located


def report_accessories(accessories: list, located: dict) -> None:
    """Print what came out, which is the point of all of it."""
    print(f"\n{len(accessories)} accessor{'y' if len(accessories) == 1 else 'ies'}:")
    for accessory in accessories:
        print(f"  {accessory.name or '<unnamed>'} ({accessory.model})")
        print(f"    identifier: {accessory.identifier}")
        print(f"    serial:     {accessory.serial_number}")
        print(f"    paired:     {accessory.paired_at:%Y-%m-%d}")

        location = located.get(accessory)
        print(f"    location:   {location or 'not seen by the network'}")


async def main() -> int:
    """Fetch, recover the keys, and decrypt."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(name)s: %(message)s")
    logging.getLogger("findmy.cloudkit").setLevel(logging.DEBUG)
    logging.getLogger("findmy.keychain").setLevel(logging.DEBUG)

    account = await get_account_async(ACCOUNT_STORE, ANISETTE_SERVER, ANISETTE_LIBS_PATH)

    try:
        async with await AsyncFindMyReader.open(account) as reader:
            await report_zones(reader)

            records = await reader.records()
            if not report_records(records):
                return 1

            if not await unlock(reader):
                print("\nNo keys, so nothing above can be decrypted.")
                return 0

            report_key_sources(
                records,
                keychain_keys=reader.keychain_keys,
                zone_keys=await reader.zone_keys(),
            )

            accessories = await reader.accessories()

            # Nothing special about an accessory that came from iCloud: locating one is
            # `fetch_location`, the same call that locates an accessory read from a plist.
            print("\nAsking the Find My network for their last known locations...")
            report_accessories(accessories, await locate(account, accessories))
    except UnhandledProtocolError as e:
        print(f"\nFailed: {e}")
        return 1
    finally:
        await account.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
