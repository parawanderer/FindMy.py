"""
Read Find My accessories straight out of an iCloud account, with no Mac involved.

The read-only probe for this whole flow. Run it against a real account to exercise
everything that can be exercised without writing anything to that account.

    cd examples && python3 fetch_beacons_from_icloud.py

Three parts, in increasing order of what they need:

  1. **Fetch** the accessory records. Needs only a logged-in account.
  2. **Ask what the account could be recovered from** -- the escrow records Apple shows
     nowhere in its own interfaces, joined against the bottles the trust-circle service
     considers usable. Needs a fresh PET, which means one extra authentication.
  3. **Decrypt.** The keys come from the `Manatee` keychain view, and this recovers them
     itself -- one call, `session.recover_service_keys`, which needs the screen-lock
     passcode of one of the account's devices. Set MANATEE_KEYS_PATH to a file of PEM keys
     to skip that and use those instead.

**Nothing here writes to the account.** No escrow record is created and no peer joins the
trust circle. Recovering the keys is entirely read-only: a share is wrapped to the
receiving peer's encryption key, and escrow recovery yields exactly that key.

The passcode is read with `getpass`, used inside one call, and not stored, logged or
retained. **No key material is written to disk** -- the keys live in memory for this run
only, which is why this asks each time rather than caching.

Logging is turned up deliberately, because the interesting output is usually a warning
rather than a result: an unmodelled protobuf field, a mismatch between the escrow proxy
and the trust-circle service, or a signature that did not verify.
"""

from __future__ import annotations

import asyncio
import getpass
import logging
import os
import sys
from pathlib import Path

from _login import get_account_async  # pyright: ignore [reportMissingImports]
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from findmy.cloudkit import AsyncBeaconStore, MissingKeyError, decrypt_records
from findmy.cloudkit.beacons import accessories_from_records
from findmy.cloudkit.pcs import PCSError
from findmy.errors import UnhandledProtocolError
from findmy.keychain import AsyncKeychainSession

# None uses the built-in Anisette generator, which is what this project recommends.
# If you change this, remove the account store first: a session is bound to the machine
# identity that established it, and a different Anisette source is a different machine.
ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"

MANATEE_KEYS_PATH = os.environ.get("MANATEE_KEYS_PATH")


def load_keys() -> list[ec.EllipticCurvePrivateKey]:
    """Load PEM private keys, one per key, concatenated in a single file."""
    if not MANATEE_KEYS_PATH:
        return []

    blob = Path(MANATEE_KEYS_PATH).read_bytes()
    keys: list[ec.EllipticCurvePrivateKey] = []

    marker = b"-----END"
    start = 0
    while (end := blob.find(marker, start)) != -1:
        end = blob.find(b"\n", end) + 1
        key = load_pem_private_key(blob[start:end], password=None)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            keys.append(key)
        start = end

    return keys


async def recover_keys(session: AsyncKeychainSession) -> list[ec.EllipticCurvePrivateKey]:
    """
    Recover the `Manatee` service keys, asking for a device passcode.

    Read-only from end to end: the shares are wrapped to a key escrow recovery yields, so
    nothing is created, signed or enrolled. See `recover_escrow_material.py` for the same
    flow reported step by step.
    """
    options = await session.recovery_options()
    if not options.recoverable:
        print("No record on this account is currently recoverable.")
        return []

    print("\nEnter the SERIAL of the record to recover from, or nothing to skip.")
    print("You will need that device's screen-lock passcode.\n")

    typed = input("serial> ").strip()
    if not typed:
        return []

    chosen = next((r for r in options.recoverable if r.serial == typed), None)
    if chosen is None:
        print("No recoverable record has that serial.")
        return []

    passcode = getpass.getpass("passcode (not echoed)> ")
    try:
        peer = await session.recover(chosen, passcode)
    finally:
        del passcode  # used inside the call above and wanted no longer

    # Every key the view holds, not just the one the pointer names. A record's protection
    # structure names whichever key protected it, which may be an older one -- and §6.8
    # resolves such a reference by matching an item's `acct`, so the whole view is the
    # lookup rather than one pointer.
    return await session.pcs_keys(peer)


async def report_recovery_options(session: AsyncKeychainSession) -> None:
    """
    Report what this account could be recovered from, if anything.

    Two services have to be asked and neither alone answers the question: the escrow proxy
    holds the human-readable metadata, and the trust-circle service knows which bottles
    are actually usable. Both are read-only.

    Only the recoverable ones are listed. This probe's use for a record is the keys it
    yields, and one that cannot be recovered from yields none -- the rest are counted so
    that an account quietly accumulating them still says so. `delete_escrow_records.py`
    lists them in full, because there they are the subject rather than the preamble.
    """
    print("\n--- What this account could be recovered from ---")

    options = await session.recovery_options()

    for record in options.recoverable:
        print(f"  {record.describe()}")

    # The rest cannot yield keys, and this probe's only use for a record is its keys. They
    # are worth a count rather than a list: an account accumulates them invisibly -- Apple
    # exposes them in no interface -- so their number is the interesting part, and
    # delete_escrow_records.py is where anything is done about it.
    stale = len(options.described_but_not_viable) + len(options.viable_but_undescribed)
    if stale:
        print(f"  ({stale} more that cannot be recovered from; see delete_escrow_records.py)")

    if not options.viability_is_trustworthy:
        print("  Nothing was reported viable, which reads as a service having a bad day")
        print("  rather than an account with no usable bottle. Worth trying again later.")


async def keys_to_decrypt_with(account) -> list[ec.EllipticCurvePrivateKey]:  # noqa: ANN001
    """
    Obtain the keys, from a file if one was supplied and by recovery otherwise.

    One session for both the report and the recovery. Opening two would cost a second
    container open and a second authentication for the same answers, and the listing the
    report already fetched is cached on the session for the recovery to reuse.
    """
    supplied = load_keys()

    try:
        async with await AsyncKeychainSession.open(account) as session:
            await report_recovery_options(session)

            if supplied:
                print(f"\nUsing {len(supplied)} key(s) from MANATEE_KEYS_PATH.")
                return supplied

            print("\n--- Recovering the keys to decrypt with ---")
            return await recover_keys(session)
    except UnhandledProtocolError as e:
        print(f"\nCould not obtain keys: {e}")
        return supplied


async def main() -> int:  # noqa: C901, PLR0912, PLR0915 -- a probe; linear reads better
    """Fetch, and decrypt if keys were supplied."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(name)s: %(message)s")
    logging.getLogger("findmy.cloudkit").setLevel(logging.DEBUG)

    account = await get_account_async(ACCOUNT_STORE, ANISETTE_SERVER, ANISETTE_LIBS_PATH)

    store = AsyncBeaconStore(account)
    try:
        info = await store.client.open_container()
        print(f"\nContainer open. CloudKit user {info.user_id}, partition {info.partition}")
        print(f"  database gateway: {info.database_gateway_url}")

        zones = await store.client.zone_retrieve()
        print(f"\n{len(zones)} zone(s):")
        for zone in zones:
            name = zone.target_zone.zone_identifier.value.name or "<unnamed>"
            protected = zone.target_zone.HasField("protection_info")
            print(f"  {name}: {zone.device_count} device(s), protected={protected}")

        records = await store.fetch_records()
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
            return 1

        # Everything below is what Stage 5 depends on and what fetching alone does not
        # prove: that a record's fields decoded at all, that they are marked encrypted,
        # and that each carries the protection structure decryption starts from.
        with_protection = sum(1 for r in records if r.protection_info is not None)
        with_fields = sum(1 for r in records if r.fields)
        print(f"\n{with_protection}/{len(records)} carry protection info")
        print(f"{with_fields}/{len(records)} decoded any fields at all")

        if with_fields == 0:
            print("\nRecords decoded but carry no fields, so Record.recordField (7) or the")
            print("field-identifier wrapper is wrong. Stage 5 cannot proceed. See GAPS.md C.")
            return 1

        sample = next((r for r in records if r.record_type == "MasterBeaconRecord"), records[0])
        print(f"\nFields of one {sample.record_type}:")
        for field_name, value in sorted(sample.fields.items()):
            size = len(value.raw) if value.raw is not None else 0
            print(
                f"  {field_name:<30} {value.type_name:<22} encrypted={value.is_encrypted} {size}B",
            )

        keys = await keys_to_decrypt_with(account)
        if not keys:
            print("\nNo keys, so nothing above can be decrypted. Set MANATEE_KEYS_PATH to")
            print("a file of PEM private keys to supply them another way.")
            return 0

        # Two unwraps, not one. The keychain service keys open the *zone*; the zone
        # yields the keys a record's keyset actually names. Going straight from the
        # keychain to a record finds nothing, and says the record belongs to someone else.
        print(f"\nUnwrapping the zone with {len(keys)} keychain key(s)...")
        try:
            record_keys = await store.zone_keys(keys)
        except PCSError as e:
            print(f"The zone did not unwrap: {e}")
            return 1

        print(f"The zone yields {len(record_keys)} key(s). Decrypting records...")
        try:
            decrypted = decrypt_records(records, record_keys)
        except MissingKeyError:
            print("None of the zone's keys protects any of these records.")
            return 1

        for record in decrypted:
            if record.undecryptable:
                print(f"  {record.name}: {len(record.undecryptable)} field(s) unreadable")

        accessories = accessories_from_records(decrypted)
        print(f"\n{len(accessories)} accessor{'y' if len(accessories) == 1 else 'ies'}:")
        for accessory in accessories:
            print(f"  {accessory.name or '<unnamed>'} ({accessory.model})")
            print(f"    identifier: {accessory.identifier}")
            print(f"    serial:     {accessory.serial_number}")
            print(f"    paired:     {accessory.paired_at:%Y-%m-%d}")

    finally:
        await store.close()
        await account.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
