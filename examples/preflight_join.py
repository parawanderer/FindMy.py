"""
Check everything a join depends on, **without writing anything**.

    cd examples && python3 preflight_join.py

**This script creates nothing, changes nothing, and never asks for a passcode.** It runs
entirely off an existing `account.json` and read-only calls, so it costs nothing to run
twice, or ten times, or to get wrong. `join_circle.py` is the one that writes.

Run it first. The thing it settles cannot be settled any other way:

**The peer identifier derivation.** A join names its beneficiary by an identifier this
client derives for an identity that does not exist yet -- so nothing inside a join can
check it, and a wrong derivation produces a voucher for a peer that is not there. That
failure lands *after* `joinWithVoucher`, which is the one call in this project that cannot
be taken back. But every peer already in the circle was named by the same rule, so
recomputing theirs and comparing settles it in advance, for free.

A match is decisive rather than suggestive. The oracle is an exact SHA-256 digest, and
digests are not reproduced by accident -- so thirteen matches out of thirteen is not
thirteen coincidences, it is the construction being right.

It also reports what the account already holds, so that what a join adds is visible against
what was there, and fetches the escrow club certificate to prove the pinned roots verify it
*before* a join is the thing that finds out otherwise.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from _login import get_account_async  # pyright: ignore [reportMissingImports]

from findmy.errors import UnhandledProtocolError
from findmy.keychain import AsyncKeychainSession
from findmy.keychain.escrow import ESCROW_LABEL_ICDP
from findmy.keychain.join import check_peer_signatures
from findmy.keychain.peers import check_peer_identifiers

ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"


async def main() -> int:  # noqa: PLR0915 -- a report, and it reads as one
    """Report on everything a join would rely on, writing nothing."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)-8s %(message)s")
    # The club certificate's reply is logged at DEBUG by the escrow proxy, and its shape is
    # the open question: if it carries the issuing chain, the four roots this library
    # bundles could be fetched and fingerprint-checked instead.
    logging.getLogger("findmy.keychain").setLevel(logging.DEBUG)

    account = await get_account_async(ACCOUNT_STORE, ANISETTE_SERVER, ANISETTE_LIBS_PATH)

    print("Nothing in this script writes to the account.\n")

    try:
        async with await AsyncKeychainSession.open(account) as session:
            # ------------------------------------------------------------------
            print("--- The trust circle ---")
            directory = await session.peer_directory(refresh=True)
            print(f"  {len(directory)} peer(s)")
            if directory.sync_token:
                print(f"  sync token held: {directory.sync_token[:24]}…")

            check = check_peer_identifiers(directory)
            checkable = len(check.matched) + len(check.mismatched)
            print(f"\n  Identifier derivation: {len(check.matched)}/{checkable} reproduced")
            if check.uncheckable:
                print(f"  {len(check.uncheckable)} peer(s) carried nothing to check against")

            for peer_hash in check.mismatched[:3]:
                print(f"    reported {peer_hash}")
                print(f"    derived  {directory.peers[peer_hash].derived_hash}")

            # The second oracle, and the only one that reaches the signing rule. Every
            # other test of it signs and verifies with the same code, so a wrong type
            # prefix or digest would agree with itself; a blob Apple's own device signed
            # cannot.
            signatures = check_peer_signatures(directory)
            print(f"  Signatures verified:   {signatures.describe()}")
            print(f"  Signing keys as DER SPKI: {signatures.der_spki_keys}")

            # ------------------------------------------------------------------
            print("\n--- What the account already holds ---")
            options = await session.recovery_options()
            print(f"  {options.describe()}")
            print(f"  {options.device_count} device(s) by serial\n")

            for record in options.recoverable:
                print(f"  recoverable: {record.describe()}")
            for record in options.described_but_not_viable:
                print(f"  residue:     {record.describe()}")

            # ------------------------------------------------------------------
            print("\n--- The escrow club certificate ---")
            certificate = await session.club_certificate()
            print(f"  issuer:  {certificate.issuer.rfc4514_string()}")
            print(f"  expires: {certificate.not_valid_after_utc:%Y-%m-%d}")
            print("  It verified against the roots bundled with this library, so the")
            print("  pinning works on this account. See the DEBUG line above for what")
            print("  else the reply carried.")

            # ------------------------------------------------------------------
            print("\n--- What a join would create ---")
            print("  1 peer in the trust circle above")
            print("  1 bottle, sealed under a passcode you choose")
            print(f"  1 escrow record, labelled {ESCROW_LABEL_ICDP}.SHA256:<new peer id>")
            print("\n  All three are permanent. The record can be deleted afterwards with")
            print("  delete_escrow_records.py; the peer stays until something removes it.")
            print("  The peer id is minted during the join, so the exact label is not")
            print("  knowable until then -- join_circle.py prints the one it used.")
    except UnhandledProtocolError as e:
        print(f"\nFailed: {e}")
        return 1
    finally:
        await account.close()

    # ----------------------------------------------------------------------
    print("\n--- Verdict ---")
    if check.mismatched:
        print("  The identifier derivation does NOT reproduce this circle's peers. Do")
        print("  not join: the voucher would name a beneficiary that does not exist,")
        print("  and that failure only surfaces after the join has been sent.")
        return 1

    if signatures.failed or signatures.vouchers_failed:
        print("  Blobs that Apple's own devices signed do not verify under this")
        print("  client's reading of the signing rule. Do not join: the blobs it")
        print("  sends would be rejected, or admitted and wrong.")
        return 1

    if not check.confirmed:
        print("  No peer carried anything to check the derivation against, so this run")
        print("  neither confirms nor denies it. Joining would be a guess.")
        return 1

    print("  Two things are ruled out, and they are the two that could not be checked")
    print("  any other way:")
    print("    the identifier derivation, against identifiers Apple produced;")
    print("    the signing construction, against signatures Apple's devices made.")
    print()
    print("  **That is not the same as a join being safe.** Everything this client")
    print("  will put in its own blobs is checked only against itself: the permanent")
    print("  info's epoch and key encoding, its machine id and millisecond timestamp,")
    print("  the stable info's policy constants, the trust merge, the shares and the")
    print("  bottle. A join remains an irreversible call with parts nothing local can")
    print("  validate -- two fewer than before, and the two nothing else could reach.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
