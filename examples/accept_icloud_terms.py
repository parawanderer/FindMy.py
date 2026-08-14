"""
Show the iCloud terms of service and let you accept them, if you decide to.

**Run this only if logging in failed with something about terms.** It is not part of
signing in, and nothing else here calls it: agreeing to a contract is a thing you do
deliberately, not a step something else takes on your behalf while you watch.

    cd examples && python3 accept_icloud_terms.py

Stage 2 §5.2. An account with unaccepted iCloud terms fails the delegate exchange that
signing in ends with, and Apple offers exactly two places to accept: one of its own
devices, or iCloud.com. Someone using this project generally has neither, which is what
this exists for.

What it does, in order:

  1. Signs in, which is expected to fail at the delegate exchange.
  2. Prints what Apple said about why, verbatim. **Which value means "terms pending" is
     not established**, so nothing here decides that for you -- if the message is about
     something else, stop and say so rather than continuing.
  3. Fetches the terms and prints them in full.
  4. Asks. Nothing is sent unless you type ACCEPT, and only then for the document you
     were just shown. Stopping here leaves the account exactly as it was.
  5. Repeats the delegate exchange, which should now succeed, and saves the session.

The terms are printed as text rather than rendered, so they are long. That is the point;
they are what you would be agreeing to.
"""

from __future__ import annotations

import asyncio
import sys

import bs4
from _login import _login_async  # pyright: ignore [reportMissingImports]

from findmy import (
    AsyncAppleAccount,
    LocalAnisetteProvider,
    LoginState,
    MobileMeDelegateError,
    RemoteAnisetteProvider,
    Terms,
    TermsError,
)

ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"


def show(terms: Terms) -> None:
    """Print one terms document in full, as text."""
    text = bs4.BeautifulSoup(terms.html, features="html.parser").get_text("\n", strip=True)

    print(f"\n{'=' * 78}")
    print(f"  {terms.page_id} terms of service")
    print(f"{'=' * 78}\n")
    print(text)
    print(f"\n{'=' * 78}")
    print(f"  end of the {terms.page_id} terms")
    print(f"{'=' * 78}\n")


def agreed(terms: Terms) -> bool:
    """Ask, and take anything other than ACCEPT as no."""
    print(f"Agreeing records acceptance of the {terms.page_id} terms on your Apple account.")
    print("Nothing has been sent yet, and typing anything else leaves it unaccepted.\n")

    return input("Type ACCEPT to agree> ").strip() == "ACCEPT"


async def main() -> int:
    """Sign in, and offer the terms if that is what stopped it."""
    anisette = (
        LocalAnisetteProvider(libs_path=ANISETTE_LIBS_PATH)
        if ANISETTE_SERVER is None
        else RemoteAnisetteProvider(ANISETTE_SERVER)
    )
    account = AsyncAppleAccount(anisette)

    try:
        try:
            await _login_async(account)
        except MobileMeDelegateError as e:
            print(f"\nSigning in failed, and Apple said:\n\n  {e}\n")
        else:
            print("\nSigning in worked, so there are no terms in the way. Nothing to do.")
            account.to_json(ACCOUNT_STORE)
            return 0

        print("If that is not about terms of service, stop here -- accepting terms will")
        print("not fix it, and which error value means terms are pending is not known.\n")

        if input("Fetch the terms of service? [y/N] > ").strip().lower() not in ("y", "yes"):
            return 1

        terms = await account.fetch_terms()
        print(f"\n{len(terms)} document(s) to read.")

        for document in terms:
            show(document)
            if not agreed(document):
                print("\nNot accepted. Nothing was sent, and your account is unchanged.")
                return 1

            await account.accept_terms(document)
            print(f"\nAccepted: {document.page_id}")

        state = await account.complete_login()
        if state != LoginState.LOGGED_IN:
            print(f"\nThe terms were accepted, but signing in ended at {state}.")
            return 1

        account.to_json(ACCOUNT_STORE)
    except TermsError as e:
        print(f"\nFailed: {e}")
        return 1
    finally:
        await account.close()

    print(f"\nSigned in, and the session is saved to {ACCOUNT_STORE}.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
