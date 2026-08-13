"""Tests for issuing a fresh PET from a logged-in account."""

from __future__ import annotations

import pytest

from findmy.errors import InvalidStateError, UnauthorizedError
from findmy.reports.account import AsyncAppleAccount
from findmy.reports.state import LoginState


class FakeAnisette:
    def to_json(self, dst=None):  # noqa: ANN001, ANN201, ARG002
        return {}

    async def close(self) -> None:
        return


def logged_in_account() -> AsyncAppleAccount:
    account = AsyncAppleAccount(FakeAnisette())  # pyright: ignore [reportArgumentType]
    account._username = "someone@example.com"  # noqa: SLF001
    account._password = "hunter2"  # noqa: SLF001
    account._set_login_state(  # noqa: SLF001
        LoginState.LOGGED_IN,
        {"dsid": "123", "mobileme_data": {"tokens": {"cloudKitToken": "ck"}}},
    )
    account._account_info = {  # noqa: SLF001
        "account_name": "someone@example.com",
        "first_name": "A",
        "last_name": "B",
        "trusted_device_2fa": False,
    }
    return account


@pytest.mark.asyncio
async def test_a_pet_is_returned_and_the_session_survives() -> None:
    # Logging in spends the PET, so this re-authenticates -- but the account must be as
    # usable afterwards as it was before, or every caller has to log in again.
    account = logged_in_account()

    async def fake_auth() -> LoginState:
        account._set_login_state(  # noqa: SLF001
            LoginState.AUTHENTICATED,
            {"idms_pet": "fresh-pet", "adsid": "456"},
        )
        return LoginState.AUTHENTICATED

    account._gsa_authenticate = fake_auth  # noqa: SLF001

    assert await account.request_pet() == "fresh-pet"

    assert account.login_state == LoginState.LOGGED_IN
    assert account.dsid == "123"
    assert account.service_tokens["cloudKitToken"] == "ck"
    assert account.account_name == "someone@example.com"


@pytest.mark.asyncio
async def test_the_session_survives_even_when_re_authentication_fails() -> None:
    account = logged_in_account()

    async def failing_auth() -> LoginState:
        account._set_login_state(LoginState.REQUIRE_2FA, {"adsid": "456"})  # noqa: SLF001
        return LoginState.REQUIRE_2FA

    account._gsa_authenticate = failing_auth  # noqa: SLF001

    with pytest.raises(UnauthorizedError, match="AUTHENTICATED"):
        await account.request_pet()

    assert account.login_state == LoginState.LOGGED_IN
    assert account.dsid == "123"


@pytest.mark.asyncio
async def test_a_pet_cannot_be_requested_before_logging_in() -> None:
    account = AsyncAppleAccount(FakeAnisette())  # pyright: ignore [reportArgumentType]

    with pytest.raises(InvalidStateError):
        await account.request_pet()
