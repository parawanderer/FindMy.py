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


def test_the_client_serial_reaches_the_header_that_names_it_in_the_device_list() -> None:
    # `X-Apple-I-SRL-NO` is what the account's device list shows as the serial, and the
    # entry is otherwise indistinguishable from a real Mac -- the model and OS strings
    # claim to be one. A recognisable serial is the difference between a device somebody
    # can identify as software they installed and one they are invited to remove.
    import asyncio  # noqa: PLC0415

    from findmy.reports.anisette import CLIENT_SERIAL, BaseAnisetteProvider  # noqa: PLC0415

    class Provider(BaseAnisetteProvider):
        @property
        def otp(self) -> str:
            return "otp"

        @property
        def machine(self) -> str:
            return "machine"

        async def close(self) -> None:
            return

        def to_json(self, dst=None):  # noqa: ANN001, ANN202, ARG002
            return {}

        @classmethod
        def from_json(cls, val):  # noqa: ANN001, ANN206, ARG003
            raise NotImplementedError

    headers = asyncio.run(Provider().get_headers("user", "device"))

    assert headers["X-Apple-I-SRL-NO"] == CLIENT_SERIAL
    assert CLIENT_SERIAL == "0FINDMYPY001"
    # Deliberately not mistakable for hardware.
    assert not CLIENT_SERIAL.isalnum() or CLIENT_SERIAL.startswith("0FINDMYPY")


def _a_provider():
    """A provider that answers headers without reaching anything."""
    from findmy.reports.anisette import BaseAnisetteProvider  # noqa: PLC0415

    class Provider(BaseAnisetteProvider):
        @property
        def otp(self) -> str:
            return "otp"

        @property
        def machine(self) -> str:
            return "machine"

        async def close(self) -> None:
            return

        def to_json(self, dst=None):  # noqa: ANN001, ANN202, ARG002
            return {"type": "aniRemote", "url": "https://a/"}

        @classmethod
        def from_json(cls, val):  # noqa: ANN001, ANN206, ARG003
            raise NotImplementedError

    return Provider()


def test_the_announce_never_carries_a_push_token() -> None:
    """Test that no push token can reach the device announce, by any route."""
    # The absence is the feature. A registered device carrying one is the most likely way
    # it becomes trusted for verification codes, and a library whose consumers became
    # second factors for their users' Apple IDs would be doing real harm. So this checks
    # the shape of the call rather than one code path: no parameter, and no mention.
    import inspect  # noqa: PLC0415

    from findmy.reports.account import AsyncAppleAccount  # noqa: PLC0415

    source = inspect.getsource(AsyncAppleAccount.announce_device)

    assert "ptkn" not in source.replace("`ptkn`", "")
    assert inspect.signature(AsyncAppleAccount.announce_device).parameters.keys() == {"self"}


def test_announcing_without_a_name_says_which_one_is_missing() -> None:
    """Test that an account with no device name refuses rather than sending a blank."""
    import asyncio  # noqa: PLC0415

    from findmy.errors import InvalidStateError  # noqa: PLC0415
    from findmy.reports.account import AsyncAppleAccount, LoginState  # noqa: PLC0415

    account = AsyncAppleAccount(_a_provider())
    account._login_state = LoginState.LOGGED_IN  # noqa: SLF001
    account._login_state_data = {"adsid": "a", "idms_hb": "h"}  # noqa: SLF001

    with pytest.raises(InvalidStateError, match="no device name"):
        asyncio.run(account.announce_device())


def test_a_restored_account_without_a_heartbeat_token_says_so() -> None:
    """Test that a file written before the token was kept explains itself."""
    import asyncio  # noqa: PLC0415

    from findmy.errors import InvalidStateError  # noqa: PLC0415
    from findmy.reports.account import AsyncAppleAccount, LoginState  # noqa: PLC0415

    account = AsyncAppleAccount(_a_provider(), device_name="OpenTagViewer App")
    account._login_state = LoginState.LOGGED_IN  # noqa: SLF001
    account._login_state_data = {"adsid": "a"}  # noqa: SLF001

    with pytest.raises(InvalidStateError, match="heartbeat token"):
        asyncio.run(account.announce_device())


def test_the_device_name_survives_being_saved_and_reloaded() -> None:
    """Test that the name is part of the account's persisted identity."""
    from findmy.reports.account import AsyncAppleAccount  # noqa: PLC0415

    account = AsyncAppleAccount(_a_provider(), device_name="OpenTagViewer App")
    state = account.to_json()

    assert state["account"]["device_name"] == "OpenTagViewer App"
    assert AsyncAppleAccount(_a_provider(), state_info=state).device_name == "OpenTagViewer App"


def test_an_account_without_a_name_writes_none() -> None:
    """Test that existing files are unchanged by this addition."""
    from findmy.reports.account import AsyncAppleAccount  # noqa: PLC0415

    account = AsyncAppleAccount(_a_provider())

    assert account.device_name is None
    assert "device_name" not in account.to_json()["account"]


def test_the_three_identity_strings_describe_one_release() -> None:
    """Test that the client info and its user agent cannot contradict each other."""
    # Stage 1 §2.2: the OS version, build, CFNetwork version and Darwin version describe
    # one real release, and Apple's own clients never disagree with themselves. Composed
    # from shared parts rather than transcribed, so this asserts the composition.
    from findmy.reports.anisette import (  # noqa: PLC0415
        CLIENT_CFNETWORK,
        CLIENT_DARWIN,
        CLIENT_MODEL,
        CLIENT_OS_BUILD,
        CLIENT_OS_VERSION,
    )

    provider = _a_provider()
    platform = f"<{CLIENT_MODEL}> <Mac OS X;{CLIENT_OS_VERSION};{CLIENT_OS_BUILD}>"

    assert provider.client.startswith(platform)
    assert provider.client_akd.startswith(platform)
    assert provider.akd_user_agent == f"akd/1.0 CFNetwork/{CLIENT_CFNETWORK} Darwin/{CLIENT_DARWIN}"


def test_the_akd_variant_says_akd_is_speaking() -> None:
    """Test that the akd client info names the right daemon."""
    # The trailing bundle is what tells a Grand Slam endpoint which daemon is speaking.
    provider = _a_provider()

    assert provider.client_akd.endswith("<com.apple.AuthKit/1 (com.apple.akd/1.0)>")
    assert "Xcode" not in provider.client_akd
    # And the existing identity is untouched: changing it invalidates every session.
    assert provider.client.endswith("<com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>")


def test_the_announce_sends_the_akd_pair_and_not_the_xcode_one() -> None:
    """Test that the announce's two identity headers are the akd variants."""
    import inspect  # noqa: PLC0415

    from findmy.reports.account import AsyncAppleAccount  # noqa: PLC0415

    source = inspect.getsource(AsyncAppleAccount.announce_device)

    assert "self._anisette.client_akd" in source
    assert "self._anisette.akd_user_agent" in source
    assert '"X-MMe-Client-Info": self._anisette.client,' not in source


class _Refusal:
    """A rejected response, standing in for whatever Grand Slam sends back."""

    def __init__(self, status: int, content: bytes, headers: dict | None = None) -> None:
        self.status_code = status
        self._content = content
        self.headers = headers or {}

    @property
    def ok(self) -> bool:
        return False

    @property
    def content(self) -> bytes:
        return self._content

    def text(self) -> str:
        return self._content.decode("utf-8", errors="replace")

    def plist(self) -> dict:
        import plistlib  # noqa: PLC0415

        return plistlib.loads(self._content)


def test_a_refused_announce_reports_the_status_grand_slam_gave() -> None:
    """Test that the nested error code and message reach the exception."""
    import plistlib  # noqa: PLC0415

    from findmy.reports.account import _describe_announce_failure  # noqa: PLC0415

    body = plistlib.dumps({"Response": {"Status": {"ec": -20101, "em": "Bad token"}}})
    described = _describe_announce_failure(_Refusal(401, body))

    assert "HTTP 401" in described
    assert "-20101" in described
    assert "Bad token" in described


def test_a_refusal_that_is_not_a_plist_still_reports_what_arrived() -> None:
    """Test that an HTML error page is not swallowed."""
    from findmy.reports.account import _describe_announce_failure  # noqa: PLC0415

    described = _describe_announce_failure(_Refusal(401, b"<html>go away</html>"))

    assert "go away" in described


def test_a_refusal_with_an_empty_body_reports_its_headers() -> None:
    """Test that a bodiless 401 still says whatever the headers said."""
    # This is the case the change exists for: a status code alone reports that something
    # was refused and nothing about why, which costs a whole run to find out.
    from findmy.reports.account import _describe_announce_failure  # noqa: PLC0415

    described = _describe_announce_failure(
        _Refusal(401, b"", {"WWW-Authenticate": 'X-Apple-HB realm="gsa"'}),
    )

    assert "empty body" in described
    assert "X-Apple-HB" in described
