"""
Telling "Apple declined" apart from "Apple said something we cannot read".

Both used to arrive as ``UnhandledProtocolError``, whose own docstring tells the reader to
report it. A 503 from Grand Slam is not a bug and there is nothing to report: the server
declined to serve, and the answer is to wait.

Reported twice against OpenTagViewer, and the second report is the useful one. One account
met a 503 at ``td_2fa_submit``, again at ``request_pet`` one second later, and again at
``login`` a minute after that -- three call sites, one bad minute at ``gsa.apple.com``.
"""

from __future__ import annotations

import pytest

from findmy.errors import (
    AppleServiceUnavailableError,
    UnhandledProtocolError,
    is_service_unavailable,
)


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504, 599])
def test_a_status_meaning_not_now_is_recognised(status: int) -> None:
    """Server errors and rate limiting are worth waiting out."""
    assert is_service_unavailable(status)


@pytest.mark.parametrize("status", [200, 201, 400, 401, 403, 404, 409, 422])
def test_a_status_meaning_you_are_wrong_is_not(status: int) -> None:
    """Retrying an unchanged request against these gets the same answer forever."""
    assert not is_service_unavailable(status)


def test_401_is_not_treated_as_weather() -> None:
    """
    The distinction that decides whether somebody is asked to sign in again.

    A 401 is permanent until the user does something. Waiting it out silently is the
    failure mode this whole classification exists to avoid, in the opposite direction.
    """
    assert not is_service_unavailable(401)


def test_it_is_catchable_as_the_error_callers_already_catch() -> None:
    """
    Subclassing is what makes this a safe upgrade.

    Every existing ``except UnhandledProtocolError`` keeps working; a caller that wants the
    distinction catches the subclass first.
    """
    error = AppleServiceUnavailableError(503, "The Grand Slam request")

    assert isinstance(error, UnhandledProtocolError)
    assert isinstance(error, RuntimeError)


def test_it_carries_the_status_so_a_caller_need_not_parse_the_message() -> None:
    """Reading the number back out of the text is what applications were reduced to."""
    error = AppleServiceUnavailableError(503, "The Grand Slam request")

    assert error.status_code == 503
    assert error.what == "The Grand Slam request"


def test_the_message_says_whose_fault_it_is_and_what_to_do() -> None:
    """A person reading this in a log should not go looking for their own mistake."""
    message = str(AppleServiceUnavailableError(503, "The Grand Slam request"))

    assert "503" in message
    assert "The Grand Slam request" in message
    assert "try again" in message


def test_the_gsa_and_two_factor_paths_both_classify() -> None:
    """
    Both sign-in requests, because the reported failure hit more than one.

    Asserted on the source rather than by driving a login, which needs an account. The
    point is that neither site raises the bare error for a 5xx any more.
    """
    import inspect

    from findmy.reports.account import AsyncAppleAccount

    for method in (AsyncAppleAccount._gsa_request, AsyncAppleAccount._sms_2fa_request):  # noqa: SLF001
        source = inspect.getsource(method)

        assert "is_service_unavailable" in source, f"{method.__name__} does not classify"
        assert "AppleServiceUnavailableError" in source, f"{method.__name__} does not raise it"
