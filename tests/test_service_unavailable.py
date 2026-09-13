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

import logging
from datetime import datetime, timezone

import pytest

from findmy.errors import (
    AppleServiceUnavailableError,
    UnhandledProtocolError,
    is_service_unavailable,
    parse_retry_after,
)
from findmy.reports.account import _refused
from findmy.util.http import HttpResponse


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
    assert "trying again" in message


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
        assert "_refused(" in source, f"{method.__name__} does not raise it"


# --- Retry-After ------------------------------------------------------------------------------
#
# **No GSA refusal observed so far has carried this header**, so these tests are about
# behaving correctly either way rather than about a value Apple is known to send. Absent is the
# common case and must not be mistaken for "retry now".

NOW = datetime(2026, 9, 13, 20, 0, 0, tzinfo=timezone.utc)


def test_a_wait_in_seconds_is_read() -> None:
    """The integer form."""
    assert parse_retry_after({"Retry-After": "120"}) == 120.0


def test_a_wait_as_an_http_date_is_measured_from_now() -> None:
    """The date form, as seconds from now."""
    assert parse_retry_after({"Retry-After": "Sun, 13 Sep 2026 20:05:00 GMT"}, NOW) == 300.0


def test_a_date_already_past_means_now_rather_than_a_negative_wait() -> None:
    """A date in the past is a valid answer, meaning "now"."""
    assert parse_retry_after({"Retry-After": "Sun, 13 Sep 2026 19:00:00 GMT"}, NOW) == 0.0


def test_the_header_is_found_whatever_its_case() -> None:
    """
    HTTP/2 sends header names in lowercase, and responses arrive here as a plain dict.

    A lookup of ``"Retry-After"`` alone would miss it on exactly the connections Apple is most
    likely to use - and miss it silently, since absent is a legitimate answer.
    """
    assert parse_retry_after({"retry-after": "30"}) == 30.0
    assert parse_retry_after({"RETRY-AFTER": "30"}) == 30.0


@pytest.mark.parametrize("headers", [None, {}, {"Content-Type": "text/html"}])
def test_no_header_is_no_wait_rather_than_a_guess(headers: dict[str, str] | None) -> None:
    """Absent is the common case, and means unknown rather than zero."""
    assert parse_retry_after(headers) is None


@pytest.mark.parametrize("value", ["soon", "-5", "1.5", "", "   ", "Not a date, 99 Foo 2026"])
def test_an_unreadable_value_is_no_wait_rather_than_a_guess(value: str) -> None:
    """
    A wrong wait is worse than none.

    Too short and the retry is refused again; too long and a person waits for nothing.
    """
    assert parse_retry_after({"Retry-After": value}) is None


def test_the_error_carries_the_wait_when_apple_gave_one() -> None:
    """Both as a number for a caller and in the message for a person."""
    error = AppleServiceUnavailableError(429, "The Grand Slam request", retry_after=90.0)

    assert error.retry_after == 90.0
    assert "2 minutes" in str(error), "rounded up - never tell somebody to retry too early"


def test_the_error_says_nothing_about_a_wait_it_was_not_given() -> None:
    """No invented number."""
    error = AppleServiceUnavailableError(429, "The Grand Slam request")

    assert error.retry_after is None
    assert "asked for" not in str(error)


def test_the_message_no_longer_promises_it_clears_on_its_own() -> None:
    """
    It used to, and for the 503s of September 2026 it was wrong.

    Those were Apple refusing the Xcode client identifier, and every retry met the same answer
    until the client changed.
    """
    assert "usually clears" not in str(AppleServiceUnavailableError(503, "The Grand Slam request"))


# --- what a refusal records -------------------------------------------------------------------


def _response(status: int, headers: dict[str, str]) -> HttpResponse:
    return HttpResponse(status, b"<html>refused</html>", headers)


def test_a_refusal_carries_the_wait_from_the_response() -> None:
    """What a caller reads off the error is what the response said."""
    error = _refused(_response(429, {"retry-after": "45"}), {}, "The Grand Slam request")

    assert error.status_code == 429
    assert error.retry_after == 45.0


def test_a_refusal_without_the_header_carries_none() -> None:
    """The case every refusal observed so far has been."""
    error = _refused(_response(429, {"Server": "Apple"}), {}, "The Grand Slam request")

    assert error.retry_after is None


def test_a_refusal_logs_what_was_sent_without_the_secrets(caplog: pytest.LogCaptureFixture) -> None:
    """
    Log enough to compare a refused request with one that works, and no secrets.

    So it carries the client info, the user agent and the serial, and never the one-time
    password, the machine id or the identity token.
    """
    sent = {
        "X-MMe-Client-Info": (
            "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        ),
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-Apple-I-SRL-NO": "0PENTAGXK7QX",
        "X-Apple-I-MD": "SECRET-OTP",
        "X-Apple-I-MD-M": "SECRET-MACHINE",
        "X-Apple-Identity-Token": "SECRET-TOKEN",
    }

    with caplog.at_level(logging.WARNING):
        _refused(
            _response(429, {"Retry-After": "45", "Server": "Apple"}),
            sent,
            "The Grand Slam request",
        )

    logged = caplog.text
    assert "com.apple.akd/1.0" in logged
    assert "0PENTAGXK7QX" in logged
    assert "Retry-After" in logged, "the response headers are the evidence and are logged whole"
    for secret in ("SECRET-OTP", "SECRET-MACHINE", "SECRET-TOKEN"):
        assert secret not in logged, f"{secret} reached the log"
