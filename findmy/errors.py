"""Exception classes."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


class InvalidCredentialsError(Exception):
    """Raised when credentials are incorrect."""


class UnauthorizedError(Exception):
    """Raised when an authorization error occurs."""


class UnhandledProtocolError(RuntimeError):
    """
    Raised when an unexpected error occurs while communicating with Apple servers.

    This is almost always a bug, so please report it.
    """


class AppleServiceUnavailableError(UnhandledProtocolError):
    """
    Raised when an Apple endpoint refuses with a status that means "not now".

    **This is weather, not a bug, and it is the one kind of protocol failure a caller can
    act on.** ``UnhandledProtocolError`` means "Apple said something this library does not
    model", and its own docstring tells the reader to report it. A 503 from Grand Slam is
    not that: nothing is unmodelled, the server declined to serve. Reporting the two
    identically sends people to file issues about Apple having a bad minute, and gives an
    application no way to tell a retry-worthy failure from a real one.

    Observed as a 503 from ``gsa.apple.com`` affecting every call for a stretch of minutes --
    see OpenTagViewer#168 and #176, where one account met it at ``td_2fa_submit``, again at
    ``request_pet`` a second later, and again at ``login`` a minute after that. **It does not
    always clear on its own:** from September 2026 the same 503 was Apple's edge refusing the
    Xcode client identifier, permanently, until the client changed.

    A subclass of ``UnhandledProtocolError`` on purpose, so existing ``except`` clauses keep
    catching it and nothing downstream breaks by upgrading. Catch this one first where the
    difference matters.

    :param status_code: what the endpoint answered with.
    :param what: which request it was, for the message.
    :param retry_after: seconds Apple asked the client to wait, from ``Retry-After``, or None
        when it did not say. See :func:`parse_retry_after`.
    """

    def __init__(self, status_code: int, what: str, retry_after: float | None = None) -> None:
        """Record what was refused, with what, and for how long, then compose the message."""
        self.status_code = status_code
        self.what = what
        self.retry_after = retry_after
        """
        Seconds Apple asked for before a retry, or None when the response did not say.

        **None is the common case, not a failure to parse.** No GSA refusal observed so far has
        carried the header, so a caller must treat None as "unknown" rather than "retry now" --
        and must not invent a number to fill it. When it is present it is Apple's own answer
        and worth showing a person, which is the whole reason to read it.
        """

        # **No promise that it clears on its own.** This used to say it usually does. For the
        # 503s of September 2026 it did not: they were Apple refusing the Xcode client
        # identifier, and every retry met the same answer until the client changed.
        wait = (
            f" Apple asked for {_describe_seconds(retry_after)} before trying again."
            if retry_after is not None
            else " Waiting and trying again may help."
        )
        super().__init__(
            f"{what} was refused with HTTP {status_code}. This is Apple declining to serve"
            f" the request rather than a response this library cannot read.{wait}",
        )


def _describe_seconds(seconds: float) -> str:
    """Describe a wait as a person would say it, rounded up so nobody retries too early."""
    whole = max(0, math.ceil(seconds))
    if whole < 60:
        return f"{whole} second{'s' if whole != 1 else ''}"
    minutes = math.ceil(whole / 60)
    return f"{minutes} minute{'s' if minutes != 1 else ''}"


def parse_retry_after(
    headers: Mapping[str, str] | None,
    now: datetime | None = None,
) -> float | None:
    """
    Seconds to wait from a response's ``Retry-After`` header, or None if it gives none.

    RFC 9110 section 10.2.3 allows two forms, and both are handled: a non-negative integer of
    seconds, or an HTTP date. A date already in the past is 0 -- it is a valid answer meaning
    "now" -- rather than a negative wait.

    **Looked up without regard to case**, and that is not pedantry. Responses reach this as a
    plain ``dict``, which is case-sensitive, and HTTP/2 transmits header names in lowercase, so
    a lookup of ``"Retry-After"`` alone would miss the header on exactly the connections Apple
    is most likely to use.

    Anything unreadable is None rather than a guess. A wrong wait is worse than none: too short
    and the retry is refused again, too long and a person stares at a countdown for nothing.

    :param now: the time a date is measured from. For tests; defaults to the current time.
    """
    if not headers:
        return None

    raw = next(
        (value for name, value in headers.items() if name.lower() == "retry-after"),
        None,
    )
    if raw is None:
        return None

    value = raw.strip()
    if value.isdigit():
        return float(int(value))

    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        # RFC 9110 dates are GMT by definition; one without a zone is read as such.
        when = when.replace(tzinfo=timezone.utc)

    reference = now if now is not None else datetime.now(timezone.utc)
    return max(0.0, (when - reference).total_seconds())


def is_service_unavailable(status_code: int) -> bool:
    """
    Whether a status means "not now" rather than "never" or "you are wrong".

    Server errors and rate limiting. Deliberately not 4xx beyond 429: those say something
    about the request, and retrying an unchanged one gets the same answer.
    """
    return status_code == 429 or 500 <= status_code <= 599


class MobileMeDelegateError(UnhandledProtocolError):
    """
    Raised when the MobileMe delegate exchange fails, carrying what the response said.

    **The response has two independent error channels**, and the interesting one is not
    the channel a success is defined by. `status` is what says a request worked;
    `localizedError` is a separate top-level field, with a human-readable `description`
    beside it, and unaccepted iCloud terms arrive there. Reading only `status` reports a
    generic failure for a response that stated the problem exactly.

    So this reports both, verbatim. Which `localizedError` value means "terms pending" is
    not established -- `UNAUTHORIZED` is a known but different value on the same channel
    -- so nothing here branches on a guess. If an account is stuck at this error *and a
    localizedError came back*, the terms flow is the remedy to try: see
    :meth:`~findmy.reports.account.AsyncAppleAccount.fetch_terms`.

    **And when no localizedError came back, it is not a terms problem at all.** The
    delegate's own `status` fails independently of that channel, and a caller that cannot
    tell the two apart will offer an empty document list to somebody whose terms are fine.
    :attr:`names_a_localized_error` is the discriminator; branch on it rather than on the
    exception type.
    """

    def __init__(
        self,
        *,
        localized_error: str | None = None,
        description: str | None = None,
        status: object = None,
        status_message: str | None = None,
    ) -> None:
        """Build the error from the response's two channels, either of which may be empty."""
        self.localized_error = localized_error
        self.description = description
        self.status = status
        self.status_message = status_message

        super().__init__(self._describe())

    @property
    def is_unauthorized(self) -> bool:
        """Whether the credential was rejected, which usually means the PET expired."""
        return self.localized_error == "UNAUTHORIZED"

    @property
    def names_a_localized_error(self) -> bool:
        """
        Whether the response used the channel unaccepted terms arrive on.

        **False means the terms flow is not the remedy, and is worth branching on.** The two
        channels fail independently: `localizedError` is where a response explains itself in
        words, and the delegate's own `status` is where it reports that it would not serve the
        account at all. A caller that treats every delegate failure as "terms pending" sends
        somebody to a document list that is empty, tells them the problem is terms, and leaves
        the actual refusal unmentioned.
        """
        return self.localized_error is not None

    def _describe(self) -> str:
        """Say what the response said, and what can be done about it."""
        said = [
            f"{name}={value!r}"
            for name, value in (
                ("localizedError", self.localized_error),
                ("description", self.description),
                ("status", self.status),
                ("status-message", self.status_message),
            )
            if value is not None
        ]
        reported = ", ".join(said) if said else "nothing about why"

        if self.is_unauthorized:
            remedy = (
                "The credential was rejected, which is usually an expired PET rather than"
                " a bad password. Log in again."
            )
        elif self.names_a_localized_error:
            remedy = (
                "If this account has unaccepted iCloud terms, fetch_terms() and"
                " accept_terms() are the remedy, and the localizedError above is worth"
                " reporting -- which value means that is not yet known."
            )
        else:
            # **Advising about localizedError here was a bug, and a user-visible one.** The
            # remedy above used to be the only alternative to UNAUTHORIZED, so a response
            # whose delegate simply refused the account was answered with a sentence about
            # terms of service and an instruction to report a field that is not in it.
            # OpenTagViewer#221 shows it on a phone: an account with nothing wrong with its
            # terms, told to go and accept some.
            #
            # What it is instead is not established from here, so this reports rather than
            # concludes. Every client sharing this sign-in path meets it on Apple IDs that
            # have never been used with an Apple device, and the advice that circulates is
            # to fill the account out at appleid.apple.com -- see macless-haystack#84, #86
            # and #87, where the same status arrives with "Account limit reached" and with
            # this same "server problem" wording.
            remedy = (
                "No localizedError came back, so this is not the terms channel and"
                " accepting terms will not change it -- the delegate refused the account"
                " itself. Clients sharing this sign-in path report this on Apple IDs that"
                " have never been used with an Apple device, and that completing the"
                " account at appleid.apple.com clears it; retrying alone generally does"
                " not. Despite the wording, it is not known to be temporary."
            )

        return f"The com.apple.mobileme delegate request failed, reporting {reported}. {remedy}"


class EmptyResponseError(RuntimeError):
    """
    Raised when Apple servers return an empty response when querying location reports.

    This is a bug on Apple's side. More info: https://github.com/malmeloo/FindMy.py/issues/185
    """


class InvalidStateError(RuntimeError):
    """
    Raised when a method is used that is in conflict with the internal account state.

    For example: calling :meth:`BaseAppleAccount.login` while already logged in.
    """
