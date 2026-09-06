"""Exception classes."""


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

    Observed as a 503 from ``gsa.apple.com`` affecting every call for a stretch of minutes,
    then clearing on its own -- see OpenTagViewer#168 and #176, where one account met it at
    ``td_2fa_submit``, again at ``request_pet`` a second later, and again at ``login`` a
    minute after that.

    A subclass of ``UnhandledProtocolError`` on purpose, so existing ``except`` clauses keep
    catching it and nothing downstream breaks by upgrading. Catch this one first where the
    difference matters.

    :param status_code: what the endpoint answered with.
    :param what: which request it was, for the message.
    """

    def __init__(self, status_code: int, what: str) -> None:
        """Record what was refused and with what, then compose the message."""
        self.status_code = status_code
        self.what = what

        super().__init__(
            f"{what} was refused with HTTP {status_code}. This is Apple declining to serve"
            " the request rather than a response this library cannot read, and it usually"
            " clears on its own -- wait and try again.",
        )


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
    -- so nothing here branches on a guess. If an account is stuck at this error, the
    terms flow is the remedy to try: see
    :meth:`~findmy.reports.account.AsyncAppleAccount.fetch_terms`.
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
        else:
            remedy = (
                "If this account has unaccepted iCloud terms, fetch_terms() and"
                " accept_terms() are the remedy, and the localizedError above is worth"
                " reporting -- which value means that is not yet known."
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
