"""Module to simplify asynchronous HTTP calls."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypedDict, cast

import aiohttp
from aiohttp import BasicAuth, ClientSession, ClientTimeout
from typing_extensions import Unpack, override

from .abc import Closable
from .parsers import decode_plist
from .tls import tls_setting

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5
"""
Seconds any one request may take, start to finish.

Ample for Apple's own hosts on an ordinary connection, and **not always ample for the
login**: a self-hosted Anisette server, a slow link or a machine generating Anisette
locally can all take longer than this, and the failure is a bare timeout partway through a
sign-in rather than anything naming a cause. Callers that need longer say so; see
:class:`~findmy.reports.account.AsyncAppleAccount`.
"""


class _RequestOptions(TypedDict, total=False):
    json: dict[str, Any] | None
    headers: dict[str, str]
    auto_retry: bool
    data: bytes


class _AiohttpRequestOptions(_RequestOptions):
    auth: BasicAuth


class _HttpRequestOptions(_RequestOptions, total=False):
    auth: BasicAuth | tuple[str, str]


class HttpResponse:
    """Response of a request made by :meth:`HttpSession`."""

    def __init__(
        self,
        status_code: int,
        content: bytes,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        """Initialize the response."""
        self._status_code = status_code
        self._content = content
        self._headers: Mapping[str, str] = headers or {}

    @property
    def status_code(self) -> int:
        """HTTP status code of the response."""
        return self._status_code

    @property
    def ok(self) -> bool:
        """Whether the status code is "OK" (2xx)."""
        return str(self._status_code).startswith("2")

    @property
    def content(self) -> bytes:
        """Raw response body, for responses that are not text."""
        return self._content

    @property
    def headers(self) -> Mapping[str, str]:
        """
        The response's headers.

        Kept because a rejection often explains itself here rather than in the body --
        Apple's authentication endpoints in particular -- and an error message assembled
        without them can only report the status code.
        """
        return self._headers

    def text(self) -> str:
        """Response content as a UTF-8 encoded string."""
        return self._content.decode("utf-8")

    def json(self) -> dict[Any, Any]:
        """Response content as a dict, obtained by JSON-decoding the response content."""
        return json.loads(self.text())

    def plist(self) -> dict[Any, Any]:
        """Response content as a dict, obtained by Plist-decoding the response content."""
        data = decode_plist(self._content)
        if not isinstance(data, dict):
            msg = f"Unknown Plist-encoded data type: {data}. This is a bug, please report it."
            raise TypeError(msg)

        return data


class HttpSession(Closable):
    """Asynchronous HTTP session manager. For internal use only."""

    def __init__(self, *, verify_tls: bool = True, timeout: float = DEFAULT_TIMEOUT) -> None:
        """
        Initialize the session.

        :param timeout: Seconds any one request may take; see :data:`DEFAULT_TIMEOUT`.
        :param verify_tls: Whether to verify server certificates. **Leave this alone.**
            Every Apple host this library talks to verifies against
            :func:`~findmy.util.tls.apple_trust_context`, and turning this off makes each
            request readable and alterable by anything on the network path -- a login
            included. The one case it exists for is a self-hosted Anisette server with a
            self-signed certificate, which is why the switch a caller actually sees is on
            that provider rather than here.
        """
        super().__init__()

        self._session: ClientSession | None = None
        self._closed: bool = False
        self._ssl = tls_setting(verify=verify_tls)
        self._timeout = timeout

    @property
    def timeout(self) -> float:
        """Seconds any one request through this session may take."""
        return self._timeout

    async def _get_session(self) -> ClientSession:
        if self._closed:
            msg = "HttpSession has been closed and cannot be used"
            raise RuntimeError(msg)

        if self._session is not None:
            return self._session

        logger.debug("Creating aiohttp session")
        self._session = ClientSession(timeout=ClientTimeout(total=self._timeout))
        return self._session

    @override
    async def close(self) -> None:
        """Close the underlying session. Should be called when session will no longer be used."""
        if self._closed:
            return  # Already closed, make it idempotent

        self._closed = True

        if self._session is not None:
            logger.debug("Closing aiohttp session")
            try:
                await self._session.close()
            except (RuntimeError, OSError, ConnectionError) as e:
                logger.warning("Error closing aiohttp session: %s", e)
            finally:
                self._session = None

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Unpack[_HttpRequestOptions],
    ) -> HttpResponse:
        """
        Make an HTTP request.

        Keyword arguments will directly be passed to :meth:`aiohttp.ClientSession.request`.
        """
        session = await self._get_session()

        # cast from http options to library supported options
        auth = kwargs.pop("auth", None)
        if isinstance(auth, tuple):
            kwargs["auth"] = BasicAuth(auth[0], auth[1])
        options = cast("_AiohttpRequestOptions", kwargs)

        auto_retry = kwargs.pop("auto_retry", False)

        retry_count = 1
        while True:  # if auto_retry is set, raise for status and retry on error
            try:
                async with await session.request(
                    method,
                    url,
                    ssl=self._ssl,
                    raise_for_status=auto_retry,
                    **options,
                ) as r:
                    return HttpResponse(r.status, await r.content.read(), dict(r.headers))
            except TimeoutError as e:  # noqa: PERF203
                # `aiohttp` raises this rather than a `ClientError`, so it is neither
                # retried nor described: a login that outran the clock arrives as a bare
                # `TimeoutError` naming nothing. Say what did not answer and what the
                # limit was, because the fix is a caller's argument and nothing else here
                # can suggest it.
                msg = (
                    f"{method} {url} did not answer within {self._timeout}s. "
                    f"If this is a slow connection or a self-hosted Anisette server, "
                    f"the timeout is a parameter -- see AsyncAppleAccount(timeout=...)."
                )
                raise TimeoutError(msg) from e
            except aiohttp.ClientError as e:
                if not auto_retry or retry_count > 3:
                    raise e from None

                retry_after = 5 * retry_count
                logger.warning(
                    "Error while making HTTP request; retrying after %i seconds. %s",
                    retry_after,
                    e,
                )
                await asyncio.sleep(retry_after)

                retry_count += 1

    async def get(self, url: str, **kwargs: Unpack[_HttpRequestOptions]) -> HttpResponse:
        """Alias for `HttpSession.request("GET", ...)`."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Unpack[_HttpRequestOptions]) -> HttpResponse:
        """Alias for `HttpSession.request("POST", ...)`."""
        return await self.request("POST", url, **kwargs)
