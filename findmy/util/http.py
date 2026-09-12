"""Module to simplify asynchronous HTTP calls."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypedDict, cast

import aiohttp
from aiohttp import BasicAuth, ClientSession, ClientTimeout
from typing_extensions import Unpack, override

from .abc import Closable
from .parsers import decode_plist
from .tls import APPLE_ROOT_CA_PEM, tls_setting

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

try:
    # Only resolves under Chaquopy. Its presence is the platform switch: everywhere else
    # imports this module and gets the aiohttp path below, unchanged.
    from java import cast, jclass

    _ON_ANDROID = True
except ImportError:
    _ON_ANDROID = False

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


class _AndroidTlsRequest:
    """
    Makes one HTTPS request through Android's own network stack instead of aiohttp's.

    **The actual fault, once it was isolated, was not the platform's TLS stack.** It was
    connection reuse: aiohttp's session (and, it turned out, `HttpURLConnection`'s own pool)
    keeps a keep-alive connection between the `init` and `complete` requests of one GSA
    exchange, and Apple's edge answers whichever of the two arrives second on that
    connection with a bare `429` -- the same fault AltSign found and fixed in AltSign#52.
    `HttpUrlConnection` was tried first because a proxy that let the request egress through
    a desktop Python's network stack got further than any direct attempt did; the class
    stayed once the real cause -- connection reuse, fixed below via `Connection: close` and
    `http.keepAlive=false` -- turned out to be the actual fix, on the reasoning that a
    platform's own stack is one fewer thing to ask Apple's edge to tolerate. Whether aiohttp
    with a non-reusing connector would have been just as sufficient here was not tested.

    Used only where `_ON_ANDROID` is true; every other platform never imports the classes
    this touches.
    """

    _URL = None
    _KeyStore = None
    _CertificateFactory = None
    _TrustManagerFactory = None
    _SSLContext = None
    _ByteArrayInputStream = None
    _ByteArrayOutputStream = None

    _socket_factory = None
    """
    Built once and reused: it is derived from the platform's own trust anchors plus Apple's
    root, and rebuilding it per request would re-walk the system trust store for no reason.
    """

    @classmethod
    def _classes(cls) -> None:
        if cls._URL is not None:
            return

        cls._URL = jclass("java.net.URL")
        cls._KeyStore = jclass("java.security.KeyStore")
        cls._CertificateFactory = jclass("java.security.cert.CertificateFactory")
        cls._TrustManagerFactory = jclass("javax.net.ssl.TrustManagerFactory")
        cls._SSLContext = jclass("javax.net.ssl.SSLContext")
        cls._ByteArrayInputStream = jclass("java.io.ByteArrayInputStream")
        cls._ByteArrayOutputStream = jclass("java.io.ByteArrayOutputStream")

        # Belt-and-braces alongside the per-request `Connection: close` header: this disables
        # HttpURLConnection's own connection pool JVM-wide, so nothing here can hand a second
        # GSA request the first one's socket even if a server response ignored the header.
        jclass("java.lang.System").setProperty("http.keepAlive", "false")

    @classmethod
    def _get_socket_factory(cls):
        if cls._socket_factory is not None:
            return cls._socket_factory

        cls._classes()

        # The platform's own trust anchors, same as `ssl.create_default_context()` gets on
        # every other platform: a null keystore tells the default TrustManagerFactory to
        # read the system's.
        platform_tmf = cls._TrustManagerFactory.getInstance(
            cls._TrustManagerFactory.getDefaultAlgorithm(),
        )
        platform_tmf.init(cast(cls._KeyStore, None))

        combined_store = cls._KeyStore.getInstance(cls._KeyStore.getDefaultType())
        combined_store.load(None, None)

        for trust_manager in platform_tmf.getTrustManagers():
            issuers = getattr(trust_manager, "getAcceptedIssuers", None)
            if issuers is None:
                continue
            for i, cert in enumerate(issuers()):
                combined_store.setCertificateEntry(f"platform-{i}", cert)

        # Apple's 2006 root, on top of the platform's own -- same policy as
        # `apple_trust_context()`, so `gsa.apple.com`'s chain verifies here too.
        cert_factory = cls._CertificateFactory.getInstance("X.509")
        apple_cert = cert_factory.generateCertificate(
            cls._ByteArrayInputStream(APPLE_ROOT_CA_PEM.encode("utf-8")),
        )
        combined_store.setCertificateEntry("apple-root", apple_cert)

        combined_tmf = cls._TrustManagerFactory.getInstance(
            cls._TrustManagerFactory.getDefaultAlgorithm(),
        )
        combined_tmf.init(combined_store)

        ctx = cls._SSLContext.getInstance("TLS")
        ctx.init(None, combined_tmf.getTrustManagers(), None)

        cls._socket_factory = ctx.getSocketFactory()
        return cls._socket_factory

    @classmethod
    def _read_all(cls, stream) -> bytes:
        if stream is None:
            return b""

        out = cls._ByteArrayOutputStream()
        chunk = bytearray(8192)
        n = stream.read(chunk)
        while n != -1:
            out.write(chunk, 0, n)
            n = stream.read(chunk)
        return bytes(out.toByteArray())

    @classmethod
    def request(
        cls,
        method: str,
        url: str,
        headers: dict[str, str],
        data: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        """Blocking. Run this off the event loop -- see `HttpSession.request`."""
        cls._classes()

        conn = cls._URL(url).openConnection()
        conn.setSSLSocketFactory(cls._get_socket_factory())
        conn.setRequestMethod(method)
        conn.setConnectTimeout(int(timeout * 1000))
        conn.setReadTimeout(int(timeout * 1000))
        conn.setInstanceFollowRedirects(False)
        conn.setDoInput(True)

        for key, value in headers.items():
            conn.setRequestProperty(key, value)

        # Apple's GSA edge answers a second request on a reused connection with 429 (the same
        # pattern AltSign hit and fixed by never reusing one -- see AltSign#52). Android's
        # HttpURLConnection keeps its own connection pool per host regardless of this header on
        # some versions, so this is belt-and-braces with the System property set once below.
        conn.setRequestProperty("Connection", "close")

        if data is not None:
            conn.setDoOutput(True)
            conn.setFixedLengthStreamingMode(len(data))
            out_stream = conn.getOutputStream()
            out_stream.write(bytearray(data))
            out_stream.flush()
            out_stream.close()

        status = conn.getResponseCode()

        response_headers: dict[str, str] = {}
        header_fields = conn.getHeaderFields()
        key_iterator = header_fields.keySet().iterator()
        while key_iterator.hasNext():
            key = key_iterator.next()
            if key is None:
                continue  # the status line itself, keyed by null in this API
            values = header_fields.get(key)
            if values and values.size() > 0:
                response_headers[str(key)] = str(values.get(values.size() - 1))

        body_stream = conn.getErrorStream() if status >= 400 else conn.getInputStream()  # noqa: PLR2004
        body = cls._read_all(body_stream)

        return HttpResponse(status, body, response_headers)


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

        Keyword arguments will directly be passed to :meth:`aiohttp.ClientSession.request`,
        except on Android -- see :class:`_AndroidTlsRequest`, which takes the same
        arguments but does not go through aiohttp at all.
        """
        if _ON_ANDROID:
            return await self._android_request(method, url, **kwargs)

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

    async def _android_request(
        self,
        method: str,
        url: str,
        **kwargs: Unpack[_HttpRequestOptions],
    ) -> HttpResponse:
        """
        The Android path: `HttpsURLConnection` on a thread, not aiohttp.

        `HttpsURLConnection` is synchronous, so it runs in a worker thread via
        :func:`asyncio.to_thread` -- this coroutine still just awaits, same as the
        aiohttp path above.
        """
        headers = dict(kwargs.get("headers") or {})

        auth = kwargs.get("auth")
        if isinstance(auth, tuple):
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode("ascii")
            headers["Authorization"] = f"Basic {token}"

        data = kwargs.get("data")
        if data is None and kwargs.get("json") is not None:
            data = json.dumps(kwargs["json"]).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")

        auto_retry = kwargs.get("auto_retry", False)

        retry_count = 1
        while True:
            try:
                response = await asyncio.to_thread(
                    _AndroidTlsRequest.request,
                    method,
                    url,
                    headers,
                    data,
                    self._timeout,
                )
            except Exception as e:  # noqa: BLE001 -- Chaquopy surfaces Java exceptions as this
                if not auto_retry or retry_count > 3:
                    msg = f"{method} {url} failed: {e}"
                    raise TimeoutError(msg) from e

                retry_after = 5 * retry_count
                logger.warning(
                    "Error while making HTTP request; retrying after %i seconds. %s",
                    retry_after,
                    e,
                )
                await asyncio.sleep(retry_after)
                retry_count += 1
                continue

            if auto_retry and not response.ok and retry_count <= 3:
                retry_after = 5 * retry_count
                logger.warning(
                    "HTTP %i from %s; retrying after %i seconds.",
                    response.status_code,
                    url,
                    retry_after,
                )
                await asyncio.sleep(retry_after)
                retry_count += 1
                continue

            return response

    async def get(self, url: str, **kwargs: Unpack[_HttpRequestOptions]) -> HttpResponse:
        """Alias for `HttpSession.request("GET", ...)`."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Unpack[_HttpRequestOptions]) -> HttpResponse:
        """Alias for `HttpSession.request("POST", ...)`."""
        return await self.request("POST", url, **kwargs)
