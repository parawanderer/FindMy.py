"""
Tests for how long a request may take, and for saying so when it takes longer.

The default suits Apple's hosts on an ordinary connection and does not suit every login:
several round trips, each measured separately, and an Anisette server in the middle that
may be generating its data on demand.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typing_extensions import override

from findmy.reports.account import AppleAccount, AsyncAppleAccount
from findmy.reports.anisette import RemoteAnisetteProvider
from findmy.util.http import DEFAULT_TIMEOUT, HttpSession

_RELEASED = threading.Event()
"""Set on teardown, so a handler stops waiting the moment the tests are done with it."""


class _Slow(BaseHTTPRequestHandler):
    """A server that accepts the connection and then does not answer."""

    def do_GET(self) -> None:
        # Waits on an event rather than a sleep, and the server is threading, so a
        # handler still blocked when the client gives up costs nothing: the next request
        # gets its own thread and teardown releases them all at once. A plain HTTPServer
        # with a sleeping handler makes each of these tests wait out the *previous* one.
        _RELEASED.wait(30)

    @override
    def log_message(self, format: str, *args: object) -> None:
        """Keep the test output clean."""


@pytest.fixture
def slow_server():  # noqa: ANN201
    """Serve a URL that connects and never replies, on a port the OS picks."""
    _RELEASED.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Slow)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        _RELEASED.set()
        server.shutdown()
        server.server_close()


def test_a_request_that_outruns_the_clock_says_what_did_not_answer(slow_server: str) -> None:
    """Test the message, because a bare TimeoutError names nothing and suggests nothing."""
    # `aiohttp` raises `TimeoutError`, which is not a `ClientError`, so this is neither
    # retried nor described unless something does it here. What a user saw before was the
    # word "TimeoutError" partway through a sign-in.
    async def run() -> None:
        session = HttpSession(timeout=0.25)
        try:
            with pytest.raises(TimeoutError, match=r"did not answer within 0\.25s"):
                await session.get(slow_server)
        finally:
            await session.close()

    asyncio.run(run())


def test_the_message_names_the_parameter_that_fixes_it(slow_server: str) -> None:
    """Test that the error says what to do, since nothing else can."""
    async def run() -> None:
        session = HttpSession(timeout=0.25)
        try:
            with pytest.raises(TimeoutError, match=r"timeout is a parameter"):
                await session.get(slow_server)
        finally:
            await session.close()

    asyncio.run(run())


def test_a_longer_timeout_is_actually_waited_out(slow_server: str) -> None:
    """Test that the number reaches the wire rather than only the constructor."""
    # The failure this catches is a parameter that is stored, exposed, serialized and
    # never passed to the client session -- which looks entirely correct from outside.
    async def elapsed(timeout: float) -> float:
        session = HttpSession(timeout=timeout)
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            with pytest.raises(TimeoutError):
                await session.get(slow_server)
        finally:
            await session.close()
        return loop.time() - started

    short = asyncio.run(elapsed(0.2))
    longer = asyncio.run(elapsed(0.8))

    assert longer > short * 2


def test_an_account_hands_its_timeout_to_the_requests_it_makes() -> None:
    from tests.test_device_identity import a_provider

    account = AsyncAppleAccount(a_provider(), timeout=30)

    assert account._http.timeout == 30  # noqa: SLF001


def test_the_sync_account_passes_it_through_too() -> None:
    from tests.test_device_identity import a_provider

    account = AppleAccount(a_provider(), timeout=30)

    assert account._asyncacc._http.timeout == 30  # noqa: SLF001


def test_saying_nothing_leaves_every_caller_where_they_were() -> None:
    from tests.test_device_identity import a_provider

    assert HttpSession().timeout == DEFAULT_TIMEOUT
    assert AsyncAppleAccount(a_provider())._http.timeout == DEFAULT_TIMEOUT  # noqa: SLF001
    assert RemoteAnisetteProvider("https://ani.example/")._http.timeout == DEFAULT_TIMEOUT  # noqa: SLF001


def test_the_anisette_fetch_has_its_own_timeout() -> None:
    """Test that the provider's own, since raising the account's does not reach it."""
    # The fetch happens inside the login, from the provider's session -- so a slow
    # Anisette server fails a sign-in that the account's timeout cannot rescue.
    provider = RemoteAnisetteProvider("https://ani.example/", timeout=45)

    assert provider._http.timeout == 45  # noqa: SLF001


def test_a_provider_that_needed_longer_still_does_after_being_restored() -> None:
    """Test that the timeout survives serialization, like the certificate switch."""
    # A provider is reconstructed from this. Reverting to the default would turn a
    # working setup back into a failing one on the next run, silently.
    state = RemoteAnisetteProvider("https://ani.example/", timeout=45).to_json()

    assert state.get("timeout") == 45
    assert RemoteAnisetteProvider.from_json(state)._http.timeout == 45  # noqa: SLF001


def test_a_default_timeout_writes_nothing_to_saved_state() -> None:
    """Test that existing files stay byte-for-byte what they were."""
    assert "timeout" not in RemoteAnisetteProvider("https://ani.example/").to_json()
