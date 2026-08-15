"""Tests for the trust store, and for verification being on unless it is turned off."""

from __future__ import annotations

import hashlib
import ssl

import pytest

from findmy.reports.anisette import RemoteAnisetteProvider
from findmy.util.http import HttpSession
from findmy.util.tls import (
    APPLE_ROOT_CA_PEM,
    APPLE_ROOT_CA_SHA256,
    TlsError,
    apple_trust_context,
    tls_setting,
)

def _common_names(context: ssl.SSLContext) -> set[str]:
    """Every trust anchor the context holds, by common name."""
    return {
        value
        for certificate in context.get_ca_certs()
        for group in certificate.get("subject", ())
        for key, value in group
        if key == "commonName"
    }


def test_the_bundled_root_is_the_certificate_it_claims_to_be() -> None:
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(APPLE_ROOT_CA_PEM)).digest()

    assert digest == APPLE_ROOT_CA_SHA256
    assert digest.hex() == "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"


def test_a_root_that_does_not_match_its_fingerprint_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A trust anchor is only an anchor once it hashes to what it should. Catching a mangled
    # copy here means failing at import rather than at the first handshake, where it would
    # read as Apple's server being unreachable.
    monkeypatch.setattr("findmy.util.tls.APPLE_ROOT_CA_SHA256", b"\x00" * 32)
    apple_trust_context.cache_clear()

    with pytest.raises(TlsError, match="Refusing to trust it"):
        apple_trust_context()

    apple_trust_context.cache_clear()


def test_the_context_adds_apples_root_to_the_platforms_own() -> None:
    context = apple_trust_context()

    assert "Apple Root CA" in _common_names(context)
    # The check above is only worth making if it can fail: an empty context has no anchors,
    # and this is what distinguishes "the root was loaded" from "the helper always says
    # yes". The platform store cannot serve as the negative case -- macOS ships this root
    # and Mozilla-derived stores do not, which is the whole reason for bundling it.
    assert "Apple Root CA" not in _common_names(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))

    # Added *on top of* the defaults, not instead of them: adding a trust anchor does not
    # weaken the ones already there, and a context holding only Apple's root would refuse
    # every other host this library talks to.
    assert len(context.get_ca_certs()) > 1

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_verification_is_on_unless_it_is_turned_off() -> None:
    assert tls_setting(verify=True) is apple_trust_context()
    assert tls_setting(verify=False) is False


def test_disabling_verification_says_so(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):
        tls_setting(verify=False)

    assert "network path" in caplog.text


# These construct a session without ever making a request, so no aiohttp session is
# created and there is nothing to close -- which keeps them synchronous.


def test_an_http_session_verifies_by_default() -> None:
    assert HttpSession()._ssl is apple_trust_context()  # noqa: SLF001


def test_an_http_session_can_be_told_not_to() -> None:
    assert HttpSession(verify_tls=False)._ssl is False  # noqa: SLF001


def test_an_anisette_provider_verifies_by_default() -> None:
    provider = RemoteAnisetteProvider("https://ani.example/")

    assert provider._http._ssl is apple_trust_context()  # noqa: SLF001
    assert provider.to_json() == {"type": "aniRemote", "url": "https://ani.example/"}


def test_the_opt_in_reaches_the_session_and_survives_a_round_trip() -> None:
    # It has to be serialized, or saving and reloading an account would silently turn a
    # working self-signed setup into a failing one.
    provider = RemoteAnisetteProvider("https://ani.example/", allow_unverified_https=True)
    assert provider._http._ssl is False  # noqa: SLF001

    state = provider.to_json()
    assert state["allow_unverified_https"] is True

    assert RemoteAnisetteProvider.from_json(state)._http._ssl is False  # noqa: SLF001


def test_an_older_saved_provider_still_loads_and_verifies() -> None:
    # A file written before this option existed carries no flag, and must keep working --
    # verifying, which is the safe direction for a default to move in.
    restored = RemoteAnisetteProvider.from_json({"type": "aniRemote", "url": "https://a/"})

    assert restored._http._ssl is apple_trust_context()  # noqa: SLF001


def test_a_provider_presents_the_serial_it_was_given() -> None:
    """Test that a serial set once reaches the header that carries it."""
    import asyncio  # noqa: PLC0415

    from findmy.reports.anisette import BaseAnisetteProvider  # noqa: PLC0415

    class Provider(BaseAnisetteProvider):
        """The base header assembly, with nothing fetched from anywhere."""

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

    provider = Provider(serial="0PENTAGVIEWR")
    headers = asyncio.run(provider.get_headers("user", "device"))

    assert provider.serial == "0PENTAGVIEWR"
    assert headers["X-Apple-I-SRL-NO"] == "0PENTAGVIEWR"
    # A per-call override still works, and is the exception rather than the way in.
    assert asyncio.run(provider.get_headers("u", "d", "0OVERRIDE001"))[
        "X-Apple-I-SRL-NO"
    ] == "0OVERRIDE001"


def test_a_chosen_serial_survives_being_saved_and_reloaded() -> None:
    """Test that a serial is serialized, so a restored account keeps its identity."""
    provider = RemoteAnisetteProvider("https://ani.example/", serial="0PENTAGVIEWR")

    state = provider.to_json()
    assert state.get("serial") == "0PENTAGVIEWR"

    # The failure this prevents: a restored account reverting to the default adds a
    # device-list entry rather than reusing the one it had.
    assert RemoteAnisetteProvider.from_json(state).serial == "0PENTAGVIEWR"


def test_the_default_is_not_written_so_existing_files_are_unchanged() -> None:
    """Test that a provider using the default serial writes no serial at all."""
    from findmy.reports.anisette import CLIENT_SERIAL  # noqa: PLC0415

    provider = RemoteAnisetteProvider("https://ani.example/")

    assert provider.serial == CLIENT_SERIAL
    assert provider.to_json() == {"type": "aniRemote", "url": "https://ani.example/"}
    # And a file written before this existed restores to the default rather than to None.
    assert RemoteAnisetteProvider.from_json(
        {"type": "aniRemote", "url": "https://a/"},
    ).serial == CLIENT_SERIAL


def test_importing_the_package_does_not_import_the_bluetooth_stack() -> None:
    """Test that `import findmy` costs nothing for a client that never scans."""
    import subprocess  # noqa: PLC0415
    import sys  # noqa: PLC0415

    # A fresh interpreter, because this process has almost certainly imported it already.
    probe = subprocess.run(  # noqa: S603
        [sys.executable, "-c", "import sys, findmy; print('bleak' in sys.modules)"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert probe.stdout.strip() == "False"


def test_the_scanner_is_still_reachable_by_the_name_it_always_had() -> None:
    """Test that going lazy did not move anything a caller imports."""
    import findmy  # noqa: PLC0415

    assert findmy.OfflineFindingScanner.__name__ == "OfflineFindingScanner"
    assert "OfflineFindingScanner" in findmy.__all__

    with pytest.raises(AttributeError, match="no attribute"):
        _ = findmy.NotAThingThatExists
