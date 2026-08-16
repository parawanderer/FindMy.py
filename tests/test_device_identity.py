"""Tests for the device identity every header claims, and for its one exception."""

from __future__ import annotations

import asyncio
import base64
import inspect
from dataclasses import replace

import pytest

from findmy.cloudkit.client import _ClientIdentity
from findmy.reports.account import (
    _ACCOUNTSD_BUNDLE,
    _GSA_USER_AGENT,
    _ICLOUD_HELPER,
    AppleAccount,
    AsyncAppleAccount,
)
from findmy.reports.anisette import (
    CLIENT_IDENTITY,
    CLIENT_SERIAL,
    BaseAnisetteProvider,
    DeviceIdentity,
    LocalAnisetteProvider,
    RemoteAnisetteProvider,
)

# A different real release, so a partial identity would show up as a contradiction rather
# than as a plausible-looking string: macOS 13.1 is build 22C65, CFNetwork 1404.0.5,
# Darwin 22.2.0.
OTHER = DeviceIdentity(
    model="MacBookPro13,2",
    os_name="macOS",
    os_version="13.1",
    os_build="22C65",
    cfnetwork="1404.0.5",
    darwin="22.2.0",
)

# Lower case on purpose: the header is uppercased on the way out, and a client aligning
# with an exchange it already made needs that to be visible rather than surprising.
A_UID = "8f0b3d64-1f7e-4a0b-9c2a-0b6f4d3e1a55"
A_DEVID = "2c1f9b7e-5a34-4d18-8f6c-9e0d7a2b4c31"


def a_provider(
    identity: DeviceIdentity = CLIENT_IDENTITY,
    serial: str = CLIENT_SERIAL,
) -> BaseAnisetteProvider:
    """Build a provider that answers headers without reaching anything."""

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
        def from_json(cls, val):  # noqa: ANN001, ANN206
            raise NotImplementedError

    return Provider(identity=identity, serial=serial)


def test_the_default_identity_sends_exactly_what_it_always_sent() -> None:
    """Test that no existing session's identity moved when this became settable."""
    # Apple binds a session to the identity, so a byte that changes here costs every
    # existing user a sign-in and leaves an entry they cannot recognise in their device
    # list. These four strings were transcribed from the code that sent them.
    provider = a_provider()

    assert provider.client == (
        "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> "
        "<com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
    )
    assert provider.client_akd == (
        "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    )
    assert provider.akd_user_agent == "akd/1.0 CFNetwork/1408.0.4 Darwin/22.5.0"

    # The mobileme login's pair, which used to be written out beside the provider's.
    assert CLIENT_IDENTITY.client_info(_ACCOUNTSD_BUNDLE) == (
        "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
    )
    assert CLIENT_IDENTITY.user_agent(_ICLOUD_HELPER) == (
        "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
    )


def test_one_identity_reaches_every_composite() -> None:
    """Test that a client that sets an identity is that device in all of them."""
    # The point of the whole thing: two headers of one request that describe different
    # machines are a signal no real client sends.
    provider = a_provider(OTHER)

    for composite in (provider.client, provider.client_akd):
        assert composite.startswith("<MacBookPro13,2> <macOS;13.1;22C65> ")
        assert "MacBookPro18,3" not in composite

    assert provider.akd_user_agent == "akd/1.0 CFNetwork/1404.0.5 Darwin/22.2.0"
    assert OTHER.user_agent(_ICLOUD_HELPER).endswith("CFNetwork/1404.0.5 Darwin/22.2.0")
    assert OTHER.client_info(_ACCOUNTSD_BUNDLE).startswith("<MacBookPro13,2> <macOS;13.1;22C65> ")


def test_the_account_reads_the_identity_rather_than_composing_one() -> None:
    """Test that the account's identity is the provider's, not a second copy."""
    account = AsyncAppleAccount(a_provider(OTHER))

    assert account.identity == OTHER
    assert account.client_info.startswith(OTHER.platform)


def test_the_mobileme_login_composes_both_of_its_headers() -> None:
    """Test that the mobileme login no longer writes the identity out by hand."""
    # It used to carry its own copy of the platform triple and its own CFNetwork/Darwin
    # pair -- a second identity that would diverge the moment either was edited.
    source = inspect.getsource(AsyncAppleAccount._login_mobileme)  # noqa: SLF001

    assert "self.identity.user_agent(" in source
    assert "self.identity.client_info(" in source
    assert "MacBookPro18,3" not in source
    assert "Darwin/" not in source


def test_cloudkit_claims_the_same_device_as_the_login() -> None:
    """Test that a set identity reaches CloudKit, which parses it back out."""
    # CloudKit swaps the bundle for cloudd's and keeps the device, so the device it keeps
    # has to be the one the account claims.
    parsed = _ClientIdentity.parse(OTHER.client_info("com.apple.AOSKit/282 (com.apple.dt.Xcode/1)"))

    assert parsed.model == "MacBookPro13,2"
    assert parsed.cloudkit_client_info.startswith("<MacBookPro13,2> <macOS;13.1;22C65> ")
    assert "cloudd" in parsed.cloudkit_client_info


def test_grand_slam_authentication_keeps_its_transcribed_user_agent() -> None:
    """Test that the one header that does not follow the identity still does not."""
    # It contradicts the client info beside it -- Darwin 18.7.0 is macOS 10.14 -- and it
    # is left that way on purpose: it is the authentication path, every session this
    # library ever established was established under it, and the only way to test a
    # change is against a live account where being wrong locks people out. This test
    # exists so that tidying it is a decision rather than an accident.
    assert _GSA_USER_AGENT == "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

    source = inspect.getsource(AsyncAppleAccount._gsa_request)  # noqa: SLF001
    assert "_GSA_USER_AGENT" in source


def test_a_default_identity_writes_nothing_to_saved_state() -> None:
    """Test that saving an account that never set one leaves existing files unchanged."""
    remote = RemoteAnisetteProvider("https://ani.example/")
    local = LocalAnisetteProvider()

    assert "identity" not in remote.to_json()
    assert "identity" not in local.to_json()


def test_a_set_identity_survives_a_round_trip() -> None:
    """Test that a restored account is the same device it was."""
    # A restored account that quietly reverted to the library's identity would be a
    # different machine, which costs a sign-in and adds a device-list entry.
    state = RemoteAnisetteProvider("https://ani.example/", identity=OTHER).to_json()

    stored = state.get("identity")
    assert stored is not None
    assert stored["os_name"] == "macOS"
    assert RemoteAnisetteProvider.from_json(state).identity == OTHER

    local_state = LocalAnisetteProvider(identity=OTHER).to_json()
    assert LocalAnisetteProvider.from_json(local_state).identity == OTHER


def test_a_partial_stored_identity_falls_back_field_by_field() -> None:
    """Test that a mapping missing fields is read rather than rejected."""
    identity = DeviceIdentity.from_json({"model": "iPhone15,2"})  # pyright: ignore [reportArgumentType]

    assert identity.model == "iPhone15,2"
    assert identity.darwin == CLIENT_IDENTITY.darwin


def test_changing_one_field_keeps_the_rest() -> None:
    """Test the documented way to claim a nearby device."""
    identity = replace(CLIENT_IDENTITY, model="MacBookAir10,1")

    assert identity.platform == "<MacBookAir10,1> <Mac OS X;13.4.1;22F8>"
    assert identity.cfnetwork == CLIENT_IDENTITY.cfnetwork


def test_supplied_ids_are_the_ones_that_go_out() -> None:
    """Test that a client that already introduced itself stays that installation."""
    account = AsyncAppleAccount(a_provider(), uid=A_UID, devid=A_DEVID)

    assert account.local_user_uuid == A_UID
    assert account.device_uuid == A_DEVID

    headers = asyncio.run(account.get_anisette_headers())
    # Uppercased, and base64 for the local user. Both are the library's doing, and a
    # client aligning with an exchange it already made has to know which it sent.
    assert headers["X-Mme-Device-Id"] == A_DEVID.upper()
    assert headers["X-Apple-I-MD-LU"] == base64.b64encode(A_UID.encode()).decode()


def test_saying_nothing_still_mints_a_fresh_pair() -> None:
    """Test that the default did not change for anyone not asking."""
    first = AsyncAppleAccount(a_provider())
    second = AsyncAppleAccount(a_provider())

    assert first.device_uuid != second.device_uuid
    assert first.local_user_uuid != second.local_user_uuid


def test_half_an_identity_is_refused_rather_than_completed_at_random() -> None:
    """Test that one id without the other does not silently mint the other."""
    # One field matching what was provisioned and one not reads as deliberate rather than
    # accidental, and is a shape no real client produces. Refusing is the cheap half.
    with pytest.raises(ValueError, match="both or neither"):
        AsyncAppleAccount(a_provider(), uid=A_UID)

    with pytest.raises(ValueError, match="both or neither"):
        AsyncAppleAccount(a_provider(), devid=A_DEVID)


def test_a_restored_account_keeps_the_ids_it_was_established_with() -> None:
    """Test that state wins over anything a caller passes."""
    # The session is bound to these. Letting an argument override what was restored is
    # how a working login becomes a second device in somebody's list.
    established = AsyncAppleAccount(a_provider(), uid=A_UID, devid=A_DEVID)
    state = established.to_json()

    restored = AsyncAppleAccount(
        a_provider(),
        state_info=state,
        uid="00000000-0000-0000-0000-000000000000",
        devid="11111111-1111-1111-1111-111111111111",
    )

    assert restored.local_user_uuid == A_UID
    assert restored.device_uuid == A_DEVID


def test_the_sync_account_passes_every_keyword_through() -> None:
    """Test that the wrapper does not force a caller to reach past it."""
    # A wrapper that accepts fewer keywords than what it wraps is a wrapper whose users
    # write to `_asyncacc` directly, which is the workaround this replaces.
    account = AppleAccount(a_provider(), uid=A_UID, devid=A_DEVID, device_name="Something")

    assert account.local_user_uuid == A_UID
    assert account.device_uuid == A_DEVID
    assert account.device_name == "Something"


def test_the_identity_and_the_serial_are_set_in_the_same_place() -> None:
    """Test that the two halves of what a device list shows travel together."""
    provider = a_provider(OTHER, serial="0OTHER00001")

    assert provider.serial == "0OTHER00001"
    assert provider.identity == OTHER

    headers = asyncio.run(provider.get_headers("user", "device", with_client_info=True))
    assert headers["X-Apple-I-SRL-NO"] == "0OTHER00001"
    assert headers["X-Mme-Client-Info"].startswith(OTHER.platform)
    assert CLIENT_SERIAL not in headers["X-Apple-I-SRL-NO"]
