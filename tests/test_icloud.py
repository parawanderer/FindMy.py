"""
Tests for the assembly: that the pieces are connected correctly.

**This is not protocol validation, and cannot be.** Every fixture here is built from this
implementation's own understanding of the format, so a test that agrees with the client
proves only that the two agree. That failure mode is not hypothetical -- the HMAC fixture
in `test_pcs.py` built its digest the same wrong way as the client and could never have
caught the bug it was written around, and several key-blob tests asserted a *search* for a
layout that the specification later stated outright.

So what these check is the wiring, which is the part a fixture can be an honest oracle
for: the two unwrap levels happening in the right order, the right half of each being
taken, keys flowing between the layers, and the containers being addressed to the right
services. A green run here means the assembly is intact. It says nothing about whether the
assembly is correct.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from findmy.icloud import AsyncFindMyClient
from findmy.keychain.session import KeychainSessionError


class FakeSession:
    """A keychain session that records what it was asked for."""

    def __init__(self, keys: list[ec.EllipticCurvePrivateKey]) -> None:
        self.keys = keys
        self.calls: list[tuple[str, Any]] = []
        self.closed = False

    async def recovery_options(self, *, refresh: bool = False):  # noqa: ANN202
        self.calls.append(("recovery_options", refresh))
        return "the-options"

    async def recover(self, record, passcode):  # noqa: ANN001, ANN202
        self.calls.append(("recover", (record, passcode)))
        return "the-peer"

    async def pcs_keys(self, peer, *, views):  # noqa: ANN001, ANN202
        self.calls.append(("pcs_keys", (peer, tuple(views))))
        return self.keys

    async def close(self) -> None:
        self.closed = True


class FakeAccount:
    """The account. Held only so the client can hand it back; nothing here calls it."""


class FakeStore:
    """A beacon store that records which keys it was handed."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.closed = False
        self.zone = [ec.generate_private_key(ec.SECP256R1())]

    async def zone_keys(self, service_keys):  # noqa: ANN001, ANN202
        self.calls.append(("zone_keys", list(service_keys)))
        return self.zone

    async def fetch_records(self, *, continuation_token=None):  # noqa: ANN001, ANN202
        self.calls.append(("fetch_records", continuation_token))
        return ["a-record"]

    async def fetch_accessories(self, service_keys, *, continuation_token=None):  # noqa: ANN001, ANN202
        self.calls.append(("fetch_accessories", (list(service_keys), continuation_token)))
        return ["an-accessory"]

    async def close(self) -> None:
        self.closed = True


def a_client(keys: list[ec.EllipticCurvePrivateKey] | None = None) -> AsyncFindMyClient:
    supplied = keys if keys is not None else [ec.generate_private_key(ec.SECP256R1())]
    return AsyncFindMyClient(  # type: ignore[arg-type]
        FakeAccount(),
        FakeSession(supplied),
        FakeStore(),
    )


# --------------------------------------------------------------------------------------
# Keys have to be present, and they are the keychain's rather than a record's
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_records_can_be_fetched_with_no_keys_at_all() -> None:
    # Fetching and decrypting are cleanly separable, and this is the half a later run
    # repeats without a passcode, a keychain or a trust circle.
    client = a_client()

    assert await client.records() == ["a-record"]
    assert client.unlocked is False


@pytest.mark.asyncio
async def test_decrypting_without_keys_says_both_ways_to_get_them() -> None:
    client = a_client()

    with pytest.raises(KeychainSessionError, match="unlock"):
        await client.accessories()

    with pytest.raises(KeychainSessionError, match="use_keys"):
        await client.zone_keys()


@pytest.mark.asyncio
async def test_unlocking_recovers_then_reads_the_views_in_that_order() -> None:
    client = a_client()

    await client.unlock("a-record", "1234")  # type: ignore[arg-type]

    names = [name for name, _ in client.session.calls]  # type: ignore[attr-defined]
    assert names == ["recover", "pcs_keys"]


@pytest.mark.asyncio
async def test_unlocking_reads_both_views_by_default() -> None:
    # Stage 5 §2 says both must be synced before decryption can begin.
    client = a_client()

    await client.unlock("a-record", "1234")  # type: ignore[arg-type]

    _, (_, views) = client.session.calls[1]  # type: ignore[attr-defined]
    assert views == ("Manatee", "ProtectedCloudStorage")


@pytest.mark.asyncio
async def test_the_passcode_reaches_recovery_and_nothing_else() -> None:
    client = a_client()

    await client.unlock("a-record", "the-passcode")  # type: ignore[arg-type]

    carrying = [call for call in client.session.calls if "the-passcode" in repr(call)]  # type: ignore[attr-defined]
    assert [name for name, _ in carrying] == ["recover"]


@pytest.mark.asyncio
async def test_keys_kept_from_an_earlier_run_skip_the_passcode_entirely() -> None:
    # The whole point of returning them: the passcode is a one-time cost.
    keys = [ec.generate_private_key(ec.SECP256R1())]
    client = a_client()

    client.use_keys(keys)

    assert client.unlocked is True
    assert await client.accessories() == ["an-accessory"]
    assert client.session.calls == []  # type: ignore[attr-defined]


# --------------------------------------------------------------------------------------
# Two levels, and the half each one takes
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_zone_is_unwrapped_with_the_keychain_keys() -> None:
    # Not with a record's, and not with what the zone itself yields. Handing the wrong
    # level presents as every record being protected for somebody else.
    keys = [ec.generate_private_key(ec.SECP256R1())]
    client = a_client()
    client.use_keys(keys)

    await client.zone_keys()

    (name, handed), = client.store.calls  # type: ignore[attr-defined]
    assert name == "zone_keys"
    assert handed == keys


@pytest.mark.asyncio
async def test_the_zone_keys_are_what_the_zone_yields_not_what_opened_it() -> None:
    keys = [ec.generate_private_key(ec.SECP256R1())]
    client = a_client()
    client.use_keys(keys)

    assert await client.zone_keys() == client.store.zone  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_the_zone_is_unwrapped_once_and_then_remembered() -> None:
    client = a_client()
    client.use_keys([ec.generate_private_key(ec.SECP256R1())])

    await client.zone_keys()
    await client.zone_keys()

    assert [name for name, _ in client.store.calls] == ["zone_keys"]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_new_keys_discard_the_zone_read_under_the_old_ones() -> None:
    # Otherwise a caller that re-unlocks keeps decrypting with keys from a zone it no
    # longer holds the opener for, and nothing says so.
    client = a_client()
    client.use_keys([ec.generate_private_key(ec.SECP256R1())])
    await client.zone_keys()

    client.use_keys([ec.generate_private_key(ec.SECP256R1())])
    await client.zone_keys()

    assert [name for name, _ in client.store.calls] == ["zone_keys", "zone_keys"]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_accessories_are_fetched_with_the_keychain_keys_not_the_zone_ones() -> None:
    # The store does both levels itself, so it takes the keychain keys. Handing it the
    # zone's would unwrap the zone with keys the zone produced.
    keys = [ec.generate_private_key(ec.SECP256R1())]
    client = a_client()
    client.use_keys(keys)

    await client.accessories()

    (name, (handed, _)), = client.store.calls  # type: ignore[attr-defined]
    assert name == "fetch_accessories"
    assert handed == keys


# --------------------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_continuation_token_reaches_the_store() -> None:
    client = a_client()
    client.use_keys([ec.generate_private_key(ec.SECP256R1())])

    await client.records(continuation_token=b"tok")
    await client.accessories(continuation_token=b"tok")

    assert client.store.calls[0] == ("fetch_records", b"tok")  # type: ignore[attr-defined]
    assert client.store.calls[1][1][1] == b"tok"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_closing_closes_both_halves() -> None:
    client = a_client()

    async with client:
        pass

    assert client.session.closed is True  # type: ignore[attr-defined]
    assert client.store.closed is True  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_the_held_keys_are_handed_out_as_a_copy() -> None:
    # A caller mutating what it was given must not empty the client.
    client = a_client()
    client.use_keys([ec.generate_private_key(ec.SECP256R1())])

    client.keychain_keys.clear()

    assert client.unlocked is True
