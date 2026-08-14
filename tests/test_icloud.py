"""
Tests for the assembly: that the pieces are connected correctly.

**This is not protocol validation, and cannot be.** Every fixture here is built from this
implementation's own understanding of the format, so a test that agrees with the reader
proves only that the two agree. That failure mode is not hypothetical -- the HMAC fixture
in `test_pcs.py` built its digest the same wrong way as the reader and could never have
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

from findmy.icloud import AsyncFindMyReader
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
    """An account that records which accessories it was asked to locate."""

    def __init__(self) -> None:
        self.asked: list[list[Any]] = []
        self.reports: dict[Any, Any] = {}

    async def fetch_location(self, keys):  # noqa: ANN001, ANN202
        self.asked.append(list(keys))
        return dict(self.reports)


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


def a_reader(keys: list[ec.EllipticCurvePrivateKey] | None = None) -> AsyncFindMyReader:
    supplied = keys if keys is not None else [ec.generate_private_key(ec.SECP256R1())]
    return AsyncFindMyReader(  # type: ignore[arg-type]
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
    reader = a_reader()

    assert await reader.records() == ["a-record"]
    assert reader.unlocked is False


@pytest.mark.asyncio
async def test_decrypting_without_keys_says_both_ways_to_get_them() -> None:
    reader = a_reader()

    with pytest.raises(KeychainSessionError, match="unlock"):
        await reader.accessories()

    with pytest.raises(KeychainSessionError, match="use_keys"):
        await reader.zone_keys()


@pytest.mark.asyncio
async def test_unlocking_recovers_then_reads_the_views_in_that_order() -> None:
    reader = a_reader()

    await reader.unlock("a-record", "1234")  # type: ignore[arg-type]

    names = [name for name, _ in reader.session.calls]  # type: ignore[attr-defined]
    assert names == ["recover", "pcs_keys"]


@pytest.mark.asyncio
async def test_unlocking_reads_both_views_by_default() -> None:
    # Stage 5 §2 says both must be synced before decryption can begin.
    reader = a_reader()

    await reader.unlock("a-record", "1234")  # type: ignore[arg-type]

    _, (_, views) = reader.session.calls[1]  # type: ignore[attr-defined]
    assert views == ("Manatee", "ProtectedCloudStorage")


@pytest.mark.asyncio
async def test_the_passcode_reaches_recovery_and_nothing_else() -> None:
    reader = a_reader()

    await reader.unlock("a-record", "the-passcode")  # type: ignore[arg-type]

    carrying = [call for call in reader.session.calls if "the-passcode" in repr(call)]  # type: ignore[attr-defined]
    assert [name for name, _ in carrying] == ["recover"]


@pytest.mark.asyncio
async def test_keys_kept_from_an_earlier_run_skip_the_passcode_entirely() -> None:
    # The whole point of returning them: the passcode is a one-time cost.
    keys = [ec.generate_private_key(ec.SECP256R1())]
    reader = a_reader()

    reader.use_keys(keys)

    assert reader.unlocked is True
    assert await reader.accessories() == ["an-accessory"]
    assert reader.session.calls == []  # type: ignore[attr-defined]


# --------------------------------------------------------------------------------------
# Two levels, and the half each one takes
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_zone_is_unwrapped_with_the_keychain_keys() -> None:
    # Not with a record's, and not with what the zone itself yields. Handing the wrong
    # level presents as every record being protected for somebody else.
    keys = [ec.generate_private_key(ec.SECP256R1())]
    reader = a_reader()
    reader.use_keys(keys)

    await reader.zone_keys()

    (name, handed), = reader.store.calls  # type: ignore[attr-defined]
    assert name == "zone_keys"
    assert handed == keys


@pytest.mark.asyncio
async def test_the_zone_keys_are_what_the_zone_yields_not_what_opened_it() -> None:
    keys = [ec.generate_private_key(ec.SECP256R1())]
    reader = a_reader()
    reader.use_keys(keys)

    assert await reader.zone_keys() == reader.store.zone  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_the_zone_is_unwrapped_once_and_then_remembered() -> None:
    reader = a_reader()
    reader.use_keys([ec.generate_private_key(ec.SECP256R1())])

    await reader.zone_keys()
    await reader.zone_keys()

    assert [name for name, _ in reader.store.calls] == ["zone_keys"]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_new_keys_discard_the_zone_read_under_the_old_ones() -> None:
    # Otherwise a caller that re-unlocks keeps decrypting with keys from a zone it no
    # longer holds the opener for, and nothing says so.
    reader = a_reader()
    reader.use_keys([ec.generate_private_key(ec.SECP256R1())])
    await reader.zone_keys()

    reader.use_keys([ec.generate_private_key(ec.SECP256R1())])
    await reader.zone_keys()

    assert [name for name, _ in reader.store.calls] == ["zone_keys", "zone_keys"]  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_accessories_are_fetched_with_the_keychain_keys_not_the_zone_ones() -> None:
    # The store does both levels itself, so it takes the keychain keys. Handing it the
    # zone's would unwrap the zone with keys the zone produced.
    keys = [ec.generate_private_key(ec.SECP256R1())]
    reader = a_reader()
    reader.use_keys(keys)

    await reader.accessories()

    (name, (handed, _)), = reader.store.calls  # type: ignore[attr-defined]
    assert name == "fetch_accessories"
    assert handed == keys


# --------------------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_continuation_token_reaches_the_store() -> None:
    reader = a_reader()
    reader.use_keys([ec.generate_private_key(ec.SECP256R1())])

    await reader.records(continuation_token=b"tok")
    await reader.accessories(continuation_token=b"tok")

    assert reader.store.calls[0] == ("fetch_records", b"tok")  # type: ignore[attr-defined]
    assert reader.store.calls[1][1][1] == b"tok"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_closing_closes_both_halves() -> None:
    reader = a_reader()

    async with reader:
        pass

    assert reader.session.closed is True  # type: ignore[attr-defined]
    assert reader.store.closed is True  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_the_held_keys_are_handed_out_as_a_copy() -> None:
    # A caller mutating what it was given must not empty the reader.
    reader = a_reader()
    reader.use_keys([ec.generate_private_key(ec.SECP256R1())])

    reader.keychain_keys.clear()

    assert reader.unlocked is True


# --------------------------------------------------------------------------------------
# Locations, which are a different service from everything above
# --------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_locating_asks_the_network_about_the_accessories_it_was_given() -> None:
    reader = a_reader()
    reader.use_keys([ec.generate_private_key(ec.SECP256R1())])

    await reader.locations(["tag-a", "tag-b"])  # type: ignore[list-item]

    assert reader._account.asked == [["tag-a", "tag-b"]]  # type: ignore[attr-defined]  # noqa: SLF001


@pytest.mark.asyncio
async def test_locating_with_no_argument_fetches_the_accessories_first() -> None:
    reader = a_reader()
    reader.use_keys([ec.generate_private_key(ec.SECP256R1())])

    await reader.locations()

    assert reader._account.asked == [["an-accessory"]]  # type: ignore[attr-defined]  # noqa: SLF001


@pytest.mark.asyncio
async def test_an_accessory_the_network_has_not_seen_is_present_and_none() -> None:
    # Omitting it would make "never seen" indistinguishable from "not asked about".
    reader = a_reader()
    reader.use_keys([ec.generate_private_key(ec.SECP256R1())])
    reader._account.reports = {"tag-a": "a-report"}  # type: ignore[attr-defined]  # noqa: SLF001

    located = await reader.locations(["tag-a", "tag-b"])  # type: ignore[list-item]

    assert located == {"tag-a": "a-report", "tag-b": None}


@pytest.mark.asyncio
async def test_locating_nothing_asks_nothing() -> None:
    reader = a_reader()
    reader.use_keys([ec.generate_private_key(ec.SECP256R1())])

    assert await reader.locations([]) == {}
    assert reader._account.asked == []  # type: ignore[attr-defined]  # noqa: SLF001
