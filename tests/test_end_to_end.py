"""
The whole decrypt path, over a synthetic account, in both shapes an account comes in.

**What this is for.** Somebody adding support for a new device, or changing a layer, can
run this and see that an account shaped like a real one still yields accessories. Nothing
else here spans more than one hop.

**Two variants, because accounts genuinely differ.** The maintainer's escrow labels already
carry the peer hash the trust circle knows; on the accounts in
`parawanderer/OpenTagViewer#140` they do not. That single difference decided whether *any*
keys were recovered, and neither shape is more correct than the other -- so both are run
through the same pipeline and both have to arrive at the same accessories.

**It does not prove Apple agrees.** The data is generated, so this proves the pipeline
handles a shape; the `[observed]` markers are the only things here that claim a shape is
real. See `tests/README.md`.
"""

from __future__ import annotations

import pytest
from fake_account import (
    AGREEING_LABEL_SUFFIX,
    CIRCLE_PEER_ID,
    DIVERGENT_LABEL_SUFFIX,
    Accessory,
    a_whole_account,
)

ACCOUNT_SHAPES = [
    pytest.param(AGREEING_LABEL_SUFFIX, id="label-suffix-is-the-peer-hash"),
    pytest.param(DIVERGENT_LABEL_SUFFIX, id="label-suffix-is-something-else"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("label_suffix", ACCOUNT_SHAPES)
async def test_an_account_yields_its_accessories(
    monkeypatch: pytest.MonkeyPatch,
    label_suffix: str,
) -> None:
    """Test the whole path: a recovered peer to named accessories, in both shapes."""
    account = a_whole_account(
        [
            Accessory(name="Backpack", identifier="BEACON-1"),
            Accessory(name="Keys", identifier="BEACON-2", emoji="\U0001f511"),
        ],
        label_suffix=label_suffix,
    )
    account.use_the_view(monkeypatch)

    found = await account.accessories()

    assert sorted(a.name or "" for a in found) == ["Backpack", "Keys"]
    assert {a.model for a in found} == {"AirTag1,1"}
    # And the keys are real ones: a master key that generates advertising keys is the
    # difference between decrypting a record and being able to find the thing.
    assert all(len(a.keys_at(0)) == 3 for a in found)


@pytest.mark.asyncio
@pytest.mark.parametrize("label_suffix", ACCOUNT_SHAPES)
async def test_the_keychain_keys_arrive_before_anything_is_decrypted(
    monkeypatch: pytest.MonkeyPatch,
    label_suffix: str,
) -> None:
    """Test the front half alone, so a failure says which half broke."""
    # Worth separating: "no accessories" is the same symptom whether the shares never
    # arrived or the records would not decrypt, and those lead in opposite directions.
    account = a_whole_account(label_suffix=label_suffix)
    account.use_the_view(monkeypatch)

    keys = await account.keychain_keys()

    assert len(keys) == 1
    assert account.circle.cuttlefish.asked_for == [CIRCLE_PEER_ID]


@pytest.mark.asyncio
async def test_an_account_whose_labels_diverge_is_asked_about_by_its_circle_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test #140 from the outside: the label is never what reaches the wire."""
    account = a_whole_account(label_suffix=DIVERGENT_LABEL_SUFFIX)
    account.use_the_view(monkeypatch)

    await account.accessories()

    assert account.circle.cuttlefish.asked_for == [CIRCLE_PEER_ID]
    assert DIVERGENT_LABEL_SUFFIX not in account.circle.cuttlefish.asked_for
    # The label is still what the record is addressed by; the two are different questions.
    assert account.circle.peer.record.peer_id == DIVERGENT_LABEL_SUFFIX


@pytest.mark.asyncio
async def test_an_accessory_with_no_name_record_still_arrives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test the shape where a beacon has no naming record beside it."""
    # A master beacon and its name live in two records joined on `associatedBeacon`, and
    # the join is not guaranteed -- so an accessory with no name must not take the others
    # with it.
    account = a_whole_account(
        [
            Accessory(name="Backpack", identifier="BEACON-1"),
            Accessory(identifier="BEACON-2", naming_record=False),
        ],
    )
    account.use_the_view(monkeypatch)

    found = await account.accessories()

    assert len(found) == 2
    assert "Backpack" in {a.name for a in found}


@pytest.mark.asyncio
async def test_an_accessory_that_declares_no_model_still_arrives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test the shape a committed macOS export actually has."""
    # **[observed]** The AirTag in the committed export carries `model=''`. A pipeline that
    # requires the field drops the accessory rather than reporting an empty model.
    account = a_whole_account([Accessory(name="Backpack", model=None)])
    account.use_the_view(monkeypatch)

    found = await account.accessories()

    assert len(found) == 1
    assert found[0].name == "Backpack"


@pytest.mark.asyncio
async def test_an_account_with_nothing_in_it_is_not_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that an account holding no accessories reports none rather than failing."""
    account = a_whole_account([])
    account.use_the_view(monkeypatch)

    assert await account.accessories() == []
