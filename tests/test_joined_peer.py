"""
Tests for resuming as a peer that already joined.

A join spends a passcode once and puts a peer of this client's own in the circle. Without
something to keep, the next run has no way back to it and has to recover somebody else's
identity with a passcode again -- which is the cost joining exists to remove.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from findmy.keychain import JoinedPeer, PeerIdentity
from findmy.keychain.join import generate_identity
from findmy.keychain.session import RecoveredPeer


def an_identity():  # noqa: ANN201
    return generate_identity(machine_id="MACHINE-1", model_id="MacBookPro18,3", creation_time=1)


def test_a_joined_peer_is_the_three_things_the_reading_path_asks_for() -> None:
    identity = an_identity()

    peer = JoinedPeer.of(identity)

    assert peer.peer_id == identity.peer_id
    assert peer.signing_key() is identity.signing_key
    assert peer.encryption_key() is identity.encryption_key


def test_it_survives_being_stored_and_brought_back() -> None:
    # The whole feature: what a later run holds has to be the same peer, keys included.
    identity = an_identity()

    restored = JoinedPeer.from_json(json.loads(json.dumps(JoinedPeer.of(identity).to_json())))

    assert restored.peer_id == identity.peer_id
    for restored_key, original in (
        (restored.signing_key(), identity.signing_key),
        (restored.encryption_key(), identity.encryption_key),
    ):
        assert restored_key.private_numbers().private_value == (
            original.private_numbers().private_value
        )
        assert restored_key.curve.name == original.curve.name == "secp384r1"


def test_what_is_written_is_json_and_nothing_else() -> None:
    # It goes into an application's own secret store, so it has to survive a JSON round
    # trip rather than only a Python one.
    written = JoinedPeer.of(an_identity()).to_json()

    assert json.loads(json.dumps(written)) == written
    assert written["type"] == "joinedPeer"
    assert sorted(written) == ["encryption_key", "peer_id", "signing_key", "type"]


def test_the_bottle_entropy_is_not_in_it() -> None:
    # The two are different routes back to the same peer and neither replaces the other:
    # entropy recovers it through escrow, under a passcode. Keeping them in one blob
    # invites a caller to store this and think the escrow route is covered.
    written = json.dumps(JoinedPeer.of(an_identity()).to_json())

    assert "entropy" not in written.lower()


def test_something_that_is_not_a_joined_peer_is_refused() -> None:
    with pytest.raises(ValueError, match="Not a joined peer"):
        JoinedPeer.from_json({"type": "keypair"})  # pyright: ignore [reportArgumentType]


def test_a_missing_key_says_which_one() -> None:
    written = JoinedPeer.of(an_identity()).to_json()
    del written["encryption_key"]  # pyright: ignore [reportGeneralTypeIssues]

    with pytest.raises(ValueError, match="encryption_key"):
        JoinedPeer.from_json(written)


def test_a_key_of_the_wrong_kind_is_refused_here_rather_than_mid_exchange() -> None:
    # An RSA key would otherwise fail deep inside an ECDH, as something that reads like a
    # protocol error rather than like the wrong file.
    import base64

    from cryptography.hazmat.primitives import serialization

    rsa_key = base64.b64encode(
        rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    ).decode()
    written = JoinedPeer.of(an_identity()).to_json()
    written["signing_key"] = rsa_key

    with pytest.raises(TypeError, match="elliptic-curve"):
        JoinedPeer.from_json(written)


def test_both_kinds_of_peer_satisfy_the_one_the_reading_path_takes() -> None:
    """Test the protocol, which is what lets a joined peer go where a recovered one does."""
    # `RecoveredPeer` satisfying this is not something the code says anywhere -- it is
    # structural. A rename of any of the three breaks every call site at once, and this
    # is the test that says so in one place.
    assert isinstance(JoinedPeer.of(an_identity()), PeerIdentity)

    for name in ("peer_id", "signing_key", "encryption_key"):
        assert hasattr(RecoveredPeer, name), f"RecoveredPeer no longer offers {name}"


def test_the_reading_path_asks_for_nothing_a_joined_peer_cannot_give() -> None:
    """Test that no session method reaches for a field only a recovery produces."""
    # The reason a joined peer works at all: `record`, `fields`, `salt`, `keys` and
    # `bottle` are never read after construction. If one starts being read, a resumed
    # client breaks on a path that a recovered one exercises constantly -- so it would
    # ship.
    import inspect

    from findmy.keychain import session

    source = inspect.getsource(session.AsyncKeychainSession)

    for field in ("peer.record", "peer.fields", "peer.salt", "peer.keys", "peer.bottle"):
        assert field not in source, f"{field} is not something a joined peer has"


def test_a_joined_peer_is_what_a_completed_join_hands_back() -> None:
    """Test that `JoinOutcome.peer` is the thing to persist, without running a join."""
    import inspect

    from findmy.keychain.session import JoinOutcome

    described = inspect.getattr_static(JoinOutcome, "peer")
    assert isinstance(described, property)
    assert described.fget is not None
    assert "JoinedPeer.of(self.identity)" in inspect.getsource(described.fget)


def test_the_client_can_resume_without_a_passcode() -> None:
    """Test that the high-level reader exposes the resume path, not just the session."""
    import inspect

    from findmy.icloud import AsyncFindMyClient

    signature = inspect.signature(AsyncFindMyClient.resume)

    assert "passcode" not in signature.parameters
    assert list(signature.parameters) == ["self", "peer", "views"]


def test_a_peer_generated_here_is_not_a_key_a_curve_check_would_pass_by_accident() -> None:
    """Test the guard against a key of the right type but the wrong curve."""
    # P-256 loads as an EC key and would sail through the type check. Nothing rejects it
    # today, which is worth knowing rather than assuming: it fails later, in the exchange.
    written = JoinedPeer.of(an_identity()).to_json()
    restored = JoinedPeer.from_json(written)

    assert restored.signing_key().curve.name == "secp384r1"
    assert isinstance(restored.encryption_key(), ec.EllipticCurvePrivateKey)
