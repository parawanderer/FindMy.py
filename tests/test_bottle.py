"""Tests for a bottled peer's key derivation (Stage 3 §6.7 step 2)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from findmy.keychain import bottle
from findmy.keychain.bottle import BottleError, derive_bottle_keys, keys_match_bottle

ENTROPY = bytes(range(64))
ADSID = "1234567890"


def hkdf(info: bytes, length: int, *, adsid: str = ADSID, entropy: bytes = ENTROPY) -> bytes:
    return HKDF(
        algorithm=hashes.SHA384(),
        length=length,
        salt=adsid.encode(),
        info=info,
    ).derive(entropy)


def test_the_symmetric_key_is_hkdf_sha384_salted_with_the_account_id() -> None:
    keys = derive_bottle_keys(ENTROPY, ADSID)

    assert keys.symmetric == hkdf(b"Escrow Symmetric Key", 32)
    assert len(keys.symmetric) == 32


def test_the_info_strings_are_verbatim() -> None:
    assert bottle.INFO_SYMMETRIC == b"Escrow Symmetric Key"
    assert bottle.INFO_SIGNING == b"Escrow Signing Private Key"
    assert bottle.INFO_ENCRYPTION == b"Escrow Encryption Private Key"


def test_the_ec_keys_ask_for_sixty_four_bits_more_than_the_order_needs() -> None:
    # FIPS 186-4 B.5.1 extra random bits: 384 + 64 = 448 bits = 56 bytes.
    assert bottle.EC_KEY_MATERIAL_LENGTH == 56
    assert bottle.EC_KEY_MATERIAL_LENGTH * 8 == 384 + 64


def test_the_ec_scalars_follow_the_extra_random_bits_method() -> None:
    keys = derive_bottle_keys(ENTROPY, ADSID)
    order = bottle._P384_ORDER  # noqa: SLF001

    for info, key in (
        (b"Escrow Signing Private Key", keys.signing),
        (b"Escrow Encryption Private Key", keys.encryption),
    ):
        material = hkdf(info, 56)
        expected = (int.from_bytes(material, "big") % (order - 1)) + 1

        assert key.private_numbers().private_value == expected


def test_the_extra_random_bits_method_is_not_a_plain_modulo() -> None:
    # The off-by-one is what keeps zero out of the range.
    order = bottle._P384_ORDER  # noqa: SLF001
    material = (order - 1).to_bytes(56, "big")

    assert bottle._scalar_from_extra_random_bits(material) == 1  # noqa: SLF001


def test_the_derived_keys_are_on_p384_not_p256() -> None:
    keys = derive_bottle_keys(ENTROPY, ADSID)

    assert keys.signing.curve.name == "secp384r1"
    assert keys.encryption.curve.name == "secp384r1"


def test_signing_and_encryption_keys_differ() -> None:
    # Only their info strings distinguish them, so a copy-paste error would show here.
    keys = derive_bottle_keys(ENTROPY, ADSID)

    assert keys.signing.private_numbers().private_value != (
        keys.encryption.private_numbers().private_value
    )


def test_two_accounts_recovering_the_same_entropy_derive_different_keys() -> None:
    # The salt is the account identifier, not a random value, and this is the point.
    ours = derive_bottle_keys(ENTROPY, "1111111111")
    theirs = derive_bottle_keys(ENTROPY, "2222222222")

    assert ours.symmetric != theirs.symmetric
    assert ours.signing.private_numbers().private_value != (
        theirs.signing.private_numbers().private_value
    )


def test_empty_entropy_is_refused() -> None:
    with pytest.raises(BottleError, match="entropy"):
        derive_bottle_keys(b"", ADSID)


def test_a_missing_account_identifier_is_refused_rather_than_salted_with_nothing() -> None:
    with pytest.raises(BottleError, match="salt"):
        derive_bottle_keys(ENTROPY, "")


def test_key_material_of_the_wrong_length_is_refused() -> None:
    with pytest.raises(BottleError, match="56 bytes"):
        bottle._scalar_from_extra_random_bits(b"\x01" * 48)  # noqa: SLF001


def test_derived_keys_are_checked_against_the_ones_the_bottle_carries() -> None:
    # The first two of the four verifications. Both failing means the passcode produced
    # the wrong entropy, which is a different problem from a bad bottle.
    keys = derive_bottle_keys(ENTROPY, ADSID)

    def encoded(key: ec.EllipticCurvePrivateKey) -> bytes:
        return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    assert keys_match_bottle(keys, encoded(keys.signing), encoded(keys.encryption)) is True

    other = ec.generate_private_key(ec.SECP384R1())
    assert keys_match_bottle(keys, encoded(other), encoded(keys.encryption)) is False
    assert keys_match_bottle(keys, encoded(keys.signing), encoded(other)) is False


def test_the_module_offers_no_way_to_establish_a_circle() -> None:
    # `establish` and `joinWithVoucher` differ by one branch and are catastrophically
    # different: the first forms a new circle, destroying the user's existing trust.
    import findmy.keychain.cuttlefish as cuttlefish  # noqa: PLC0415

    for module in (bottle, cuttlefish):
        assert not [name for name in dir(module) if "establish" in name.lower()]


# --------------------------------------------------------------------------------------
# Opening a bottle (§6.7 steps 3 and 4)
# --------------------------------------------------------------------------------------


def seal_bottle(keys, contents: bytes, *, escrow_keys: bool = True):  # noqa: ANN001, ANN201
    """Seal a bottle the way §6.7 step 4 says one is sealed."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: PLC0415

    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    iv = b"\x07" * 16
    encryptor = Cipher(algorithms.AES(keys.symmetric), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(contents) + encryptor.finalize()

    inner = cf.OTBottle(
        peer_id="PEER-1",
        bottle_id="BOTTLE-1",
        ciphertext=cf.OTAuthenticatedCiphertext(
            ciphertext=ciphertext,
            authentication_code=encryptor.tag,
            initialization_vector=iv,
        ),
    )
    if escrow_keys:
        encodings = bottle.public_key_encodings(keys.signing)
        inner.escrowed_signing_key = encodings["x962-uncompressed"]
        inner.escrowed_encryption_key = bottle.public_key_encodings(keys.encryption)[
            "x962-uncompressed"
        ]

    return cf.Bottle(bottle=inner.SerializeToString(), bottle_id="BOTTLE-1")


def internal_bottle() -> bytes:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    return cf.OTInternalBottle(
        signing_key=cf.OTPrivateKey(key_type=1, key_data=b"S" * 48),
        encryption_key=cf.OTPrivateKey(key_type=2, key_data=b"E" * 48),
    ).SerializeToString()


def test_a_bottle_opens_to_the_sponsors_private_keys() -> None:
    keys = derive_bottle_keys(ENTROPY, ADSID)
    sealed = seal_bottle(keys, internal_bottle())

    opened = bottle.open_bottle(sealed, keys)

    assert opened.signing_key == b"S" * 48
    assert opened.encryption_key == b"E" * 48
    assert opened.key_encoding == "x962-uncompressed"


def test_the_tag_travels_beside_the_ciphertext_not_appended_to_it() -> None:
    # Appending it, as most constructions do, would leave sixteen stray bytes on the
    # plaintext and the protobuf parse would fail rather than the tag check.
    keys = derive_bottle_keys(ENTROPY, ADSID)
    sealed = seal_bottle(keys, internal_bottle())

    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    inner = cf.OTBottle.FromString(sealed.bottle)
    assert len(inner.ciphertext.authentication_code) == 16
    assert len(inner.ciphertext.initialization_vector) == 16


def test_a_wrong_passcodes_keys_are_caught_before_decryption_is_attempted() -> None:
    # The escrowed-key check says *which* thing is wrong: a mismatch is a wrong passcode,
    # where a tag failure with matching keys would be a bottle that is not what it claims.
    keys = derive_bottle_keys(ENTROPY, ADSID)
    sealed = seal_bottle(keys, internal_bottle())
    wrong = derive_bottle_keys(b"different entropy entirely", ADSID)

    with pytest.raises(BottleError, match="wrong entropy"):
        bottle.open_bottle(sealed, wrong)


def test_a_bottle_that_does_not_authenticate_is_reported_differently() -> None:
    keys = derive_bottle_keys(ENTROPY, ADSID)
    sealed = seal_bottle(keys, internal_bottle())

    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    inner = cf.OTBottle.FromString(sealed.bottle)
    inner.ciphertext.ciphertext = bytes(len(inner.ciphertext.ciphertext))
    sealed.bottle = inner.SerializeToString()

    with pytest.raises(BottleError, match="not what it claims"):
        bottle.open_bottle(sealed, keys)


def test_an_empty_bottle_is_refused() -> None:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    with pytest.raises(BottleError, match="no sealed contents"):
        bottle.open_bottle(cf.Bottle(), derive_bottle_keys(ENTROPY, ADSID))


def test_the_key_encoding_that_matched_is_reported() -> None:
    # The specification does not say which encoding escrowed public keys use, so one live
    # bottle settles it and the answer is worth carrying out.
    keys = derive_bottle_keys(ENTROPY, ADSID)
    opened = bottle.open_bottle(seal_bottle(keys, internal_bottle()), keys)

    assert opened.key_encoding in bottle.public_key_encodings(keys.signing)


def test_the_salt_is_found_by_checking_against_the_bottle() -> None:
    # An account carries more than one identifier that looks like an account number, and
    # the specification names one of them. The check is free, offline and unambiguous, so
    # trying the candidates beats picking one and reporting a wrong passcode.
    keys = derive_bottle_keys(ENTROPY, "the-real-adsid")
    encodings = bottle.public_key_encodings

    found, salt = bottle.find_bottle_keys(
        ENTROPY,
        ["wrong-one", "the-real-adsid", "another"],
        encodings(keys.signing)["x962-uncompressed"],
        encodings(keys.encryption)["x962-uncompressed"],
    )

    assert salt == "the-real-adsid"
    assert found.symmetric == keys.symmetric


def test_no_matching_salt_reports_the_escrowed_key_size() -> None:
    keys = derive_bottle_keys(ENTROPY, ADSID)
    escrowed = bottle.public_key_encodings(keys.signing)["der-spki"]

    with pytest.raises(BottleError, match="120 bytes each"):
        bottle.find_bottle_keys(ENTROPY, ["nope"], escrowed, escrowed)


def test_empty_and_duplicate_salts_are_skipped() -> None:
    keys = derive_bottle_keys(ENTROPY, ADSID)
    encodings = bottle.public_key_encodings

    found, salt = bottle.find_bottle_keys(
        ENTROPY,
        ["", ADSID, ADSID],
        encodings(keys.signing)["x962-uncompressed"],
        encodings(keys.encryption)["x962-uncompressed"],
    )

    assert salt == ADSID
    assert found.symmetric == keys.symmetric


def test_a_peer_key_is_a_public_point_followed_by_its_scalar() -> None:
    # [observed] 145 bytes: a 97-byte uncompressed P-384 point, then a 48-byte scalar.
    # Not DER, not PKCS#8.
    key = ec.generate_private_key(ec.SECP384R1())
    point = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    scalar = key.private_numbers().private_value.to_bytes(48, "big")

    parsed = bottle.parse_peer_private_key(point + scalar)

    assert len(point + scalar) == 145
    assert parsed.private_numbers().private_value == key.private_numbers().private_value


def test_the_two_halves_of_a_peer_key_check_each_other() -> None:
    # Deriving the public key from the scalar must reproduce the point beside it, so a
    # misread layout fails here rather than at a signature that will not verify.
    key = ec.generate_private_key(ec.SECP384R1())
    other = ec.generate_private_key(ec.SECP384R1())

    mismatched = other.public_key().public_bytes(
        Encoding.X962,
        PublicFormat.UncompressedPoint,
    ) + key.private_numbers().private_value.to_bytes(48, "big")

    with pytest.raises(BottleError, match="do not agree"):
        bottle.parse_peer_private_key(mismatched)


def test_a_peer_key_of_the_wrong_length_names_the_expected_one() -> None:
    with pytest.raises(BottleError, match="145 bytes"):
        bottle.parse_peer_private_key(b"\x04" * 97)


# --------------------------------------------------------------------------------------
# Creating a bottle (§6.9.3)
# --------------------------------------------------------------------------------------


def _p384():
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    return ec.generate_private_key(ec.SECP384R1())


def _sealed(entropy: bytes = b"\x33" * 72, adsid: str = "1234567890"):
    from findmy.keychain.bottle import seal_bottle  # noqa: PLC0415

    signing, encryption = _p384(), _p384()
    created = seal_bottle(
        peer_id="SHA256:new",
        signing_key=signing,
        encryption_key=encryption,
        entropy=entropy,
        adsid=adsid,
        bottle_id="4A1E5B9C-0000-4000-8000-000000000000",
    )
    return created, signing, encryption


def test_a_sealed_bottle_opens_with_nothing_but_its_entropy_and_the_account() -> None:
    # The whole point of the bottle: a future recovery has the passcode, which yields the
    # entropy, and nothing else. If sealing and opening disagree anywhere -- the info
    # strings, the 32-byte IV, the detached tag -- this yields nothing.
    from findmy.keychain.bottle import derive_bottle_keys, open_bottle  # noqa: PLC0415

    created, signing, encryption = _sealed()

    opened = open_bottle(created.bottle, derive_bottle_keys(created.entropy, "1234567890"))

    assert opened.signing().private_numbers() == signing.private_numbers()
    assert opened.encryption().private_numbers() == encryption.private_numbers()
    assert opened.escrowed_key_verified
    assert opened.key_encoding == "der-spki"


def test_a_bottle_is_signed_by_the_peer_it_belongs_to() -> None:
    # §6.7 step 3 calls the second signature the sponsoring peer's, which is what it is
    # when reading one. The rule is the peer the bottle is for -- this client.
    from findmy.keychain.bottle import derive_bottle_keys, open_bottle  # noqa: PLC0415
    from findmy.keychain.join import public_spki  # noqa: PLC0415
    from findmy.keychain.peers import Peer  # noqa: PLC0415

    created, signing, _ = _sealed()
    itself = Peer(
        hash="SHA256:new",
        signing_key=public_spki(signing.public_key()),
        encryption_key=b"",
        machine_id="",
        model_id="",
    )

    opened = open_bottle(
        created.bottle,
        derive_bottle_keys(created.entropy, "1234567890"),
        sponsor=itself,
    )

    assert opened.sponsor_verified


def test_the_wrong_account_does_not_open_it() -> None:
    # The adsid is the HKDF salt, so two accounts with the same entropy derive different
    # keys. That is what the salt is for.
    from findmy.keychain.bottle import BottleError, derive_bottle_keys, open_bottle  # noqa: PLC0415

    created, _, _ = _sealed()

    with pytest.raises(BottleError, match="do not match"):
        open_bottle(created.bottle, derive_bottle_keys(created.entropy, "9999999999"))


def test_the_seal_uses_a_thirty_two_byte_iv() -> None:
    # Not 12, not 16 -- the two a GCM implementation offers by default.
    created, _, _ = _sealed()

    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    inner = cf.OTBottle()
    inner.ParseFromString(created.bottle.bottle)

    assert len(inner.ciphertext.initialization_vector) == 32
    assert len(inner.ciphertext.authentication_code) == 16


def test_the_private_keys_are_point_then_scalar_at_key_type_one() -> None:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415
    from findmy.keychain.bottle import derive_bottle_keys  # noqa: PLC0415
    from findmy.keychain.bottle import open_bottle as _open  # noqa: PLC0415

    created, signing, _ = _sealed()
    opened = _open(created.bottle, derive_bottle_keys(created.entropy, "1234567890"))

    assert opened.signing_key_type == 1
    assert len(opened.signing_key) == 97 + 48
    assert opened.signing_key[0] == 0x04
    assert cf.OTPrivateKey  # the message this came from


def test_the_escrow_record_and_the_bottle_share_one_derivation() -> None:
    # escrowedSPKI is OTBottle.escrowedSigningKey, and both come from the same entropy.
    # Two calls that each generate their own would enrol and join cleanly and recover to
    # a peer that does not exist.
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    created, _, _ = _sealed()

    inner = cf.OTBottle()
    inner.ParseFromString(created.bottle.bottle)

    assert created.escrowed_spki == inner.escrowed_signing_key
    assert created.bottle_id == inner.bottle_id == created.bottle.bottle_id
