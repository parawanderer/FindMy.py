"""
Tests for escrow recovery (Stage 3 §6.1–§6.5).

The exchange itself needs a real account and a real device passcode, so what is proved
here is everything around it: the framing, the header rewrites, the cipher selection, the
two uses of the passcode, and the SRP parameterisation that fails identically to a wrong
passcode when it is wrong.
"""

from __future__ import annotations

import hashlib

import pytest
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from findmy.keychain import recovery
from findmy.keychain.escrow import build_keyvault_message
from findmy.keychain.recovery import (
    RecoveryChallenge,
    RecoveryError,
    build_recovery_proof,
    parse_challenge,
    unwrap_inner_blob,
    unwrap_outer_blob,
)


def a_challenge(club_type_id: int | None = None) -> RecoveryChallenge:
    return RecoveryChallenge(
        label="com.apple.icdp.record.PEER",
        transaction_id="TX",
        prefix=b"\x01\x02\x03\x04",
        header=bytes(range(24)),
        exchange_token=bytes(range(8)),
        salt=b"salt" * 4,
        server_public=b"B" * 256,
        dsid="1234567890",
        club_type_id=club_type_id,
    )


# --------------------------------------------------------------------------------------
# SRP parameterisation -- the deviation that fails like a wrong passcode
# --------------------------------------------------------------------------------------


def test_the_identity_is_included_in_the_private_key_hash_during_recovery() -> None:
    # Recovery is standard SRP-6a. Grand Slam authentication omits the identity, the
    # library carries that as a process-global, and findmy.reports.account sets it the
    # other way at import -- so getting this wrong is the default, not an accident.
    assert srp._no_username_in_x is True  # noqa: SLF001 -- set by the account module

    with recovery._identity_in_private_key():  # noqa: SLF001
        assert srp._no_username_in_x is False  # noqa: SLF001

    assert srp._no_username_in_x is True  # noqa: SLF001


def test_the_global_is_restored_even_when_the_exchange_fails() -> None:
    with pytest.raises(RuntimeError), recovery._identity_in_private_key():  # noqa: SLF001
        msg = "boom"
        raise RuntimeError(msg)

    assert srp._no_username_in_x is True  # noqa: SLF001


def test_the_identity_actually_changes_the_derived_key() -> None:
    # Proving the toggle is not merely cosmetic.
    salt, password = b"salt", "1234"

    with recovery._identity_in_private_key():  # noqa: SLF001
        with_identity = srp.gen_x(hashlib.sha256, salt, "1234567890", password)

    without_identity = srp.gen_x(hashlib.sha256, salt, "1234567890", password)

    assert with_identity != without_identity


# --------------------------------------------------------------------------------------
# The challenge
# --------------------------------------------------------------------------------------


def test_a_challenge_is_read_out_of_its_three_sections() -> None:
    blob = build_keyvault_message(bytes(range(24)), [b"request-id", b"the-salt", b"server-B"])

    challenge = parse_challenge({"respBlob": blob, "dsid": 1234567890}, "LABEL", "TX")

    assert challenge.exchange_token == b"request-id"


def test_a_blob_arrives_as_base64_text_not_as_plist_data() -> None:
    # [observed] The escrow proxy carries respBlob as a string, the same encoding the
    # request uses in the other direction -- not as a plist `data` element.
    import base64  # noqa: PLC0415

    blob = build_keyvault_message(bytes(range(24)), [b"request-id", b"the-salt", b"server-B"])
    encoded = base64.b64encode(blob).decode()

    challenge = parse_challenge({"respBlob": encoded, "dsid": 1}, "LABEL", "TX")

    assert challenge.exchange_token == b"request-id"
    assert challenge.salt == b"the-salt"
    assert challenge.server_public == b"server-B"


def test_a_blob_that_is_neither_bytes_nor_base64_is_reported_clearly() -> None:
    with pytest.raises(RecoveryError, match="neither bytes nor base64"):
        parse_challenge({"respBlob": 12345, "dsid": 1}, "LABEL", "TX")


def test_a_challenge_without_a_dsid_is_refused() -> None:
    # The dsid is the SRP identity, so there is no exchange without it.
    blob = build_keyvault_message(bytes(range(24)), [b"a", b"b", b"c"])

    with pytest.raises(RecoveryError, match="dsid"):
        parse_challenge({"respBlob": blob}, "LABEL", "TX")


# --------------------------------------------------------------------------------------
# The proof
# --------------------------------------------------------------------------------------


def test_the_proof_declares_its_own_length_not_the_challenges() -> None:
    # The four leading bytes are a message's own total length. Echoing the length of the
    # message being replied to is exactly as wrong as writing zeros, and was what the
    # service rejected with "CLUBH ERROR: An internal error occurred."
    framed = build_recovery_proof(a_challenge(), b"M1")

    assert int.from_bytes(framed[:4], "big") == len(framed)
    assert framed[:4] != b"\x01\x02\x03\x04"


def test_the_proof_rewrites_two_header_fields() -> None:
    framed = build_recovery_proof(a_challenge(), b"M1")
    header = framed[4:28]

    assert int.from_bytes(header[0:4], "big") == 165
    assert int.from_bytes(header[4:8], "big") == 0
    # The rest of the header is the one that arrived, untouched.
    assert header[8:] == bytes(range(24))[8:]


def test_the_second_header_field_depends_on_the_club_type() -> None:
    framed = build_recovery_proof(a_challenge(club_type_id=1), b"M1")

    assert int.from_bytes(framed[8:12], "big") == 2


def test_the_token_section_declares_eight_bytes_but_occupies_twenty() -> None:
    # Zeros are appended after the data and the offsets account for the larger footprint.
    # Padding the data itself to twenty and declaring twenty parses, and is rejected.
    from findmy.keychain.escrow import parse_keyvault_message  # noqa: PLC0415

    framed = build_recovery_proof(a_challenge(), b"M1")
    _, sections = parse_keyvault_message(framed, 24, 2)

    assert sections[0] == bytes(range(8))
    assert sections[1] == b"M1"

    # The second section starts twenty bytes after the first, not twelve.
    offsets_at = 4 + 24
    assert int.from_bytes(framed[offsets_at + 4 : offsets_at + 8], "big") == 20


def test_the_token_is_the_eight_byte_one_not_the_headers_sixteen() -> None:
    # The reply carries two identifiers. Only the exchange token is re-sent as a section;
    # the transaction id travels back inside the header untouched.
    framed = build_recovery_proof(a_challenge(), b"M1")

    assert framed[12:28] == bytes(range(24))[8:]  # the header's id, carried through
    assert bytes(range(8)) in framed


# --------------------------------------------------------------------------------------
# The outer blob
# --------------------------------------------------------------------------------------


def outer_blob(version: int, key: bytes, plaintext: bytes, *, header_length: int = 24) -> bytes:
    header = bytearray(header_length)
    header[4:8] = version.to_bytes(4, "big")

    if version == 0:
        iv = b"\x01" * 16
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        body = encryptor.update(padded) + encryptor.finalize()
    else:
        iv = b"\x02" * 16
        encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        body = encryptor.update(plaintext) + encryptor.finalize() + encryptor.tag

    return build_keyvault_message(bytes(header), [b"M2", iv, body])


def test_a_version_zero_blob_is_aes_cbc_under_the_session_key() -> None:
    key = bytes(range(32))
    blob = outer_blob(0, key, b"the inner blob")

    assert unwrap_outer_blob(blob, key, club_type_id=None) == b"the inner blob"


def test_a_version_two_blob_is_aes_gcm_with_a_sixteen_byte_nonce() -> None:
    key = bytes(range(32))
    blob = outer_blob(2, key, b"the inner blob")

    assert unwrap_outer_blob(blob, key, club_type_id=None) == b"the inner blob"


def test_a_version_two_blob_that_does_not_authenticate_is_refused() -> None:
    key = bytes(range(32))
    blob = bytearray(outer_blob(2, key, b"the inner blob"))
    blob[-1] ^= 0xFF

    with pytest.raises(RecoveryError, match="authenticate"):
        unwrap_outer_blob(bytes(blob), key, club_type_id=None)


def test_version_one_is_refused_rather_than_guessed_at() -> None:
    blob = build_keyvault_message(bytes(4) + (1).to_bytes(4, "big") + bytes(16), [b"", b"", b""])

    with pytest.raises(RecoveryError, match="version 1"):
        unwrap_outer_blob(blob, bytes(32), club_type_id=None)


def test_a_club_type_makes_the_header_longer() -> None:
    # 40 bytes rather than 24. Reading it at the wrong length puts every section adrift.
    key = bytes(range(32))
    blob = outer_blob(0, key, b"payload", header_length=40)

    assert unwrap_outer_blob(blob, key, club_type_id=1) == b"payload"
    with pytest.raises(Exception, match=r".*"):
        unwrap_outer_blob(blob, key, club_type_id=None)


# --------------------------------------------------------------------------------------
# The inner blob -- where the passcode is spent a second time
# --------------------------------------------------------------------------------------


def inner_blob(passcode: str, material: bytes, iterations: int = 1000) -> bytes:
    salt = b"S" * 32
    header = bytearray(16)
    header[8:12] = iterations.to_bytes(4, "big")

    derived = hashlib.pbkdf2_hmac("sha256", passcode.encode(), salt, iterations, 16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(material) + padder.finalize()
    encryptor = Cipher(algorithms.AES(derived), modes.CBC(salt[:16])).encryptor()
    body = encryptor.update(padded) + encryptor.finalize()

    # Six sections: 1 is the salt and 3 the data; the rest are unaccounted for.
    return build_keyvault_message(bytes(header), [b"", salt, b"", body, b"", b""])


def test_the_inner_blob_is_decrypted_with_the_passcode() -> None:
    blob = inner_blob("123456", b"the bottled peer")

    assert unwrap_inner_blob(blob, "123456") == b"the bottled peer"


def test_one_section_is_both_the_salt_and_the_iv() -> None:
    # Section 1 serves as the PBKDF2 salt and, in its first sixteen bytes, the CBC IV.
    # Using a different IV must fail, which is what pins the double duty.
    blob = inner_blob("123456", b"the bottled peer")
    salt = b"S" * 32
    derived = hashlib.pbkdf2_hmac("sha256", b"123456", salt, 1000, 16)

    from findmy.keychain.escrow import parse_keyvault_message  # noqa: PLC0415

    _, sections = parse_keyvault_message(blob, 16, 6)
    wrong_iv = Cipher(algorithms.AES(derived), modes.CBC(b"\x00" * 16)).decryptor()
    garbled = wrong_iv.update(sections[3]) + wrong_iv.finalize()

    assert not garbled.startswith(b"the bottled peer")


def test_the_iteration_count_comes_from_the_blobs_own_header() -> None:
    # Not a fixed constant: the third of four 32-bit header values.
    blob = inner_blob("123456", b"material", iterations=7)

    assert unwrap_inner_blob(blob, "123456") == b"material"


def test_an_impossible_iteration_count_is_refused() -> None:
    # Built by hand, since PBKDF2 will not produce one.
    blob = build_keyvault_message(bytes(16), [b"", b"S" * 32, b"", b"data", b"", b""])

    with pytest.raises(RecoveryError, match="iterations"):
        unwrap_inner_blob(blob, "123456")


def test_the_wrong_passcode_does_not_yield_the_material() -> None:
    blob = inner_blob("123456", b"the bottled peer")

    assert unwrap_inner_blob(blob, "654321") != b"the bottled peer"
