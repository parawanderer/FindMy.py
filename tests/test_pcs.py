"""
Tests for PCS decryption (Stage 5) and the DER reader it depends on.

Everything here is self-consistency: no real record has been decrypted, and these tests
cannot prove the specification was read correctly. What they do prove is that the parts
the specification states exactly are implemented exactly -- the twenty-character labels,
the ten PBKDF2 iterations, the little-endian reversal, the low-bit mask, the MPI-framed
wrapped key, the twelve-byte GCM tag, and the field context that is authenticated
alongside the header.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from findmy.cloudkit import der, pcs
from findmy.cloudkit.der import DerError

CONTEXT = pcs.FieldContext(
    zone_name="BeaconStore",
    record_name="BEACON-1",
    field_name="privateKey",
)

# --------------------------------------------------------------------------------------
# DER
# --------------------------------------------------------------------------------------


def der_tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    length = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def der_sequence(*elements: bytes) -> bytes:
    return der_tlv(0x30, b"".join(elements))


def der_set(*elements: bytes) -> bytes:
    return der_tlv(0x31, b"".join(elements))


def der_int(value: int) -> bytes:
    if value == 0:
        return der_tlv(0x02, b"\x00")
    return der_tlv(0x02, value.to_bytes((value.bit_length() + 8) // 8, "big"))


def der_octet(content: bytes) -> bytes:
    return der_tlv(0x04, content)


def der_context(number: int, content: bytes) -> bytes:
    """An EXPLICIT context tag, which wraps rather than replaces the inner element."""
    return der_tlv(0xA0 | number, content)


def der_application(number: int, content: bytes) -> bytes:
    return der_tlv(0x60 | number, content)


def test_der_reads_a_sequence_of_integers() -> None:
    element, _ = der.parse_one(der_sequence(der_int(1), der_int(2)))

    assert [child.as_int() for child in element.children()] == [1, 2]


def test_der_reads_a_long_form_length() -> None:
    payload = b"x" * 300
    element, _ = der.parse_one(der_octet(payload))

    assert element.as_bytes() == payload


def test_der_rejects_indefinite_length() -> None:
    with pytest.raises(DerError):
        der.parse_one(b"\x30\x80\x00\x00")


def test_der_rejects_a_truncated_element() -> None:
    with pytest.raises(DerError):
        der.parse_one(b"\x04\x10\x01\x02")


def test_der_unwraps_an_explicit_context_tag() -> None:
    element, _ = der.parse_one(der_context(2, der_octet(b"abcd")))

    assert element.is_context(2)
    assert element.unwrap().as_bytes() == b"abcd"


def test_der_retains_each_elements_own_bytes() -> None:
    # The protection structure's HMAC covers the DER of two of its members, so a parse
    # that discards the encoding cannot verify it.
    encoded = der_sequence(der_int(1), der_octet(b"abc"))
    element, _ = der.parse_one(encoded)

    assert element.raw == encoded
    assert element.children()[1].raw == der_octet(b"abc")


def test_expect_application_rejects_the_wrong_tag() -> None:
    # [APPLICATION 1] is used by two different structures, told apart by where they
    # appear rather than by their tag.
    with pytest.raises(DerError):
        der.expect_application(der_application(5, der_sequence()), 1)


# --------------------------------------------------------------------------------------
# Labels and key derivation
# --------------------------------------------------------------------------------------


def test_every_label_is_exactly_twenty_characters() -> None:
    # Not a coincidence, and not something to normalise away.
    assert [len(label) for label in pcs.ALL_LABELS] == [20] * 5


def test_labels_are_verbatim_including_their_spaces() -> None:
    assert pcs.LABEL_SHARE_KEY == b"MsaeEooevaX fooo 012"
    assert pcs.LABEL_ENCRYPTION_KEY == b"encryption key key m"
    assert pcs.KEY_ID_INPUT == b"M key input data 2 u"


def test_the_kdf_is_sp800_108_counter_mode_with_an_empty_context() -> None:
    master = bytes(range(16))
    expected = hmac.new(
        master,
        struct.pack(">I", 1) + pcs.LABEL_ENCRYPTION_KEY + b"\x00" + struct.pack(">I", 128),
        hashlib.sha256,
    ).digest()[:16]

    assert pcs.derive_key(master, pcs.LABEL_ENCRYPTION_KEY) == expected


def test_the_kdf_counter_starts_at_one_and_advances_for_longer_outputs() -> None:
    master = bytes(range(16))
    long_key = pcs.derive_key(master, pcs.LABEL_ENCRYPTION_KEY, length=48)

    blocks = b""
    for counter in (1, 2):
        block = struct.pack(">I", counter) + pcs.LABEL_ENCRYPTION_KEY + b"\x00"
        blocks += hmac.new(master, block + struct.pack(">I", 48 * 8), hashlib.sha256).digest()

    assert long_key == blocks[:48]


def test_derived_key_matches_the_input_key_length_by_default() -> None:
    assert len(pcs.derive_key(bytes(range(16)), pcs.LABEL_ENCRYPTION_KEY)) == 16


def test_key_id_is_two_stages_not_a_digest() -> None:
    master = bytes(range(16))
    label_key = pcs.derive_key(master, pcs.LABEL_KEY_ID)
    expected = hmac.new(label_key, pcs.KEY_ID_INPUT, hashlib.sha256).digest()

    assert pcs.compute_key_id(master) == expected
    assert pcs.compute_key_id(master) != hashlib.sha256(master).digest()


# --------------------------------------------------------------------------------------
# The master EC key: ten iterations, reversed, low bits, conditionally subtracted
# --------------------------------------------------------------------------------------


def test_master_ec_key_uses_ten_pbkdf2_iterations_and_a_128_byte_output() -> None:
    master = bytes(range(16))
    raw = hashlib.pbkdf2_hmac("sha256", master, b"full master key", 10, dklen=128)
    expected = int.from_bytes(raw[::-1], "big") & ((1 << 256) - 1)
    if expected > pcs._P256_ORDER:  # noqa: SLF001
        expected -= pcs._P256_ORDER  # noqa: SLF001

    assert pcs.derive_master_ec_private_key(master) == expected


def test_master_ec_key_reverses_the_pbkdf2_output() -> None:
    # Produced little-endian, consumed big-endian. Skipping the reversal yields a
    # perfectly valid-looking scalar that is simply the wrong key.
    master = bytes(range(16))
    raw = hashlib.pbkdf2_hmac("sha256", master, b"full master key", 10, dklen=128)
    unreversed = int.from_bytes(raw, "big") & ((1 << 256) - 1)

    assert pcs.derive_master_ec_private_key(master) != unreversed


def test_master_ec_key_keeps_the_low_bits_not_the_high_ones() -> None:
    # A mask, not the bits2int convention. The two are indistinguishable by the
    # conditional subtraction that follows, so nothing downstream would catch this.
    master = bytes(range(16))
    raw = hashlib.pbkdf2_hmac("sha256", master, b"full master key", 10, dklen=128)
    high_bits = int.from_bytes(raw[::-1], "big") >> (len(raw) * 8 - 256)

    assert pcs.derive_master_ec_private_key(master) != high_bits


def test_master_ec_key_is_a_usable_p256_scalar() -> None:
    for seed in range(8):
        scalar = pcs.derive_master_ec_private_key(bytes([seed]) * 16)
        key = ec.derive_private_key(scalar, ec.SECP256R1())

        assert 1 <= scalar < pcs._P256_ORDER  # noqa: SLF001
        assert key.curve.name == "secp256r1"


# --------------------------------------------------------------------------------------
# Field decryption
# --------------------------------------------------------------------------------------


def make_unwrapped(master_key: bytes = bytes(range(16))) -> pcs.UnwrappedProtection:
    return pcs.UnwrappedProtection(
        master_key=master_key,
        share_key_derived=False,
        read_only=False,
        hmac_verified=True,
        signature_verified=True,
    )


def test_field_roundtrips_through_encrypt_and_decrypt() -> None:
    unwrapped = make_unwrapped()
    sealed = pcs.encrypt_field(b"hello beacon", unwrapped, CONTEXT, iv=b"\x00" * 12)

    assert pcs.decrypt_field(sealed, unwrapped, CONTEXT) == b"hello beacon"


def test_the_gcm_tag_is_twelve_bytes_not_sixteen() -> None:
    # A library left at GCM's default rejects every message, and the failure looks like
    # corruption rather than misconfiguration.
    unwrapped = make_unwrapped()
    sealed = pcs.encrypt_field(b"x" * 32, unwrapped, CONTEXT, iv=b"\x01" * 12)
    parsed = pcs.parse_encrypted_field(sealed)

    assert len(parsed.tag) == 12
    assert len(parsed.iv) == 12
    assert len(parsed.ciphertext) == 32


def test_a_real_header_is_six_bytes() -> None:
    unwrapped = make_unwrapped()
    sealed = pcs.encrypt_field(b"p", unwrapped, CONTEXT, iv=b"\x02" * 12)

    assert len(pcs.parse_encrypted_field(sealed).header) == 6


def test_ciphertext_overhead_is_thirty_bytes() -> None:
    # Six-byte header, twelve-byte IV, twelve-byte tag. This is what lets a plaintext
    # size be read off a ciphertext size without holding any key.
    unwrapped = make_unwrapped()
    sealed = pcs.encrypt_field(b"x" * 57, unwrapped, CONTEXT, iv=b"\x03" * 12)

    assert len(sealed) == 57 + 30


def test_the_aad_is_the_header_followed_by_the_field_context() -> None:
    header = bytes([3, 0xAA, 0xBB, 2, 0xCC, 0xDD])

    assert pcs.build_aad(header, CONTEXT) == header + b"BeaconStore-BEACON-1-privateKey"


def test_the_context_string_is_hyphen_joined() -> None:
    assert CONTEXT.as_bytes() == b"BeaconStore-BEACON-1-privateKey"


def test_decryption_fails_with_the_header_alone_as_authenticated_data() -> None:
    # That was the original reading, and it fails every field with nothing but a GCM
    # error to go on.
    unwrapped = make_unwrapped()
    sealed = pcs.encrypt_field(b"payload", unwrapped, CONTEXT, iv=b"\x04" * 12)
    parsed = pcs.parse_encrypted_field(sealed)

    decryptor = Cipher(
        algorithms.AES(pcs.derive_encryption_key(unwrapped.master_key)),
        modes.GCM(parsed.iv, parsed.tag, min_tag_length=12),
    ).decryptor()
    decryptor.authenticate_additional_data(parsed.header)

    with pytest.raises(InvalidTag):
        decryptor.update(parsed.ciphertext)
        decryptor.finalize()


@pytest.mark.parametrize(
    "wrong",
    [
        pcs.FieldContext("OtherZone", "BEACON-1", "privateKey"),
        pcs.FieldContext("BeaconStore", "BEACON-2", "privateKey"),
        pcs.FieldContext("BeaconStore", "BEACON-1", "publicKey"),
    ],
)
def test_a_ciphertext_is_bound_to_its_zone_record_and_field(wrong: pcs.FieldContext) -> None:
    # Moving a ciphertext elsewhere must not decrypt. That is the point of the binding.
    unwrapped = make_unwrapped()
    sealed = pcs.encrypt_field(b"secret", unwrapped, CONTEXT, iv=b"\x05" * 12)

    with pytest.raises(pcs.PCSError, match="authenticate"):
        pcs.decrypt_field(sealed, unwrapped, wrong)


def test_key_id_skips_the_length_byte_but_the_aad_keeps_it() -> None:
    unwrapped = make_unwrapped()
    sealed = pcs.encrypt_field(b"p", unwrapped, CONTEXT, iv=b"\x06" * 12, key_id_split=(2, 3))
    parsed = pcs.parse_encrypted_field(sealed)

    full_key_id = pcs.compute_key_id(unwrapped.master_key)

    assert parsed.key_id == full_key_id[:5]
    assert parsed.header == bytes([3]) + full_key_id[:2] + bytes([3]) + full_key_id[2:5]


def test_a_field_of_another_version_is_refused_rather_than_guessed_at() -> None:
    with pytest.raises(pcs.PCSError, match="version"):
        pcs.parse_encrypted_field(bytes([4, 0, 0, 0]) + b"\x00" * 32)


def test_a_truncated_field_is_reported_as_truncated() -> None:
    with pytest.raises(pcs.PCSError):
        pcs.parse_encrypted_field(bytes([3, 0, 0, 0]) + b"\x00" * 4)


def test_decrypting_with_the_wrong_key_is_caught_before_gcm_even_runs() -> None:
    unwrapped = make_unwrapped()
    sealed = pcs.encrypt_field(b"secret", unwrapped, CONTEXT, iv=b"\x07" * 12)

    other = make_unwrapped(bytes(range(16, 32)))
    with pytest.raises(pcs.PCSError, match="different key"):
        pcs.decrypt_field(sealed, other, CONTEXT)


def test_a_tampered_ciphertext_fails_to_authenticate() -> None:
    unwrapped = make_unwrapped()
    sealed = bytearray(pcs.encrypt_field(b"secret payload", unwrapped, CONTEXT, iv=b"\x08" * 12))
    sealed[-1] ^= 0xFF

    with pytest.raises(pcs.PCSError, match="authenticate"):
        pcs.decrypt_field(bytes(sealed), unwrapped, CONTEXT)


# --------------------------------------------------------------------------------------
# The RFC 6637 key wrap
# --------------------------------------------------------------------------------------


def wrap_master_key(recipient: ec.EllipticCurvePublicKey, master_key: bytes) -> bytes:
    """Wrap a master key exactly as the specification says PCS wraps one."""
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared = ephemeral.exchange(ec.ECDH(), recipient)
    kek = hashlib.sha256(struct.pack(">I", 1) + shared + pcs._RFC6637_PARAM).digest()  # noqa: SLF001

    # Algorithm byte, key, big-endian checksum, then padding whose bytes equal its length.
    framed = bytes([1]) + master_key + (sum(master_key) % 65536).to_bytes(2, "big")
    padding_length = -len(framed) % 8 or 8
    framed += bytes([padding_length]) * padding_length

    wrapped = aes_key_wrap(kek[:16], framed)

    # OpenPGP MPI encoding: a bit count, a compact point, then a length and the key.
    x = ephemeral.public_key().public_numbers().x.to_bytes(32, "big")
    return (256).to_bytes(2, "big") + x + bytes([len(wrapped)]) + wrapped


def test_a_wrapped_key_roundtrips() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    master_key = bytes(range(16))

    ciphertext = wrap_master_key(private_key.public_key(), master_key)

    assert pcs.unwrap_share_key(private_key, ciphertext) == master_key


def test_the_wrapped_key_length_prefix_counts_bits_not_bytes() -> None:
    # Reading it as bytes overruns immediately, which is why it is worth a test.
    private_key = ec.generate_private_key(ec.SECP256R1())
    ciphertext = wrap_master_key(private_key.public_key(), bytes(range(16)))

    assert int.from_bytes(ciphertext[:2], "big") == 256
    # 2-byte bit count, 32-byte point, 1-byte length, then a 24-byte frame that AES key
    # wrap turns into 32.
    assert len(ciphertext) == 2 + 32 + 1 + 32


def test_the_fingerprint_is_the_literal_word_zero_padded_to_twenty_bytes() -> None:
    # Not a key fingerprint, not a hash, and not eleven bytes.
    assert pcs._RFC6637_PARAM.endswith(b"fingerprint" + b"\x00" * 9)  # noqa: SLF001
    assert b"Anonymous Sender    " in pcs._RFC6637_PARAM  # noqa: SLF001


def test_the_ephemeral_point_is_rebuilt_from_its_x_coordinate_alone() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    x = key.public_key().public_numbers().x

    rebuilt = pcs._decompress_x(x.to_bytes(32, "big"))  # noqa: SLF001

    assert rebuilt.public_numbers().x == x


def test_a_point_not_on_the_curve_is_rejected() -> None:
    with pytest.raises(pcs.PCSError, match="not on P-256"):
        pcs._decompress_x(b"\x00" * 31 + b"\x01")  # noqa: SLF001


def test_a_wrapped_key_with_a_bad_checksum_is_refused() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral = ec.generate_private_key(ec.SECP256R1())

    shared = ephemeral.exchange(ec.ECDH(), private_key.public_key())
    kek = hashlib.sha256(struct.pack(">I", 1) + shared + pcs._RFC6637_PARAM).digest()  # noqa: SLF001

    framed = bytes([1]) + bytes(range(16)) + b"\xff\xff"  # deliberately wrong checksum
    framed += bytes([5]) * 5
    wrapped = aes_key_wrap(kek[:16], framed)

    x = ephemeral.public_key().public_numbers().x.to_bytes(32, "big")
    ciphertext = (256).to_bytes(2, "big") + x + bytes([len(wrapped)]) + wrapped

    with pytest.raises(pcs.PCSError, match="checksum"):
        pcs.unwrap_share_key(private_key, ciphertext)


def test_a_wrapped_key_for_someone_else_fails_its_integrity_check() -> None:
    ours = ec.generate_private_key(ec.SECP256R1())
    theirs = ec.generate_private_key(ec.SECP256R1())

    ciphertext = wrap_master_key(theirs.public_key(), bytes(range(16)))

    with pytest.raises(pcs.PCSError, match="integrity check"):
        pcs.unwrap_share_key(ours, ciphertext)


# --------------------------------------------------------------------------------------
# The protection structure
# --------------------------------------------------------------------------------------


def build_protection(
    *,
    entries: list[tuple[bytes, bytes, int | None]],
    truncated_key_id: bytes,
    version: int = 1,
    hmac_master_key: bytes | None = None,
    meta: bytes = b"meta",
    signature_data: bytes | None = None,
) -> bytes:
    """Build a ShareProtection the way the specification lays one out."""
    share_keys = []
    for public_key, ciphertext, flags in entries:
        parts = [der_sequence(der_int(1), der_octet(public_key)), der_octet(ciphertext)]
        if flags is not None:
            parts.append(der_int(flags))
        share_keys.append(der_sequence(*parts))

    keyset = der_sequence(der_int(0), der_set(*share_keys))

    # The object signature: what the SignatureData's `data` OCTET STRING holds. The HMAC
    # covers *this*, not the SEQUENCE wrapping it -- so the fixture must sign it directly,
    # or it encodes the reader's bug instead of the format.
    object_signature = signature_data if signature_data is not None else der_octet(b"sigdata")
    signature_data = der_sequence(der_int(version), der_octet(object_signature))

    if hmac_master_key is None:
        mac = b"\xaa" * 32
    else:
        mac = hmac.new(
            pcs.derive_hmac_key(hmac_master_key),
            keyset + meta + object_signature,
            hashlib.sha256,
        ).digest()

    return der_application(
        1,
        der_sequence(
            keyset,
            der_context(0, der_octet(meta)),
            der_context(1, signature_data),
            # The hmac sits here, between two context tags, with no tag of its own.
            der_octet(mac),
            der_context(2, der_octet(truncated_key_id)),
        ),
    )


def test_protection_parses_the_untagged_hmac_between_two_tagged_fields() -> None:
    # A decoder that assumes tags ascend monotonically misparses this.
    raw = build_protection(
        entries=[(b"\x02" + b"\x11" * 32, b"ct", None)],
        truncated_key_id=b"\x01\x02\x03\x04",
    )
    protection = pcs.ShareProtection.from_der(raw)

    assert protection.hmac == b"\xaa" * 32
    assert protection.truncated_key_id == b"\x01\x02\x03\x04"
    assert protection.meta == b"meta"
    assert protection.signature_data.version == 1


def test_protection_retains_the_der_the_hmac_covers() -> None:
    raw = build_protection(
        entries=[(b"\x02" + b"\x11" * 32, b"ct", None)],
        truncated_key_id=b"\x01\x02\x03\x04",
    )
    protection = pcs.ShareProtection.from_der(raw)

    assert protection.keyset_der.startswith(b"\x30")  # a SEQUENCE, tag and length included
    assert protection.signature_data_der.startswith(b"\x30")
    assert protection.keyset_der in raw
    assert protection.signature_data_der in raw


def test_protection_parses_every_entry_of_the_keyset() -> None:
    raw = build_protection(
        entries=[
            (b"\x02" + b"\x11" * 32, b"ct-one", None),
            (b"\x03" + b"\x22" * 32, b"ct-two", 1),
        ],
        truncated_key_id=b"\x01\x02\x03\x04",
    )
    protection = pcs.ShareProtection.from_der(raw)

    assert len(protection.keys) == 2
    assert protection.keys[1].read_only is True
    assert protection.keys[0].read_only is False


def test_the_hmac_covers_keyset_then_meta_then_signature_data() -> None:
    master_key = bytes(range(16))
    raw = build_protection(
        entries=[(b"\x02" + b"\x11" * 32, b"ct", None)],
        truncated_key_id=b"\x01\x02\x03\x04",
        hmac_master_key=master_key,
    )
    protection = pcs.ShareProtection.from_der(raw)

    assert pcs.verify_protection_hmac(protection, master_key) is True
    assert pcs.verify_protection_hmac(protection, bytes(range(16, 32))) is False


# --------------------------------------------------------------------------------------
# The structure's own signature
# --------------------------------------------------------------------------------------


def object_signature_der(
    *,
    roll_count: int = 1,
    outer_sign_key_type: int = 2,
    public_key_type: int = 3,
    public_key: bytes = b"\x02" + b"\x11" * 32,
    signature: bytes = b"sig",
    key_id: bytes = b"",
    symm_key_count: int | None = None,
    attributes: bytes | None = None,
    ec_key_list: bytes | None = None,
    signature2: bytes | None = None,
) -> bytes:
    """Build an ObjectSignature the way the specification lays one out."""
    parts = [
        der_int(roll_count),
        der_int(outer_sign_key_type),
        der_sequence(der_int(public_key_type), der_octet(public_key)),
        der_sequence(der_octet(key_id), der_int(1), der_octet(signature)),
    ]
    if symm_key_count is not None:
        parts.append(der_context(0, der_int(symm_key_count)))
    if signature2 is not None:
        parts.append(der_context(1, der_sequence(der_octet(b""), der_int(1), der_octet(signature2))))
    if ec_key_list is not None:
        parts.append(der_context(2, ec_key_list))
    if attributes is not None:
        parts.append(der_context(3, attributes))
    return der_sequence(*parts)


def test_object_signature_parses_its_optional_members_by_tag() -> None:
    parsed = pcs.ObjectSignature.from_der(
        object_signature_der(symm_key_count=7, attributes=der_sequence(der_int(1))),
    )

    assert parsed.roll_count == 1
    assert parsed.outer_sign_key_type == 2
    assert parsed.public.key_type == 3
    assert parsed.symm_key_count == 7
    assert parsed.attributes_der == der_sequence(der_int(1))
    assert parsed.ec_key_list_der == b""


def test_an_absent_symm_key_count_contributes_four_zero_bytes() -> None:
    # This is the asymmetry that fails verification with no other symptom.
    protection = pcs.ShareProtection.from_der(
        build_protection(entries=[], truncated_key_id=b"\x01\x02\x03\x04"),
    )

    without = pcs.ObjectSignature.from_der(object_signature_der())
    explicit_zero = pcs.ObjectSignature.from_der(object_signature_der(symm_key_count=0))

    assert pcs.build_signed_data(protection, without) == pcs.build_signed_data(
        protection,
        explicit_zero,
    )


def test_absent_attributes_and_ec_key_list_contribute_nothing() -> None:
    # The other half of the asymmetry: omitted, not zeroed.
    protection = pcs.ShareProtection.from_der(
        build_protection(entries=[], truncated_key_id=b"\x01\x02\x03\x04"),
    )

    without = pcs.build_signed_data(protection, pcs.ObjectSignature.from_der(object_signature_der()))
    with_attrs = pcs.build_signed_data(
        protection,
        pcs.ObjectSignature.from_der(object_signature_der(attributes=der_sequence(der_int(1)))),
    )

    assert len(with_attrs) > len(without)
    assert with_attrs.startswith(without)


def test_the_signed_data_is_a_concatenation_in_the_specified_order() -> None:
    protection = pcs.ShareProtection.from_der(
        build_protection(entries=[], truncated_key_id=b"\x01\x02\x03\x04", meta=b"the-meta"),
    )
    signature = pcs.ObjectSignature.from_der(
        object_signature_der(roll_count=9, outer_sign_key_type=4, public_key_type=5),
    )

    signed = pcs.build_signed_data(protection, signature)

    assert signed.startswith(protection.keyset_der + b"the-meta")
    tail = signed[len(protection.keyset_der) + len(b"the-meta") :]
    assert tail[:4] == (4).to_bytes(4, "big")  # outerSignKeyType, before rollCount
    assert tail[4:8] == (9).to_bytes(4, "big")  # rollCount
    assert tail[8:12] == (0).to_bytes(4, "big")  # symmKeyCount, absent means zero
    assert tail[12:16] == (5).to_bytes(4, "big")  # public.keytype


def signed_protection(master_key: bytes, *, use_past_signature: bool = False) -> pcs.ShareProtection:
    """Build a protection structure whose signature actually verifies."""
    signing_key = ec.derive_private_key(
        pcs.derive_master_ec_private_key(master_key),
        ec.SECP256R1(),
    )

    # The signature covers the assembled data, which includes the keyset DER -- so the
    # structure has to be built once to learn that, then rebuilt with the real signature.
    def build(signature_der: bytes) -> pcs.ShareProtection:
        raw = build_protection(
            entries=[],
            truncated_key_id=pcs.compute_key_id(master_key)[:4],
            version=5,
            hmac_master_key=master_key,
            signature_data=signature_der,
        )
        return pcs.ShareProtection.from_der(raw)

    draft = build(object_signature_der())
    placeholder = pcs.ObjectSignature.from_der(object_signature_der())
    signed = pcs.build_signed_data(draft, placeholder)

    real = signing_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    if use_past_signature:
        return build(object_signature_der(signature=b"stale", signature2=real))
    return build(object_signature_der(signature=real))


def test_the_signature_verifies_under_the_master_ec_key() -> None:
    # Which is what makes B4's low-bit masking load-bearing rather than decorative.
    master_key = bytes(range(16))

    assert pcs.verify_protection_signature(signed_protection(master_key), master_key) is True


def test_a_signature_under_another_key_does_not_verify() -> None:
    master_key = bytes(range(16))

    assert pcs.verify_protection_signature(signed_protection(master_key), bytes(16)) is False


def test_a_stale_signature_falls_back_to_the_past_one() -> None:
    # Key rotation, not corruption.
    master_key = bytes(range(16))
    protection = signed_protection(master_key, use_past_signature=True)

    assert pcs.verify_protection_signature(protection, master_key) is True


def test_a_key_id_naming_another_signer_is_rejected_before_verifying() -> None:
    # A mismatch names the wrong key immediately, where a failed verification does not.
    master_key = bytes(range(16))
    other = pcs.compress_public_key(ec.generate_private_key(ec.SECP256R1()).public_key())

    protection = pcs.ShareProtection.from_der(
        build_protection(
            entries=[],
            truncated_key_id=b"\x01\x02\x03\x04",
            signature_data=object_signature_der(key_id=other),
        ),
    )

    assert pcs.verify_protection_signature(protection, master_key) is False


# --------------------------------------------------------------------------------------
# Unwrapping end to end
# --------------------------------------------------------------------------------------


def protection_for(
    private_key: ec.EllipticCurvePrivateKey,
    master_key: bytes,
    *,
    version: int = 5,
    flags: int | None = None,
    key_id_of: bytes | None = None,
) -> pcs.ShareProtection:
    """Build a structure protecting `master_key` for `private_key`."""
    ciphertext = wrap_master_key(private_key.public_key(), master_key)
    raw = build_protection(
        entries=[(pcs.compress_public_key(private_key.public_key()), ciphertext, flags)],
        truncated_key_id=pcs.compute_key_id(key_id_of or master_key)[:4],
        version=version,
        hmac_master_key=key_id_of or master_key,
    )
    return pcs.ShareProtection.from_der(raw)


def test_unwrap_recovers_the_master_key() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    master_key = bytes(range(16))

    # Version 5 means the share key is not derived.
    result = pcs.unwrap_protection(protection_for(private_key, master_key), [private_key])

    assert result.master_key == master_key
    assert result.share_key_derived is False
    assert result.hmac_verified is True


def test_unwrap_applies_the_share_key_derivation_below_version_five() -> None:
    # The branch that is easy to miss: it produces a key that fails every later check.
    private_key = ec.generate_private_key(ec.SECP256R1())
    master_key = bytes(range(16))
    share_key = pcs.derive_key(master_key, pcs.LABEL_SHARE_KEY)

    protection = protection_for(private_key, master_key, version=1, key_id_of=share_key)
    result = pcs.unwrap_protection(protection, [private_key])

    assert result.master_key == share_key
    assert result.share_key_derived is True


def test_unwrap_skips_the_share_key_derivation_for_a_read_only_entry() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    master_key = bytes(range(16))

    protection = protection_for(private_key, master_key, version=1, flags=1)
    result = pcs.unwrap_protection(protection, [private_key])

    assert result.master_key == master_key
    assert result.share_key_derived is False
    assert result.read_only is True


def test_unwrap_matches_a_key_by_its_public_half_never_by_position() -> None:
    # The keyset is a SET, so entries are unordered.
    ours = ec.generate_private_key(ec.SECP256R1())
    theirs = ec.generate_private_key(ec.SECP256R1())
    master_key = bytes(range(16))

    raw = build_protection(
        entries=[
            (pcs.compress_public_key(theirs.public_key()), b"not-for-us", None),
            (
                pcs.compress_public_key(ours.public_key()),
                wrap_master_key(ours.public_key(), master_key),
                None,
            ),
        ],
        truncated_key_id=pcs.compute_key_id(master_key)[:4],
        version=5,
        hmac_master_key=master_key,
    )

    result = pcs.unwrap_protection(pcs.ShareProtection.from_der(raw), [ours])
    assert result.master_key == master_key


def test_a_record_we_hold_no_key_for_is_reported_as_missing_not_as_a_failure() -> None:
    ours = ec.generate_private_key(ec.SECP256R1())
    theirs = ec.generate_private_key(ec.SECP256R1())

    raw = build_protection(
        entries=[(pcs.compress_public_key(theirs.public_key()), b"ct", None)],
        truncated_key_id=b"\x01\x02\x03\x04",
    )

    with pytest.raises(pcs.MissingKeyError):
        pcs.unwrap_protection(pcs.ShareProtection.from_der(raw), [ours])


def test_unwrap_rejects_a_key_whose_id_does_not_match() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    ciphertext = wrap_master_key(private_key.public_key(), bytes(range(16)))

    raw = build_protection(
        entries=[(pcs.compress_public_key(private_key.public_key()), ciphertext, None)],
        truncated_key_id=b"\xde\xad\xbe\xef",
        version=5,
    )

    with pytest.raises(pcs.PCSError, match="key id"):
        pcs.unwrap_protection(pcs.ShareProtection.from_der(raw), [private_key])


def test_a_failing_hmac_is_reported_but_not_fatal_by_default() -> None:
    # The key id already matched, so the key is most likely right and this module's
    # reading of what the HMAC covers is most likely wrong.
    private_key = ec.generate_private_key(ec.SECP256R1())
    master_key = bytes(range(16))
    ciphertext = wrap_master_key(private_key.public_key(), master_key)

    raw = build_protection(
        entries=[(pcs.compress_public_key(private_key.public_key()), ciphertext, None)],
        truncated_key_id=pcs.compute_key_id(master_key)[:4],
        version=5,
    )
    protection = pcs.ShareProtection.from_der(raw)

    result = pcs.unwrap_protection(protection, [private_key])
    assert result.hmac_verified is False

    with pytest.raises(pcs.PCSError, match="HMAC"):
        pcs.unwrap_protection(protection, [private_key], require_hmac=True)


def test_decryption_works_against_a_key_recovered_from_a_protection_structure() -> None:
    """The whole stage, end to end: unwrap a structure, then read a field with it."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    master_key = bytes(range(16))

    unwrapped = pcs.unwrap_protection(protection_for(private_key, master_key), [private_key])
    sealed = pcs.encrypt_field(b"AirTag", unwrapped, CONTEXT, iv=b"\x09" * 12)

    assert pcs.decrypt_field(sealed, unwrapped, CONTEXT) == b"AirTag"


# --------------------------------------------------------------------------------------
# Keychain-held keys
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("explicit", [True, False])
def test_a_v2_private_key_is_read_whether_its_tag_wraps_or_replaces(explicit: bool) -> None:
    # The specification says EXPLICIT; the implicit reading is accepted too, since the
    # difference is one level of nesting and is unambiguous to detect.
    key = ec.generate_private_key(ec.SECP256R1())
    scalar = key.private_numbers().private_value.to_bytes(32, "big")

    body = der_sequence(der_octet(scalar)) if explicit else der_octet(scalar)
    parsed = pcs.parse_keychain_private_key(der_application(5, body))

    assert parsed.private_numbers().private_value == key.private_numbers().private_value


def test_a_v1_private_key_is_refused_rather_than_misread() -> None:
    # Find My is a v2 service. The v1 form exists but is a different shape.
    with pytest.raises(pcs.PCSError, match="APPLICATION 5"):
        pcs.parse_keychain_private_key(der_sequence(der_octet(b"\x01" * 32)))


def test_a_private_key_scalar_out_of_range_is_reported_not_crashed_on() -> None:
    with pytest.raises(pcs.PCSError, match="not valid for P-256"):
        pcs.parse_keychain_private_key(der_application(5, der_octet(b"\x00" * 32)))


def test_compressed_public_keys_are_what_the_keyset_is_matched_on() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    compressed = pcs.compress_public_key(key.public_key())

    assert len(compressed) == 33
    assert compressed[0] in (0x02, 0x03)


def test_a_key_is_matched_however_its_public_half_is_written() -> None:
    # "Compressed" is not X9.62 here: [observed] the service key item's acct is 32 bytes
    # with no sign byte. Comparing 33-byte X9.62 bytes against that never matches, and the
    # failure claims the record is not encrypted for this client, which is far stronger and
    # wrong.
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        Encoding,
        PublicFormat,
    )

    from findmy.cloudkit.pcs import public_key_forms  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    uncompressed = key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    forms = public_key_forms(key)

    assert key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint) in forms
    assert uncompressed in forms
    assert uncompressed[1:33] in forms  # the bare x coordinate, as acct holds it
    assert uncompressed[1:] in forms


def test_the_bare_x_form_is_the_length_a_real_acct_is() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    from findmy.cloudkit.pcs import public_key_forms  # noqa: PLC0415

    key = ec.generate_private_key(ec.SECP256R1()).public_key()

    assert 32 in {len(form) for form in public_key_forms(key)}


def test_another_key_still_does_not_match_any_form() -> None:
    # Widening the forms must not widen what matches: every form is bytes the key itself
    # produces, so a different key cannot collide with one.
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    from findmy.cloudkit.pcs import public_key_forms  # noqa: PLC0415

    ours = public_key_forms(ec.generate_private_key(ec.SECP256R1()).public_key())
    theirs = public_key_forms(ec.generate_private_key(ec.SECP256R1()).public_key())

    assert not (ours & theirs)


# --------------------------------------------------------------------------------------
# Two levels, and the half each one takes (§4 step 0)
# --------------------------------------------------------------------------------------


def build_meta(
    master_key: bytes,
    *,
    symm_keys: list[bytes] | None = None,
    identity_keys: list[bytes] | None = None,
) -> bytes:
    """Build a meta member: DER, then encrypted under the master key with no context."""
    from findmy.cloudkit.pcs import (  # noqa: PLC0415
        FieldContext,
        UnwrappedProtection,
        encrypt_field,
    )

    def length(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + length(len(body)) + body

    members = b""

    if symm_keys:
        inner = b"".join(tlv(0x04, k) for k in symm_keys)
        members += tlv(0xA0, tlv(0x31, inner))

    if identity_keys:
        # Each identity: SEQUENCE { string, keyset OCTET STRING holding DER }
        keysets = b""
        for scalar in identity_keys:
            v_data = tlv(0x65, tlv(0x04, _pcs_key_message(scalar)))
            # The nested keyset, per §4 step 6: a string, the keys, a set, and a hash.
            nested = tlv(
                0x30,
                tlv(0x0C, b"k") + tlv(0x31, v_data) + tlv(0x31, b"") + tlv(0x04, bytes(32)),
            )
            # An identity is { integer, keyset }, and the keyset is an OCTET STRING of DER.
            keysets += tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, nested))
        members += tlv(0xA2, tlv(0x31, keysets))

    plaintext = tlv(0x30, members)

    holder = UnwrappedProtection(
        master_key=master_key,
        share_key_derived=False,
        read_only=False,
        hmac_verified=False,
        signature_verified=None,
    )
    return encrypt_field(plaintext, holder, FieldContext.none(), iv=bytes(12))


def _pcs_key_message(scalar: bytes) -> bytes:
    from findmy.cloudkit.proto import cuttlefish_pb2 as cf  # noqa: PLC0415

    return cf.PcsServiceKeys(encryption_key=cf.PcsPrivateKey(key=scalar)).SerializeToString()


def test_meta_yields_both_halves_and_they_are_different_things() -> None:
    # Steps 1 to 5 yield one key. Everything else the structure carries is in meta, and the
    # two halves are for different levels: master keys decrypt fields, EC keys unwrap the
    # level below. Taking the same half at both levels is the mistake the table prevents.
    from findmy.cloudkit.pcs import read_meta  # noqa: PLC0415

    master = bytes(range(16))
    extra = bytes(range(16, 32))
    scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value

    meta = build_meta(master, symm_keys=[extra], identity_keys=[scalar.to_bytes(32, "big")])
    contents = read_meta(meta, master)

    assert contents.symmetric_keys == [extra]
    assert len(contents.private_keys) == 1
    assert contents.private_keys[0].private_numbers().private_value == scalar


def test_meta_is_authenticated_with_an_empty_context() -> None:
    # A structure member has no zone, record or field name to bind to, so the AAD is the
    # header alone. This is the one place §6's context rule does not apply.
    from findmy.cloudkit.pcs import FieldContext  # noqa: PLC0415

    assert FieldContext.none().as_bytes() == b""
    assert FieldContext("BeaconStore", "rec", "f").as_bytes() == b"BeaconStore-rec-f"


def test_an_unreadable_meta_does_not_cost_the_master_key() -> None:
    # At the record level meta is not needed to decrypt a field, so a meta this cannot read
    # must not discard the key that was already recovered.
    from findmy.cloudkit.pcs import read_meta  # noqa: PLC0415

    contents = read_meta(b"\x03\x00\x00\x02\x00\x00" + bytes(40), bytes(range(16)))

    assert contents.symmetric_keys == []
    assert contents.private_keys == []


def test_a_zone_unwraps_into_the_keys_its_records_use() -> None:
    # §4 step 0. The service key opens the zone; the zone yields the EC keys a record's
    # keyset names. Going straight from keychain to record finds nothing and reports the
    # record as protected for someone else, which is what being locked out looks like.
    from findmy.cloudkit.pcs import unwrap_zone  # noqa: PLC0415

    service_key = ec.generate_private_key(ec.SECP256R1())
    zone_master = bytes(range(16))
    zone_scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value

    zone_der = build_protection(
        entries=[(pcs.compress_public_key(service_key.public_key()), wrap_master_key(
            service_key.public_key(), zone_master), None)],
        truncated_key_id=pcs.compute_key_id(zone_master)[:4],
        version=5,
        hmac_master_key=zone_master,
        meta=build_meta(zone_master, identity_keys=[zone_scalar.to_bytes(32, "big")]),
    )

    keys = unwrap_zone(zone_der, [service_key])

    assert keys[0].private_numbers().private_value == zone_scalar


def test_a_zone_with_no_identity_still_yields_its_derived_key() -> None:
    # §5's master EC key is the one construction turning a zone-level secret into an
    # elliptic-curve key, so a zone whose meta carries only symmetric keys is not
    # keyless -- it has whatever those derive to.
    from findmy.cloudkit.pcs import master_ec_keys, unwrap_zone  # noqa: PLC0415

    service_key = ec.generate_private_key(ec.SECP256R1())
    zone_master = bytes(range(16))
    extra = bytes(range(16, 32))

    zone_der = build_protection(
        entries=[(pcs.compress_public_key(service_key.public_key()), wrap_master_key(
            service_key.public_key(), zone_master), None)],
        truncated_key_id=pcs.compute_key_id(zone_master)[:4],
        version=5,
        hmac_master_key=zone_master,
        meta=build_meta(zone_master, symm_keys=[extra]),
    )

    keys = unwrap_zone(zone_der, [service_key])

    # One per master key: the one unwrapped to us, then each of symmKeys.
    assert len(keys) == 2
    assert [k.private_numbers().private_value for k in keys] == [
        m.private_numbers().private_value for m in master_ec_keys([zone_master, extra])
    ]


def test_the_derived_key_is_the_one_that_verifies_a_signature() -> None:
    # It is the same derivation §4 step 4 verifies with, so offering it as a zone key is
    # not a new construction -- it is the existing one, asked a different question.
    from findmy.cloudkit.pcs import derive_master_ec_private_key, master_ec_keys  # noqa: PLC0415

    master = bytes(range(16))

    assert master_ec_keys([master])[0].private_numbers().private_value == (
        derive_master_ec_private_key(master)
    )


def test_a_meta_that_holds_neither_member_names_its_tags(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # It decoded and held nothing, which means the reader is looking in the wrong place
    # rather than anything being malformed. That is the hardest failure to diagnose from a
    # message, and naming the tags is what settles it.
    import logging  # noqa: PLC0415

    from findmy.cloudkit.pcs import parse_meta  # noqa: PLC0415

    # A SEQUENCE holding [7] rather than [0] or [2].
    plaintext = bytes([0x30, 0x04, 0xA7, 0x02, 0x04, 0x00])

    with caplog.at_level(logging.WARNING, logger="findmy.cloudkit.pcs"):
        contents = parse_meta(plaintext)

    assert not contents.symmetric_keys
    assert not contents.private_keys
    assert "[7]" in caplog.text


def test_a_meta_wrapped_in_an_application_tag_is_still_read() -> None:
    # Every other structure here is application-tagged, so looking through one costs
    # nothing and a wrapper that is not there is simply not found.
    from findmy.cloudkit.pcs import parse_meta  # noqa: PLC0415

    master = bytes(range(16))
    inner = build_meta(master, symm_keys=[bytes(range(16, 32))])

    from findmy.cloudkit.pcs import read_meta  # noqa: PLC0415

    assert read_meta(inner, master).symmetric_keys == [bytes(range(16, 32))]
    assert parse_meta(bytes([0x30, 0x00])).symmetric_keys == []


def test_the_der_describer_names_nested_tags() -> None:
    from findmy.cloudkit import der  # noqa: PLC0415

    element, _ = der.parse_one(bytes([0x30, 0x06, 0xA0, 0x04, 0x31, 0x02, 0x04, 0x00]))

    described = der.describe(element)

    assert "[0]" in described
    assert "16" in described  # the SEQUENCE's own universal tag


def test_an_identity_is_walked_rather_than_indexed_into() -> None:
    # The members around the keyset are unnamed, so their positions are not something to
    # rely on. Searching is safe here because a candidate must parse as the private-key
    # CHOICE and yield a scalar of a known length -- a wrong element yields no key.
    from findmy.cloudkit import der  # noqa: PLC0415
    from findmy.cloudkit.pcs import _identity_keys  # noqa: PLC0415

    def length(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + length(len(body)) + body

    scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    v_data = tlv(0x65, tlv(0x04, _pcs_key_message(scalar.to_bytes(32, "big"))))

    # Deliberately buried at a different depth and position from the documented one.
    buried = tlv(0x30, tlv(0x02, b"\x09") + tlv(0xA3, tlv(0x31, v_data)))
    identity = tlv(0x30, tlv(0x0C, b"x") + tlv(0x04, buried))

    element, _ = der.parse_one(identity)
    keys = _identity_keys(element)

    assert len(keys) == 1
    assert keys[0].private_numbers().private_value == scalar


def test_an_identity_holding_no_key_yields_none_rather_than_a_wrong_one() -> None:
    from findmy.cloudkit import der  # noqa: PLC0415
    from findmy.cloudkit.pcs import _identity_keys  # noqa: PLC0415

    # A structure of the right shape carrying bytes that are not a key.
    element, _ = der.parse_one(bytes([0x30, 0x06, 0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]))

    assert _identity_keys(element) == []


def test_a_set_of_keys_yields_all_of_them_not_a_pair() -> None:
    # Both levels inside meta are SET OF. Handing a whole SET to the key reader half-works
    # -- it returns a pair, because that is what a ServiceKeys holds -- so a set of five
    # keys yields two and the short list looks complete.
    from findmy.cloudkit import der  # noqa: PLC0415
    from findmy.cloudkit.pcs import _identity_keys  # noqa: PLC0415

    def length(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + length(len(body)) + body

    scalars = [
        ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
        for _ in range(5)
    ]
    entries = b"".join(
        tlv(0x65, tlv(0x04, _pcs_key_message(v.to_bytes(32, "big")))) for v in scalars
    )
    identity = tlv(0x30, tlv(0x0C, b"x") + tlv(0x31, entries))

    element, _ = der.parse_one(identity)
    keys = _identity_keys(element)

    assert len(keys) == 5
    assert {k.private_numbers().private_value for k in keys} == set(scalars)


def test_one_unreadable_entry_does_not_end_the_set() -> None:
    # The other shape that produces a short list that looks complete.
    from findmy.cloudkit import der  # noqa: PLC0415
    from findmy.cloudkit.pcs import _identity_keys  # noqa: PLC0415

    def length(n: int) -> bytes:
        return bytes([n]) if n < 0x80 else bytes([0x81, n])

    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + length(len(body)) + body

    good = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
    entries = (
        tlv(0x04, b"\xde\xad\xbe\xef")
        + tlv(0x65, tlv(0x04, _pcs_key_message(good.to_bytes(32, "big"))))
    )
    identity = tlv(0x30, tlv(0x31, entries))

    element, _ = der.parse_one(identity)
    keys = _identity_keys(element)

    assert [k.private_numbers().private_value for k in keys] == [good]


def test_the_hmac_covers_the_object_signature_not_its_wrapper() -> None:
    # SignatureData is SEQUENCE { version, data }, and the HMAC covers what `data` holds.
    # Encoding the wrapper adds the version and the octet string's header, and then the
    # HMAC fails on every structure while the key id still matches -- a wrong key fails
    # both checks, so failing only one is the signature of this mistake.
    master = bytes(range(16))
    key = ec.generate_private_key(ec.SECP256R1())

    der_bytes = build_protection(
        entries=[(pcs.compress_public_key(key.public_key()), b"ct", None)],
        truncated_key_id=b"\x00\x00\x00\x00",
        hmac_master_key=master,
    )
    protection = pcs.ShareProtection.from_der(der_bytes)

    assert pcs.verify_protection_hmac(protection, master) is True

    # The wrapper's DER is strictly longer, so signing it cannot coincide.
    assert len(protection.signature_data_der) > len(protection.signature_data.data)


def test_a_keyset_yields_its_key_and_not_its_checksum() -> None:
    # [observed] The nested keyset is [APPLICATION 2] { name, keys SET, set, hash }, and
    # its hash is 32 bytes -- exactly a P-256 scalar's length. Reading the keyset *as* a
    # key therefore succeeds, returning the digest, and a walk that stops at the first
    # member to yield something never looks inside `keys` where the real blob is.
    from findmy.cloudkit import der  # noqa: PLC0415
    from findmy.cloudkit.pcs import _identity_keys  # noqa: PLC0415

    def length(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + length(len(body)) + body

    real = ec.generate_private_key(ec.SECP256R1())
    uncompressed = real.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    blob = uncompressed[1:33] + real.private_numbers().private_value.to_bytes(32, "big")

    keyset = tlv(
        0x62,  # [APPLICATION 2], constructed
        tlv(
            0x30,
            tlv(0x0C, b"")
            + tlv(0x31, tlv(0x30, tlv(0x04, blob)))
            + tlv(0x31, b"")
            + tlv(0x04, bytes(range(32))),  # the hash: a scalar's length, and not a key
        ),
    )
    identity = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, keyset))

    element, _ = der.parse_one(identity)
    found = [k.private_numbers().private_value for k in _identity_keys(element)]

    assert real.private_numbers().private_value in found


def test_a_keyset_without_its_application_wrapper_is_read_too() -> None:
    # The same members, reached by iterating rather than through [APPLICATION 2]. Worth
    # having separately: in this shape the 32-byte digest is not picked up at all, so the
    # key being found does not depend on which of the two paths reached it.
    from findmy.cloudkit import der  # noqa: PLC0415
    from findmy.cloudkit.pcs import _identity_keys  # noqa: PLC0415

    def length(n: int) -> bytes:
        return bytes([n]) if n < 0x80 else bytes([0x81, n])

    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + length(len(body)) + body

    real = ec.generate_private_key(ec.SECP256R1())
    uncompressed = real.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    blob = uncompressed[1:33] + real.private_numbers().private_value.to_bytes(32, "big")
    digest = bytes(range(32))

    keyset = tlv(
        0x30,
        tlv(0x31, tlv(0x30, tlv(0x04, blob))) + tlv(0x04, digest),
    )

    element, _ = der.parse_one(keyset)
    found = [k.private_numbers().private_value for k in _identity_keys(element)]

    assert real.private_numbers().private_value in found
    assert int.from_bytes(digest, "big") not in found


def a_keyset(blob: bytes, *, digest: bytes | None = None, wrapped: bool = True) -> bytes:
    """A ShareProtectionKeySet: name, keys, set, and its own SHA-256."""

    def length(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    def tlv(tag: int, body: bytes) -> bytes:
        return bytes([tag]) + length(len(body)) + body

    members = tlv(0x0C, b"") + tlv(0x31, tlv(0x30, tlv(0x04, blob))) + tlv(0x31, b"")

    # The digest covers the structure with `hash` absent, so it is computed over exactly
    # what this would encode to without that member.
    without = tlv(0x30, members)
    if wrapped:
        without = tlv(0x62, without)

    real = hashlib.sha256(without).digest()
    inner = tlv(0x30, members + tlv(0x04, digest if digest is not None else real))

    return tlv(0x62, inner) if wrapped else inner


def test_a_keysets_checksum_verifies_over_itself_without_its_hash() -> None:
    from findmy.cloudkit import der  # noqa: PLC0415
    from findmy.cloudkit.pcs import verify_keyset_hash  # noqa: PLC0415

    element, _ = der.parse_one(a_keyset(bytes(range(64)), wrapped=False))

    assert verify_keyset_hash(element) is True


def test_a_keyset_whose_checksum_is_wrong_says_so() -> None:
    # This digest is what was being returned as a key. Checking it names the mistake where
    # it happens, rather than five levels later as a key that matches nothing.
    from findmy.cloudkit import der  # noqa: PLC0415
    from findmy.cloudkit.pcs import verify_keyset_hash  # noqa: PLC0415

    element, _ = der.parse_one(a_keyset(bytes(range(64)), digest=bytes(32), wrapped=False))

    assert verify_keyset_hash(element) is False


def test_a_structure_with_no_checksum_is_not_reported_as_failing() -> None:
    from findmy.cloudkit import der  # noqa: PLC0415
    from findmy.cloudkit.pcs import verify_keyset_hash  # noqa: PLC0415

    element, _ = der.parse_one(bytes([0x30, 0x03, 0x02, 0x01, 0x01]))

    assert verify_keyset_hash(element) is None


def test_rebuilding_reuses_the_members_that_arrived() -> None:
    # DER orders a SET OF by encoded value, so re-encoding from parsed values can differ
    # from the input. Emitting the original spans sidesteps that rather than answering it.
    from findmy.cloudkit import der  # noqa: PLC0415

    raw = bytes([0x30, 0x06, 0x02, 0x01, 0x09, 0x04, 0x01, 0xFF])
    element, _ = der.parse_one(raw)

    rebuilt = der.rebuild_without(element, 1)

    assert rebuilt == bytes([0x30, 0x03, 0x02, 0x01, 0x09])
