"""Tests for escrow enrolment: the pinned roots, the blob and the metadata (Stage 3 §4.5)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import plistlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import srp._pysrp as srp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

from findmy.keychain.enrolment import (
    AES_IV_LENGTH,
    OUTER_KEY_LENGTH,
    PINNED_ROOT_FINGERPRINTS,
    DeviceDescription,
    EnrolmentError,
    PinnedRoots,
    blob_digest,
    build_escrow_blob,
    build_inner_message,
    build_metadata,
    build_record,
    escrow_timestamp,
    new_bottle_entropy,
    record_label,
    seal_to_club,
    srp_verifier,
)
from findmy.keychain.escrow import _parse_metadata, parse_keyvault_message
from findmy.keychain.recovery import unwrap_inner_blob

DSID = "1234567890"
PEER_ID = "SHA256:" + base64.b64encode(b"\x11" * 32).decode()
LABEL = f"com.apple.icdp.record.{PEER_ID}"
PASSCODE = "123456"
NOW = datetime(2026, 1, 1, 12, 30, 45, tzinfo=timezone.utc)

RECORD = build_record("2026-01-01 12:30:45", b"\x07" * 72)


# --------------------------------------------------------------------------------------
# Certificates, made here so that the whole verification path can be exercised
# --------------------------------------------------------------------------------------


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _make_root(serial: int, *, common_name: str = "Escrow Service Root CA") -> tuple:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _make_club(
    issuer_key,
    issuer: x509.Certificate,
    *,
    not_after: datetime = NOW + timedelta(days=30),
) -> tuple:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name("Escrow Club"))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(not_after)
        .sign(issuer_key, hashes.SHA256())
    )
    return key, certificate


@pytest.fixture
def pinned(monkeypatch: pytest.MonkeyPatch) -> tuple:
    """A root that this test pins, standing in for one of Apple's four."""
    key, certificate = _make_root(103)
    monkeypatch.setattr(
        "findmy.keychain.enrolment.PINNED_ROOT_FINGERPRINTS",
        {103: certificate.fingerprint(hashes.SHA256())},
    )
    return key, certificate


# --------------------------------------------------------------------------------------
# Pinning
# --------------------------------------------------------------------------------------


def test_a_root_is_accepted_only_when_its_fingerprint_matches(pinned) -> None:
    _, certificate = pinned
    roots = PinnedRoots.load([certificate.public_bytes(serialization.Encoding.DER)])

    assert list(roots.by_version) == [103]
    assert roots


def test_a_root_with_an_unknown_fingerprint_is_refused() -> None:
    _, certificate = _make_root(103)

    with pytest.raises(EnrolmentError, match="not one of the pinned"):
        PinnedRoots.load([certificate.public_bytes(serialization.Encoding.DER)])


def test_a_root_whose_serial_disagrees_with_its_version_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The version *is* the serial number, so a certificate that fingerprints as 103 and
    # says 102 is two statements of identity disagreeing.
    _, certificate = _make_root(102)
    monkeypatch.setattr(
        "findmy.keychain.enrolment.PINNED_ROOT_FINGERPRINTS",
        {103: certificate.fingerprint(hashes.SHA256())},
    )

    with pytest.raises(EnrolmentError, match="serial number"):
        PinnedRoots.load([certificate.public_bytes(serialization.Encoding.DER)])


def test_pem_is_accepted_as_well_as_der(pinned) -> None:
    _, certificate = pinned
    roots = PinnedRoots.load([certificate.public_bytes(serialization.Encoding.PEM)])

    assert list(roots.by_version) == [103]


def test_the_real_fingerprints_are_the_four_the_specification_names() -> None:
    assert sorted(PINNED_ROOT_FINGERPRINTS) == [101, 102, 103, 500]
    assert all(len(digest) == 32 for digest in PINNED_ROOT_FINGERPRINTS.values())


def test_the_bundled_roots_are_the_four_and_match_their_fingerprints() -> None:
    # The fingerprint check is not relaxed for the roots that ship with the library. It is
    # the reason they could be delivered by any route at all -- a wrong file cannot match
    # one -- so a bundled certificate that fails is a corrupted install, and this is the
    # test that says so.
    roots = PinnedRoots.bundled()

    assert sorted(roots.by_version) == [101, 102, 103, 500]
    for version, certificate in roots.by_version.items():
        assert certificate.fingerprint(hashes.SHA256()) == PINNED_ROOT_FINGERPRINTS[version]
        assert certificate.serial_number == version
        assert certificate.subject == certificate.issuer


def test_the_bundled_roots_are_four_independent_anchors_not_a_chain() -> None:
    # 101 does not sign 102. All four go in the store, and the club certificate chains to
    # whichever issued it -- which is why the subjects differ only by the serialNumber
    # attribute, and why matching an issuer picks exactly one.
    roots = PinnedRoots.bundled()
    subjects = {certificate.subject for certificate in roots.by_version.values()}

    assert len(subjects) == 4


def test_the_files_ship_inside_the_package() -> None:
    # A data file that lives beside the source but is not packaged works in a checkout and
    # fails in a wheel, where nothing in this suite would notice.
    import findmy  # noqa: PLC0415

    package = Path(findmy.__file__).parent
    for version in (101, 102, 103, 500):
        assert (package / "keychain" / "roots" / f"{version}.crt").is_file()


def test_the_root_in_active_use_may_be_the_one_that_expires_first() -> None:
    # 101 to 103 run to 2049; 500 was issued in 2022 with a ten-year life. If 500 is the
    # one in use, 2032 is the deadline on this hardcoded set -- so this asserts the fact
    # rather than leaving it in a comment nobody re-reads.
    roots = PinnedRoots.bundled()

    assert roots.by_version[500].not_valid_after_utc.year == 2032
    assert all(roots.by_version[v].not_valid_after_utc.year == 2049 for v in (101, 102, 103))


def test_a_caller_can_still_supply_their_own_set(pinned) -> None:
    _, certificate = pinned
    roots = PinnedRoots.load([certificate.public_bytes(serialization.Encoding.DER)])

    assert list(roots.by_version) == [103]


def test_a_club_certificate_verifies_against_its_pinned_root(pinned) -> None:
    from findmy.keychain.enrolment import verify_club_certificate

    root_key, root = pinned
    _, club = _make_club(root_key, root)
    roots = PinnedRoots.load([root.public_bytes(serialization.Encoding.DER)])

    verified = verify_club_certificate(
        club.public_bytes(serialization.Encoding.DER),
        roots,
        now=NOW,
    )
    assert verified.subject == club.subject


def test_nothing_verifies_without_roots() -> None:
    from findmy.keychain.enrolment import verify_club_certificate

    root_key, root = _make_root(103)
    _, club = _make_club(root_key, root)

    with pytest.raises(EnrolmentError, match="No pinned escrow roots"):
        verify_club_certificate(club.public_bytes(serialization.Encoding.DER), PinnedRoots(), now=NOW)


def test_a_club_certificate_from_another_issuer_is_refused_rather_than_chained(pinned) -> None:
    from findmy.keychain.enrolment import verify_club_certificate

    _, root = pinned
    other_key, other = _make_root(103, common_name="Somebody Else")
    _, club = _make_club(other_key, other)
    roots = PinnedRoots.load([root.public_bytes(serialization.Encoding.DER)])

    # And it reads as rotation rather than as a broken account: the pinned set is fixed
    # and Apple's is not, so an unrecognised issuer means a newer root has to ship here.
    with pytest.raises(EnrolmentError, match="rotated to a root newer"):
        verify_club_certificate(club.public_bytes(serialization.Encoding.DER), roots, now=NOW)


def test_a_forged_club_certificate_is_refused(pinned) -> None:
    from findmy.keychain.enrolment import verify_club_certificate

    _, root = pinned
    # Same issuer name, so it gets as far as the signature check and no further.
    impostor_key, _ = _make_root(103, common_name="Escrow Service Root CA")
    _, club = _make_club(impostor_key, root)
    roots = PinnedRoots.load([root.public_bytes(serialization.Encoding.DER)])

    with pytest.raises(EnrolmentError, match="did not verify"):
        verify_club_certificate(club.public_bytes(serialization.Encoding.DER), roots, now=NOW)


def test_an_expired_club_certificate_is_refused(pinned) -> None:
    from findmy.keychain.enrolment import verify_club_certificate

    root_key, root = pinned
    _, club = _make_club(root_key, root, not_after=NOW + timedelta(days=1))
    roots = PinnedRoots.load([root.public_bytes(serialization.Encoding.DER)])

    with pytest.raises(EnrolmentError, match="expired"):
        verify_club_certificate(
            club.public_bytes(serialization.Encoding.DER),
            roots,
            now=NOW + timedelta(days=2),
        )


# --------------------------------------------------------------------------------------
# The inner message
# --------------------------------------------------------------------------------------


def _inner() -> bytes:
    return build_inner_message(
        dsid=DSID,
        label=LABEL,
        timestamp=escrow_timestamp(NOW),
        password=PASSCODE,
        record=RECORD,
        salt=b"\x05" * 64,
    )


def test_the_inner_message_is_what_the_recovery_reader_reads_back() -> None:
    # The decisive test for §4.5.1's inner layer: the reader was written from §6.5, which
    # describes the same message from the other direction. Section indices, the iteration
    # count's position in the header, the salt doubling as the IV and the PBKDF2
    # parameters all have to agree for this to come back.
    assert unwrap_inner_blob(_inner(), PASSCODE) == RECORD


def test_the_inner_message_carries_its_six_sections_in_order() -> None:
    header, sections = parse_keyvault_message(_inner(), 16, 6)

    assert int.from_bytes(header[0:4], "big") == 160
    assert int.from_bytes(header[8:12], "big") == 10000  # the PBKDF2 iteration count

    assert sections[0] == DSID.encode()
    assert sections[1] == b"\x05" * 64
    assert sections[4] == LABEL.encode()
    assert sections[5] == b"2026-01-01 12:30:45"


def test_padded_sections_declare_their_length_and_occupy_their_footprint() -> None:
    # The declared length stays the true one; the zeros are appended after it, and only
    # the offsets know about them. A section that declares its padded size parses fine and
    # is wrong, which is why this is checked rather than assumed.
    inner = _inner()
    offsets_at = 4 + 16
    offsets = [
        int.from_bytes(inner[offsets_at + i * 4 : offsets_at + (i + 1) * 4], "big")
        for i in range(7)
    ]

    assert offsets[1] - offsets[0] == 16  # the dsid's footprint
    assert offsets[5] - offsets[4] == 80  # the label's
    assert offsets[6] - offsets[5] == 24  # the timestamp's


def test_a_record_is_refused_under_an_empty_passcode() -> None:
    with pytest.raises(EnrolmentError, match="empty passcode"):
        build_inner_message(
            dsid=DSID,
            label=LABEL,
            timestamp=escrow_timestamp(NOW),
            password="",
            record=RECORD,
        )


@pytest.mark.parametrize(
    "material",
    [plistlib.dumps({"something": "else"}), b"not a plist at all"],
    ids=["a plist with no entropy", "not a plist"],
)
def test_escrowing_material_with_no_entropy_is_refused(material: bytes) -> None:
    # Refused rather than warned about: a record with no entropy recovers *successfully*
    # and yields nothing, and the proxy reports it as usable for as long as the account
    # exists. That is worse than a failed enrolment, and nothing corrects it afterwards.
    with pytest.raises(EnrolmentError, match="BottledPeerEntropy"):
        build_inner_message(
            dsid=DSID,
            label=LABEL,
            timestamp=escrow_timestamp(NOW),
            password=PASSCODE,
            record=material,
        )


def test_the_record_is_three_keys_and_no_more() -> None:
    # The other fields Apple's clients include -- SecureBackupIDMSData, the passwords, the
    # versions -- are not required, and synthesising them would be inventing plausible
    # values for fields nothing reads.
    fields = plistlib.loads(build_record("2026-01-01 12:30:45", new_bottle_entropy()))

    assert sorted(fields) == [
        "BackupVersion",
        "BottledPeerEntropy",
        "com.apple.securebackup.timestamp",
    ]
    assert len(fields["BottledPeerEntropy"]) == 72
    assert fields["BackupVersion"] == "1"
    assert fields["com.apple.securebackup.timestamp"] == "2026-01-01 12:30:45"


def test_entropy_is_fresh_each_time_and_never_invented_by_a_builder() -> None:
    # Generated once by the caller and given to both halves of a join. A builder that made
    # its own would produce a record the bottle cannot agree with, and nothing between here
    # and a recovery months later would notice.
    assert len(new_bottle_entropy()) == 72
    assert new_bottle_entropy() != new_bottle_entropy()

    with pytest.raises(TypeError):
        build_record("2026-01-01 12:30:45")  # pyright: ignore [reportCallIssue]


def test_entropy_of_the_wrong_length_is_refused() -> None:
    with pytest.raises(EnrolmentError, match="72 bytes"):
        build_record("2026-01-01 12:30:45", b"\x00" * 32)


# --------------------------------------------------------------------------------------
# The verifier
# --------------------------------------------------------------------------------------


def test_the_verifier_authenticates_a_recovery_under_the_same_passcode() -> None:
    # The only check worth making on a verifier: run the exchange it exists for. This uses
    # the same SRP library the recovery path uses, with the identity in the private-key
    # hash as §6.3 requires -- the setting whose being wrong looks exactly like a wrong
    # passcode, months later and with nothing to recover.
    salt = b"\x09" * 64
    verifier = srp_verifier(DSID, PASSCODE, salt)

    previous = srp._no_username_in_x  # noqa: SLF001
    srp.no_username_in_x(False)
    try:
        user = srp.User(DSID, PASSCODE, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, public = user.start_authentication()

        server = srp.Verifier(
            DSID,
            salt,
            verifier,
            public,
            hash_alg=srp.SHA256,
            ng_type=srp.NG_2048,
        )
        server_salt, server_public = server.get_challenge()

        proof = user.process_challenge(server_salt, server_public)
        assert proof is not None

        user.verify_session(server.verify_session(proof))
    finally:
        srp.no_username_in_x(previous)

    assert user.authenticated()
    assert server.authenticated()


def test_the_verifier_is_padded_to_the_group_size() -> None:
    assert len(srp_verifier(DSID, PASSCODE, b"\x01" * 64)) == 256


def test_a_different_passcode_gives_a_different_verifier() -> None:
    salt = b"\x02" * 64
    assert srp_verifier(DSID, "123456", salt) != srp_verifier(DSID, "654321", salt)
    assert srp_verifier(DSID, PASSCODE, salt) != srp_verifier("9", PASSCODE, salt)


# --------------------------------------------------------------------------------------
# The outer message
# --------------------------------------------------------------------------------------


def test_the_outer_message_unseals_to_the_inner_one(pinned) -> None:
    # A stand-in for what Apple's service does with the blob, which is the only way to
    # check five sections that are otherwise opaque.
    root_key, root = pinned
    club_key, club = _make_club(root_key, root)

    inner = _inner()
    outer = seal_to_club(inner, club)
    header, sections = parse_keyvault_message(outer, 20, 5)

    assert int.from_bytes(header[0:4], "big") == 161

    keys = club_key.decrypt(
        sections[2],
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),  # noqa: S303
            algorithm=hashes.SHA1(),  # noqa: S303
            label=None,
        ),
    )
    aes_key, hmac_key = keys[:OUTER_KEY_LENGTH], keys[OUTER_KEY_LENGTH:]
    assert len(hmac_key) == OUTER_KEY_LENGTH

    # Section 1 authenticates the whole of section 2, the IV included.
    assert hmac.compare_digest(sections[0], hmac.new(hmac_key, sections[1], "sha256").digest())

    iv, ciphertext = sections[1][:AES_IV_LENGTH], sections[1][AES_IV_LENGTH:]
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    assert unpadder.update(plaintext) + unpadder.finalize() == inner

    spki = club.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.PKCS1,
    )
    assert sections[3] == hashlib.sha256(spki).digest()
    assert sections[4] == hashlib.sha256(inner).digest()


def test_the_two_hashes_inside_the_blob_are_sha256_and_the_announcement_is_sha1(
    pinned,
) -> None:
    # Three digests, none derivable from the others. This is the one that would survive a
    # well-meaning tidy-up of "obsolete SHA-1" and stop the blob being decryptable.
    root_key, root = pinned
    _, club = _make_club(root_key, root)

    built = build_escrow_blob(
        dsid=DSID,
        label=LABEL,
        timestamp=escrow_timestamp(NOW),
        password=PASSCODE,
        record=RECORD,
        certificate=club,
    )

    assert base64.b64decode(built.digest) == hashlib.sha1(built.blob).digest()  # noqa: S324
    assert len(base64.b64decode(blob_digest(b"anything"))) == 20


def test_sealing_to_a_certificate_that_is_not_rsa_is_refused(pinned) -> None:
    root_key, root = pinned
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name("Escrow Club"))
        .issuer_name(root.subject)
        .public_key(key.public_key())
        .serial_number(8)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .sign(root_key, hashes.SHA256())
    )

    with pytest.raises(EnrolmentError, match="RSA"):
        seal_to_club(_inner(), certificate)


# --------------------------------------------------------------------------------------
# Labels, timestamps and metadata
# --------------------------------------------------------------------------------------


def test_a_label_is_built_from_a_peer_identifier() -> None:
    assert record_label(PEER_ID) == LABEL


def test_a_bottle_id_is_refused_as_a_label() -> None:
    # The specific confusion §4.4 warns about: a bottleID is a UUID and addresses nothing.
    with pytest.raises(EnrolmentError, match="not a peer identifier"):
        record_label("4A1E5B9C-0000-4000-8000-000000000000")


def test_the_timestamp_has_a_space_and_no_zone() -> None:
    assert escrow_timestamp(NOW) == "2026-01-01 12:30:45"


def test_one_timestamp_reaches_all_four_places() -> None:
    timestamp = escrow_timestamp(NOW)
    inner = build_inner_message(
        dsid=DSID,
        label=LABEL,
        timestamp=timestamp,
        password=PASSCODE,
        record=RECORD,
        salt=b"\x05" * 64,
    )
    _, sections = parse_keyvault_message(inner, 16, 6)
    metadata = plistlib.loads(
        build_metadata(
            _device(),
            timestamp=timestamp,
            bottle_id="4A1E5B9C-0000-4000-8000-000000000000",
            escrowed_spki=b"\x04" * 65,
            password=PASSCODE,
        ),
    )

    assert sections[5].decode() == timestamp
    assert plistlib.loads(RECORD)["com.apple.securebackup.timestamp"] == timestamp
    assert metadata["com.apple.securebackup.timestamp"] == timestamp
    assert metadata["ClientMetadata"]["SecureBackupMetadataTimestamp"] == timestamp


def _device() -> DeviceDescription:
    return DeviceDescription(
        name="A Linux box",
        model="LinuxPC1,1",
        serial="X0X0X0X0X0X0",
        build="24A335",
        model_class="PC",
        platform="linux",
        machine_id="MID",
    )


def test_the_metadata_is_a_binary_plist_the_listing_can_describe() -> None:
    # The reader was written against records Apple's own clients wrote, and §4.5.2 spells
    # three keys differently. A record this library enrols must still be describable by
    # this library's listing, which is what this checks.
    raw = build_metadata(
        _device(),
        timestamp=escrow_timestamp(NOW),
        bottle_id="4A1E5B9C-0000-4000-8000-000000000000",
        escrowed_spki=b"\x04" * 65,
        password=PASSCODE,
    )
    assert raw.startswith(b"bplist")

    record = _parse_metadata(LABEL, raw)

    assert record.device_name == "A Linux box"
    assert record.device_model == "LinuxPC1,1"
    assert record.serial == "X0X0X0X0X0X0"
    assert record.bottle_id == "4A1E5B9C-0000-4000-8000-000000000000"
    assert record.passcode_generation == 13
    assert record.escrowed_at == NOW
    assert record.is_recovery_candidate
    assert record.peer_id == PEER_ID


def test_the_metadata_keys_are_the_irregular_spellings_and_not_the_tidy_ones() -> None:
    # Three of these were once written as an implementation's internal field names, and a
    # record under those spellings is one §5.1's listing cannot describe. None of the six
    # is derivable from its neighbours -- camelCase, reverse-DNS, PascalCase and a
    # lower-case `i` in `iCSCs`, all in one dictionary -- so they are checked literally.
    metadata = plistlib.loads(
        build_metadata(
            _device(),
            timestamp=escrow_timestamp(NOW),
            bottle_id="4A1E5B9C-0000-4000-8000-000000000000",
            escrowed_spki=b"\x04" * 65,
            password=PASSCODE,
        ),
    )

    assert sorted(metadata) == [
        "ClientMetadata",
        "SecureBackupUsesMultipleiCSCs",
        "bottleID",
        "build",
        "com.apple.securebackup.timestamp",
        "escrowedSPKI",
        "passcodeGeneration",
        "serial",
    ]


@pytest.mark.parametrize(
    ("password", "numeric", "length"),
    [("123456", True, 6), ("hunter2", False, 0), ("0000", True, 4)],
)
def test_the_passphrase_shape_is_described_honestly(
    password: str,
    numeric: bool,
    length: int,
) -> None:
    metadata = plistlib.loads(
        build_metadata(
            _device(),
            timestamp=escrow_timestamp(NOW),
            bottle_id="4A1E5B9C-0000-4000-8000-000000000000",
            escrowed_spki=b"\x04" * 65,
            password=password,
        ),
    )
    client = metadata["ClientMetadata"]

    assert client["SecureBackupUsesNumericPassphrase"] is numeric
    assert client["SecureBackupNumericPassphraseLength"] == length


def test_a_root_about_to_expire_is_reported_while_there_is_time(
    pinned,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # 500 is the root a live club certificate chains to, and it expires in 2032 where the
    # other three run to 2049. So this set has a real end date, and the failure that
    # follows is enrolment refusing with a message about certificates months after anyone
    # could have acted. A year's notice is the point.
    from findmy.keychain.enrolment import verify_club_certificate  # noqa: PLC0415

    root_key, root = pinned
    _, club = _make_club(root_key, root, not_after=NOW + timedelta(days=300))
    roots = PinnedRoots.load([root.public_bytes(serialization.Encoding.DER)])

    with caplog.at_level("WARNING"):
        verify_club_certificate(
            club.public_bytes(serialization.Encoding.DER),
            roots,
            # Inside the root's own validity, but within a year of its end.
            now=NOW + timedelta(days=200),
        )

    assert "has to ship before then" in caplog.text


def test_a_root_with_years_left_says_nothing(pinned, caplog: pytest.LogCaptureFixture) -> None:
    from findmy.keychain.enrolment import verify_club_certificate  # noqa: PLC0415

    root_key, root = pinned
    _, club = _make_club(root_key, root)
    roots = PinnedRoots.load([root.public_bytes(serialization.Encoding.DER)])

    with caplog.at_level("WARNING"):
        verify_club_certificate(club.public_bytes(serialization.Encoding.DER), roots, now=NOW)

    assert caplog.text == ""


def test_the_four_roots_are_told_apart_only_by_their_serial_number_attribute() -> None:
    # All four share a common name, an organisation and an OU. The X.520 serialNumber
    # attribute is the whole difference, so a matcher comparing common names -- or one
    # dropping an attribute it did not recognise -- would have four candidates and no way
    # to choose. This is why the issuer match compares the whole DN.
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    roots = PinnedRoots.bundled()

    without_serial = set()
    for version, certificate in roots.by_version.items():
        attributes = {
            attribute.oid.dotted_string: attribute.value
            for attribute in certificate.subject
        }
        assert attributes["2.5.4.5"] == str(version)  # X.520 serialNumber
        assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0
        ].value == "Escrow Service Root CA"

        without_serial.add(
            tuple(sorted((k, v) for k, v in attributes.items() if k != "2.5.4.5")),
        )

    assert len(without_serial) == 1
