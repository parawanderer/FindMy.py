"""
Frozen transcripts of what this library writes, so that a change to it is visible.

Every input here is fixed -- fixed keys, a fixed timestamp, a fixed salt -- because a
transcript of something random says nothing. Where a format is unavoidably random, the
random part is named and excluded rather than quietly dropped; see the ECDSA note below.

See `golden.py` for what this catches that the rest of the suite does not.
"""

from __future__ import annotations

import plistlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ec
from golden import (
    assert_golden,
    der_transcript,
    keyvault_transcript,
    plist_transcript,
    protobuf_transcript,
    transcript,
)

from findmy.keychain.enrolment import (
    DeviceDescription,
    build_inner_message,
    build_metadata,
    build_record,
    escrow_timestamp,
    record_label,
)
from findmy.keychain.escrow import KeyVaultSection, build_keyvault_message
from findmy.keychain.join import make_permanent_info

# Fixed everything. A golden file is only worth having if the same run produces the same
# bytes, so nothing here may be generated, timed or random.
NOW = datetime(2026, 1, 1, 12, 30, 45, tzinfo=timezone.utc)
TIMESTAMP = escrow_timestamp(NOW)
DSID = "1234567890"
PEER_ID = "SHA256:" + "A" * 43 + "="
PASSCODE = "123456"
ENTROPY = bytes(range(72))
SALT = b"\x05" * 64

# Derived from a fixed scalar rather than generated: a P-384 signing key that is the same
# key on every machine and every run.
SIGNING_KEY = ec.derive_private_key(0x1F2E3D4C5B6A79887766554433221100, ec.SECP384R1())


def test_the_escrow_record_is_the_three_key_plist_it_has_always_been() -> None:
    record = build_record(TIMESTAMP, ENTROPY)

    assert_golden(
        "escrow_record",
        transcript("escrow record (§4.5.3)", record, plist_transcript(record)),
    )


def test_the_escrow_metadata_still_carries_apples_own_spellings() -> None:
    # Six keys in five different casings, none derivable from its neighbours. A quiet
    # change to any of them makes a record this library writes unrecognisable in a
    # listing -- which is the only place a person ever sees one.
    device = DeviceDescription(
        name="A Linux box",
        model="LinuxPC1,1",
        serial="X0X0X0X0X0X0",
        build="24A335",
        model_class="PC",
        platform="linux",
        machine_id="MID",
    )
    metadata = build_metadata(
        device,
        timestamp=TIMESTAMP,
        bottle_id="4A1E5B9C-0000-4000-8000-000000000000",
        escrowed_spki=b"\x04" * 65,
        password=PASSCODE,
    )

    assert_golden(
        "escrow_metadata",
        transcript("escrow metadata (§4.5.2)", metadata, plist_transcript(metadata)),
    )


def test_the_inner_message_frames_its_six_sections_the_same_way() -> None:
    # The salt is fixed, so the PBKDF2 derivation and the AES-CBC ciphertext under it are
    # too. If this digest moves, a record enrolled by the new code will not open under
    # the old reader, or the other way round.
    inner = build_inner_message(
        dsid=DSID,
        label=record_label(PEER_ID),
        timestamp=TIMESTAMP,
        password=PASSCODE,
        record=build_record(TIMESTAMP, ENTROPY),
        salt=SALT,
    )

    assert_golden(
        "escrow_inner_message",
        transcript(
            "escrow inner message (§4.5.1)",
            inner,
            keyvault_transcript(inner, header_length=16, sections=6),
        ),
    )


def test_keyvault_framing_still_places_its_offsets_where_it_did() -> None:
    # Including a padded section, which is the part of this framing that is easy to get
    # wrong in a way nothing else notices: the declared length stays the true length and
    # the footprint grows.
    framed = build_keyvault_message(
        bytes(range(24)),
        [b"request-id", KeyVaultSection(b"salt", 20), b"server-public-value"],
    )

    assert_golden(
        "keyvault_message",
        transcript(
            "keyvault framing",
            framed,
            keyvault_transcript(framed, header_length=24, sections=3),
        ),
    )


def test_the_permanent_info_a_peer_identifier_digests_is_unchanged() -> None:
    # **The signature is excluded on purpose.** ECDSA is randomised, so signing the same
    # bytes twice gives two different signatures and a golden over one would fail every
    # run. What matters here is the signed bytes: a peer's identifier is a digest over
    # exactly these, so a field that moves renames every peer this client makes.
    blob = make_permanent_info(
        SIGNING_KEY,
        signing_public=b"\x04" + bytes(range(96)),
        encryption_public=b"\x04" + bytes(range(96, 192)),
        machine_id="MACHINE-1",
        model_id="MacBookPro18,3",
        creation_time=1767270645,
    )

    assert_golden(
        "permanent_info",
        transcript(
            "peer permanent info (signed bytes only; ECDSA is randomised)",
            blob.info,
            protobuf_transcript(blob.info),
        ),
    )


def test_a_transcript_describes_the_structure_and_not_the_secrets() -> None:
    """Test that nothing in a transcript is a value somebody should not paste."""
    # These get attached to issues. Key material must appear as a length and a digest,
    # never as itself -- a rule worth a test rather than a comment, since the natural
    # thing for a describer to do is print what it found.
    record = build_record(TIMESTAMP, ENTROPY)
    lines = "\n".join(plist_transcript(record))

    assert "BottledPeerEntropy" in lines
    assert ENTROPY.hex() not in lines
    assert repr(ENTROPY) not in lines
    assert "bytes (72)" in lines


def test_a_transcript_reads_der_without_the_parser_it_is_checking() -> None:
    """Test the separate DER reader against a structure built here by hand."""
    # If this used `findmy.cloudkit.der`, a transcript of that parser's output would
    # agree with it by construction, which is the whole failure this file exists to see.
    inner = b"\x02\x01\x07"  # INTEGER 7
    sequence = bytes([0x30, len(inner)]) + inner

    assert der_transcript(sequence, depth=0) == [
        "SEQUENCE (3)",
        "  INTEGER (1)",
        "    sha256 " + __import__("hashlib").sha256(b"\x07").hexdigest()[:16],
    ]


def test_something_that_is_not_der_is_described_rather_than_raising() -> None:
    """Test that an opaque payload does not take the transcript down with it."""
    # Half these payloads are protobuf inside a tag; a describer that throws on the first
    # one is a describer nobody can use.
    described = der_transcript(b"\x30\x03\x02\x7f\x41", depth=0)

    assert len(described) == 1
    assert described[0].startswith("<not DER:")


def test_a_record_is_still_readable_by_the_reader_that_reads_apples() -> None:
    """Test that the frozen record parses, so a stale golden is caught as stale."""
    # A transcript proves the bytes did not move. It does not prove they are *right*, and
    # the pairing is what makes the freeze meaningful rather than decorative.
    record = plistlib.loads(build_record(TIMESTAMP, ENTROPY))

    assert record["BottledPeerEntropy"] == ENTROPY
    assert record["com.apple.securebackup.timestamp"] == TIMESTAMP
