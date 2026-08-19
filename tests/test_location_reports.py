"""
Tests for the last hop: an encrypted location report becoming a latitude and longitude.

This is what the library exists to produce, and until now nothing imported
`findmy.reports.reports` at all -- the chain master key -> `keys_at(n)` -> encrypted
payload -> coordinates was broken at the third link, in the sense that nothing checked it.

The encryptor here is **written from the format, not from the decryptor**: a fixture built
by calling the code under test in reverse proves only that it is its own inverse. This one
does what a finder device does -- generate an ephemeral key, agree with the tag's
advertised key, derive, seal -- so the two meet from opposite sides.
"""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from golden import assert_golden, digest, transcript

from findmy.keys import KeyPair
from findmy.reports.reports import LocationReport

# The report clock counts from 11323 days before the Unix epoch -- Apple's own epoch,
# 2001-01-01 -- in seconds, in four bytes.
APPLE_EPOCH_OFFSET = 60 * 60 * 24 * 11323

# Fixed, so the golden below is the same on every machine. A tag's advertising key and
# the finder's ephemeral key, neither generated.
TAG_KEY = KeyPair(bytes(range(1, 29)))
EPHEMERAL_SCALAR = 0x0FEDCBA987654321FEDCBA987654321FEDCBA98765432100
WHEN = datetime(2026, 1, 1, 12, 30, 45, tzinfo=timezone.utc)


def encrypt_report(  # noqa: PLR0913 -- a report's every field, and there are seven
    key: KeyPair,
    *,
    latitude: float = 52.379189,
    longitude: float = 4.899431,
    accuracy: int = 12,
    status: int = 3,
    when: datetime = WHEN,
    confidence: int = 2,
    new_format: bool = False,
    ephemeral_scalar: int = EPHEMERAL_SCALAR,
) -> bytes:
    """
    Build the payload a finder device uploads, as Apple's format defines it.

    :param new_format: The 89-byte shape macOS 14 introduced, which carries an extra byte
        between the timestamp and the confidence. Both are in the wild.
    """
    plaintext = struct.pack(
        ">iiBB",
        round(latitude * 1e7),
        round(longitude * 1e7),
        accuracy,
        status,
    )

    ephemeral = ec.derive_private_key(ephemeral_scalar, ec.SECP224R1())
    point = ephemeral.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    # The finder agrees with the key the tag is advertising, which is the public half of
    # the key the owner holds.
    advertised = ec.derive_private_key(
        int.from_bytes(key.private_key_bytes, "big"),
        ec.SECP224R1(),
    ).public_key()
    shared = ephemeral.exchange(ec.ECDH(), advertised)

    symmetric = hashlib.sha256(shared + b"\x00\x00\x00\x01" + point).digest()

    encryptor = Cipher(algorithms.AES(symmetric[:16]), modes.GCM(symmetric[16:])).encryptor()
    sealed = encryptor.update(plaintext) + encryptor.finalize()

    seconds = int(when.timestamp()) - APPLE_EPOCH_OFFSET
    lead = seconds.to_bytes(4, "big") + (b"\x00" if new_format else b"")

    return lead + bytes([confidence]) + point + sealed + encryptor.tag


def a_report(**kwargs: object) -> LocationReport:
    """Build a report as it arrives from Apple: payload plus the key digest it is under."""
    payload = encrypt_report(TAG_KEY, **kwargs)  # pyright: ignore [reportArgumentType]
    return LocationReport(payload, TAG_KEY.hashed_adv_key_bytes)


# --------------------------------------------------------------------------------------
# The whole hop
# --------------------------------------------------------------------------------------


def test_a_report_decrypts_to_the_place_it_was_sealed_with() -> None:
    report = a_report()

    report.decrypt(TAG_KEY)

    assert report.is_decrypted
    assert round(report.latitude, 6) == 52.379189
    assert round(report.longitude, 6) == 4.899431
    assert report.horizontal_accuracy == 12
    assert report.status == 3
    assert report.timestamp == WHEN


def test_the_eighty_nine_byte_format_decrypts_to_the_same_place() -> None:
    # macOS 14 added a byte between the timestamp and the confidence, and the reader
    # drops it by *length*. Both shapes are in the wild simultaneously, so a change that
    # handles one and not the other is invisible on whichever machine you tested on.
    old = a_report()
    new = a_report(new_format=True)

    assert len(old.payload) == 88
    assert len(new.payload) == 89

    old.decrypt(TAG_KEY)
    new.decrypt(TAG_KEY)

    assert (old.latitude, old.longitude) == (new.latitude, new.longitude)
    assert old.horizontal_accuracy == new.horizontal_accuracy


def test_the_confidence_is_read_from_a_different_byte_in_each_format() -> None:
    # It moves with the extra byte, and it is read without decrypting anything -- so a
    # reader that took it from a fixed offset would return the confidence of one format
    # and a slice of an ephemeral key for the other.
    assert a_report(confidence=2).confidence == 2
    assert a_report(confidence=2, new_format=True).confidence == 2


def test_a_southern_and_western_location_survives_the_round_trip() -> None:
    # Latitude and longitude are signed 32-bit. Reading them unsigned puts anything south
    # of the equator or west of Greenwich on the other side of the planet, and half the
    # obvious test coordinates are in neither hemisphere that would catch it.
    report = a_report(latitude=-33.856159, longitude=-151.215256)

    report.decrypt(TAG_KEY)

    assert round(report.latitude, 6) == -33.856159
    assert round(report.longitude, 6) == -151.215256


def test_the_timestamp_is_read_against_apples_epoch_and_not_unix() -> None:
    # 11323 days apart. Getting it wrong dates every report to 1970 and sorts a history
    # into an order that looks plausible and is not.
    report = a_report(when=WHEN)

    assert report.timestamp == WHEN
    assert int.from_bytes(report.payload[0:4], "big") != int(WHEN.timestamp())


# --------------------------------------------------------------------------------------
# What a caller gets wrong
# --------------------------------------------------------------------------------------


def test_a_report_refuses_a_key_it_was_not_sealed_to() -> None:
    other = KeyPair(bytes(range(29, 57)))
    report = a_report()

    assert not report.can_decrypt(other)
    with pytest.raises(ValueError, match="Cannot decrypt"):
        report.decrypt(other)


def test_asking_where_it_is_before_decrypting_says_so() -> None:
    # Rather than returning a coordinate derived from ciphertext, which is a number and
    # looks like an answer.
    report = a_report()

    for attribute in ("latitude", "longitude", "horizontal_accuracy", "status", "key"):
        with pytest.raises(RuntimeError, match=r"unavailable|Full key"):
            getattr(report, attribute)


def test_decrypting_twice_is_not_an_error() -> None:
    report = a_report()

    report.decrypt(TAG_KEY)
    report.decrypt(TAG_KEY)

    assert round(report.latitude, 6) == 52.379189


# --------------------------------------------------------------------------------------
# Being a value: order, equality, storage
# --------------------------------------------------------------------------------------


def test_reports_sort_by_when_they_were_recorded() -> None:
    # A history is presented in order, and `bisect.insort` in the fetcher depends on this.
    earlier = a_report(when=WHEN - timedelta(hours=2))
    later = a_report(when=WHEN)

    assert earlier < later
    assert sorted([later, earlier]) == [earlier, later]


def test_two_reports_of_one_moment_and_place_are_one_report() -> None:
    # Apple returns duplicates across overlapping key windows, and the fetcher relies on
    # a set to drop them -- so equality and hashing have to agree about what a duplicate
    # is. Note the payloads differ: each was sealed under its own ephemeral key.
    first, second = a_report(), a_report(ephemeral_scalar=EPHEMERAL_SCALAR + 1)
    first.decrypt(TAG_KEY)
    second.decrypt(TAG_KEY)

    assert first.payload != second.payload
    assert first == second
    assert len({first, second}) == 1


def test_a_decrypted_report_restores_from_storage_still_decrypted() -> None:
    report = a_report()
    report.decrypt(TAG_KEY)

    restored = LocationReport.from_json(report.to_json())

    assert restored.is_decrypted
    assert restored.latitude == report.latitude
    assert restored.key.private_key_bytes == TAG_KEY.private_key_bytes


def test_an_encrypted_report_is_stored_without_a_key_it_does_not_have() -> None:
    report = a_report()

    stored = report.to_json()

    assert stored["type"] == "locReportEncrypted"
    assert "key" not in stored
    assert not LocationReport.from_json(stored).is_decrypted


# --------------------------------------------------------------------------------------
# Frozen
# --------------------------------------------------------------------------------------


def test_a_report_sealed_the_old_way_still_decodes_to_the_same_place() -> None:
    """Test the frozen payload, which is the point of the whole corpus."""
    # Both keys and the timestamp are fixed, so this payload is a constant. Someone
    # adding support for a new report shape can run this and see that the shape people
    # already have still decodes -- which no amount of freshly generated fixtures shows,
    # since those move with whatever produced them.
    payload = encrypt_report(TAG_KEY)
    report = LocationReport(payload, TAG_KEY.hashed_adv_key_bytes)
    report.decrypt(TAG_KEY)

    assert_golden(
        "location_report",
        transcript(
            "location report, 88-byte form",
            payload,
            [
                # In UTC, not as the property returns it: `timestamp` converts to the
                # local zone, so a transcript of it would differ by machine and the
                # golden would fail for whoever is not in the zone that wrote it.
                f"  timestamp    {report.timestamp.astimezone(timezone.utc).isoformat()}",
                f"  confidence   {report.confidence}",
                f"  ephemeral    (57) sha256 {digest(payload[5:62])}",
                f"  ciphertext   (10) sha256 {digest(payload[62:72])}",
                f"  tag          (16) sha256 {digest(payload[72:])}",
                f"  decrypts to  {report.latitude}, {report.longitude}"
                f" +/-{report.horizontal_accuracy}m status {report.status}",
            ],
        ),
    )
