"""
Grand Slam's ``hsc`` 409 with no ``au`` is a request for a second factor.

Since 2026-10-12 a password Apple accepts but wants a code for is answered at the SRP
``complete`` step with ``hsc`` 409 and no ``au`` (malmeloo/FindMy.py#278, OpenTagViewer#248).
``au`` is what ``_gsa_authenticate`` reads to decide whether a code is needed, so the sign-in was
taken as finished and the ``mobileme`` login after it failed with ``status=1``.

These run the whole SRP exchange offline, against a verifier built from the same password, so
what is tested is ``_gsa_authenticate``'s own decision and not a stand-in for it.
"""

from __future__ import annotations

import hashlib
import hmac
import plistlib
from typing import Any

import pytest
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from findmy.reports.account import AsyncAppleAccount, _normalize_2fa_status
from findmy.reports.anisette import RemoteAnisetteProvider
from findmy.reports.state import LoginState
from findmy.util.crypto import encrypt_password

USERNAME = "someone@example.com"
PASSWORD = "hunter2"
SALT = bytes(range(16))
ITERATIONS = 1000


def _verification_key() -> bytes:
    """What Apple holds for ``PASSWORD``: ``g^x mod N``, with no username in ``x``."""
    derived = encrypt_password(PASSWORD, SALT, ITERATIONS, "s2k")
    n, g = srp.get_ng(srp.NG_2048, None, None)
    inner = hashlib.sha256(b":" + derived).digest()
    x = int.from_bytes(hashlib.sha256(SALT + inner).digest(), "big")
    return srp.long_to_bytes(pow(g, x, n))


def _encrypt_spd(session_key: bytes, spd: dict[str, Any]) -> bytes:
    """The inverse of ``util.crypto.decrypt_spd_aes_cbc``."""
    key = hmac.new(session_key, b"extra data key:", hashlib.sha256).digest()
    iv = hmac.new(session_key, b"extra data iv:", hashlib.sha256).digest()[:16]
    padder = padding.PKCS7(128).padder()
    data = padder.update(plistlib.dumps(spd)) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _account_answering_complete_with(status: dict[str, Any]) -> AsyncAppleAccount:
    """An account whose Grand Slam is a real SRP verifier that answers ``complete`` with ``status``."""
    account = AsyncAppleAccount(RemoteAnisetteProvider("http://127.0.0.1:1/"))
    verifier: list[srp.Verifier] = []

    async def answer(params: dict[str, Any]) -> dict[str, Any]:
        if params["o"] == "init":
            server = srp.Verifier(
                USERNAME,
                SALT,
                _verification_key(),
                params["A2k"],
                hash_alg=srp.SHA256,
                ng_type=srp.NG_2048,
            )
            verifier.append(server)
            _, b = server.get_challenge()
            return {
                "Status": {"ec": 0},
                "sp": "s2k",
                "s": SALT,
                "i": ITERATIONS,
                "B": b,
                "c": "cookie",
            }

        server = verifier[0]
        m2 = server.verify_session(params["M1"])
        assert m2 is not None, "the client's proof did not verify; the fixture is wrong"
        spd = {
            "adsid": "000000-00-00000000-0000-0000-0000-000000000000",
            "GsIdmsToken": "idms-token",
            "acname": USERNAME,
            "fn": "Some",
            "ln": "One",
        }
        return {
            "Status": dict(status),
            "M2": m2,
            "spd": _encrypt_spd(server.get_session_key(), spd),
        }

    account._gsa_request = answer  # type: ignore[method-assign]  # noqa: SLF001
    return account


@pytest.mark.asyncio
async def test_a_409_without_au_asks_for_a_trusted_device_code() -> None:
    """The case from #278: Apple wants a code and says so only with hsc 409."""
    account = _account_answering_complete_with({"ec": 0, "hsc": 409})

    state = await account._gsa_authenticate(USERNAME, PASSWORD)  # noqa: SLF001

    assert state == LoginState.REQUIRE_2FA
    assert account._account_info is not None  # noqa: SLF001
    assert account._account_info["trusted_device_2fa"]  # noqa: SLF001


@pytest.mark.asyncio
async def test_no_409_and_no_au_is_still_a_finished_sign_in() -> None:
    """An account that needs no code must not be asked for one."""
    account = _account_answering_complete_with({"ec": 0, "hsc": 200})

    state = await account._gsa_authenticate(USERNAME, PASSWORD)  # noqa: SLF001

    assert state == LoginState.AUTHENTICATED


@pytest.mark.asyncio
async def test_an_au_apple_did_send_is_kept() -> None:
    """A 409 naming ``au`` already says which kind of code; it is not overwritten."""
    account = _account_answering_complete_with({"ec": 0, "hsc": 409, "au": "secondaryAuth"})

    state = await account._gsa_authenticate(USERNAME, PASSWORD)  # noqa: SLF001

    assert state == LoginState.REQUIRE_2FA
    assert account._account_info is not None  # noqa: SLF001
    assert not account._account_info["trusted_device_2fa"]  # noqa: SLF001


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ({"hsc": 409}, {"hsc": 409, "au": "trustedDeviceSecondaryAuth"}),
        ({"hsc": 409, "au": ""}, {"hsc": 409, "au": "trustedDeviceSecondaryAuth"}),
        ({"hsc": 409, "au": "secondaryAuth"}, {"hsc": 409, "au": "secondaryAuth"}),
        ({"hsc": 200}, {"hsc": 200}),
        ({}, {}),
    ],
)
def test_only_a_409_without_au_is_changed(
    status: dict[str, Any],
    expected: dict[str, Any],
) -> None:
    _normalize_2fa_status(status)
    assert status == expected
