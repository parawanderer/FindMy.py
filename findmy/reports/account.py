"""Module containing most of the code necessary to interact with an Apple account."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import plistlib
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import (
    TYPE_CHECKING,
    Any,
    Concatenate,
    Literal,
    TypedDict,
    TypeVar,
    cast,
    overload,
)

import bs4
import srp._pysrp as srp
from typing_extensions import NotRequired, ParamSpec, override

from findmy import util
from findmy.errors import (
    EmptyResponseError,
    InvalidCredentialsError,
    InvalidStateError,
    MobileMeDelegateError,
    UnauthorizedError,
    UnhandledProtocolError,
)

from .anisette import AnisetteMapping, get_provider_from_mapping
from .reports import LocationReport, LocationReportsFetcher
from .state import LoginState
from .terms import (
    ICLOUD_TERMS,
    TERMS_UI_URL,
    Terms,
    TermsError,
    parse_buddyml,
    require_fetched,
    setup_headers,
    terms_request_body,
)
from .twofactor import (
    AsyncSecondFactorMethod,
    AsyncSmsSecondFactor,
    AsyncTrustedDeviceSecondFactor,
    BaseSecondFactorMethod,
    SyncSecondFactorMethod,
    SyncSmsSecondFactor,
    SyncTrustedDeviceSecondFactor,
)

if TYPE_CHECKING:
    import io
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from findmy.accessory import RollingKeyPairSource
    from findmy.keys import HasHashedPublicKey
    from findmy.util.types import MaybeCoro

    from .anisette import BaseAnisetteProvider, DeviceIdentity

logger = logging.getLogger(__name__)

srp.rfc5054_enable()
srp.no_username_in_x()

# Which Apple daemon a request claims to be, in the trailing group of a client info and
# the leading token of a user agent. Only the bundle differs between them -- the device
# is one device, and comes from :attr:`BaseAppleAccount.identity`.
_ACCOUNTSD_BUNDLE = "com.apple.AOSKit/282 (com.apple.accountsd/113)"
_ICLOUD_HELPER = "com.apple.iCloudHelper/282"

_GSA_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
"""
The user agent Grand Slam authentication is performed under.

**Deliberately not composed from the identity**, and the one string here that does not
follow it. It describes macOS 10.14 while the client info beside it describes whatever the
identity claims, which is a contradiction -- and it is left alone because it is on the
authentication path. Every session this library has established was established under it;
a change here cannot be tested without a live account, and being wrong means nobody can
log in. It is named here rather than inlined so that it is one decision, visible, rather
than a constant somebody tidies away by accident.
"""


class _AccountInfo(TypedDict):
    account_name: str
    first_name: str
    last_name: str
    trusted_device_2fa: bool


class _AccountStateMappingIds(TypedDict):
    uid: str
    devid: str


class _AccountStateMappingAccount(TypedDict):
    username: str | None
    password: str | None
    info: _AccountInfo | None

    device_name: NotRequired[str]
    """
    What this client registers as in the account's device list.

    Written only when set, so existing files stay valid -- and keep whatever entry they
    already have. A name that reverted on reload would describe, under a second name, a
    device the user is already looking at.
    """


class _AccountStateMappingLoginState(TypedDict):
    state: int
    data: dict  # TODO: make typed  # noqa: TD002, TD003


class AccountStateMapping(TypedDict):
    """JSON mapping representing state of an Apple account instance."""

    type: Literal["account"]

    ids: _AccountStateMappingIds
    account: _AccountStateMappingAccount
    login: _AccountStateMappingLoginState
    anisette: AnisetteMapping


_P = ParamSpec("_P")
_R = TypeVar("_R")
_A = TypeVar("_A", bound="BaseAppleAccount")
_F = Callable[Concatenate[_A, _P], _R]


def _require_login_state(*states: LoginState) -> Callable[[_F], _F]:
    """Enforce a login state as precondition for a method."""

    def decorator(func: _F) -> _F:
        @wraps(func)
        def wrapper(acc: _A, *args: _P.args, **kwargs: _P.kwargs) -> _R:  # pyright: ignore [reportInvalidTypeVarUse]
            if not isinstance(acc, BaseAppleAccount):
                msg = "This decorator can only be used on instances of BaseAppleAccount."
                raise TypeError(msg)

            if acc.login_state not in states:
                msg = (
                    f"Invalid login state! Currently: {acc.login_state}"
                    f" but should be one of: {states}"
                )
                raise InvalidStateError(msg)

            return func(acc, *args, **kwargs)

        return wrapper

    return decorator


def _extract_phone_numbers(html: str) -> list[dict]:
    soup = bs4.BeautifulSoup(html, features="html.parser")
    data_elem = soup.find("script", {"class": "boot_args"})
    if not data_elem:
        msg = "Could not find HTML element containing phone numbers"
        raise RuntimeError(msg)

    data = json.loads(data_elem.text)
    return data.get("direct", {}).get("phoneNumberVerification", {}).get("trustedPhoneNumbers", [])


# Headers a Grand Slam rejection tends to explain itself in. A 401 here carries no body
# worth the name on some paths, and the reason is in a header instead -- so an error
# assembled from the status code alone reports that something was refused and nothing
# about why, which costs a whole run to find out.
_EXPLANATORY_HEADERS = ("www-authenticate", "x-apple-i-request-error", "x-apple-i-error")


def _describe_announce_failure(resp: util.http.HttpResponse) -> str:
    """
    Assemble everything the server said about a rejected announce.

    Grand Slam answers with a plist even when it refuses, and the useful part is nested:
    `Response.Status` carries an error code (`ec`) and a message (`em`). A rejection that
    is not a plist -- an HTML error page, an empty body -- falls back to raw text, and the
    headers are reported either way.
    """
    parts = [f"HTTP {resp.status_code}"]

    try:
        body: Any = resp.plist()
    except Exception:  # noqa: BLE001 -- any failure here just means it is not a plist
        body = None

    if isinstance(body, dict):
        status = body.get("Response", {}).get("Status", body.get("Status", body))
        parts.append(f"body {status!r}" if status else f"body {body!r}")
    else:
        text = resp.text().strip() if resp.content else ""
        parts.append(f"body {text[:500]!r}" if text else "an empty body")

    explanatory = {
        name: value
        for name, value in resp.headers.items()
        if name.lower() in _EXPLANATORY_HEADERS
    }
    if explanatory:
        parts.append(f"headers {explanatory!r}")

    return "Announcing the device was refused: " + ", ".join(parts)


class BaseAppleAccount(util.abc.Closable, util.abc.Serializable[AccountStateMapping], ABC):
    """Base class for an Apple account."""

    @property
    @abstractmethod
    def login_state(self) -> LoginState:
        """The current login state of the account."""
        raise NotImplementedError

    @property
    @abstractmethod
    def account_name(self) -> str | None:
        """
        The name of the account as reported by Apple.

        This is usually an e-mail address.
        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def first_name(self) -> str | None:
        """
        First name of the account holder as reported by Apple.

        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def last_name(self) -> str | None:
        """
        Last name of the account holder as reported by Apple.

        May be None in some cases, such as when not logged in.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def dsid(self) -> str:
        """
        The numeric identifier of this account.

        Used as the username half of the HTTP Basic credential that iCloud services
        expect, paired with whichever service token is appropriate. Note this is a
        different identifier from the `adsid` used during authentication.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def service_tokens(self) -> Mapping[str, str]:
        """
        The iCloud service tokens obtained while logging in, keyed by service name.

        Look tokens up by name and fail with the name that was missing; the set returned
        varies, and no position in it is meaningful.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def adsid(self) -> str | None:
        """
        The account identifier issued during authentication.

        **A different value from :attr:`dsid`**, despite both being account identifiers
        and both arriving in the same payload. Services want one or the other and they are
        not interchangeable.

        None for a session established before this was retained, in which case
        :meth:`request_pet` obtains it.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def device_uuid(self) -> str:
        """
        The identifier this installation presents itself to Apple as.

        Sent as `X-Mme-Device-Id`. Generated once and persisted with the rest of the
        account state, or supplied at construction by a client that already introduced
        itself to Apple. It must not be regenerated: a session is bound to the machine
        identity that established it, and an identity that changes per login makes every
        login look like a new machine -- which is the pattern two-factor authentication
        exists to detect, and which fills a user's device list with entries they are
        invited to remove.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def local_user_uuid(self) -> str:
        """
        The local user identifier, sent base64-encoded as `X-Apple-I-MD-LU`.

        The other half of what :attr:`device_uuid` names, and it travels with it: a client
        that supplies one supplies both. Readable so that a caller made responsible for
        these can assert what actually goes out, rather than trusting that what it passed
        is what is being sent.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def client_info(self) -> str:
        """
        The client identity string sent as `X-Mme-Client-Info`.

        Names the model, OS release and bundle this client claims to be. Its parts must be
        internally consistent and stable across logins.

        This is one composite of the identity; :attr:`identity` is the identity itself,
        and is what a caller reads to build another.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def identity(self) -> DeviceIdentity:
        """
        The device this account claims to be, in every header that names one.

        Set on the Anisette provider, which is where it is stored and serialized, and read
        from there by everything that sends a client info or a user agent -- so one value
        describes one machine no matter which request carries it.

        A path that composes its own does not fail. It contradicts the others, which is
        what a real client never does.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def device_name(self) -> str | None:
        """
        What this client registers as in the account's device list, if it has been set.

        The other field a person reads in that list, beside :attr:`serial`. Without it an
        entry is named after whatever hardware the client claims to be -- a bare `iPhone`
        among the user's real ones, with nothing to tell it apart and a *Remove from
        Account* button beside it.

        Setting this does not register anything. :meth:`announce_device` does.
        """
        raise NotImplementedError

    @abstractmethod
    def announce_device(self) -> MaybeCoro[None]:
        """
        Register this client's name in the account's device list.

        **This writes to the user's account**, and it is what turns an entry named after
        claimed hardware into one the user can recognise as software they installed.

        Signing in already registered a device; this names it. Doing it once is enough --
        the registration is the client's identity for the life of the installation, and
        creating a fresh one per operation would ask for a verification code every time.

        .. note::
            **No push token is ever sent.** A registered device that carries one is the
            most likely way it becomes trusted for verification codes, and a library that
            made its consumers into second factors for their users' Apple IDs would be
            doing real harm. There is no parameter for it and no way to switch it on.

        :raises InvalidStateError: If no device name was set on this account.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def serial(self) -> str:
        """
        The device serial this account presents, in `X-Apple-I-SRL-NO`.

        The other half of the identity :attr:`client_info` describes, and the half a person
        actually reads: it is what names this client in the account's device list. Set it
        on the Anisette provider, which is where it is stored and serialized; everything
        that sends it reads it from here, so one value describes one device.

        A path that sends a different one does not fail -- it **registers a second device**,
        next to a button inviting the owner to remove something they do not recognise.
        """
        raise NotImplementedError

    @abstractmethod
    def request_pet(self) -> MaybeCoro[str]:
        """
        Obtain a fresh password-equivalent token by authenticating again.

        Logging in spends the PET it produces, so a logged-in account has none to give.
        Some iCloud services want one anyway; this issues a new one without spending it.
        """
        raise NotImplementedError

    @abstractmethod
    def login(self, username: str, password: str) -> MaybeCoro[LoginState]:
        """Log in to an Apple account using a username and password."""
        raise NotImplementedError

    @abstractmethod
    def fetch_terms(self, *names: str) -> MaybeCoro[list[Terms]]:
        """
        Fetch the iCloud terms of service, so they can be shown to the user.

        Unaccepted terms block the login, and the only ways Apple offers to accept them
        need one of its devices. This is the first half of accepting them here.
        """
        raise NotImplementedError

    @abstractmethod
    def accept_terms(self, terms: Terms) -> MaybeCoro[None]:
        """
        Record the user's agreement to terms obtained from :meth:`fetch_terms`.

        Call only once they have read them and agreed. It takes the fetched object rather
        than a name so that nothing can accept terms it never showed anyone.
        """
        raise NotImplementedError

    @abstractmethod
    def complete_login(self) -> MaybeCoro[LoginState]:
        """
        Repeat the delegate exchange, finishing a login that something interrupted.

        The last step of the terms flow, once acceptance is recorded.
        """
        raise NotImplementedError

    @abstractmethod
    def get_2fa_methods(self) -> MaybeCoro[Sequence[BaseSecondFactorMethod]]:
        """
        Get a list of 2FA methods that can be used as a secondary challenge.

        Currently, only SMS-based 2FA methods are supported.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_request(self, phone_number_id: int) -> MaybeCoro[None]:
        """
        Request a 2FA code to be sent to a specific phone number ID.

        Consider using :meth:`BaseSecondFactorMethod.request` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def sms_2fa_submit(self, phone_number_id: int, code: str) -> MaybeCoro[LoginState]:
        """
        Submit a 2FA code that was sent to a specific phone number ID.

        Consider using :meth:`BaseSecondFactorMethod.submit` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def td_2fa_request(self) -> MaybeCoro[None]:
        """
        Request a 2FA code to be sent to a trusted device.

        Consider using :meth:`BaseSecondFactorMethod.request` instead.
        """
        raise NotImplementedError

    @abstractmethod
    def td_2fa_submit(self, code: str) -> MaybeCoro[LoginState]:
        """
        Submit a 2FA code that was sent to a trusted device.

        Consider using :meth:`BaseSecondFactorMethod.submit` instead.
        """
        raise NotImplementedError

    @overload
    @abstractmethod
    def fetch_location_history(
        self,
        keys: HasHashedPublicKey,
    ) -> MaybeCoro[list[LocationReport]]: ...

    @overload
    @abstractmethod
    def fetch_location_history(
        self,
        keys: RollingKeyPairSource,
    ) -> MaybeCoro[list[LocationReport]]: ...

    @overload
    @abstractmethod
    def fetch_location_history(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> MaybeCoro[dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]]: ...

    @abstractmethod
    def fetch_location_history(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
    ) -> MaybeCoro[
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ]:
        """
        Fetch location history for :class:`HasHashedPublicKey`s and :class:`RollingKeyPairSource`s.

        Note that location history for devices is provided on a best-effort
        basis and may not be fully complete or stable. Multiple consecutive calls to this method
        may result in different location reports, especially for reports further in the past.
        However, each one of these reports is guaranteed to be in line with the data reported by
        Apple, and the most recent report will always be included in the results.

        Unless you really need to use this method, and use :meth:`fetch_location` instead.
        """
        raise NotImplementedError

    @overload
    @abstractmethod
    def fetch_location(
        self,
        keys: HasHashedPublicKey,
    ) -> MaybeCoro[LocationReport | None]: ...

    @overload
    @abstractmethod
    def fetch_location(
        self,
        keys: RollingKeyPairSource,
    ) -> MaybeCoro[LocationReport | None]: ...

    @overload
    @abstractmethod
    def fetch_location(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> MaybeCoro[
        dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None] | None
    ]: ...

    @abstractmethod
    def fetch_location(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
    ) -> MaybeCoro[
        LocationReport
        | dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]
        | None
    ]:
        """
        Fetch location for :class:`HasHashedPublicKey`s.

        Returns a dictionary mapping :class:`HasHashedPublicKey`s to their location reports.
        """
        raise NotImplementedError

    @abstractmethod
    def get_anisette_headers(
        self,
        with_client_info: bool = False,
        serial: str | None = None,
    ) -> MaybeCoro[dict[str, str]]:
        """
        Retrieve a complete dictionary of Anisette headers.

        Utility method for :meth:`AnisetteProvider.get_headers` using this account's user/device ID.
        """
        raise NotImplementedError


class AsyncAppleAccount(BaseAppleAccount):
    """An async implementation of :meth:`BaseAppleAccount`."""

    # auth endpoints
    _ENDPOINT_GSA = "https://gsa.apple.com/grandslam/GsService2"
    # Note the host: `gsas`, not `gsa`. One letter, a different host, and no useful error
    # if you get it wrong.
    _ENDPOINT_POSTDATA = "https://gsas.apple.com/grandslam/GsService2/postdata"
    _ENDPOINT_LOGIN_MOBILEME = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
    _ENDPOINT_TERMS_UI = TERMS_UI_URL

    # 2fa auth endpoints
    _ENDPOINT_2FA_METHODS = "https://gsa.apple.com/auth"
    _ENDPOINT_2FA_SMS_REQUEST = "https://gsa.apple.com/auth/verify/phone"
    _ENDPOINT_2FA_SMS_SUBMIT = "https://gsa.apple.com/auth/verify/phone/securitycode"
    _ENDPOINT_2FA_TD_REQUEST = "https://gsa.apple.com/auth/verify/trusteddevice"
    _ENDPOINT_2FA_TD_SUBMIT = "https://gsa.apple.com/grandslam/GsService2/validate"

    # reports endpoints
    _ENDPOINT_REPORTS_FETCH = "https://gateway.icloud.com/findmyservice/v2/fetch"

    def __init__(  # noqa: PLR0913 -- all keyword-only, and each is a separate decision
        self,
        anisette: BaseAnisetteProvider,
        *,
        state_info: AccountStateMapping | None = None,
        device_name: str | None = None,
        uid: str | None = None,
        devid: str | None = None,
        timeout: float = util.http.DEFAULT_TIMEOUT,
    ) -> None:
        """
        Initialize the apple account.

        :param anisette: An instance of :meth:`AsyncAnisetteProvider`.
        :param timeout: Seconds any one request this account makes may take.

            **Raise it for a slow sign-in.** Logging in is several round trips -- two SRP
            exchanges with Grand Slam, then the mobileme delegate -- and each is measured
            against this separately. The default suits Apple's own hosts on an ordinary
            connection; a congested link, a machine that suspends mid-request, or a
            self-hosted Anisette server that generates its data on demand can all exceed
            it, and what a user sees is a sign-in that fails partway through for no
            stated reason.

            It is not persisted with the account: it describes the machine and the
            network, not the session, and a restored account should take whatever the
            program running it now thinks is reasonable. Note that an Anisette provider
            keeps its own -- this one does not reach the fetch that provider makes.
        :param device_name: What this client registers as in the account's device list.
            :meth:`announce_device` is what sends it; setting this alone changes nothing.
        :param uid: The local user identifier. Defaults to a fresh random one. See
            :attr:`local_user_uuid`.

            **It is base64-encoded on the way out**, so `X-Apple-I-MD-LU` carries
            `base64(uid)` rather than `uid`. Pass the decoded value. A client aligning
            with an exchange it already made should check which of the two that exchange
            sent -- both conventions exist, and the `anisette` package sends the value
            raw.
        :param devid: The device identifier, sent as `X-Mme-Device-Id`, **uppercased**.
            Defaults to a fresh random one. See :attr:`device_uuid`.

            **Pass both or neither.** A client that introduced itself to Apple before this
            account existed -- one that provisioned its own Anisette, say -- has to give
            both to be the same installation it already was. One matching and one not is
            worse than neither: it is a shape no real client produces.
        :raises ValueError: If exactly one of `uid` and `devid` is given.
        """
        # Before `super().__init__()`, so a refused account is one that never began
        # rather than one that half exists: `Closable.__del__` runs on an object whose
        # `__init__` raised, and an object with nothing to close should have nothing to
        # collect either.
        if (uid is None) != (devid is None):
            msg = (
                "uid and devid are one identity: pass both or neither. "
                "A client that matches one of them and mints the other is two devices "
                "sharing a serial, which is worse than being one unfamiliar device."
            )
            raise ValueError(msg)

        super().__init__()

        self._anisette: BaseAnisetteProvider = anisette
        # `state_info` wins over both, always. A restored account keeps the identity it was
        # established under -- Apple binds a session to it, and swapping it because a
        # caller passed something is how a working login turns into a second device.
        self._uid: str = state_info["ids"]["uid"] if state_info else (uid or str(uuid.uuid4()))
        self._devid: str = (
            state_info["ids"]["devid"] if state_info else (devid or str(uuid.uuid4()))
        )

        # TODO: combine, user/pass should be "all or nothing"  # noqa: TD002, TD003
        self._username: str | None = state_info["account"]["username"] if state_info else None
        self._password: str | None = state_info["account"]["password"] if state_info else None

        self._login_state: LoginState = (
            LoginState(state_info["login"]["state"]) if state_info else LoginState.LOGGED_OUT
        )
        self._login_state_data: dict = state_info["login"]["data"] if state_info else {}

        self._device_name: str | None = device_name or (
            state_info["account"].get("device_name") if state_info else None
        )

        self._account_info: _AccountInfo | None = (
            state_info["account"]["info"] if state_info else None
        )

        self._http: util.http.HttpSession = util.http.HttpSession(timeout=timeout)
        self._reports: LocationReportsFetcher = LocationReportsFetcher(self)
        self._closed: bool = False

    def _set_login_state(
        self,
        state: LoginState,
        data: dict | None = None,
    ) -> LoginState:
        # clear account info if downgrading state (e.g. LOGGED_IN -> LOGGED_OUT)
        if state < self._login_state:
            logger.debug("Clearing cached account information")
            self._account_info = None

        logger.info("Transitioning login state: %s -> %s", self._login_state, state)
        self._login_state = state
        self._login_state_data = data or {}

        return state

    @property
    @override
    def login_state(self) -> LoginState:
        """See :meth:`BaseAppleAccount.login_state`."""
        return self._login_state

    @property
    @_require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    @override
    def account_name(self) -> str | None:
        """See :meth:`BaseAppleAccount.account_name`."""
        return self._account_info["account_name"] if self._account_info else None

    @property
    @_require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    @override
    def first_name(self) -> str | None:
        """See :meth:`BaseAppleAccount.first_name`."""
        return self._account_info["first_name"] if self._account_info else None

    @property
    @_require_login_state(
        LoginState.LOGGED_IN,
        LoginState.AUTHENTICATED,
        LoginState.REQUIRE_2FA,
    )
    @override
    def last_name(self) -> str | None:
        """See :meth:`BaseAppleAccount.last_name`."""
        return self._account_info["last_name"] if self._account_info else None

    @property
    @_require_login_state(LoginState.LOGGED_IN)
    @override
    def dsid(self) -> str:
        """See :meth:`BaseAppleAccount.dsid`."""
        return self._login_state_data["dsid"]

    @property
    @_require_login_state(LoginState.LOGGED_IN)
    @override
    def service_tokens(self) -> Mapping[str, str]:
        """See :meth:`BaseAppleAccount.service_tokens`."""
        return self._login_state_data["mobileme_data"]["tokens"]

    @property
    @override
    def adsid(self) -> str | None:
        """See :meth:`BaseAppleAccount.adsid`."""
        return self._login_state_data.get("adsid")

    @property
    @override
    def device_uuid(self) -> str:
        """See :meth:`BaseAppleAccount.device_uuid`."""
        return self._devid

    @property
    @override
    def local_user_uuid(self) -> str:
        """See :meth:`BaseAppleAccount.local_user_uuid`."""
        return self._uid

    @property
    @override
    def client_info(self) -> str:
        """See :meth:`BaseAppleAccount.client_info`."""
        return self._anisette.client

    @property
    @override
    def identity(self) -> DeviceIdentity:
        """See :meth:`BaseAppleAccount.identity`."""
        return self._anisette.identity

    @property
    @override
    def serial(self) -> str:
        """See :meth:`BaseAppleAccount.serial`."""
        return self._anisette.serial

    @property
    @override
    def device_name(self) -> str | None:
        """See :meth:`BaseAppleAccount.device_name`."""
        return self._device_name

    @override
    def to_json(self, path: str | Path | io.TextIOBase | None = None, /) -> AccountStateMapping:
        account: _AccountStateMappingAccount = {
            "username": self._username,
            "password": self._password,
            "info": self._account_info,
        }
        if self._device_name is not None:
            account["device_name"] = self._device_name

        res: AccountStateMapping = {
            "type": "account",
            "ids": {"uid": self._uid, "devid": self._devid},
            "account": account,
            "login": {
                "state": self._login_state.value,
                "data": self._login_state_data,
            },
            "anisette": self._anisette.to_json(),
        }

        return util.files.save_and_return_json(res, path)

    @classmethod
    @override
    def from_json(
        cls,
        val: str | Path | io.TextIOBase | io.BufferedIOBase | AccountStateMapping,
        /,
        *,
        anisette_libs_path: str | Path | None = None,
    ) -> AsyncAppleAccount:
        val = util.files.read_data_json(val)
        assert val["type"] == "account"

        try:
            ani_provider = get_provider_from_mapping(val["anisette"], libs_path=anisette_libs_path)
            return cls(ani_provider, state_info=val)
        except KeyError as e:
            msg = f"Failed to restore account data: {e}"
            raise ValueError(msg) from None

    @override
    async def close(self) -> None:
        """
        Close any sessions or other resources in use by this object.

        Should be called when the object will no longer be used.
        """
        if self._closed:
            return  # Already closed, make it idempotent

        self._closed = True

        # Close in proper order: anisette first, then HTTP session
        try:
            await self._anisette.close()
        except (RuntimeError, OSError, ConnectionError) as e:
            logger.warning("Error closing anisette provider: %s", e)

        try:
            await self._http.close()
        except (RuntimeError, OSError, ConnectionError) as e:
            logger.warning("Error closing HTTP session: %s", e)

    @_require_login_state(LoginState.LOGGED_OUT)
    @override
    async def login(self, username: str, password: str) -> LoginState:
        """See :meth:`BaseAppleAccount.login`."""
        # LOGGED_OUT -> (REQUIRE_2FA or AUTHENTICATED)
        new_state = await self._gsa_authenticate(username, password)
        if new_state == LoginState.REQUIRE_2FA:  # pass control back to handle 2FA
            return new_state

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def get_2fa_methods(self) -> Sequence[AsyncSecondFactorMethod]:
        """See :meth:`BaseAppleAccount.get_2fa_methods`."""
        methods: list[AsyncSecondFactorMethod] = []

        if self._account_info is None:
            return []

        if self._account_info["trusted_device_2fa"]:
            methods.append(AsyncTrustedDeviceSecondFactor(self))

        # sms
        auth_page = await self._sms_2fa_request("GET", self._ENDPOINT_2FA_METHODS)
        try:
            phone_numbers = _extract_phone_numbers(auth_page)
            methods.extend(
                AsyncSmsSecondFactor(
                    self,
                    number.get("id") or -1,
                    number.get("numberWithDialCode") or "-",
                )
                for number in phone_numbers
            )
        except RuntimeError:
            logger.warning("Unable to extract phone numbers from login page")

        return methods

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def sms_2fa_request(self, phone_number_id: int) -> None:
        """See :meth:`BaseAppleAccount.sms_2fa_request`."""
        data = {"phoneNumber": {"id": phone_number_id}, "mode": "sms"}

        await self._sms_2fa_request(
            "PUT",
            self._ENDPOINT_2FA_SMS_REQUEST,
            data,
        )

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """See :meth:`BaseAppleAccount.sms_2fa_submit`."""
        data = {
            "phoneNumber": {"id": phone_number_id},
            "securityCode": {"code": str(code)},
            "mode": "sms",
        }

        await self._sms_2fa_request(
            "POST",
            self._ENDPOINT_2FA_SMS_SUBMIT,
            data,
        )

        # REQUIRE_2FA -> AUTHENTICATED
        new_state = await self._gsa_authenticate()
        if new_state != LoginState.AUTHENTICATED:
            msg = f"Unexpected state after submitting 2FA: {new_state}"
            raise UnhandledProtocolError(msg)

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def td_2fa_request(self) -> None:
        """See :meth:`BaseAppleAccount.td_2fa_request`."""
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
        }
        await self._sms_2fa_request(
            "GET",
            self._ENDPOINT_2FA_TD_REQUEST,
            headers=headers,
        )

    @_require_login_state(LoginState.REQUIRE_2FA)
    @override
    async def td_2fa_submit(self, code: str) -> LoginState:
        """See :meth:`BaseAppleAccount.td_2fa_submit`."""
        headers = {
            "security-code": code,
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
        }
        await self._sms_2fa_request(
            "GET",
            self._ENDPOINT_2FA_TD_SUBMIT,
            headers=headers,
        )

        # REQUIRE_2FA -> AUTHENTICATED
        new_state = await self._gsa_authenticate()
        if new_state != LoginState.AUTHENTICATED:
            msg = f"Unexpected state after submitting 2FA: {new_state}"
            raise UnhandledProtocolError(msg)

        # AUTHENTICATED -> LOGGED_IN
        return await self._login_mobileme()

    @_require_login_state(LoginState.LOGGED_IN)
    async def request_pet(self) -> str:
        """
        Obtain a fresh password-equivalent token by authenticating again.

        A PET is the short-lived credential that logging in produces, and a few iCloud
        services want it rather than a service token. Logging in **spends** it -- it is
        the credential the service tokens are exchanged for -- so by the time an account
        is logged in there is none left to hand out. This authenticates again and returns
        the new one without exchanging it, leaving the account's existing session intact.

        Two things worth knowing before calling it:

        - It makes a real authentication request, and the token it returns expires in
          about five minutes. Ask for one when it is about to be used, not in advance.
        - It requires the stored password, so it does not work for a session restored
          without one.

        :raises UnauthorizedError: If re-authentication does not complete, which most
            likely means a second factor is being demanded.
        """
        logger.info("Re-authenticating to obtain a fresh PET")

        # _gsa_authenticate replaces the login state, so the current one is put back
        # afterwards: this is meant to hand out a token, not to change what the account is.
        previous_state = self._login_state
        previous_data = self._login_state_data
        previous_info = self._account_info

        try:
            new_state = await self._gsa_authenticate()
            if new_state != LoginState.AUTHENTICATED:
                msg = (
                    f"Re-authentication ended in state {new_state} rather than"
                    " AUTHENTICATED, so no PET was issued."
                )
                raise UnauthorizedError(msg)

            pet = self._login_state_data.get("idms_pet")
            if not pet:
                msg = "Re-authentication succeeded but returned no PET"
                raise UnhandledProtocolError(msg)

            # Take the chance to record the identifier too, for a session saved before it
            # was carried forward.
            fresh_adsid = self._login_state_data.get("adsid")
        finally:
            self._login_state = previous_state
            self._login_state_data = previous_data
            self._account_info = previous_info

        if fresh_adsid and not self._login_state_data.get("adsid"):
            self._login_state_data["adsid"] = fresh_adsid

        return pet

    async def _fresh_pet(self) -> str:
        """
        Renew the PET if this account can, and return one fit to send.

        **The terms flow puts a human reading a contract in the middle of a five-minute
        credential.** Sending whatever token the failed delegate request used means the
        agreement is posted with an expired PET and rejected -- after the user has read
        the terms and agreed to them, which is the worst moment to demand a re-login. So
        each terms request authenticates again immediately beforehand.

        **That is always possible during a blocked login, and not by luck.** Renewing a
        PET repeats the SRP exchange, which needs the password -- and terms can only
        block a login that is *in progress*, so the password is necessarily in hand. A
        session restored from storage is past this stage entirely.

        The exception is §5.1's weekly token refresh, which repeats this stage unattended.
        If Apple has published new terms by then and no password is retained, there is
        nothing to renew with and a fresh sign-in is the only answer. So this falls back
        to the token already held rather than failing at the renewal, which leaves the
        request to fail on its own terms -- more informative than a pre-emptive error.
        """
        held = self._login_state_data.get("idms_pet", "")
        if not self._password:
            logger.debug("No stored password, so the PET already held is the one sent")
            return held

        previous = (self._login_state, self._login_state_data, self._account_info)
        try:
            state = await self._gsa_authenticate()
        except (InvalidCredentialsError, UnauthorizedError, UnhandledProtocolError):
            logger.warning("Could not renew the PET; sending the one held", exc_info=True)
            state = None

        if state != LoginState.AUTHENTICATED:
            if state is not None:
                logger.warning(
                    "Re-authentication ended at %s rather than AUTHENTICATED, so the PET"
                    " was not renewed and the request may be rejected as expired",
                    state,
                )
            self._login_state, self._login_state_data, self._account_info = previous
            return held

        return self._login_state_data.get("idms_pet", held)

    @_require_login_state(LoginState.AUTHENTICATED)
    async def fetch_terms(self, *names: str) -> list[Terms]:
        """
        Fetch the iCloud terms of service, so they can be shown to the user.

        An account with terms it has not accepted fails the delegate exchange, and the
        only places Apple offers to accept are one of its own devices or iCloud.com --
        a dead end for someone here because they have neither. So this fetches the text,
        and :meth:`accept_terms` records agreement to what this returned.

        **This is where the terms flow starts, and it is deliberately not the whole of
        it.** Show what comes back, let the user read it, and call :meth:`accept_terms`
        only if they agree. Nothing here accepts anything.

        Callable while the account is `AUTHENTICATED` -- the state a failed delegate
        request leaves it in.

        :param names: Which terms documents to ask for. Defaults to iCloud's.
        :returns: One :class:`~findmy.reports.terms.Terms` per page returned.
        :raises TermsError: If the response cannot be read or carries no terms.
        """
        wanted = names or (ICLOUD_TERMS,)
        logger.info("Fetching terms of service: %s", ", ".join(wanted))

        headers = await self.get_anisette_headers()
        headers.update(
            setup_headers(self.client_info, self._username or "", await self._fresh_pet()),
        )
        headers.update(
            {
                "Accept": "application/x-buddyml",
                "Content-Type": "text/plist",
                "X-Apple-I-Appearance": "1",
            },
        )

        resp = await self._http.post(
            self._ENDPOINT_TERMS_UI,
            headers=headers,
            data=terms_request_body(wanted),
        )
        if not resp.ok:
            msg = f"Fetching the terms of service failed with status {resp.status_code}"
            raise TermsError(msg)

        return parse_buddyml(resp.text())

    @_require_login_state(LoginState.AUTHENTICATED)
    async def accept_terms(self, terms: Terms) -> None:
        """
        Record the user's agreement to terms obtained from :meth:`fetch_terms`.

        **Call this only after the user has read them and said yes.** Taking the fetched
        object rather than a name is the point: a library cannot tell whether a human
        read anything, but it can refuse to agree to a contract it never obtained, and
        that is the strongest guarantee available here.

        Afterwards the delegate request should succeed, which :meth:`complete_login`
        repeats.

        .. note::
            **The credential is renewed immediately before the request.** A PET lasts
            about five minutes, and reading a contract takes longer than that, so a flow
            that showed the terms and then sent whatever token it started with would fail
            for everyone who actually read them -- and fail *after* they agreed, which is
            the worst place to put a re-login. See :meth:`_fresh_pet`.

        :param terms: Exactly what :meth:`fetch_terms` returned for the document being
            agreed to.
        :raises TermsError: If the terms did not come from a fetch, or if Apple did not
            accept the agreement. **A non-success is raised rather than swallowed**:
            reporting acceptance that did not happen fails confusingly a stage later.
        """
        require_fetched(terms)

        logger.info("Accepting terms of service: %s", terms.page_id)

        headers = await self.get_anisette_headers()
        headers.update(
            setup_headers(self.client_info, self._username or "", await self._fresh_pet()),
        )
        headers["Content-Type"] = "application/xml"

        # No body: the URL is the whole of the request.
        resp = await self._http.post(terms.agree_url, headers=headers, data=b"")
        if not resp.ok:
            msg = (
                f"Accepting the {terms.page_id} terms failed with status"
                f" {resp.status_code}, so they have not been accepted."
            )
            raise TermsError(msg)

        logger.info("Terms of service accepted: %s", terms.page_id)

    @_require_login_state(LoginState.AUTHENTICATED)
    async def complete_login(self) -> LoginState:
        """
        Repeat the delegate exchange, finishing a login that something interrupted.

        The last step of the terms flow: authentication succeeded, the delegate request
        did not, and once the reason is dealt with the exchange is simply repeated. It is
        the same step :meth:`login` runs on its own when nothing goes wrong.
        """
        return await self._login_mobileme()

    @_require_login_state(LoginState.LOGGED_IN)
    async def fetch_raw_reports(  # noqa: C901
        self,
        devices: list[tuple[list[str], list[str]]],
    ) -> list[LocationReport]:
        """Make a request for location reports, returning raw data."""
        logger.debug("Fetching raw reports for %d device(s)", len(devices))

        now = datetime.now(tz=timezone.utc)
        start_ts = int((now - timedelta(days=7)).timestamp()) * 1000
        end_ts = int(now.timestamp()) * 1000

        auth = (self.dsid, self.service_tokens["searchPartyToken"])
        data = {
            "clientContext": {
                "clientBundleIdentifier": "com.apple.icloud.searchpartyuseragent",
                "policy": "foregroundClient",
            },
            "fetch": [
                {
                    "ownedDeviceIds": [],
                    "keyType": 1,
                    "startDate": start_ts,
                    "startDateSecondary": start_ts,
                    "endDate": end_ts,
                    "primaryIds": device_keys[0],
                    "secondaryIds": device_keys[1],
                }
                for device_keys in devices
            ],
        }

        async def _do_request() -> util.http.HttpResponse:
            # bandaid fix for https://github.com/malmeloo/FindMy.py/issues/185
            # Symptom: HTTP 200 but empty response
            # Remove when real issue fixed
            retry_counter = 1
            _max_retries = 5
            while True:
                resp = await self._http.post(
                    self._ENDPOINT_REPORTS_FETCH,
                    auth=auth,
                    headers=await self.get_anisette_headers(),
                    json=data,
                )

                if resp.status_code != 200 or resp.text().strip():
                    return resp

                if retry_counter > _max_retries:
                    logger.warning(
                        "Max retries reached, returning empty response. "
                        "Location reports might be missing!"
                    )
                    msg = (
                        "Empty response received from Apple servers. "
                        "This is most likely a bug on Apple's side."
                        "More info: https://github.com/malmeloo/FindMy.py/issues/185"
                    )
                    raise EmptyResponseError(msg)

                retry_time = 2 * retry_counter
                logger.warning(
                    "Empty response received when fetching reports, retrying in %d seconds (%d/%d)",
                    retry_time,
                    retry_counter,
                    _max_retries,
                )

                await asyncio.sleep(retry_time)
                retry_counter += 1

        r = await _do_request()
        if r.status_code == 401:
            logger.info("Got 401 while fetching reports, redoing login")

            # **Asked before trying, so that "needs a password" is an auth failure and
            # not a `ValueError`.** A session restored from saved state need not carry
            # one -- that is the point of saving state -- and `_gsa_authenticate` then
            # raises a bare `ValueError("No username or password specified")` from three
            # frames down, which says nothing about authentication and is not what the
            # CloudKit half of this library raises for the same situation. Anything
            # trying to tell "the user must sign in again" from "transient" had to catch
            # both shapes and read the message of one.
            if not self._username or not self._password:
                msg = (
                    "Apple rejected the report fetch and this session holds no password"
                    " to authenticate again with, so it cannot recover on its own. The"
                    " user has to sign in."
                )
                raise UnauthorizedError(msg)

            new_state = await self._gsa_authenticate()
            if new_state != LoginState.AUTHENTICATED:
                msg = f"Unexpected login state after reauth: {new_state}. Please log in again."
                raise UnauthorizedError(msg)
            await self._login_mobileme()

            r = await _do_request()

        if r.status_code == 401:
            msg = "Not authorized to fetch reports."
            raise UnauthorizedError(msg)

        try:
            resp = r.json()
        except json.JSONDecodeError:
            resp = {}
        if not r.ok or resp.get("acsnLocations", {}).get("statusCode") != "200":
            msg = f"Failed to fetch reports: {resp.get('statusCode')}"
            raise UnhandledProtocolError(msg)

        # parse reports
        reports: list[LocationReport] = []
        for key_reports in resp.get("acsnLocations", {}).get("locationPayload", []):
            hashed_adv_key_bytes = base64.b64decode(key_reports["id"])

            for report in key_reports.get("locationInfo", []):
                payload = base64.b64decode(report)
                loc_report = LocationReport(payload, hashed_adv_key_bytes)

                reports.append(loc_report)

        return reports

    @overload
    async def fetch_location_history(
        self,
        keys: HasHashedPublicKey,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_location_history(
        self,
        keys: RollingKeyPairSource,
    ) -> list[LocationReport]: ...

    @overload
    async def fetch_location_history(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    @override
    async def fetch_location_history(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """See `BaseAppleAccount.fetch_location_history`."""
        return await self._reports.fetch_location_history(keys)

    @overload
    async def fetch_location(
        self,
        keys: HasHashedPublicKey,
    ) -> LocationReport | None: ...

    @overload
    async def fetch_location(
        self,
        keys: RollingKeyPairSource,
    ) -> LocationReport | None: ...

    @overload
    async def fetch_location(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]: ...

    @_require_login_state(LoginState.LOGGED_IN)
    @override
    async def fetch_location(
        self,
        keys: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> (
        LocationReport
        | dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]
        | None
    ):
        """See :meth:`BaseAppleAccount.fetch_location`."""
        hist = await self.fetch_location_history(keys)
        if isinstance(hist, list):
            return sorted(hist)[-1] if hist else None

        return {dev: sorted(reports)[-1] if reports else None for dev, reports in hist.items()}

    @_require_login_state(LoginState.LOGGED_OUT, LoginState.REQUIRE_2FA, LoginState.LOGGED_IN)
    async def _gsa_authenticate(
        self,
        username: str | None = None,
        password: str | None = None,
    ) -> LoginState:
        # use stored values for re-authentication
        self._username = username or self._username
        self._password = password or self._password

        logger.info("Attempting authentication for user %s", self._username)

        if not self._username or not self._password:
            msg = "No username or password specified"
            raise ValueError(msg)

        logger.debug("Starting authentication with username")

        usr = srp.User(self._username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, a2k = usr.start_authentication()
        r = await self._gsa_request(
            {"A2k": a2k, "u": self._username, "ps": ["s2k", "s2k_fo"], "o": "init"},
        )

        logger.debug("Verifying response to auth request")

        if r["Status"].get("ec") != 0:
            msg = "Email verification failed: " + r["Status"].get("em")
            raise InvalidCredentialsError(msg)
        sp = r.get("sp")
        if not isinstance(sp, str) or sp not in {"s2k", "s2k_fo"}:
            msg = f"This implementation only supports s2k and sk2_fo. Server returned {sp}"
            raise UnhandledProtocolError(msg)

        logger.debug("Attempting password challenge")

        usr.p = util.crypto.encrypt_password(self._password, r["s"], r["i"], sp)
        m1 = usr.process_challenge(r["s"], r["B"])
        if m1 is None:
            msg = "Failed to process challenge"
            raise UnhandledProtocolError(msg)
        r = await self._gsa_request(
            {"c": r["c"], "M1": m1, "u": self._username, "o": "complete"},
        )

        logger.debug("Verifying password challenge response")

        if r["Status"].get("ec") != 0:
            msg = "Password authentication failed: " + r["Status"].get("em")
            raise InvalidCredentialsError(msg)
        usr.verify_session(r.get("M2"))
        if not usr.authenticated():
            msg = "Failed to verify session"
            raise UnhandledProtocolError(msg)

        logger.debug("Decrypting SPD data in response")

        spd = util.parsers.decode_plist(
            util.crypto.decrypt_spd_aes_cbc(
                usr.get_session_key() or b"",
                r["spd"],
            ),
        )

        logger.debug("Received account information")
        self._account_info = cast(
            "_AccountInfo",
            {
                "account_name": spd.get("acname"),
                "first_name": spd.get("fn"),
                "last_name": spd.get("ln"),
                "trusted_device_2fa": False,
            },
        )

        au = r["Status"].get("au")
        if au in ("secondaryAuth", "trustedDeviceSecondaryAuth"):
            logger.info("Detected 2FA requirement: %s", au)

            self._account_info["trusted_device_2fa"] = au == "trustedDeviceSecondaryAuth"

            return self._set_login_state(
                LoginState.REQUIRE_2FA,
                {"adsid": spd["adsid"], "idms_token": spd["GsIdmsToken"]},
            )
        if au is None:
            logger.info("GSA authentication successful")

            tokens = spd.get("t", {})
            idms_pet = tokens.get("com.apple.gs.idms.pet", {}).get("token", "")
            # The heartbeat token, which is what `postdata` authenticates with. Kept
            # rather than dropped: it is issued here and nowhere else, so recovering it
            # later means authenticating again.
            idms_hb = tokens.get("com.apple.gs.idms.hb", {}).get("token", "")
            return self._set_login_state(
                LoginState.AUTHENTICATED,
                {"idms_pet": idms_pet, "idms_hb": idms_hb, "adsid": spd["adsid"]},
            )

        msg = f"Unknown auth value: {au}"
        raise UnhandledProtocolError(msg)

    @_require_login_state(LoginState.AUTHENTICATED)
    async def _login_mobileme(self) -> LoginState:
        logger.info("Logging into com.apple.mobileme")
        adsid = self._login_state_data.get("adsid")
        data = plistlib.dumps(
            {
                "apple-id": self._username,
                "delegates": {"com.apple.mobileme": {}},
                "password": self._login_state_data["idms_pet"],
                "client-id": self._uid,
            },
        )

        headers = {
            "X-Apple-ADSID": self._login_state_data["adsid"],
            # Composed rather than written out: a second copy of the identity here is a
            # second device the moment either copy moves. Speaking as accountsd, which is
            # the daemon that logs into the mobileme delegate.
            "User-Agent": self.identity.user_agent(_ICLOUD_HELPER),
            "X-Mme-Client-Info": self.identity.client_info(_ACCOUNTSD_BUNDLE),
        }
        headers.update(await self.get_anisette_headers())

        resp = await self._http.post(
            self._ENDPOINT_LOGIN_MOBILEME,
            auth=(self._username or "", self._login_state_data["idms_pet"]),
            data=data,
            headers=headers,
        )
        data = resp.plist()

        mobileme_data = data.get("delegates", {}).get("com.apple.mobileme", {})

        # Checked in the order Stage 2 §4 gives, which is not the order that looks
        # natural: `localizedError` is a separate channel from the two `status` fields,
        # and it is where a response explains itself. Reading only `status` -- which is
        # the obvious implementation, since a success is defined by it -- turns a
        # response that named the problem into "failed with status 1".
        localized_error = data.get("localizedError")
        status = data.get("status")
        failed = localized_error is not None or (status is not None and status != 0)

        # A missing `service-data` is that delegate having failed, not a malformed
        # response, so its own status is the explanation rather than a KeyError here.
        service_data = mobileme_data.get("service-data")
        if failed or service_data is None:
            error = MobileMeDelegateError(
                localized_error=localized_error,
                description=data.get("description"),
                status=status if failed else mobileme_data.get("status"),
                status_message=mobileme_data.get("status-message"),
            )
            if localized_error is not None:
                # Logged as well as raised: which value means "terms pending" is not
                # established, so the first account to hit one is how it becomes known.
                logger.warning(
                    "The delegate request reported localizedError=%r, description=%r",
                    localized_error,
                    data.get("description"),
                )
            raise error

        return self._set_login_state(
            LoginState.LOGGED_IN,
            {
                "dsid": data["dsid"],
                "mobileme_data": service_data,
                # Carried forward rather than discarded: it is a different identifier from
                # `dsid`, some services want it, and re-authenticating to recover it is a
                # round trip for a value already in hand.
                "adsid": adsid,
                # Likewise, and for the same reason: `announce_device` needs it, and it is
                # only ever issued by the GSA exchange that has just finished.
                "idms_hb": self._login_state_data.get("idms_hb", ""),
            },
        )

    async def _sms_2fa_request(
        self,
        method: str,
        url: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
    ) -> str:
        adsid = self._login_state_data["adsid"]
        idms_token = self._login_state_data["idms_token"]
        identity_token = base64.b64encode((adsid + ":" + idms_token).encode()).decode()

        headers = headers or {}
        headers.update(
            {
                "User-Agent": "Xcode",
                "Accept-Language": "en-us",
                "X-Apple-Identity-Token": identity_token,
            },
        )
        headers.update(await self.get_anisette_headers(with_client_info=True))

        r = await self._http.request(
            method,
            url,
            json=data,
            headers=headers,
        )
        if not r.ok:
            msg = f"SMS 2FA request failed: {r.status_code}"
            raise UnhandledProtocolError(msg)

        return r.text()

    async def _gsa_request(self, parameters: dict[str, Any]) -> dict[str, Any]:
        body = {
            "Header": {
                "Version": "1.0.1",
            },
            "Request": {
                "cpd": await self._anisette.get_cpd(
                    self._uid,
                    self._devid,
                ),
                **parameters,
            },
        }

        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            # The one user agent in the library that is **not** composed from the
            # identity, and the only place two headers of one request disagree: this
            # claims Darwin 18.7.0, which is macOS 10.14, beside a client info claiming
            # 13.4.1. It is transcribed from an observed akd build and has authenticated
            # every session this library has ever established, which is exactly why it is
            # still here -- changing the working authentication path to tidy it is an
            # experiment that can only be run against a live account, and a failed one
            # locks people out. A caller that sets its own identity should know this
            # header does not follow it. See `_GSA_USER_AGENT`.
            "User-Agent": _GSA_USER_AGENT,
            # `_GSA_USER_AGENT` speaks as akd; matching client info to it rather than to
            # Xcode is what keeps this endpoint from refusing the request outright with a
            # 503 -- see `BaseAnisetteProvider.client_akd`.
            "X-MMe-Client-Info": self._anisette.client_akd,
        }

        resp = await self._http.post(
            self._ENDPOINT_GSA,
            headers=headers,
            data=plistlib.dumps(body),
        )
        if not resp.ok:
            msg = f"Error response for GSA request: {resp.status_code}"
            raise UnhandledProtocolError(msg)
        return resp.plist()["Response"]

    @_require_login_state(LoginState.AUTHENTICATED, LoginState.LOGGED_IN)
    @override
    async def announce_device(self) -> None:
        """See :meth:`BaseAppleAccount.announce_device`."""
        if not self._device_name:
            msg = (
                "This account has no device name to announce. Set one when constructing"
                " it -- AsyncAppleAccount(anisette, device_name=...) -- since the entry"
                " is otherwise named after whatever hardware this client claims to be."
            )
            raise InvalidStateError(msg)

        adsid = self._login_state_data.get("adsid", "")
        heartbeat = self._login_state_data.get("idms_hb", "")
        if not adsid or not heartbeat:
            msg = (
                "The heartbeat token this call authenticates with is missing, so the"
                " account was restored from a file written before it was kept. Logging in"
                " again obtains one."
            )
            raise InvalidStateError(msg)

        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            # The akd variant of both, and they have to agree: this endpoint is told
            # which daemon is speaking by the client info's trailing bundle, and the user
            # agent has to describe the same release the client info claims. Sending the
            # Xcode variant beside an akd user agent -- or a Darwin 18 agent beside a
            # macOS 13 client info -- is a request that contradicts itself.
            "User-Agent": self._anisette.akd_user_agent,
            "X-MMe-Client-Info": self._anisette.client_akd,
            "X-Apple-HB-Token": base64.b64encode(f"{adsid}:{heartbeat}".encode()).decode(),
            "X-Apple-I-UrlSwitch-Info": base64.b64encode(f"{adsid}:postdata".encode()).decode(),
            "X-Apple-I-Service-Type": "itunesstore",
            "X-Apple-I-CDP-Status": "true",
            "X-Apple-I-OT-Status": "true",
            "X-Apple-I-CK-Presence": "true",
            "X-Apple-AK-DataRecoveryService-Status": "1",
            "X-Apple-I-Device-Configuration-Mode": "0",
            "X-Apple-I-DeviceUserMode": "0",
            "X-Apple-Requested-Partition": "0",
            "X-Apple-I-TimeZone-Offset": "0",
            "x-apple-i-device-type": "1",
        }
        headers.update(await self.get_anisette_headers())

        body = {
            "Header": {"Version": "1.0.1"},
            "Request": {
                "dn": self._device_name,
                "event": "liveness",
                "loc": "en_US",
                # Empty: this client provides none.
                "services": [],
                "cfuids": [],
                "cdpStatus": True,
                "circleStatus": True,
                "otStatus": True,
                "icscStatus": True,
                "prkgen": True,
                "denyICloudWebAccess": True,
                "icloudMailEnabled": False,
                "stingrayDisabledIndicator": False,
                "rep": 1,
                "ut": 1,
                "signinPartition": 1,
                "isLegacyContactAssignee": 1,
                "isRecoveryContactAssignee": 1,
                "reason": 5,
                "usrt": 4,
                "pkc": "1",
                # There is deliberately no `ptkn` here, and no way to add one. A push
                # token is the most likely reason a registered device becomes trusted for
                # verification codes, and this client must never become a second factor
                # for somebody's Apple ID. Absent, not empty.
            },
        }

        logger.info("Announcing this device to the account as %r", self._device_name)

        resp = await self._http.post(
            self._ENDPOINT_POSTDATA,
            headers=headers,
            data=plistlib.dumps(body),
        )
        if not resp.ok:
            # The whole reply at DEBUG, because the exception truncates and this is the
            # one shot at understanding a refusal without another round trip.
            logger.debug(
                "postdata refused with HTTP %d; headers %r; body %r",
                resp.status_code,
                dict(resp.headers),
                resp.content[:2000],
            )
            raise UnhandledProtocolError(_describe_announce_failure(resp))

    @override
    async def get_anisette_headers(
        self,
        with_client_info: bool = False,
        serial: str | None = None,
    ) -> dict[str, str]:
        """See :meth:`BaseAppleAccount.get_anisette_headers`."""
        return await self._anisette.get_headers(self._uid, self._devid, serial, with_client_info)


class AppleAccount(BaseAppleAccount):
    """
    A sync implementation of :meth:`BaseappleAccount`.

    Uses :meth:`AsyncappleAccount` internally.
    """

    def __init__(  # noqa: PLR0913 -- all keyword-only, and each is a separate decision
        self,
        anisette: BaseAnisetteProvider,
        *,
        state_info: AccountStateMapping | None = None,
        device_name: str | None = None,
        uid: str | None = None,
        devid: str | None = None,
        timeout: float = util.http.DEFAULT_TIMEOUT,
    ) -> None:
        """See :meth:`AsyncAppleAccount.__init__`."""
        # Every keyword the async account takes, passed straight through. A wrapper that
        # accepts fewer is a wrapper whose users reach past it into `_asyncacc`, which is
        # how identity fields end up being set by a workaround that breaks on a rename.
        self._asyncacc = AsyncAppleAccount(
            anisette=anisette,
            state_info=state_info,
            device_name=device_name,
            uid=uid,
            devid=devid,
            timeout=timeout,
        )

        try:
            self._evt_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._evt_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._evt_loop)

        super().__init__(self._evt_loop)

    @override
    async def close(self) -> None:
        """See :meth:`AsyncAppleAccount.close`."""
        await self._asyncacc.close()

    @property
    @override
    def login_state(self) -> LoginState:
        """See :meth:`AsyncAppleAccount.login_state`."""
        return self._asyncacc.login_state

    @property
    @override
    def account_name(self) -> str | None:
        """See :meth:`AsyncAppleAccount.login_state`."""
        return self._asyncacc.account_name

    @property
    @override
    def first_name(self) -> str | None:
        """See :meth:`AsyncAppleAccount.first_name`."""
        return self._asyncacc.first_name

    @property
    @override
    def last_name(self) -> str | None:
        """See :meth:`AsyncAppleAccount.last_name`."""
        return self._asyncacc.last_name

    @property
    @override
    def dsid(self) -> str:
        """See :meth:`AsyncAppleAccount.dsid`."""
        return self._asyncacc.dsid

    @property
    @override
    def service_tokens(self) -> Mapping[str, str]:
        """See :meth:`AsyncAppleAccount.service_tokens`."""
        return self._asyncacc.service_tokens

    @property
    @override
    def adsid(self) -> str | None:
        """See :meth:`AsyncAppleAccount.adsid`."""
        return self._asyncacc.adsid

    @property
    @override
    def device_uuid(self) -> str:
        """See :meth:`AsyncAppleAccount.device_uuid`."""
        return self._asyncacc.device_uuid

    @property
    @override
    def local_user_uuid(self) -> str:
        """See :meth:`AsyncAppleAccount.local_user_uuid`."""
        return self._asyncacc.local_user_uuid

    @property
    @override
    def client_info(self) -> str:
        """See :meth:`AsyncAppleAccount.client_info`."""
        return self._asyncacc.client_info

    @property
    @override
    def identity(self) -> DeviceIdentity:
        """See :meth:`AsyncAppleAccount.identity`."""
        return self._asyncacc.identity

    @property
    @override
    def serial(self) -> str:
        """See :meth:`AsyncAppleAccount.serial`."""
        return self._asyncacc.serial

    @property
    @override
    def device_name(self) -> str | None:
        """See :meth:`AsyncAppleAccount.device_name`."""
        return self._asyncacc.device_name

    @override
    def announce_device(self) -> None:
        """See :meth:`AsyncAppleAccount.announce_device`."""
        return self._evt_loop.run_until_complete(self._asyncacc.announce_device())

    @override
    def to_json(self, dst: str | Path | None = None, /) -> AccountStateMapping:
        return self._asyncacc.to_json(dst)

    @classmethod
    @override
    def from_json(
        cls,
        val: str | Path | io.TextIOBase | io.BufferedIOBase | AccountStateMapping,
        /,
        *,
        anisette_libs_path: str | Path | None = None,
    ) -> AppleAccount:
        val = util.files.read_data_json(val)
        try:
            ani_provider = get_provider_from_mapping(val["anisette"], libs_path=anisette_libs_path)
            return cls(ani_provider, state_info=val)
        except KeyError as e:
            msg = f"Failed to restore account data: {e}"
            raise ValueError(msg) from None

    @override
    def request_pet(self) -> str:
        """See :meth:`AsyncAppleAccount.request_pet`."""
        coro = self._asyncacc.request_pet()
        return self._evt_loop.run_until_complete(coro)

    @override
    def login(self, username: str, password: str) -> LoginState:
        """See :meth:`AsyncAppleAccount.login`."""
        coro = self._asyncacc.login(username, password)
        return self._evt_loop.run_until_complete(coro)

    @override
    def fetch_terms(self, *names: str) -> list[Terms]:
        """See :meth:`AsyncAppleAccount.fetch_terms`."""
        coro = self._asyncacc.fetch_terms(*names)
        return self._evt_loop.run_until_complete(coro)

    @override
    def accept_terms(self, terms: Terms) -> None:
        """See :meth:`AsyncAppleAccount.accept_terms`."""
        coro = self._asyncacc.accept_terms(terms)
        return self._evt_loop.run_until_complete(coro)

    @override
    def complete_login(self) -> LoginState:
        """See :meth:`AsyncAppleAccount.complete_login`."""
        coro = self._asyncacc.complete_login()
        return self._evt_loop.run_until_complete(coro)

    @override
    def get_2fa_methods(self) -> Sequence[SyncSecondFactorMethod]:
        """See :meth:`AsyncAppleAccount.get_2fa_methods`."""
        coro = self._asyncacc.get_2fa_methods()
        methods = self._evt_loop.run_until_complete(coro)

        res = []
        for m in methods:
            if isinstance(m, AsyncSmsSecondFactor):
                res.append(SyncSmsSecondFactor(self, m.phone_number_id, m.phone_number))
            elif isinstance(m, AsyncTrustedDeviceSecondFactor):
                res.append(SyncTrustedDeviceSecondFactor(self))
            else:
                msg = (
                    f"Failed to cast 2FA object to sync alternative: {m}."
                    f" This is a bug, please report it."
                )
                raise TypeError(msg)

        return res

    @override
    def sms_2fa_request(self, phone_number_id: int) -> None:
        """See :meth:`AsyncAppleAccount.sms_2fa_request`."""
        coro = self._asyncacc.sms_2fa_request(phone_number_id)
        return self._evt_loop.run_until_complete(coro)

    @override
    def sms_2fa_submit(self, phone_number_id: int, code: str) -> LoginState:
        """See :meth:`AsyncAppleAccount.sms_2fa_submit`."""
        coro = self._asyncacc.sms_2fa_submit(phone_number_id, code)
        return self._evt_loop.run_until_complete(coro)

    @override
    def td_2fa_request(self) -> None:
        """See :meth:`AsyncAppleAccount.td_2fa_request`."""
        coro = self._asyncacc.td_2fa_request()
        return self._evt_loop.run_until_complete(coro)

    @override
    def td_2fa_submit(self, code: str) -> LoginState:
        """See :meth:`AsyncAppleAccount.td_2fa_submit`."""
        coro = self._asyncacc.td_2fa_submit(code)
        return self._evt_loop.run_until_complete(coro)

    @overload
    def fetch_location_history(
        self,
        keys: HasHashedPublicKey,
    ) -> list[LocationReport]: ...

    @overload
    def fetch_location_history(
        self,
        keys: RollingKeyPairSource,
    ) -> list[LocationReport]: ...

    @overload
    def fetch_location_history(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]: ...

    @override
    def fetch_location_history(
        self,
        keys: HasHashedPublicKey
        | Sequence[HasHashedPublicKey | RollingKeyPairSource]
        | RollingKeyPairSource,
    ) -> (
        list[LocationReport] | dict[HasHashedPublicKey | RollingKeyPairSource, list[LocationReport]]
    ):
        """See `BaseAppleAccount.fetch_location_history`."""
        coro = self._asyncacc.fetch_location_history(keys)
        return self._evt_loop.run_until_complete(coro)

    @overload
    def fetch_location(
        self,
        keys: HasHashedPublicKey,
    ) -> LocationReport | None: ...

    @overload
    def fetch_location(
        self,
        keys: RollingKeyPairSource,
    ) -> LocationReport | None: ...

    @overload
    def fetch_location(
        self,
        keys: Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]: ...

    @override
    def fetch_location(
        self,
        keys: HasHashedPublicKey
        | RollingKeyPairSource
        | Sequence[HasHashedPublicKey | RollingKeyPairSource],
    ) -> (
        LocationReport
        | dict[HasHashedPublicKey | RollingKeyPairSource, LocationReport | None]
        | None
    ):
        """See :meth:`BaseAppleAccount.fetch_location`."""
        hist = self.fetch_location_history(keys)
        if isinstance(hist, list):
            return sorted(hist)[-1] if hist else None

        return {dev: sorted(reports)[-1] if reports else None for dev, reports in hist.items()}

    @override
    def get_anisette_headers(
        self,
        with_client_info: bool = False,
        serial: str | None = None,
    ) -> dict[str, str]:
        """See :meth:`AsyncAppleAccount.get_anisette_headers`."""
        coro = self._asyncacc.get_anisette_headers(with_client_info, serial)
        return self._evt_loop.run_until_complete(coro)
