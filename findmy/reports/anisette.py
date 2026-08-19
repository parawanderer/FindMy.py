"""Module for Anisette header providers."""

from __future__ import annotations

import asyncio
import base64
import io
import locale
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Literal, TypedDict

from anisette import Anisette, AnisetteHeaders
from typing_extensions import NotRequired, Required, override

from findmy import util

logger = logging.getLogger(__name__)

# The identity this client presents as. **These describe one real release and move
# together**: the OS version, the build, the CFNetwork version and the Darwin version are
# not independent, and Apple's own clients never contradict themselves. macOS 13.4.1 is
# build 22F8, CFNetwork 1408.0.4, Darwin 22.5.0.
#
# They are parts rather than finished strings because the same identity has to appear in
# more than one composite -- and a request whose client info claims one release while its
# user agent claims another is a contradiction no real client produces.
#
# **Changing any of them changes the identity**, which invalidates existing sessions and
# adds a device-list entry rather than renaming one. See :data:`CLIENT_SERIAL`.
CLIENT_MODEL = "MacBookPro18,3"
CLIENT_OS = "Mac OS X"
CLIENT_OS_VERSION = "13.4.1"
CLIENT_OS_BUILD = "22F8"
CLIENT_CFNETWORK = "1408.0.4"
CLIENT_DARWIN = "22.5.0"

_XCODE_BUNDLE = "com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)"
_AKD_BUNDLE = "com.apple.AuthKit/1 (com.apple.akd/1.0)"


class DeviceIdentityMapping(TypedDict):
    """JSON mapping representing a :class:`DeviceIdentity`."""

    model: str
    os_name: str
    os_version: str
    os_build: str
    cfnetwork: str
    darwin: str


@dataclass(frozen=True)
class DeviceIdentity:
    """
    The device a client claims to be, in every header that names one.

    Requests carry this identity in more than one composite string -- the client info a
    request is made under, and the user agent beside it -- and **Apple's own clients never
    contradict themselves** about which machine they are. So it is one value, held in
    parts, and every string that needs a part composes it from here rather than
    transcribing one.

    A client that produces its own Anisette has an identity already -- a native ADI
    implementation initialises with a client-info string of its own -- and this is how the
    two halves are made to agree. Pass it to a provider:

    >>> RemoteAnisetteProvider(url, identity=DeviceIdentity(
    ...     model="MacBookPro13,2",
    ...     os_name="macOS",
    ...     os_version="13.1",
    ...     os_build="22C65",
    ...     cfnetwork="1404.0.5",
    ...     darwin="22.2.0",
    ... ))

    Every field is required, deliberately. **The six describe one real release**: macOS
    13.4.1 is build 22F8, CFNetwork 1408.0.4, Darwin 22.5.0, and a partial identity --
    a new model and OS beside the old CFNetwork -- is the contradiction this class exists
    to prevent. Nothing here validates that they correspond, because nothing here knows
    Apple's release table; stating all six is what makes the omission visible instead.

    To change some of it, say so:

    >>> replace(CLIENT_IDENTITY, model="MacBookAir10,1")

    .. warning::
        **Changing the identity changes the login identity.** Apple binds a session to
        it, so an account stored under a different one may need signing in again, and the
        old device-list entry stays until it is removed by hand -- a changed identity adds
        an entry rather than editing one. It is not a per-request detail; set it once,
        before first login, and leave it.
    """

    model: str
    """The hardware model, e.g. `MacBookPro18,3`. First group of the client info."""

    os_name: str
    """The OS name, e.g. `Mac OS X` or `iPhone OS`. Apple spells these exactly."""

    os_version: str
    """The OS release, e.g. `13.4.1`."""

    os_build: str
    """The build of that release, e.g. `22F8`."""

    cfnetwork: str
    """The CFNetwork version of that release. Appears only in user agents."""

    darwin: str
    """The Darwin (kernel) version of that release. Appears only in user agents."""

    @property
    def platform(self) -> str:
        """
        The `<model> <os;version;build>` prefix every client-info string starts with.

        What is left when the bundle -- the part saying which Apple daemon is speaking --
        is stripped off. Clients that address a service as some other daemon keep this and
        replace the bundle.
        """
        return f"<{self.model}> <{self.os_name};{self.os_version};{self.os_build}>"

    def client_info(self, bundle: str) -> str:
        """
        Build a client-info string for a request made as `bundle`.

        :param bundle: The trailing group, without its angle brackets, naming the
            framework and daemon speaking -- e.g. `com.apple.AuthKit/1 (com.apple.akd/1.0)`.
        """
        return f"{self.platform} <{bundle}>"

    def user_agent(self, product: str) -> str:
        """
        Build a user agent for a request made as `product`.

        :param product: The leading token, e.g. `akd/1.0` or `com.apple.iCloudHelper/282`.
            The CFNetwork and Darwin versions after it describe the release
            :attr:`platform` claims, which is the whole reason they are not written out at
            each call site.
        """
        return f"{product} CFNetwork/{self.cfnetwork} Darwin/{self.darwin}"

    def to_json(self) -> DeviceIdentityMapping:
        """Serialize to a JSON mapping."""
        return {
            "model": self.model,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "os_build": self.os_build,
            "cfnetwork": self.cfnetwork,
            "darwin": self.darwin,
        }

    @classmethod
    def from_json(cls, val: DeviceIdentityMapping) -> DeviceIdentity:
        """
        Deserialize from a JSON mapping.

        Missing fields fall back to the library's own identity, so a mapping written by an
        older version stays readable -- but a stored identity is an identity a session is
        bound to, and :meth:`to_json` writes all six.
        """
        return cls(
            model=val.get("model", CLIENT_MODEL),
            os_name=val.get("os_name", CLIENT_OS),
            os_version=val.get("os_version", CLIENT_OS_VERSION),
            os_build=val.get("os_build", CLIENT_OS_BUILD),
            cfnetwork=val.get("cfnetwork", CLIENT_CFNETWORK),
            darwin=val.get("darwin", CLIENT_DARWIN),
        )


CLIENT_IDENTITY = DeviceIdentity(
    model=CLIENT_MODEL,
    os_name=CLIENT_OS,
    os_version=CLIENT_OS_VERSION,
    os_build=CLIENT_OS_BUILD,
    cfnetwork=CLIENT_CFNETWORK,
    darwin=CLIENT_DARWIN,
)
"""
The identity this client presents as when a caller does not supply one.

**It does not move.** Every session already established is bound to it, so changing this
default would silently change the identity of every account that did not ask for one --
which costs a sign-in and leaves an unrecognisable entry in a device list. A client that
wants a different identity passes one; see :class:`DeviceIdentity`.
"""

CLIENT_SERIAL = "0FINDMYPY001"
"""
The serial this client presents as, in `X-Apple-I-SRL-NO`.

**It is what names this client in the account's device list**, which is the one place a
person ever sees it -- and the entry is otherwise indistinguishable from a real Mac, since
the model and OS strings above claim to be one. A recognisable serial is the difference
between a device somebody can identify as software they installed and one they are invited
to remove because they do not recognise it.

Deliberately implausible as a real serial: nothing should mistake it for hardware.

> **Changing this changes the login identity.** It is part of what Apple binds a session
> to, so an account stored under a different serial may need signing in again, and the old
> device-list entry stays until it is removed by hand -- a new serial adds an entry rather
> than renaming one.
"""



class RemoteAnisetteMapping(TypedDict, total=False):
    """JSON mapping representing state of a remote Anisette provider."""

    type: Required[Literal["aniRemote"]]
    url: Required[str]

    serial: str
    """
    The serial this provider presents as, when it is not the library's default.

    Written only when it differs, so existing files stay valid -- and, more to the point,
    keep the identity they already have. A restored account that reverted to the default
    would add a device-list entry rather than reusing the one it had.
    """

    identity: DeviceIdentityMapping
    """
    The device this provider claims to be, when it is not the library's own.

    Written only when it differs, for the same reason as the serial -- and with more at
    stake, since it is the larger half of what Apple binds a session to. A restored
    account that quietly reverted to the default would be a different machine.
    """

    timeout: float
    """
    Seconds a fetch from this server may take, when it is not the library's default.

    Written only when it differs. A provider is reconstructed from this, so a saved setup
    that needed longer would otherwise start failing again the next time it is loaded.
    """

    allow_unverified_https: bool
    """
    Only written when it is true, so existing files stay valid and unchanged.

    It has to be written at all because a provider is reconstructed from this: a user whose
    own server has a self-signed certificate would otherwise find that saving and reloading
    an account silently turned their working setup into a failing one.
    """


class LocalAnisetteMapping(TypedDict):
    """JSON mapping representing state of a local Anisette provider."""

    type: Literal["aniLocal"]
    prov_data: str | None

    serial: NotRequired[str]
    """The serial this provider presents as, written only when it is not the default."""

    identity: NotRequired[DeviceIdentityMapping]
    """The device this provider claims to be, written only when it is not the default."""


AnisetteMapping = RemoteAnisetteMapping | LocalAnisetteMapping


def get_provider_from_mapping(
    mapping: AnisetteMapping,
    *,
    libs_path: str | Path | None = None,
) -> RemoteAnisetteProvider | LocalAnisetteProvider:
    """Get the correct Anisette provider instance from saved JSON data."""
    if mapping["type"] == "aniRemote":
        return RemoteAnisetteProvider.from_json(mapping)
    if mapping["type"] == "aniLocal":
        return LocalAnisetteProvider.from_json(mapping, libs_path=libs_path)
    msg = f"Unknown anisette type: {mapping['type']}"
    raise ValueError(msg)


class BaseAnisetteProvider(util.abc.Closable, util.abc.Serializable, ABC):
    """
    Abstract base class for Anisette providers.

    Generously derived from https://github.com/nythepegasus/grandslam/blob/main/src/grandslam/gsa.py#L41.
    """

    def __init__(
        self,
        *,
        serial: str = CLIENT_SERIAL,
        identity: DeviceIdentity = CLIENT_IDENTITY,
    ) -> None:
        """
        Initialize the provider.

        :param identity: What device this client claims to be; see :class:`DeviceIdentity`.
            The same argument as the serial, one field over -- and the same consequence for
            changing it once an account exists.
        :param serial: What this client presents as its device serial. Set it once, here:
            it is part of an identity rather than a per-request detail, and a path that
            sends a different one **registers a second device** rather than failing.
        """
        super().__init__()

        self._serial = serial
        self._identity = identity

    @property
    def identity(self) -> DeviceIdentity:
        """
        The device this provider claims to be, in every header that names one.

        Read by everything that sends a client info or a user agent -- here and on the
        account -- so that no two of them can describe different machines.
        """
        return self._identity

    @property
    def serial(self) -> str:
        """
        The serial this provider presents as, in `X-Apple-I-SRL-NO`.

        Read by everything that needs the identity -- including the CloudKit client, which
        takes it from the account rather than keeping a second copy. One value, one device.
        """
        return self._serial

    @property
    @abstractmethod
    def otp(self) -> str:
        """A seemingly random base64 string containing 28 bytes."""
        raise NotImplementedError

    @property
    @abstractmethod
    def machine(self) -> str:
        """A base64 encoded string of 60 'random' bytes."""
        raise NotImplementedError

    @property
    def timestamp(self) -> str:
        """Current timestamp in ISO 8601 format."""
        return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat() + "Z"

    @property
    def timezone(self) -> str:
        """Abbreviation of the timezone of the device."""
        return str(datetime.now().astimezone().tzinfo)

    @property
    def locale(self) -> str:
        """Locale of the device (e.g. en_US)."""
        return locale.getdefaultlocale()[0] or "en_US"

    @property
    def router(self) -> str:
        """
        A number, either 17106176 or 50660608.

        It doesn't seem to matter which one we use.
        - 17106176 is used by Sideloadly and Provision (android) based servers.
        - 50660608 is used by Windows iCloud based servers.
        """
        return "17106176"

    @property
    def client(self) -> str:
        """
        Client string.

        The format is as follows:
        <%MODEL%> <%OS%;%MAJOR%.%MINOR%(%SPMAJOR%,%SPMINOR%);%BUILD%>
         <%AUTHKIT_BUNDLE_ID%/%AUTHKIT_VERSION% (%APP_BUNDLE_ID%/%APP_VERSION%)>

        Where:
            MODEL: The model of the device (e.g. MacBookPro15,1 or 'PC'
            OS: The OS of the device (e.g. Mac OS X or Windows)
            MAJOR: The major version of the OS (e.g. 10)
            MINOR: The minor version of the OS (e.g. 15)
            SPMAJOR: The major version of the service pack (e.g. 0) (Windows only)
            SPMINOR: The minor version of the service pack (e.g. 0) (Windows only)
            BUILD: The build number of the OS (e.g. 19C57)
            AUTHKIT_BUNDLE_ID: The bundle ID of the AuthKit framework (e.g. com.apple.AuthKit)
            AUTHKIT_VERSION: The version of the AuthKit framework (e.g. 1)
            APP_BUNDLE_ID: The bundle ID of the app (e.g. com.apple.dt.Xcode)
            APP_VERSION: The version of the app (e.g. 3594.4.19)
        """
        return self._identity.client_info(_XCODE_BUNDLE)

    @property
    def client_akd(self) -> str:
        """
        The same identity, speaking as **akd** rather than as Xcode.

        The trailing bundle says which Apple daemon is speaking, and Grand Slam endpoints
        that authenticate with a heartbeat token expect `akd` -- so telling one of them
        that Xcode is speaking, while the `User-Agent` beside it says akd, is a request
        that contradicts itself.

        Same platform as :attr:`client`, by construction rather than by transcription.
        """
        return self._identity.client_info(_AKD_BUNDLE)

    @property
    def akd_user_agent(self) -> str:
        """
        The user agent that goes with :attr:`client_akd`.

        Built from the same identity, because the CFNetwork and Darwin versions have to
        describe the release the client info claims. A fixed string here is how a request
        ends up announcing macOS 10.14 and macOS 13.4.1 at once.
        """
        return self._identity.user_agent("akd/1.0")

    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str | None = None,
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """
        Generate a complete dictionary of Anisette headers.

        Consider using :meth:`BaseAppleAccount.get_anisette_headers` instead.

        :param serial: Overrides this provider's own for one call. Defaults to it, which
            is what a caller should want -- see :attr:`serial`.
        """
        headers = {
            # Current Time
            "X-Apple-I-Client-Time": self.timestamp,
            "X-Apple-I-TimeZone": self.timezone,
            # Locale
            "loc": self.locale,
            "X-Apple-Locale": self.locale,
            # 'One Time Password'
            "X-Apple-I-MD": self.otp,
            # 'Local User ID'
            "X-Apple-I-MD-LU": base64.b64encode(str(user_id).encode()).decode(),
            # 'Machine ID'
            "X-Apple-I-MD-M": self.machine,
            # 'Routing Info', some implementations convert this to an integer
            "X-Apple-I-MD-RINFO": self.router,
            # 'Device Unique Identifier'
            "X-Mme-Device-Id": str(device_id).upper(),
            # 'Device Serial Number'
            "X-Apple-I-SRL-NO": serial or self._serial,
        }

        if with_client_info:
            headers["X-Mme-Client-Info"] = self.client
            headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
            headers["X-Xcode-Version"] = "11.2 (11B41)"

        return headers

    async def get_cpd(
        self,
        user_id: str,
        device_id: str,
        serial: str | None = None,
    ) -> dict[str, str]:
        """
        Generate a complete dictionary of CPD data.

        Intended for internal use.
        """
        cpd = {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
        }
        cpd.update(await self.get_headers(user_id, device_id, serial))

        return cpd


class RemoteAnisetteProvider(BaseAnisetteProvider, util.abc.Serializable[RemoteAnisetteMapping]):
    """Anisette provider. Fetches headers from a remote Anisette server."""

    _ANISETTE_DATA_VALID_FOR = 30

    def __init__(
        self,
        server_url: str,
        *,
        serial: str = CLIENT_SERIAL,
        identity: DeviceIdentity = CLIENT_IDENTITY,
        allow_unverified_https: bool = False,
        timeout: float = util.http.DEFAULT_TIMEOUT,
    ) -> None:
        """
        Initialize the provider with URL to te remote server.

        :param server_url: Where to fetch Anisette headers from.
        :param timeout: Seconds the fetch from this server may take.

            **Separate from the account's, and often the one that matters.** This fetch
            happens inside a login, so a server that is slow to generate its data fails
            the sign-in rather than itself -- and raising the account's timeout does
            nothing for it, because the request is made here. Public servers are shared
            and can be slow; one you host yourself may be generating on demand.

            Persisted, for the reason the certificate switch is: a provider is
            reconstructed from its saved state, and reverting to the default would turn a
            working setup back into a failing one on the next run.
        :param serial: What this client presents as its device serial; see
            :attr:`BaseAnisetteProvider.serial`.
        :param identity: What device this client claims to be; see
            :class:`DeviceIdentity`.
        :param allow_unverified_https: Skip certificate verification for **this server
            only**. Off by default, and the only switch of its kind in the library.

            It exists for one case: an Anisette server you run yourself, over HTTPS, with a
            self-signed certificate. A server reached over plain `http://` needs nothing --
            there is no TLS to verify -- and a public server with a real certificate needs
            nothing either. Everything Apple-facing is verified regardless of this flag; it
            reaches no request but the one to this URL.

            Turning it on means anything on the network path to that server can read and
            alter the Anisette data your logins are built from.
        """
        super().__init__(serial=serial, identity=identity)

        self._server_url = server_url
        self._allow_unverified_https = allow_unverified_https
        self._timeout = timeout

        self._http = util.http.HttpSession(
            verify_tls=not allow_unverified_https,
            timeout=timeout,
        )

        self._anisette_data: dict[str, str] | None = None
        self._anisette_data_expires_at: float = 0
        self._closed = False

    @override
    def to_json(self, dst: str | Path | io.TextIOBase | None = None, /) -> RemoteAnisetteMapping:
        """See :meth:`BaseAnisetteProvider.serialize`."""
        state: RemoteAnisetteMapping = {
            "type": "aniRemote",
            "url": self._server_url,
        }
        if self._serial != CLIENT_SERIAL:
            state["serial"] = self._serial
        if self._identity != CLIENT_IDENTITY:
            state["identity"] = self._identity.to_json()
        if self._timeout != util.http.DEFAULT_TIMEOUT:
            state["timeout"] = self._timeout
        if self._allow_unverified_https:
            state["allow_unverified_https"] = True

        return util.files.save_and_return_json(state, dst)

    @classmethod
    @override
    def from_json(
        cls, val: str | Path | io.TextIOBase | io.BufferedIOBase | RemoteAnisetteMapping
    ) -> RemoteAnisetteProvider:
        """See :meth:`BaseAnisetteProvider.deserialize`."""
        val = util.files.read_data_json(val)

        assert val["type"] == "aniRemote"

        server_url = val["url"]

        identity = val.get("identity")

        return cls(
            server_url,
            serial=val.get("serial", CLIENT_SERIAL),
            identity=DeviceIdentity.from_json(identity) if identity else CLIENT_IDENTITY,
            allow_unverified_https=val.get("allow_unverified_https", False),
            timeout=val.get("timeout", util.http.DEFAULT_TIMEOUT),
        )

    @property
    @override
    def otp(self) -> str:
        """See :meth:`BaseAnisetteProvider.otp`."""
        otp = (self._anisette_data or {}).get("X-Apple-I-MD")
        if otp is None:
            logger.warning("X-Apple-I-MD header not found! Returning fallback...")
        return otp or ""

    @property
    @override
    def machine(self) -> str:
        """See :meth:`BaseAnisetteProvider.machine`."""
        machine = (self._anisette_data or {}).get("X-Apple-I-MD-M")
        if machine is None:
            logger.warning("X-Apple-I-MD-M header not found! Returning fallback...")
        return machine or ""

    @override
    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str | None = None,
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """See :meth::meth:`BaseAnisetteProvider.get_headers`."""
        if self._closed:
            msg = "RemoteAnisetteProvider has been closed and cannot be used"
            raise RuntimeError(msg)

        if self._anisette_data is None or time.time() >= self._anisette_data_expires_at:
            logger.info("Fetching anisette data from %s", self._server_url)

            r = await self._http.get(self._server_url, auto_retry=True)
            self._anisette_data = r.json()
            self._anisette_data_expires_at = time.time() + self._ANISETTE_DATA_VALID_FOR

        return await super().get_headers(user_id, device_id, serial, with_client_info)

    @override
    async def close(self) -> None:
        """See :meth:`AnisetteProvider.close`."""
        if self._closed:
            return  # Already closed, make it idempotent

        self._closed = True

        try:
            await self._http.close()
        except (RuntimeError, OSError, ConnectionError) as e:
            logger.warning("Error closing anisette HTTP session: %s", e)


class LocalAnisetteProvider(BaseAnisetteProvider, util.abc.Serializable[LocalAnisetteMapping]):
    """Local anisette provider using the `anisette` library."""

    def __init__(
        self,
        *,
        state_blob: BytesIO | None = None,
        libs_path: str | Path | None = None,
        serial: str = CLIENT_SERIAL,
        identity: DeviceIdentity = CLIENT_IDENTITY,
    ) -> None:
        """
        Initialize the provider.

        :param serial: What this client presents as its device serial; see
            :attr:`BaseAnisetteProvider.serial`.
        :param identity: What device this client claims to be; see
            :class:`DeviceIdentity`.
        """
        super().__init__(serial=serial, identity=identity)

        if isinstance(libs_path, str):
            libs_path = Path(libs_path)

        # we do not yet initialize Anisette in order to prevent blocking the event loop,
        # since the anisette library will download the required libraries synchronously.
        self._ani: Anisette | None = None

        self._ani_data: AnisetteHeaders | None = None
        self._libs_path: Path | None = libs_path
        self._state_blob: BytesIO | None = state_blob

    @property
    def _is_new_session(self) -> bool:
        return self._state_blob is None

    async def _get_ani(self) -> Anisette:
        if self._ani is not None:
            return self._ani

        if self._libs_path is None or not self._libs_path.is_file():
            logger.info(
                "The Anisette engine will download libraries required for operation, "
                "this may take a few seconds...",
            )
        if self._libs_path is None:
            logger.info(
                "To speed up future local Anisette initializations, "
                "provide a filesystem path to load the libraries from.",
            )

        files: list[BinaryIO | Path] = []
        if self._state_blob is not None:
            files.append(self._state_blob)
        if self._libs_path is not None and self._libs_path.exists():
            files.append(self._libs_path)

        loop = asyncio.get_running_loop()
        ani = await loop.run_in_executor(None, Anisette.load, *files)
        is_provisioned = await loop.run_in_executor(None, lambda: ani.is_provisioned)

        if self._libs_path is not None:
            ani.save_libs(self._libs_path)

        if not self._is_new_session and not is_provisioned:
            logger.warning(
                "The Anisette state that was loaded has not yet been provisioned. "
                "Was the previous session saved properly?",
            )

        # pre-provision to ensure that the VM has initialized
        await loop.run_in_executor(None, ani.provision)

        self._ani = ani
        return ani

    @override
    def to_json(self, dst: str | Path | io.TextIOBase | None = None, /) -> LocalAnisetteMapping:
        """See :meth:`BaseAnisetteProvider.serialize`."""
        if self._ani is None:
            # Anisette has not been called yet, so the future has not yet resolved.
            # We don't want to wait here, so we just return the original state blob.
            # If the state blob is None, this means we have a new session that has not
            # been provisioned yet, so we will not save the provisioning data.
            if self._state_blob is None:
                prov_data = None
            else:
                prov_data = base64.b64encode(self._state_blob.getvalue()).decode("utf-8")
        else:
            # Anisette has been initialized, so we can save the provisioning data.
            with BytesIO() as buf:
                self._ani.save_provisioning(buf)
                prov_data = base64.b64encode(buf.getvalue()).decode("utf-8")

        state: LocalAnisetteMapping = {
            "type": "aniLocal",
            "prov_data": prov_data,
        }
        if self._serial != CLIENT_SERIAL:
            state["serial"] = self._serial
        if self._identity != CLIENT_IDENTITY:
            state["identity"] = self._identity.to_json()

        return util.files.save_and_return_json(state, dst)

    @classmethod
    @override
    def from_json(
        cls,
        val: str | Path | io.TextIOBase | io.BufferedIOBase | LocalAnisetteMapping,
        *,
        libs_path: str | Path | None = None,
    ) -> LocalAnisetteProvider:
        """See :meth:`BaseAnisetteProvider.deserialize`."""
        val = util.files.read_data_json(val)

        assert val["type"] == "aniLocal"

        prov_data = val["prov_data"]
        state_blob = None if prov_data is None else BytesIO(base64.b64decode(prov_data))

        identity = val.get("identity")

        return cls(
            state_blob=state_blob,
            libs_path=libs_path,
            serial=val.get("serial", CLIENT_SERIAL),
            identity=DeviceIdentity.from_json(identity) if identity else CLIENT_IDENTITY,
        )

    @override
    async def get_headers(
        self,
        user_id: str,
        device_id: str,
        serial: str | None = None,
        with_client_info: bool = False,
    ) -> dict[str, str]:
        """See :meth:`BaseAnisetteProvider.get_headers`."""
        ani = await self._get_ani()

        # run in executor to prevent blocking the event loop,
        # since get_data may make blocking network requests.
        loop = asyncio.get_running_loop()
        self._ani_data = await loop.run_in_executor(None, ani.get_data)

        return await super().get_headers(user_id, device_id, serial, with_client_info)

    @property
    @override
    def otp(self) -> str:
        """See :meth:`BaseAnisetteProvider.otp`."""
        machine = (self._ani_data or {}).get("X-Apple-I-MD")
        if machine is None:
            logger.warning("X-Apple-I-MD header not found! Returning fallback...")
        return machine or ""

    @property
    @override
    def machine(self) -> str:
        """See :meth:`BaseAnisetteProvider.machine`."""
        machine = (self._ani_data or {}).get("X-Apple-I-MD-M")
        if machine is None:
            logger.warning("X-Apple-I-MD-M header not found! Returning fallback...")
        return machine or ""

    @override
    async def close(self) -> None:
        """See :meth:`BaseAnisetteProvider.close`."""
