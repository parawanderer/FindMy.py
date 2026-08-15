"""A package providing everything you need to work with Apple's FindMy network."""

from typing import TYPE_CHECKING, Any

from .accessory import (
    FindMyAccessory,
    FindMyAccessoryMapping,
    FixedRollingKeyPairAccessory,
    FixedRollingKeyPairAccessoryMapping,
    RollingKeyPairSource,
)
from .errors import (
    InvalidCredentialsError,
    InvalidStateError,
    MobileMeDelegateError,
    UnauthorizedError,
    UnhandledProtocolError,
)
from .keys import HasHashedPublicKey, HasPublicKey, KeyPair, KeyPairMapping, KeyPairType
from .reports import (
    AccountStateMapping,
    AnisetteMapping,
    AppleAccount,
    AsyncAppleAccount,
    AsyncSmsSecondFactor,
    AsyncTrustedDeviceSecondFactor,
    BaseAnisetteProvider,
    BaseAppleAccount,
    BaseSecondFactorMethod,
    LocalAnisetteMapping,
    LocalAnisetteProvider,
    LocationReport,
    LocationReportDecryptedMapping,
    LocationReportEncryptedMapping,
    LocationReportMapping,
    LoginState,
    RemoteAnisetteMapping,
    RemoteAnisetteProvider,
    SmsSecondFactorMethod,
    SyncSmsSecondFactor,
    SyncTrustedDeviceSecondFactor,
    Terms,
    TermsError,
    TrustedDeviceSecondFactorMethod,
)

__all__ = (
    "AccountStateMapping",
    "AnisetteMapping",
    "AppleAccount",
    "AsyncAppleAccount",
    "AsyncSmsSecondFactor",
    "AsyncTrustedDeviceSecondFactor",
    "BaseAnisetteProvider",
    "BaseAppleAccount",
    "BaseSecondFactorMethod",
    "FindMyAccessory",
    "FindMyAccessoryMapping",
    "FixedRollingKeyPairAccessory",
    "FixedRollingKeyPairAccessoryMapping",
    "HasHashedPublicKey",
    "HasPublicKey",
    "InvalidCredentialsError",
    "InvalidStateError",
    "KeyPair",
    "KeyPairMapping",
    "KeyPairType",
    "LocalAnisetteMapping",
    "LocalAnisetteProvider",
    "LocationReport",
    "LocationReportDecryptedMapping",
    "LocationReportEncryptedMapping",
    "LocationReportMapping",
    "LoginState",
    "MobileMeDelegateError",
    "NearbyOfflineFindingDevice",
    "OfflineFindingDevice",
    "OfflineFindingScanner",
    "RemoteAnisetteMapping",
    "RemoteAnisetteProvider",
    "RollingKeyPairSource",
    "SeparatedOfflineFindingDevice",
    "SmsSecondFactorMethod",
    "SyncSmsSecondFactor",
    "SyncTrustedDeviceSecondFactor",
    "Terms",
    "TermsError",
    "TrustedDeviceSecondFactorMethod",
    "UnauthorizedError",
    "UnhandledProtocolError",
)


# The scanner is reached lazily, so that importing this package does not require `bleak`.
#
# `bleak` is the Bluetooth stack, and it is not a small dependency: `pyobjc-core` and two
# CoreBluetooth frameworks on macOS, seven `winrt-*` packages on Windows, `dbus-fast` on
# Linux. Everything else here -- logging in, reading reports, fetching accessories from
# iCloud -- reaches Apple over the network and touches no radio, and a frozen application
# that never scans was paying tens of megabytes for a module it never called.
#
# It could not be avoided from outside: importing a submodule executes this file first, so
# there was no import path into the library that did not pull the radio in. PyInstaller's
# `excludes` does not help either, because the exclusion has to survive `import findmy`.
#
# `from findmy import OfflineFindingScanner` still works, and still needs `bleak` -- the
# cost is now paid by the clients that scan.
_SCANNER_EXPORTS = frozenset(
    {
        "NearbyOfflineFindingDevice",
        "OfflineFindingDevice",
        "OfflineFindingScanner",
        "SeparatedOfflineFindingDevice",
    },
)

if TYPE_CHECKING:  # so that type checkers and IDEs still resolve these names
    from .scanner import (
        NearbyOfflineFindingDevice,
        OfflineFindingDevice,
        OfflineFindingScanner,
        SeparatedOfflineFindingDevice,
    )


def __getattr__(name: str) -> Any:  # noqa: ANN401 -- a re-export of whatever was asked for
    """Import the scanner on first use, rather than on importing this package."""
    if name in _SCANNER_EXPORTS:
        from . import scanner  # noqa: PLC0415 -- deferred on purpose; see above

        return getattr(scanner, name)

    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
