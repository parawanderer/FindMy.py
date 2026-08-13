"""Access to material held in the user's iCloud Keychain."""

from .bottle import (
    BottleError,
    BottleKeys,
    derive_bottle_keys,
    keys_match_bottle,
)
from .cuttlefish import (
    CuttlefishError,
    ViableBottles,
    fetch_viable_bottles,
    make_cuttlefish_client,
)
from .escrow import (
    AsyncEscrowProxy,
    EscrowError,
    EscrowListing,
    EscrowRecord,
    RecoveryOptions,
    escrow_host,
    join_recovery_options,
    parse_keyvault_message,
)
from .join import (
    JoinError,
    SignedBlob,
    make_join_request,
    make_peer,
    make_voucher,
    require_key_shares,
)
from .recovery import (
    RecoveryChallenge,
    RecoveryError,
    recover_bottled_peer,
    unwrap_inner_blob,
    unwrap_outer_blob,
)
from .session import (
    AsyncKeychainSession,
    KeychainSessionError,
    RecoveredPeer,
)
from .shares import (
    KeyShare,
    ShareError,
    fetch_recoverable_shares,
    sfies_decrypt,
    sfies_decrypt_archive,
    unarchive,
    unwrap_share,
)

__all__ = (
    "AsyncEscrowProxy",
    "AsyncKeychainSession",
    "BottleError",
    "BottleKeys",
    "CuttlefishError",
    "EscrowError",
    "EscrowListing",
    "EscrowRecord",
    "JoinError",
    "KeyShare",
    "KeychainSessionError",
    "RecoveredPeer",
    "RecoveryChallenge",
    "RecoveryError",
    "RecoveryOptions",
    "ShareError",
    "SignedBlob",
    "ViableBottles",
    "derive_bottle_keys",
    "escrow_host",
    "fetch_recoverable_shares",
    "fetch_viable_bottles",
    "join_recovery_options",
    "keys_match_bottle",
    "make_cuttlefish_client",
    "make_join_request",
    "make_peer",
    "make_voucher",
    "parse_keyvault_message",
    "recover_bottled_peer",
    "require_key_shares",
    "sfies_decrypt",
    "sfies_decrypt_archive",
    "unarchive",
    "unwrap_inner_blob",
    "unwrap_outer_blob",
    "unwrap_share",
)
