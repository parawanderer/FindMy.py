"""
Cuttlefish: the server side of Apple's keychain trust-circle protocol.

Implements the read-only part of Stage 3 §2 and §5 step 2 of the Find My key-export
protocol specification -- asking which sealed bottles an account could actually be
recovered from.

Cuttlefish is not a service of its own. It is invoked as a server-side function through a
CloudKit container, so this module is a thin layer over
:class:`~findmy.cloudkit.client.AsyncCloudKitClient` rather than an HTTP client.

**Recovery is not implemented.** This answers "what could I recover from", which is the
half that creates nothing and needs no passcode. See :mod:`findmy.keychain.escrow` for the
other half of that question, and for why the two services must be asked together.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from google.protobuf.message import DecodeError

from findmy.cloudkit.client import AsyncCloudKitClient
from findmy.cloudkit.constants import CUTTLEFISH_BUNDLE, CUTTLEFISH_SERVICE, KEYCHAIN_CONTAINER
from findmy.cloudkit.proto import cuttlefish_pb2 as cf
from findmy.errors import UnhandledProtocolError

if TYPE_CHECKING:
    from findmy.reports.account import AsyncAppleAccount

logger = logging.getLogger(__name__)

METHOD_FETCH_VIABLE_BOTTLES = "fetchViableBottles"

# The specification gives this filter value without saying what it selects.
VIABLE_BOTTLES_FILTER = 1


class CuttlefishError(UnhandledProtocolError):
    """Raised when a Cuttlefish call fails or its result cannot be read."""


@dataclass(frozen=True)
class ViableBottles:
    """Which bottles Cuttlefish considers usable."""

    valid: list[str]
    """Bottle identifiers that can be recovered from. These join to an escrow record's
    `label`."""

    partial_count: int
    """
    How many bottles exist in a not-fully-usable state.

    A count rather than a list on purpose: the protocol's entry for these carries no
    fields at all, so there is nothing to report but the number.
    """

    entries: list[cf.EscrowData]
    """
    The valid entries in full, each carrying its sealed bottle.

    Kept because opening a bottle needs no further call: the listing that judged it viable
    already returned it.
    """


def make_cuttlefish_client(account: AsyncAppleAccount) -> AsyncCloudKitClient:
    """
    Build a CloudKit client pointed at the keychain container.

    A different container from the accessory one, opened the same way -- so this is
    ordinary Stage 4 machinery aimed somewhere else, not a second transport.
    """
    return AsyncCloudKitClient(
        account,
        container=KEYCHAIN_CONTAINER,
        bundle=CUTTLEFISH_BUNDLE,
    )


async def fetch_viable_bottles(client: AsyncCloudKitClient) -> ViableBottles:
    """
    Ask which bottles this account could be recovered from.

    Read-only: it creates nothing and needs no passcode.

    :param client: A CloudKit client on the keychain container; see
        :func:`make_cuttlefish_client`.
    :raises CuttlefishError: If the call fails, or its result does not decode.
    """
    request = cf.FetchViableBottlesRequest(filter=VIABLE_BOTTLES_FILTER, metrics=b"")

    serialized = await client.function_invoke(
        CUTTLEFISH_SERVICE,
        METHOD_FETCH_VIABLE_BOTTLES,
        request.SerializeToString(),
    )

    response = cf.FetchViableBottlesResponse()
    try:
        response.ParseFromString(serialized)
    except DecodeError as e:
        # Worth distinguishing from a CloudKit error: the operation *succeeded*. CloudKit
        # neither parses nor validates this payload, so a failure here is about the inner
        # message and says nothing about the call.
        msg = (
            f"CloudKit accepted the call but its result did not decode as a"
            f" {METHOD_FETCH_VIABLE_BOTTLES} response ({e}). The inner message layer is"
            " what is wrong, not the CloudKit envelope."
        )
        raise CuttlefishError(msg) from None

    valid = [entry.id for entry in response.valid if entry.id]
    logger.info(
        "Cuttlefish reports %d viable bottle(s) and %d partial",
        len(valid),
        len(response.partial),
    )

    return ViableBottles(
        valid=valid,
        partial_count=len(response.partial),
        entries=[entry for entry in response.valid if entry.id],
    )
