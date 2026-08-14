"""
The escrow proxy: listing, recovering from, creating and deleting escrow records.

Implements Stage 3 §4 and §5 of the Find My key-export protocol specification. "Escrow
record" is Apple's *secure backup*: a copy of a device's keychain material, sealed under
that device's screen-lock passcode, which anyone knowing the passcode can recover.

Listing is the part with a use of its own. Escrow records outlive the devices that made
them: an account observed while the specification was written held eight records for iMac
Pros whose device entries had been removed years earlier. Nothing in any Apple interface
enumerates them, so an account can accumulate them invisibly, and this is the only way for
a user to see what is there.

This module carries the transport and the commands. The two that are not merely reads have
their construction elsewhere, because in both cases the difficult part is what to send
rather than how:

* :mod:`findmy.keychain.recovery` builds the SRP proof `recover` takes.
* :mod:`findmy.keychain.enrolment` builds the blob and metadata `enroll` takes, and gets
  the club certificate verified against pinned roots before sealing anything to it.

Deletion is here in full, and :meth:`AsyncEscrowProxy.delete_record` documents the four
rules that make it safe to offer. The short version: only records with no usable bottle
are offered by default, deletion is impossible without a listing to judge that from, the
serial must be typed back, and none of it stops new records being created.
"""

from __future__ import annotations

import base64
import logging
import plistlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from typing_extensions import override

from findmy.errors import UnhandledProtocolError
from findmy.util.abc import Closable
from findmy.util.http import HttpSession

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from findmy.reports.account import AsyncAppleAccount

logger = logging.getLogger(__name__)

ESCROW_LABEL_SECURE_BACKUP = "com.apple.securebackup.record"
"""The record class escrow records themselves live under."""

ESCROW_LABEL_ICDP = "com.apple.icdp.record"
"""The record class the club certificate lives under, used when enrolling."""

COMPANION_SUFFIX = ".double"
"""
Marks a companion record, which shares its parent's label but for this suffix.

Nothing in enrolment creates one -- only deletion mentions them -- so if they exist they
are made by Apple's own clients. **[observed]** None appeared among twelve records on one
account, so a listing may well contain none at all; a deletion must still issue both calls
regardless, since a record that does have a companion would otherwise leave it orphaned.
"""

# Each command is named twice, in two spellings, and both must be right. The body spelling
# is not simply the uppercase of the path -- `get_club_cert` loses a word, `srp_init`
# keeps its separator, `get_records` loses its -- so the pairs are tabulated rather than
# derived. Sending the path spelling in the body is rejected with "Wrong command sent".
COMMAND_SPELLINGS = {
    "get_records": "GETRECORDS",
    "get_club_cert": "GETCLUB",
    "srp_init": "SRP_INIT",
    "recover": "RECOVER",
    "enroll": "ENROLL",
    "delete": "DELETE",
}

DELETION_DOES_NOT_STOP_THE_SOURCE = (
    "Deleting these records removes what is already on the account. It does not stop new"
    " ones appearing. Escrow records are created by whatever signs in and enrols -- if a"
    " tool is still doing that with a fresh identity each run, it will keep leaving them"
    " behind at the same rate."
)
"""
Worth showing wherever a user is told a cleanup succeeded.

"I cleaned up" is easily mistaken for "this will not come back", and on an account whose
records are still arriving weekly that mistake costs another year of accumulation before
anyone looks again.
"""

ROOT_CERT_VERSIONS = (101, 102, 103, 500)
"""
The certificate versions a client declares it will accept.

The escrow service authenticates against a pinned set of certificates, and these name the
versions this client understands. They are sent on the commands that involve the club
machinery; omitting them appears to leave the club handler with nothing to select and it
fails internally rather than saying what is missing.
"""

_CONTENT_TYPE = "application/x-apple-plst"
"""Note: not the text/x-xml-plist that Grand Slam uses."""

_USER_AGENT = "com.apple.sbd/638.100.48 CFNetwork/1408.0.4 Darwin/22.5.0"
_CLIENT_INFO_BUNDLE = "com.apple.AuthKit/1 (com.apple.sbd/638.100.48)"


class EscrowError(UnhandledProtocolError):
    """Raised when the escrow proxy rejects a request."""

    def __init__(self, message: str, *, reported: bool = False) -> None:
        """
        Initialize the error.

        :param reported: Whether the **service itself** described the failure, rather than
            the request failing in transport. The distinction matters exactly once: an
            enrolment that fails because a record already exists is worth resolving by
            deleting that label and enrolling again, and doing that on a transport failure
            would delete a record whose contents this client never established.
        """
        super().__init__(message)
        self.reported = reported


def _cert_versions() -> dict[str, list[int]]:
    """Build the pinned-certificate versions a club-handling command declares."""
    return {
        "baseRootCertVersions": list(ROOT_CERT_VERSIONS),
        "trustedRootCertVersions": list(ROOT_CERT_VERSIONS),
    }


def escrow_host(partition: str) -> str:
    """
    Derive the escrow proxy's host from the account's iCloud partition.

    The protocol does not hand this over. The configuration key it is supposed to come
    from is absent for this kind of client, and hardcoding a partition -- as at least one
    implementation does -- works only for accounts that happen to live on it. Every
    per-account iCloud service is named `p<N>-<service>.icloud.com`, and the partition is
    readable from the URLs opening a CloudKit container returns.

    :param partition: The bare partition number, e.g. `"24"`.
    """
    return f"https://p{partition}-escrowproxy.icloud.com:443"


@dataclass(frozen=True)
class EscrowRecord:
    """
    One escrow record, as far as it could be understood.

    The schema is genuinely unstable: of twelve records on one account, eleven described a
    device and one had a different shape entirely, with no serial, build or bottle id. So
    every field here may be absent, and :attr:`metadata` keeps the whole decoded plist so
    that a record this class does not understand is still inspectable rather than lost.
    """

    label: str
    """
    What addresses this record at the escrow proxy, shaped
    `com.apple.icdp.record.<peerId>`.

    Also the value the trust-circle service reports as a bottle's id, so this is what the
    two services join on -- **not** :attr:`bottle_id`, which is a different string of a
    different shape identifying the bottle rather than the record. Every command
    addressing one specific record takes this.

    **A label cannot be constructed.** The peer id inside it is a digest, so nothing a
    user can see -- a serial, a device name, a date -- yields it. Records are located by
    listing and by nothing else. Two records for the same physical device carry entirely
    different labels whenever the client that made them regenerated its identity in
    between, which is what makes them countable as runs rather than as devices.
    """

    device_name: str | None
    device_model: str | None
    device_model_class: str | None
    serial: str | None
    """What a user matches against their own device list. Also what a deletion must
    confirm against, since every entry looks structurally alike."""

    build: str | None
    escrowed_at: datetime | None
    bottle_id: str | None
    """
    The bottle inside the record, as a UUID.

    Not interchangeable with :attr:`label` and never equal to it. Its presence is what
    makes a record recoverable at all, but it is not how anything is addressed.
    """
    passcode_generation: int | None
    metadata: dict[str, Any]
    """The whole decoded metadata plist."""

    @property
    def peer_id(self) -> str:
        """
        The peer this record belongs to, taken from its label.

        The label is `com.apple.icdp.record.<peerId>`, and the peer id is a
        `SHA256:`-prefixed base64 digest -- the same value a peer carries as its `hash`,
        which is why peers are addressed by hash rather than by name. So a listing already
        names the sponsoring peer a voucher would have to name, without asking anything
        further.

        Returns the whole label if it does not carry the expected prefix, rather than
        guessing at a substring.
        """
        prefix = f"{ESCROW_LABEL_ICDP}."
        base = self.companion_of
        return base.removeprefix(prefix)

    @property
    def is_companion(self) -> bool:
        """Whether this record is another's companion rather than a device of its own."""
        return self.label.endswith(COMPANION_SUFFIX)

    @property
    def companion_of(self) -> str:
        """The label this record is a companion to, or its own label if it is not one."""
        if self.is_companion:
            return self.label[: -len(COMPANION_SUFFIX)]
        return self.label

    @property
    def is_recovery_candidate(self) -> bool:
        """
        Whether this record could be recovered from at all.

        A record with no bottle id is not broken -- it is a different kind of record --
        but it cannot be a recovery candidate.
        """
        return self.bottle_id is not None

    def describe(self) -> str:
        """Render the record the way it should be shown to a person."""
        parts = [self.device_name or "unnamed device"]
        if self.device_model:
            parts.append(self.device_model)
        if self.serial:
            parts.append(f"serial {self.serial}")
        if self.escrowed_at:
            parts.append(f"escrowed {self.escrowed_at:%Y-%m-%d}")
        return ", ".join(parts)


@dataclass(frozen=True)
class EscrowListing:
    """What listing an account's escrow records returned."""

    records: list[EscrowRecord]
    unreadable: list[str]
    """Labels whose metadata could not be decoded. Reported, never silently dropped."""

    status: int | None
    message: str | None

    @property
    def recovery_candidates(self) -> list[EscrowRecord]:
        """The records that carry a bottle id."""
        return [record for record in self.records if record.is_recovery_candidate]


@dataclass(frozen=True)
class RecoveryOptions:
    """
    What an account can actually be recovered from, once both services have been asked.

    The escrow proxy knows the human-readable metadata and Cuttlefish knows which bottles
    are usable, so neither alone answers the question -- and the two mismatches are worth
    reporting rather than quietly dropping, because they are the signal that this
    library's model has drifted from what Apple returns.
    """

    recoverable: list[EscrowRecord]
    """Records that are both described and usable. These are the real options."""

    described_but_not_viable: list[EscrowRecord]
    """Records the proxy knows about that Cuttlefish did not list as viable."""

    viable_but_undescribed: list[str]
    """Bottle ids Cuttlefish listed that no escrow record describes."""

    viability_reported: bool = True
    """
    Whether the trust-circle service actually reported any usable bottle.

    See :attr:`viability_is_trustworthy`.
    """

    @property
    def viability_is_trustworthy(self) -> bool:
        """
        Whether viability is worth judging a deletion by.

        Viability is the guard on deletion, which makes a *transiently* non-viable bottle
        dangerous: a service outage, or a peer briefly unreachable, would make live
        recovery paths look like debris and invite deleting something real.

        A client cannot tell a transient outage from a bottle that is genuinely gone. What
        it can tell is when the answer is not worth trusting at all, and the clearest such
        case is **no viable bottles reported whatsoever**. An account with escrow records
        but no usable bottle is possible; an account where every record simultaneously
        became unusable is far more likely to be a service having a bad day. Since the
        consequence of being wrong is destroying a real device's recovery path, that reads
        as "ask again later" rather than "everything here is junk".
        """
        return self.viability_reported

    @property
    def safe_to_delete(self) -> list[EscrowRecord]:
        """
        Records whose deletion takes away no capability anyone had.

        A record with no usable bottle cannot be recovered from, so removing it destroys
        nothing. This is the list a user should be offered.

        Non-viability can be transient -- a service down, a peer briefly unreachable --
        which is why the serial confirmation stays in place underneath rather than being
        replaced by this.
        """
        if not self.viability_is_trustworthy:
            return []
        return list(self.described_but_not_viable)

    @property
    def unsafe_to_delete(self) -> list[EscrowRecord]:
        """
        Records that are a live recovery path for a real device.

        Deleting one destroys that device's ability to recover its keychain, and its owner
        finds out after a wipe, at the worst possible moment, with no undo.
        """
        return list(self.recoverable)

    @property
    def device_count(self) -> int:
        """
        How many distinct devices these records represent.

        Grouped by **serial**, not by record, because the two differ: one device can hold
        several escrow records, each under its own peer identity, if it enrolled more than
        once. **[observed]** Four serials across seven records on one account -- an
        identity minted per run against a reused serial.

        Records with no serial each count as their own device, since nothing distinguishes
        them.
        """
        every = self.recoverable + self.described_but_not_viable
        return len({record.serial or record.label for record in every})

    def describe(self) -> str:
        """Summarise the result the way it should be reported."""
        parts = [f"{len(self.recoverable)} recoverable"]
        if self.described_but_not_viable:
            parts.append(f"{len(self.described_but_not_viable)} described but not viable")
        if self.viable_but_undescribed:
            parts.append(f"{len(self.viable_but_undescribed)} viable but undescribed")
        return ", ".join(parts)


def join_recovery_options(
    listing: EscrowListing,
    viable_bottle_ids: Iterable[str],
    *,
    partial_count: int | None = None,
) -> RecoveryOptions:
    """
    Join escrow metadata against the bottles Cuttlefish considers usable.

    A bottle without metadata cannot be described to a user; metadata without a viable
    bottle cannot be recovered from. Both mismatches are reported.

    **The join is on the record's label**, which is what the trust-circle service reports
    as a bottle's id. A record's `bottleID` is a different value of a different shape -- a
    UUID naming the bottle rather than the record -- and matching on it as well would be
    forgiving of a confusion that should be caught instead.

    :param listing: What the escrow proxy returned.
    :param viable_bottle_ids: What Cuttlefish returned as valid.
    :param partial_count: How many bottles Cuttlefish called partial. Supplying it turns
        that count into a cross-check: it has matched the number of described-but-unviable
        records everywhere the two have been compared.
    """
    viable = set(viable_bottle_ids)

    recoverable: list[EscrowRecord] = []
    not_viable: list[EscrowRecord] = []
    for record in listing.records:
        if not record.is_recovery_candidate:
            # Not a recovery candidate at all, rather than a mismatch: a record with no
            # bottle is a different kind of record, not a broken one.
            continue
        if record.label in viable:
            recoverable.append(record)
        else:
            not_viable.append(record)

    undescribed = sorted(viable - {record.label for record in listing.records})

    # The two directions are not equally interesting, and warning about both in one line
    # made the ordinary one look like a fault on every run.
    #
    # A record the escrow proxy describes and Cuttlefish will not accept is **residue**:
    # escrow records outlive the devices that wrote them, Apple shows them in no
    # interface, and an account accumulates them. Expected, and only actionable through
    # delete_escrow_records.py.
    if not_viable:
        logger.info(
            "%d escrow record(s) are described but not recoverable from, which is ordinary"
            " residue rather than a fault. delete_escrow_records.py removes them.",
            len(not_viable),
        )

    # This direction is the surprising one: Cuttlefish will accept a bottle the escrow
    # proxy did not describe, so the listing is incomplete and something recoverable is
    # invisible to the user.
    if undescribed:
        logger.warning(
            "%d bottle(s) are viable but appear in no escrow record: %s. The escrow"
            " listing is therefore incomplete, and a recovery option is being hidden.",
            len(undescribed),
            ", ".join(undescribed),
        )

    if partial_count is not None and partial_count != len(not_viable):
        # The two counts corresponded exactly on every account observed, so a discrepancy
        # is a sign the join has gone wrong rather than a fact about the account.
        logger.warning(
            "Cuttlefish reported %d partial bottle(s) but the join produced %d record(s)"
            " that are described and not viable. These counts have matched everywhere"
            " they have been compared, so the join is the thing to suspect.",
            partial_count,
            len(not_viable),
        )

    return RecoveryOptions(
        recoverable=recoverable,
        described_but_not_viable=not_viable,
        viable_but_undescribed=undescribed,
        viability_reported=bool(viable),
    )


# **[observed]** A rejected `recover` comes back as HTTP 409 carrying a *complete* reply:
# `status`, `message`, `respBlob` and `version`. So a non-2xx status does not mean the body
# is unstructured -- reading it as plain text throws away the two fields that say what
# happened and leaves a truncated XML dump in the exception instead.
_FAILURE_FIELDS = ("status", "message", "errorCode", "errorMessage")


def _failure(command: str, resp: object) -> EscrowError:
    """
    Build the error for a non-2xx reply, reading the body as a property list first.

    The escrow proxy answers a rejection with the same plist shape it answers success
    with, so the useful part -- a numeric `status` and a `message` naming the fault -- is
    in there. Falling back to the raw text is for a body that genuinely is not one.
    """
    status_code = getattr(resp, "status_code", "?")

    try:
        data = resp.plist()  # pyright: ignore [reportAttributeAccessIssue]
    except Exception:  # noqa: BLE001 -- any failure here just means it is not a plist
        data = None

    if isinstance(data, dict):
        described = ", ".join(
            f"{key} {data[key]!r}" for key in _FAILURE_FIELDS if data.get(key) is not None
        )
        blob = " (a respBlob came back too)" if data.get("respBlob") else ""
        msg = (
            f"Escrow proxy rejected {command} with HTTP {status_code}:"
            f" {described or 'no status or message'}{blob}"
        )
        # The service described this rather than the request failing in transport.
        return EscrowError(msg, reported=True)

    try:
        body = resp.content.decode("utf-8", errors="replace").strip()  # pyright: ignore [reportAttributeAccessIssue]
    except (AttributeError, UnicodeDecodeError):  # pragma: no cover
        body = ""

    detail = f": {body[:500]}" if body else ""
    return EscrowError(f"Escrow proxy returned HTTP {status_code} for {command}{detail}")


def _parse_metadata(label: str, encoded: bytes | str) -> EscrowRecord:
    """Decode one record's metadata plist, tolerating a shape this does not know."""
    raw = base64.b64decode(encoded) if isinstance(encoded, str) else encoded
    metadata: dict[str, Any] = plistlib.loads(raw)

    # Two spellings each, because §4.5.2 once described these keys by an implementation's
    # internal field names -- `clientMetadata` and `timestamp` -- and was corrected to the
    # reverse-DNS and PascalCase forms §5.1 observed on real records. Records written by
    # anything that followed the earlier text still exist, and a record this reader cannot
    # describe is a record nobody can safely delete, so it stays tolerant. The writer sends
    # only the correct spellings.
    client = metadata.get("ClientMetadata") or metadata.get("clientMetadata") or {}
    escrowed_at = metadata.get("com.apple.securebackup.timestamp") or metadata.get("timestamp")
    if isinstance(escrowed_at, str):
        try:
            escrowed_at = datetime.fromisoformat(escrowed_at.replace("Z", "+00:00"))
        except ValueError:
            escrowed_at = None
    elif not isinstance(escrowed_at, datetime):
        escrowed_at = None

    if isinstance(escrowed_at, datetime) and escrowed_at.tzinfo is None:
        # Dates in a property list are UTC, but plistlib decodes them without a timezone.
        # Attaching it here keeps a naive datetime from leaking into comparisons later.
        escrowed_at = escrowed_at.replace(tzinfo=timezone.utc)

    return EscrowRecord(
        label=label,
        device_name=client.get("device_name"),
        device_model=client.get("device_model"),
        device_model_class=client.get("device_model_class"),
        serial=metadata.get("serial"),
        build=metadata.get("build"),
        escrowed_at=escrowed_at,
        bottle_id=metadata.get("bottleID"),
        # camelCase, and present on only the newest records.
        passcode_generation=metadata.get("passcodeGeneration"),
        metadata=metadata,
    )


class AsyncEscrowProxy(Closable):
    """
    A read-only client for the escrow proxy.

    The escrow proxy authenticates with the account's **PET** -- the short-lived
    password-equivalent token from logging in -- rather than with an iCloud service token.
    That has two consequences worth knowing before using this class:

    * A PET expires in about five minutes, so an instance is only useful immediately
      after a login.
    * FindMy.py does not keep one. It exchanges the PET for iCloud service tokens as the
      last step of logging in and then discards it, so there is nothing to read off a
      logged-in account. The token has to be supplied by whatever performed the login.
    """

    def __init__(self, account: AsyncAppleAccount, host: str, pet: str) -> None:
        """
        Initialize the client.

        :param account: A logged-in account, for its Anisette identity and account name.
        :param host: The escrow proxy's base URL; see :func:`escrow_host`.
        :param pet: A fresh PET, from `com.apple.gs.idms.pet`. See the class docstring on
            why this is a parameter rather than something read off the account.
        """
        super().__init__()

        if not pet:
            msg = "The escrow proxy needs a PET; an empty one will be rejected"
            raise EscrowError(msg)

        self._account = account
        self._host = host.rstrip("/")
        self._pet = pet
        self._http = HttpSession()

    def replace_pet(self, pet: str) -> None:
        """
        Swap in a freshly issued token.

        A PET lasts about five minutes, so anything holding a proxy for longer than one
        exchange has to renew it rather than reconstruct the client around it.
        """
        if not pet:
            msg = "The escrow proxy needs a PET; an empty one will be rejected"
            raise EscrowError(msg)
        self._pet = pet

    @override
    async def close(self) -> None:
        """Close the underlying HTTP session."""
        await self._http.close()

    async def _headers(self) -> dict[str, str]:
        client_info = self._account.client_info
        groups = [part.split(">", 1)[0] for part in client_info.split("<") if ">" in part]
        prefix = "".join(f"<{part}> " for part in groups[:2])

        headers = {
            "Content-Type": _CONTENT_TYPE,
            "User-Agent": _USER_AGENT,
            "X-Mme-Client-Info": f"{prefix}<{_CLIENT_INFO_BUNDLE}>",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Apple-I-Locale": "en_US",
            "x-apple-i-device-type": "1",
        }
        headers.update(await self._account.get_anisette_headers())
        return headers

    async def _command(
        self,
        command: str,
        *,
        label: str,
        user_action_label: str,
        extra: dict[str, Any] | None = None,
        transaction_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Send one escrow-proxy command.

        :param command: The URL spelling, e.g. `get_records`. The body spelling is looked
            up rather than derived; they are not the same word.
        :param label: Overloaded, and which meaning applies depends on the command. For
            `get_records` and `get_club_cert` it names a record *class*; for `srp_init`,
            `recover`, `enroll` and `delete` it names one *specific* record, by the label
            from a listing -- never by a `bottleID`, which addresses nothing.
        :param user_action_label: A free-text description of why, which Apple keeps. It
            should describe what is actually happening, and must not impersonate a
            first-party Apple process.
        """
        body_command = COMMAND_SPELLINGS.get(command)
        if body_command is None:
            msg = f"Unknown escrow command {command!r}"
            raise EscrowError(msg)

        body: dict[str, Any] = {
            "command": body_command,
            "label": label,
            "transactionUUID": transaction_id or str(uuid.uuid4()).upper(),
            "userActionLabel": user_action_label,
            "version": 1,
            **(extra or {}),
        }

        resp = await self._http.post(
            f"{self._host}/escrowproxy/api/{command}",
            auth=(self._account.account_name or "", self._pet),
            headers=await self._headers(),
            data=plistlib.dumps(body),
        )

        if not resp.ok:
            raise _failure(command, resp)

        data = resp.plist()
        # Check success before reading anything else. The messages are specific and worth
        # surfacing verbatim.
        if data.get("success") is False or data.get("errorCode"):
            message = data.get("errorMessage") or "no message"
            msg = f"Escrow proxy rejected {command}: {message} (code {data.get('errorCode')})"
            raise EscrowError(msg, reported=True)

        return data

    async def list_records(
        self,
        *,
        user_action_label: str = "FindMy.py listing escrow records",
    ) -> EscrowListing:
        """
        List the escrow records on this account.

        Read-only: it creates nothing, needs no passcode, and has no side effects beyond
        the free-text label appearing in Apple's logs.

        Note that the result will contain records the user no longer recognises -- devices
        sold, wiped or removed years ago -- because removing a device from an account does
        not remove its escrow record. That is exactly why "delete the one you don't
        recognise" is dangerous advice, and why this module offers no deletion.
        """
        data = await self._command(
            "get_records",
            label=ESCROW_LABEL_SECURE_BACKUP,
            user_action_label=user_action_label,
        )

        records: list[EscrowRecord] = []
        unreadable: list[str] = []

        for entry in data.get("metadataList") or []:
            label = entry.get("label", "")
            try:
                records.append(_parse_metadata(label, entry["metadata"]))
            except (KeyError, ValueError, plistlib.InvalidFileException):
                logger.warning("Could not decode escrow metadata for %s", label or "<unlabelled>")
                unreadable.append(label)

        # Which spelling real records use, both ways round. This is what settled §4.5.2's
        # key names against §5.1's: the service stores the plist verbatim, so a listing is
        # direct evidence of what a working client writes. Kept because it costs one line
        # and would catch the same drift again -- and it counts the absent spellings too,
        # since a diagnostic that only reports what it found leaves the absent case silent.
        if records:
            logger.debug(
                "Metadata key spellings in this listing: %s",
                ", ".join(
                    f"{key} {sum(1 for r in records if key in r.metadata)}/{len(records)}"
                    for key in (
                        "ClientMetadata",
                        "clientMetadata",
                        "com.apple.securebackup.timestamp",
                        "timestamp",
                    )
                ),
            )

        logger.info(
            "Account holds %d escrow record(s), %d of them recoverable",
            len(records),
            sum(1 for record in records if record.is_recovery_candidate),
        )

        return EscrowListing(
            records=records,
            unreadable=unreadable,
            status=data.get("status"),
            message=data.get("message"),
        )

    async def srp_init(
        self,
        label: str,
        client_public: bytes,
        transaction_id: str,
        *,
        user_action_label: str = "FindMy.py beginning escrow recovery",
    ) -> dict[str, Any]:
        """
        Begin a passcode-authenticated recovery for one record.

        :param label: The record's own label from a listing -- never a `bottleID`, which
            addresses nothing.
        :param client_public: The SRP client's public value A.
        :param transaction_id: Shared with the `recover` call that follows it.
        """
        return await self._command(
            "srp_init",
            label=label,
            user_action_label=user_action_label,
            transaction_id=transaction_id,
            extra={
                "blob": base64.b64encode(client_public).decode(),
                **_cert_versions(),
            },
        )

    async def recover(
        self,
        label: str,
        proof_blob: bytes,
        transaction_id: str,
        *,
        dsid: str | None = None,
        user_action_label: str = "FindMy.py completing escrow recovery",
    ) -> dict[str, Any]:
        """
        Complete a recovery begun with :meth:`srp_init`.

        :param proof_blob: The framed SRP proof, from `build_recovery_proof`.
        :param transaction_id: The **same** id the `srp_init` call used.
        :param dsid: Echoed back from the `srp_init` reply. Listed among the per-command
            body fields without it being said which commands take it; the service hands
            one out here and it costs nothing to return it.
        """
        extra: dict[str, Any] = {
            "blob": base64.b64encode(proof_blob).decode(),
            **_cert_versions(),
        }
        if dsid is not None:
            extra["dsid"] = dsid

        return await self._command(
            "recover",
            label=label,
            user_action_label=user_action_label,
            transaction_id=transaction_id,
            extra=extra,
        )

    async def get_club_cert(
        self,
        transaction_id: str,
        *,
        user_action_label: str = "FindMy.py fetching the escrow club certificate",
    ) -> dict[str, Any]:
        """
        Fetch the certificate an escrow blob is encrypted to.

        Read-only, and the first half of an enrolment: it shares its transaction id with
        the `enroll` that follows. The label is the record **class**, not a specific
        record, because no record exists yet.

        **What comes back must be verified against pinned roots before anything is
        encrypted to it** -- see :func:`findmy.keychain.enrolment.verify_club_certificate`,
        which is why this returns the raw response rather than a certificate.

        :param transaction_id: Shared with the `enroll` request.
        """
        response = await self._command(
            "get_club_cert",
            label=ESCROW_LABEL_ICDP,
            user_action_label=user_action_label,
            transaction_id=transaction_id,
            extra=_cert_versions(),
        )

        # **[observed] The reply carries the leaf and nothing else** -- `clubCert` plus
        # `dsid`, `message`, `status` and `version`. So the issuing chain is not available
        # here, and the four roots have to be carried by the client; fetching and
        # fingerprint-checking them at runtime is not an option Apple offers.
        #
        # Still logged, because that answer has a shelf life: if a future reply does carry
        # a chain, this is what would show it.
        logger.debug(
            "get_club_cert returned: %s",
            ", ".join(
                f"{key}={len(value)}B" if isinstance(value, (bytes, str)) else f"{key}={value!r}"
                for key, value in sorted(response.items())
            ),
        )

        return response

    async def enroll(  # noqa: PLR0913 -- the fields an enrolment sends, and it is six
        self,
        label: str,
        *,
        blob: bytes,
        blob_digest: str,
        metadata: bytes,
        dsid: str,
        transaction_id: str,
        user_action_label: str = "FindMy.py enrolling an escrow record",
    ) -> dict[str, Any]:
        """
        Create an escrow record.

        **This is a write, and nothing removes what it leaves except a deliberate
        deletion.** Prefer :func:`findmy.keychain.enrolment.enrol_record`, which builds
        every field of this and gets the certificate verified before the blob is sealed.

        :param label: The new record's own label, `com.apple.icdp.record.<peerId>`.
        :param blob: The escrow blob.
        :param blob_digest: Base64 of that blob's **SHA-1**, not SHA-256.
        :param metadata: The binary property list describing the record.
        :param transaction_id: The **same** id `get_club_cert` used.
        """
        return await self._command(
            "enroll",
            label=label,
            user_action_label=user_action_label,
            transaction_id=transaction_id,
            extra={
                "blob": base64.b64encode(blob).decode(),
                "blobDigest": blob_digest,
                "metadata": base64.b64encode(metadata).decode(),
                "dsid": dsid,
                # No certificate versions here, unlike every other club-handling command.
                # They ask which roots the client will accept, and `get_club_cert` -- the
                # first half of this same transaction -- already answered that.
            },
        )

    async def delete_label(
        self,
        label: str,
        *,
        user_action_label: str = "FindMy.py removing a record it just failed to enrol",
    ) -> None:
        """
        Delete whatever is at one label, with none of :meth:`delete_record`'s guards.

        **Not the method to reach for.** :meth:`delete_record` exists because a listing
        contains records the user no longer recognises, and its four rules stop one being
        removed on a judgement call. None of them applies here, which is why this is
        separate and narrow rather than a flag on that method.

        It is for exactly one case: an enrolment the service refused because a record
        already exists at a label **this client generated moments earlier** for an identity
        it created itself. There is no user judgement in that, and nothing else can be at
        that label.

        :param label: The record's label.
        """
        logger.warning("Deleting whatever is at %s, unconditionally", label)
        await self._command("delete", label=label, user_action_label=user_action_label)

    async def delete_record(
        self,
        record: EscrowRecord,
        options: RecoveryOptions,
        *,
        confirm: str,
        allow_viable: bool = False,
        user_action_label: str = "FindMy.py deleting an escrow record",
    ) -> None:
        """
        Delete one escrow record, and its companion if it has one.

        **This is irreversible and the protocol offers no protection at all.** Any client
        holding a valid PET can destroy any escrow record on the account, including one a
        real device depends on, and nothing server-side will refuse. Every safeguard is
        here, in the client. There are four, and each removes a different way of getting
        this wrong:

        1. **A listing is required.** `options` comes from joining the escrow proxy
           against the trust-circle service, and a record not in it cannot be deleted.
           Without viability every record looks alike, which is the situation these rules
           exist to prevent -- so if a listing cannot be obtained, deletion is not offered.
        2. **Viable records are refused.** A record with no usable bottle takes away no
           capability anyone had. A viable one is a live recovery path for a real device.
           Removing the dangerous option is stronger than asking a user to be careful
           around it; `allow_viable` exists so that the exception is deliberate and
           separately worded rather than a prompt someone clicks through.
        3. **The serial must be typed back**, in full and exactly. Not a list position:
           every entry looks structurally alike, and a list contains devices the user sold
           or wiped years ago, so "delete the one you don't recognise" is dangerous advice.
           Records carrying no serial confirm against their label instead.
        4. **Both labels are deleted**, companion first. A record this client created has
           no companion and that call will address nothing, which is harmless; a
           first-party record does have one, and deleting only the main record orphans it.

        None of this stops new records appearing -- see :data:`DELETION_DOES_NOT_STOP_THE_SOURCE`.

        :param record: The record to delete, from `options`.
        :param options: The joined listing that judged its viability.
        :param confirm: The record's serial, typed back in full. Its label, for a record
            that has no serial.
        :param allow_viable: Permit deleting a record that is a live recovery path.
        :raises EscrowError: If any of the four rules is not satisfied.
        """
        if not options.viability_is_trustworthy:
            msg = (
                "The trust-circle service reported no usable bottle at all, which is more"
                " likely a service having a bad day than every record on the account"
                " becoming unusable at once. Refusing to delete anything on that basis:"
                " viability is the guard here, and it is not currently worth trusting."
            )
            raise EscrowError(msg)

        known = {r.label for r in options.recoverable + options.described_but_not_viable}
        if record.label not in known:
            msg = (
                "This record is not in the listing supplied, so its viability is unknown."
                " Deleting a record whose viability has not been established is exactly"
                " what these checks exist to prevent."
            )
            raise EscrowError(msg)

        if record.is_companion:
            msg = (
                f"{record.label} is a companion record. Delete the record it belongs to"
                f" ({record.companion_of}) instead; that removes both."
            )
            raise EscrowError(msg)

        if record in options.unsafe_to_delete and not allow_viable:
            msg = (
                f"{record.label} is a live recovery path for {record.describe()}."
                " Deleting it destroys that device's ability to recover its keychain, and"
                " its owner would not find out until after a wipe. Refusing."
            )
            raise EscrowError(msg)

        expected = record.serial or record.label
        if confirm != expected:
            msg = (
                "The confirmation does not match this record. Deletion confirms against"
                " the serial typed out in full, never a list position, because every"
                " record looks structurally alike."
            )
            raise EscrowError(msg)

        logger.warning("Deleting escrow record %s (%s)", record.label, record.describe())

        # The companion first. Its absence is expected for a record this client made, so a
        # failure here must not stop the record itself being removed.
        try:
            await self._command(
                "delete",
                label=record.label + COMPANION_SUFFIX,
                user_action_label=user_action_label,
            )
        except EscrowError as e:
            logger.info("No companion record to delete for %s (%s)", record.label, e)

        await self._command(
            "delete",
            label=record.label,
            user_action_label=user_action_label,
        )


# --------------------------------------------------------------------------------------
# KeyVault framing
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyVaultSection:
    """
    One section of a framed message, which may occupy more space than it declares.

    A section is normally a 4-byte big-endian length followed by that many bytes. Some
    are padded: the declared length stays the true length of the data, zero bytes are
    **appended** after it, and the offsets account for the larger footprint. So a
    "20-byte" section holding eight bytes is a length of 8, the eight bytes, and eight
    zeros -- four plus eight plus eight.

    Padding the *data* to twenty instead, and declaring twenty, produces a section that
    parses and is wrong, which is why this is a type rather than a convention.
    """

    data: bytes

    footprint: int | None = None
    """Total bytes this section occupies, its length prefix included. None means exact."""

    def encode(self) -> bytes:
        """Render the section, padded if it has a footprint."""
        body = len(self.data).to_bytes(4, "big") + self.data
        if self.footprint is None:
            return body
        if self.footprint < len(body):
            msg = f"A {len(body)}-byte section cannot fit a {self.footprint}-byte footprint"
            raise EscrowError(msg)
        return body.ljust(self.footprint, b"\x00")


def split_keyvault_message(
    data: bytes,
    header_length: int,
    section_count: int,
) -> tuple[bytes, bytes, list[bytes]]:
    """
    Split the framing both escrow blobs use, which appears nowhere else in this protocol.

    The first four bytes are the **total length of the message**, big-endian. They are
    easy to mistake for padding -- a reader can ignore them and everything still parses --
    but a writer cannot: the service checks them, and a message whose declared length
    disagrees with its actual one is rejected with an internal error that names nothing.
    **[observed]** a reply of 384 bytes declared 0x00000180.

    Then a header of `header_length` bytes, then one 4-byte big-endian offset per section
    -- and **one more offset than there are sections**, the last marking end of data. Each
    section then begins with its own 4-byte length.

    Computing the base from the section count rather than from the count plus one puts
    every section four bytes out and produces garbage that looks like a decryption
    failure, which is why this is a function with tests rather than arithmetic inline.

    :param data: The framed message.
    :param header_length: *H*, the header's length.
    :param section_count: *S*, how many sections to read.
    :returns: The four leading bytes, the header, and the sections in order.
    """
    offsets_at = 4 + header_length
    base = offsets_at + (section_count + 1) * 4

    if len(data) < base:
        msg = (
            f"KeyVault message is {len(data)} bytes, too short for a {header_length}-byte"
            f" header and {section_count} section offset(s)"
        )
        raise EscrowError(msg)

    prefix = data[:4]
    declared = int.from_bytes(prefix, "big")
    if declared != len(data):
        # Not fatal for reading -- everything is addressed by offset -- but worth saying,
        # since it means this framing is not what it is assumed to be.
        logger.warning(
            "KeyVault message declares %d bytes but is %d",
            declared,
            len(data),
        )

    header = data[4 : 4 + header_length]

    sections: list[bytes] = []
    for index in range(section_count):
        raw_offset = data[offsets_at + index * 4 : offsets_at + (index + 1) * 4]
        offset = base + int.from_bytes(raw_offset, "big")

        if offset + 4 > len(data):
            msg = f"KeyVault section {index} starts past the end of the message"
            raise EscrowError(msg)

        length = int.from_bytes(data[offset : offset + 4], "big")
        section = data[offset + 4 : offset + 4 + length]
        if len(section) != length:
            msg = f"KeyVault section {index} claims {length} bytes but is truncated"
            raise EscrowError(msg)

        sections.append(section)

    return prefix, header, sections


def parse_keyvault_message(
    data: bytes,
    header_length: int,
    section_count: int,
) -> tuple[bytes, list[bytes]]:
    """Parse a framed message, discarding its four leading bytes."""
    _, header, sections = split_keyvault_message(data, header_length, section_count)
    return header, sections


def build_keyvault_message(
    header: bytes,
    sections: Sequence[bytes | KeyVaultSection],
) -> bytes:
    """
    Build a message in the framing :func:`parse_keyvault_message` reads.

    The leading four bytes are computed, not supplied: they are this message's own total
    length. Echoing the length of the message being replied to is wrong for the same
    reason inventing zeros is -- it is a property of the message carrying it.

    :param sections: Plain bytes for an ordinary section, or a :class:`KeyVaultSection`
        for one that occupies more room than it declares.
    """
    prepared = [s if isinstance(s, KeyVaultSection) else KeyVaultSection(s) for s in sections]

    offsets_at = 4 + len(header)
    base = offsets_at + (len(prepared) + 1) * 4

    body = b""
    offsets: list[int] = []
    for section in prepared:
        offsets.append(len(body))
        body += section.encode()
    offsets.append(len(body))  # one more than there are sections

    total = base + len(body)

    return (
        total.to_bytes(4, "big")
        + header
        + b"".join(offset.to_bytes(4, "big") for offset in offsets)
        + body
    )[: base + len(body)]
