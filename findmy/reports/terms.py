"""
The iCloud terms of service, and accepting them without an Apple device.

Stage 2 §5.2. An account with unaccepted iCloud terms fails the MobileMe delegate
exchange, and Apple offers two places to accept: one of its own devices, or iCloud.com.
For someone whose reason for being here is not having an Apple device, that is a dead
end -- which is why this flow exists at all, for what is otherwise a small thing.

**Fetching and accepting are deliberately two calls.** The protocol hands back the terms
text, so there is no reason to accept on a user's behalf, and doing so would be agreeing
to a contract on their account without showing it to them. :func:`parse_buddyml` yields
the text and the URL that records agreement, and accepting takes what that produced. A
library cannot know whether a human read anything, but it can refuse to accept terms it
never fetched, and that is the strongest guarantee available here.

.. note::
    The response is **BuddyML**, an Apple XML dialect used by Setup Assistant -- not a
    property list, despite arriving from an endpoint whose every other response is one.
"""

from __future__ import annotations

import base64
import logging
import plistlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET

from typing_extensions import override

from findmy.errors import UnhandledProtocolError

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

TERMS_UI_URL = "https://setup.icloud.com/setup/iosbuddy/ui/genericTermsUI"

#: The terms document this project needs agreed. Named in the request and matched against
#: the `id` of the page that comes back.
ICLOUD_TERMS = "iCloud"

# §5.3. These endpoints are addressed as Settings would address them, so the bundle is
# Preferences rather than the `akd` of §3.2 -- the setup headers are a different set, not
# the delegate request's with additions.
_SETUP_CLIENT_INFO_BUNDLE = "com.apple.AppleAccount/1.0 (com.apple.Preferences/1112.96)"

# The root element's start tag, and so the end of the prolog: `<?xml`, `<!--` and
# `<!DOCTYPE` all begin `<?` or `<!`, and no element may appear before the root.
_ROOT_ELEMENT = re.compile(r"<[A-Za-z_]")


class TermsError(UnhandledProtocolError):
    """Raised when the terms of service cannot be fetched, read or accepted."""


@dataclass(frozen=True)
class Terms:
    """
    One terms document, as fetched. What :meth:`accept_terms` takes.

    Hold it, show :attr:`html` to the user, and hand this object back only if they agree.
    """

    #: Which document this is -- the `id` of its page, e.g. `iCloud`.
    page_id: str
    #: The URL that records agreement. Empty means this cannot be accepted.
    agree_url: str
    #: The terms themselves, as HTML, to be rendered and read.
    html: str

    @override
    def __repr__(self) -> str:
        """Describe this without printing the terms, which run to tens of kilobytes."""
        return (
            f"Terms(page_id={self.page_id!r}, agree_url={self.agree_url!r},"
            f" html=<{len(self.html)} characters>)"
        )


def require_fetched(terms: Terms) -> None:
    """
    Insist that these terms came from a fetch, before agreeing to them.

    The guarantee the two-call API exists for. Nothing can establish that a human read a
    contract, but agreeing to one this never obtained is refusable -- so terms with no
    text, or with nowhere to record agreement, are refused here rather than sent.

    :raises TermsError: If they were not fetched.
    """
    if terms.agree_url and terms.html:
        return

    msg = (
        "These terms carry no text or no URL to agree at, so they did not come from"
        " fetch_terms() and nothing here will accept them."
    )
    raise TermsError(msg)


def terms_request_body(names: Sequence[str]) -> bytes:
    """Build the plist body that asks for the named terms documents."""
    return plistlib.dumps(
        {
            "format": "plist/buddyml",
            "terms": [{"name": name} for name in names],
        },
    )


def setup_headers(client_info: str, apple_id: str, pet: str) -> dict[str, str]:
    """
    Build the setup headers of §5.3, which are *not* the delegate request's of §3.2.

    :param client_info: The client identity string, as `<model> <os> <bundle>`. The model
        and OS are kept and the bundle replaced, so these endpoints see the same device
        the rest of the client claims to be.
    :param apple_id: The Apple ID, as the HTTP Basic username.
    :param pet: A **fresh** password-equivalent token, as the Basic password. One lasts
        about five minutes, which is less time than reading a contract takes -- see
        :meth:`~findmy.reports.account.AsyncAppleAccount.accept_terms`.
    """
    groups = [part.split(">", 1)[0] for part in client_info.split("<") if ">" in part]
    prefix = "".join(f"<{part}> " for part in groups[:2])

    # `<iPhone OS;18.1;22B83>` -- the build is the last component, and the user-agent
    # wants it on its own.
    build = groups[1].split(";")[-1] if len(groups) > 1 else ""

    credential = base64.b64encode(f"{apple_id}:{pet}".encode()).decode()

    return {
        "Authorization": f"Basic {credential}",
        # Setup Assistant, matching the `iosbuddy` endpoint the delegate request uses.
        "User-Agent": f"iOS iPhone {build} iPhone Setup Assistant",
        "X-MMe-Client-Info": f"{prefix}<{_SETUP_CLIENT_INFO_BUNDLE}>",
        "X-MMe-Country": "US",
        "X-MMe-Language": "en,en-US",
        "Cookie": "repairSteps=",
    }


def parse_buddyml(document: str) -> list[Terms]:
    """
    Read a BuddyML terms document.

    :param document: The response body, as text. **XML, not a plist.**
    :returns: One :class:`Terms` per page in the document.
    :raises TermsError: If the document cannot be read, carries no URL to accept at, or
        yields no terms text at all.
    """
    _reject_doctype(document)

    try:
        # Safe by the check above: what makes an XML parser dangerous here is entity
        # expansion, which needs a document type declaration to declare the entities in.
        root = ET.fromstring(document)  # noqa: S314
    except ET.ParseError as e:
        msg = f"The terms response is not well-formed XML: {e}"
        raise TermsError(msg) from e

    client_info = root.find(".//clientInfo")
    agree_url = client_info.get("agreeUrl", "") if client_info is not None else ""
    if not agree_url:
        msg = (
            "The terms document carries no clientInfo agreeUrl, so there is nowhere to"
            " record agreement and nothing here can accept it."
        )
        raise TermsError(msg)

    terms = []
    for page in root.iter("page"):
        page_id = page.get("id", "")
        html = _character_data(page.find(".//html"))

        if not html:
            # The trap this whole function is shaped around: an XML reader that does not
            # treat CDATA as characters returns a blank page and raises nothing, so the
            # user is shown an empty contract to agree to.
            logger.warning("Terms page %r carries no text and will not be offered", page_id)
            continue

        terms.append(Terms(page_id=page_id, agree_url=agree_url, html=html))

    if not terms:
        msg = (
            "The terms document yielded no text at all. If it has pages, its character"
            " data is not being read -- the terms are usually inside CDATA."
        )
        raise TermsError(msg)

    return terms


def _reject_doctype(document: str) -> None:
    """
    Refuse a document that declares a document type, before it reaches the XML parser.

    Entity expansion is what makes parsing untrusted XML dangerous, and entities have to
    be declared in a `DOCTYPE` to be expanded. Only the prolog is examined: the terms
    themselves are HTML and may well open with `<!DOCTYPE html>`, which is inside the
    document rather than part of it.
    """
    root = _ROOT_ELEMENT.search(document)
    prolog = document[: root.start()] if root else document

    if "<!DOCTYPE" in prolog.upper():
        msg = "The terms response declares a document type, which nothing here will parse."
        raise TermsError(msg)


def _character_data(element: ET.Element | None) -> str:
    """
    Take an element's contents as text, whether they arrived as CDATA or as markup.

    Inside CDATA -- the usual case -- the whole of the HTML is character data and there
    are no child elements to walk. A document that escaped its markup instead parses as
    real elements, and those are serialised back rather than flattened, which would drop
    every tag and leave the terms unreadable in a subtler way than an empty page.
    """
    if element is None:
        return ""

    parts = [element.text or ""]
    parts.extend(ET.tostring(child, encoding="unicode") for child in element)

    return "".join(parts).strip()
