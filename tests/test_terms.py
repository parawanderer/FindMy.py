"""
Tests for the terms-of-service flow of Stage 2 §5.2.

**No document here was captured from Apple.** Terms only arrive for an account that has
unaccepted ones, which is not a state to arrange deliberately, so every fixture below is
built from the specification's description of BuddyML rather than from a response. That
limits what they can prove: they check that this reader takes what §5.2 says to take from
the shape §5.2 describes, not that Apple's documents have that shape.

The one exception, and the reason these are worth writing at all, is the CDATA case. That
failure is silent -- an XML reader that does not treat CDATA as characters yields an empty
page, raises nothing, and offers the user a blank contract to agree to -- so a test that
would notice it is worth having even against a fixture, because what it pins down is this
reader's behaviour rather than Apple's.

**The live path is unexercised**, like the write paths: nothing here has fetched real
terms, accepted them, or seen which `localizedError` value announces them.
"""

from __future__ import annotations

import pytest

from findmy.errors import MobileMeDelegateError
from findmy.reports.terms import (
    Terms,
    TermsError,
    parse_buddyml,
    require_fetched,
    setup_headers,
    terms_request_body,
)

AGREE_URL = "https://setup.icloud.com/setup/iosbuddy/acceptTOS/iCloud"

# Markup inside the terms, so that a reader flattening it to plain text is distinguishable
# from one keeping it. Also an ampersand, which is only legal here because of the CDATA.
TERMS_HTML = "<h1>iCloud Terms</h1><p>Terms &amp; conditions apply.</p>"


def a_document(html: str = TERMS_HTML, *, cdata: bool = True, page_id: str = "iCloud") -> str:
    """Build a BuddyML document of the shape §5.2 describes."""
    body = f"<![CDATA[{html}]]>" if cdata else html

    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<buddyml>"
        f'<clientInfo agreeUrl="{AGREE_URL}"/>'
        f'<page id="{page_id}">'
        f"<html>{body}</html>"
        "</page>"
        "</buddyml>"
    )


# --------------------------------------------------------------------------------------
# Reading the document
# --------------------------------------------------------------------------------------


def test_the_terms_inside_cdata_arrive_whole() -> None:
    # The trap the whole reader is shaped around. A reader that does not treat CDATA as
    # character data returns "" here and raises nothing at all.
    (terms,) = parse_buddyml(a_document())

    assert terms.html == TERMS_HTML


def test_the_page_id_and_agree_url_come_from_where_the_spec_says() -> None:
    # The id is the page's, the URL is clientInfo's, and they are separate elements.
    (terms,) = parse_buddyml(a_document())

    assert terms.page_id == "iCloud"
    assert terms.agree_url == AGREE_URL


def test_markup_that_was_not_in_cdata_keeps_its_tags() -> None:
    # A document that escaped its markup instead of wrapping it parses as real elements.
    # Flattening those to their text would drop every tag -- the same blank-screen fault
    # as the CDATA one, only subtler, since something does come out.
    (terms,) = parse_buddyml(a_document(cdata=False))

    assert "<h1>" in terms.html
    assert "iCloud Terms" in terms.html


def test_every_page_is_returned() -> None:
    document = (
        "<buddyml>"
        f'<clientInfo agreeUrl="{AGREE_URL}"/>'
        '<page id="iCloud"><html><![CDATA[<p>one</p>]]></html></page>'
        '<page id="AppleMediaServices"><html><![CDATA[<p>two</p>]]></html></page>'
        "</buddyml>"
    )

    assert [t.page_id for t in parse_buddyml(document)] == ["iCloud", "AppleMediaServices"]


def test_a_page_with_no_text_is_dropped_rather_than_offered_blank() -> None:
    document = (
        "<buddyml>"
        f'<clientInfo agreeUrl="{AGREE_URL}"/>'
        '<page id="Empty"><html></html></page>'
        '<page id="iCloud"><html><![CDATA[<p>real</p>]]></html></page>'
        "</buddyml>"
    )

    assert [t.page_id for t in parse_buddyml(document)] == ["iCloud"]


def test_a_document_with_no_text_anywhere_fails_loudly() -> None:
    # What a CDATA regression would look like: every page blank, nothing raised. So the
    # reader raises instead, and says which reading is at fault.
    document = f'<buddyml><clientInfo agreeUrl="{AGREE_URL}"/><page id="iCloud"/></buddyml>'

    with pytest.raises(TermsError, match="CDATA"):
        parse_buddyml(document)


def test_no_agree_url_means_the_terms_cannot_be_accepted() -> None:
    document = "<buddyml><page id=\"iCloud\"><html><![CDATA[<p>x</p>]]></html></page></buddyml>"

    with pytest.raises(TermsError, match="agreeUrl"):
        parse_buddyml(document)


def test_a_plist_where_buddyml_belongs_is_reported_as_such() -> None:
    # These endpoints answer with plists everywhere else, so this is the mistake worth
    # having a legible failure for.
    with pytest.raises(TermsError):
        parse_buddyml("<plist><dict><key>status</key><integer>0</integer></dict></plist>")


def test_a_document_type_declaration_is_refused_before_parsing() -> None:
    bomb = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE buddyml [<!ENTITY a "aaaaaaaaaa">]>'
        f'<buddyml><clientInfo agreeUrl="{AGREE_URL}"/>'
        '<page id="iCloud"><html>&a;</html></page></buddyml>'
    )

    with pytest.raises(TermsError, match="document type"):
        parse_buddyml(bomb)


def test_a_doctype_inside_the_terms_is_not_mistaken_for_the_document_s() -> None:
    # The terms are HTML and may well open with one. Only the prolog is examined, so a
    # DOCTYPE in the payload must not refuse a perfectly ordinary document.
    (terms,) = parse_buddyml(a_document("<!DOCTYPE html><html><body>hi</body></html>"))

    assert terms.html.startswith("<!DOCTYPE html>")


# --------------------------------------------------------------------------------------
# Not accepting what was never fetched
# --------------------------------------------------------------------------------------


def test_accepting_terms_that_carry_no_text_is_refused() -> None:
    # The guarantee the two-call API exists for. Nothing can prove a human read the
    # terms, but agreeing to a contract this never obtained is refusable, and refused.
    with pytest.raises(TermsError, match="did not come"):
        require_fetched(Terms(page_id="iCloud", agree_url=AGREE_URL, html=""))


def test_accepting_terms_with_nowhere_to_agree_is_refused() -> None:
    with pytest.raises(TermsError, match="did not come"):
        require_fetched(Terms(page_id="iCloud", agree_url="", html=TERMS_HTML))


def test_accepting_what_a_fetch_returned_is_allowed() -> None:
    # The guard has to let the real case through, or it is only testing itself.
    (terms,) = parse_buddyml(a_document())

    require_fetched(terms)


def test_terms_do_not_print_themselves() -> None:
    # They run to tens of kilobytes, and a repr that dumps them makes every log holding
    # one unreadable.
    terms = Terms(page_id="iCloud", agree_url=AGREE_URL, html=TERMS_HTML)

    assert TERMS_HTML not in repr(terms)
    assert "iCloud" in repr(terms)


# --------------------------------------------------------------------------------------
# The request
# --------------------------------------------------------------------------------------


def test_the_request_asks_for_the_named_documents_in_buddyml() -> None:
    import plistlib

    body = plistlib.loads(terms_request_body(["iCloud"]))

    assert body == {"format": "plist/buddyml", "terms": [{"name": "iCloud"}]}


def test_the_setup_headers_keep_the_device_and_replace_the_bundle() -> None:
    # §5.3: these endpoints are addressed as Settings would, so the bundle is Preferences
    # -- but the model and OS stay whatever the rest of the client claims to be.
    headers = setup_headers(
        "<iPhone14,2> <iPhone OS;18.1;22B83> <com.apple.akd/1.0 (com.apple.akd/1.0)>",
        "someone@example.com",
        "the-pet",
    )

    assert headers["X-MMe-Client-Info"] == (
        "<iPhone14,2> <iPhone OS;18.1;22B83>"
        " <com.apple.AppleAccount/1.0 (com.apple.Preferences/1112.96)>"
    )


def test_the_setup_user_agent_carries_the_build() -> None:
    headers = setup_headers(
        "<iPhone14,2> <iPhone OS;18.1;22B83> <com.apple.akd/1.0 (com.apple.akd/1.0)>",
        "someone@example.com",
        "the-pet",
    )

    assert headers["User-Agent"] == "iOS iPhone 22B83 iPhone Setup Assistant"


def test_the_pet_is_the_basic_password_not_the_password() -> None:
    import base64

    headers = setup_headers("<M> <OS;1;B> <b>", "someone@example.com", "the-pet")

    scheme, credential = headers["Authorization"].split(" ", 1)
    assert scheme == "Basic"
    assert base64.b64decode(credential) == b"someone@example.com:the-pet"


# --------------------------------------------------------------------------------------
# Noticing that terms are why the login failed
# --------------------------------------------------------------------------------------


def test_the_delegate_error_reports_the_channel_a_reader_would_miss() -> None:
    # `localizedError` is separate from the two `status` fields a success is defined by,
    # and it is where a response explains itself. Both are reported verbatim.
    error = MobileMeDelegateError(
        localized_error="SOME_UNKNOWN_VALUE",
        description="Please review the iCloud Terms and Conditions.",
        status=1,
    )

    assert "SOME_UNKNOWN_VALUE" in str(error)
    assert "Please review the iCloud Terms and Conditions." in str(error)


def test_the_delegate_error_offers_the_terms_flow_without_guessing_at_it() -> None:
    # Which value means "terms pending" is unestablished, so the remedy is offered rather
    # than triggered, and the value is flagged as worth reporting.
    error = MobileMeDelegateError(localized_error="SOME_UNKNOWN_VALUE", status=1)

    assert "fetch_terms()" in str(error)
    assert "not yet known" in str(error)


def test_an_unauthorized_delegate_response_is_not_offered_the_terms_flow() -> None:
    # A known value on the same channel, and a different problem: an expired PET.
    error = MobileMeDelegateError(localized_error="UNAUTHORIZED", status=1)

    assert error.is_unauthorized
    assert "fetch_terms()" not in str(error)
    assert "expired PET" in str(error)


def test_a_failure_that_says_nothing_still_says_that() -> None:
    error = MobileMeDelegateError()

    assert "nothing about why" in str(error)
