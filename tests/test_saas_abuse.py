"""SaaS-abuse detector: catch credential harvesters hosted on trusted platforms
(Google Forms, DocuSign, *.web.app, ...) without flagging genuine SaaS mail, and
close the trust.py hole that used to clear them."""
from phishing_analyzer import pipeline
from phishing_analyzer.attributes import saas_abuse

_AUTH = "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass header.from={d}\n"
_BODY = ("Please sign in to verify your account and confirm your identity to "
         "avoid suspension.")


def _analyze(raw):
    r = pipeline.analyze_raw(raw)
    sa = next(a["score"] for a in r["attributes"] if a["name"] == "saas_abuse")
    return r["overall"]["verdict"], sa


def test_headline_authenticated_google_form_harvester_is_not_cleared():
    # An authenticated gmail.com sender with a Google Forms credential link used to be
    # capped to "legitimate" by the sender-trust discount. It must not be anymore.
    raw = ("From: IT <it.support@gmail.com>\nSubject: Account verification required\n"
           + _AUTH.format(d="gmail.com") + "\n" + _BODY
           + " https://docs.google.com/forms/d/e/1FAIpQLxyz/viewform")
    verdict, sa = _analyze(raw)
    assert sa >= 0.5
    assert verdict != "legitimate"


def test_app_hosting_login_page_fires():
    raw = ("From: Support <no-reply@mailer123.com>\nSubject: Microsoft account\n"
           + _AUTH.format(d="mailer123.com")
           + "\nYour Microsoft login expired, please log in: "
           "https://ms-login-verify.web.app/auth")
    verdict, sa = _analyze(raw)
    assert sa >= 0.5
    assert verdict != "legitimate"


def test_genuine_doc_share_stays_silent():
    # A real Google Doc share with no login language must NOT fire.
    raw = ("From: Bob <bob@company.com>\nSubject: The deck\n"
           + _AUTH.format(d="company.com")
           + "\nHi, here is the deck for tomorrow: "
           "https://docs.google.com/document/d/1abc/edit  Thanks!")
    verdict, sa = _analyze(raw)
    assert sa == 0.0


def test_genuine_first_party_docusign_does_not_fire():
    # A real DocuSign envelope FROM docusign.net linking to docusign.net is the
    # service emailing about itself, not third-party abuse.
    raw = ("From: DocuSign <dse@docusign.net>\nSubject: Please review and sign\n"
           + _AUTH.format(d="docusign.net")
           + "\nYou have a new document to review and sign: "
           "https://na3.docusign.net/signing/abc")
    _, sa = _analyze(raw)
    assert sa == 0.0


def test_body_only_no_links_is_silent():
    _, sa = _analyze(_BODY)
    assert sa == 0.0


def test_no_saas_link_scores_zero_directly():
    r = saas_abuse.score("Click https://example.com/login to sign in",
                         sender="a@b.com", context={"headers": {"from": "a@b.com"}})
    assert r.score == 0.0
