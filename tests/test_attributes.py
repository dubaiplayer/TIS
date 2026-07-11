"""
Crafted positive/negative cases per attribute. These lock in behavior so each
module can be tuned independently without regressions. Run:

    .venv/Scripts/python.exe -m pytest -q
"""
from phishing_analyzer.attributes import (
    urgency, fear_threat, reward, curiosity, authority, financial,
    credential, generic_greeting, sender_domain, links, grammar, caps_tone,
    sender_auth, link_deception, obfuscation, attachment_risk, ATTRIBUTE_NAMES,
)
from phishing_analyzer import pipeline


def _s(fn, text, **kw):
    return fn(text, **kw).score


# --- lexical attributes: positive fires, benign corporate text stays silent ---

BENIGN = ("Hi John, attached is the quarterly gas nomination report for review. "
          "Let me know if the volumes look right before the meeting on Thursday. Thanks, Dave")


def test_urgency():
    assert _s(urgency.score, "Please act now — respond within 24 hours, do not delay.") > 0.4
    assert _s(urgency.score, BENIGN) == 0.0


def test_fear_threat():
    assert _s(fear_threat.score, "Your account was suspended due to unusual activity.") > 0.4
    assert _s(fear_threat.score, BENIGN) == 0.0


def test_reward():
    hi = _s(reward.score, "You won the lottery! Claim your one million dollars now.")
    assert hi > 0.6
    assert _s(reward.score, BENIGN) == 0.0


def test_curiosity():
    assert _s(curiosity.score, "You have a new message; a pending message is held.") > 0.0
    assert _s(curiosity.score, BENIGN) == 0.0


def test_authority():
    assert _s(authority.score, "This is the IT security team at your bank.") > 0.4
    assert _s(authority.score, BENIGN) == 0.0


def test_financial():
    hi = _s(financial.score, "Complete the wire transfer of funds; beneficiary next of "
                             "kin. Amount: $4,500,000 to account number 12345.")
    assert hi > 0.7
    assert _s(financial.score, BENIGN) == 0.0


def test_credential():
    assert _s(credential.score, "Verify your account and confirm your identity — sign in here.") > 0.6
    assert _s(credential.score, BENIGN) == 0.0


def test_generic_greeting():
    assert _s(generic_greeting.score, "Dear Customer, we need your attention.") > 0.0
    assert _s(generic_greeting.score, "Hi John, see attached.") == 0.0


# --- non-lexical attributes ---

def test_sender_domain_brand_from_freemail():
    r = sender_domain.score("body", sender="PayPal Support <security-alert@gmail.com>")
    assert r.score > 0.4
    ok = sender_domain.score("body", sender="Dave Allen <dave.allen@enron.com>")
    assert ok.score == 0.0


def test_sender_domain_lookalike():
    r = sender_domain.score("body", sender="Service <help@paypa1.com>")
    assert r.score > 0.4


def test_sender_domain_unavailable():
    r = sender_domain.score("body", sender=None)
    assert r.score == 0.0 and r.label.startswith("unavailable")


def test_links():
    hi = _s(links.score, "Click here http://bit.ly/x9 or verify at http://192.168.1.1/login")
    assert hi > 0.4
    assert _s(links.score, "See our report at https://www.enron.com/investors") == 0.0


def test_grammar_relative():
    # Both are email-length (>20 checkable words); only the second is misspelled.
    clean = _s(grammar.score,
               "please review the attached quarterly document and reply with your comments "
               "before the meeting tomorrow afternoon so we can finalize the budget numbers "
               "and send the summary to the wider team next week thanks again for the help")
    bad = _s(grammar.score,
             "pls kindly recieve teh atached documnt and confrim yuor acount informations "
             "imediately to aviod the supension of your servce becuse our secrity departmnt "
             "detcted unusal activty and you must verifie yuor detals now befor its to late")
    assert bad > clean


def test_caps_tone():
    hi = _s(caps_tone.score, "ACT NOW!!! FINAL WARNING — VERIFY YOUR ACCOUNT IMMEDIATELY!!!")
    assert hi > 0.4
    assert _s(caps_tone.score, BENIGN) < 0.2


# --- pipeline integration (rules-only, deterministic) ---

def test_pipeline_ranks_phish_above_legit():
    phish = pipeline.analyze(
        "Dear Customer, URGENT!!! Your account was suspended. Verify your account now: "
        "http://bit.ly/scam. Wire transfer of funds to beneficiary required.",
        sender="Bank Security <alert@gmail.com>", use_classifier=False)
    legit = pipeline.analyze(BENIGN, sender="Dave Allen <dave.allen@enron.com>",
                             use_classifier=False)
    assert phish["overall"]["risk_score"] > legit["overall"]["risk_score"]
    assert phish["overall"]["verdict"] in ("phishing", "suspicious")
    assert legit["overall"]["verdict"] == "legitimate"
    # structure sanity
    assert len(phish["attributes"]) == len(ATTRIBUTE_NAMES)
    assert all({"name", "score", "label", "explanation", "evidence_spans"} <= a.keys()
               for a in phish["attributes"])


# --- real-world detectors (need the email context) ---

def test_sender_auth_fail_and_misalign():
    bad = {"headers": {"from": "PayPal <svc@paypal-support.com>",
                       "reply_to": "attacker@evil.ru", "return_path": "<b@evil.ru>",
                       "authentication_results": "mx; spf=fail; dkim=fail; dmarc=fail",
                       "received_spf": None, "dkim_signature": None}}
    assert sender_auth.score("body", context=bad).score > 0.6
    ok = {"headers": {"from": "Jane <jane@northwind.com>",
                      "return_path": "<jane@northwind.com>", "reply_to": None,
                      "authentication_results": "mx; spf=pass; dkim=pass; dmarc=pass",
                      "received_spf": None, "dkim_signature": "present"}}
    assert sender_auth.score("body", context=ok).score == 0.0


def test_sender_auth_unavailable():
    r = sender_auth.score("body", context=None)
    assert r.score == 0.0 and r.label.startswith("unavailable")


def test_link_deception_anchor_mismatch():
    bad = '<a href="http://secure-login.ru/x">sign in to paypal.com</a>'
    assert link_deception.score("", context={"html": bad}).score > 0.4
    clean = '<a href="https://www.paypal.com/login">sign in to paypal.com</a>'
    assert link_deception.score("", context={"html": clean}).score == 0.0


def test_link_deception_punycode_in_text():
    assert link_deception.score("verify at http://xn--pple-43d.com/go", context=None).score > 0.0
    assert link_deception.score("see https://www.enron.com/investors", context=None).score == 0.0


def test_obfuscation_zero_width_and_homoglyph():
    zwsp, cyr = "​", "а"
    assert obfuscation.score(f"please ver{zwsp}ify now").score > 0.0
    assert obfuscation.score(f"conf{cyr}rm your identity").score > 0.0
    assert obfuscation.score("please verify your account normally").score == 0.0


def test_attachment_risk():
    bad = {"attachments": [{"filename": "invoice.pdf.exe", "content_type": "application/octet-stream"}]}
    assert attachment_risk.score("body", context=bad).score > 0.5
    ok = {"attachments": [{"filename": "report.pdf", "content_type": "application/pdf"}]}
    assert attachment_risk.score("body", context=ok).score == 0.0
    assert attachment_risk.score("body", context=None).label.startswith("unavailable")
