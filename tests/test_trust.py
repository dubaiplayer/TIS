"""Sender-trust discount: genuine authenticated mail with phishing-shaped wording
should not be flagged, while spoofs and header-less body text are unchanged."""
from phishing_analyzer import pipeline

# Wording that (correctly) trips the lexical panel + classifier on its own.
BODY = ("Your account was suspended due to unusual activity. Verify your account "
        "immediately within 24 hours or it will be permanently blocked. Confirm "
        "your identity now.")

_AUTH = "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass header.from={d}\n"


def _verdict(raw):
    return pipeline.analyze_raw(raw)["overall"]["verdict"]


def test_genuine_authenticated_brand_is_not_phishing():
    raw = (f"From: Chase <no-reply@chase.com>\nSubject: Security alert\n"
           + _AUTH.format(d="chase.com")
           + "List-Unsubscribe: <https://chase.com/unsub>\n\n" + BODY)
    assert _verdict(raw) == "legitimate"


def test_authenticated_unsubscribe_clears_unlisted_domain():
    raw = (f"From: MyCU <alerts@mylocalcu.org>\nSubject: Security alert\n"
           + _AUTH.format(d="mylocalcu.org")
           + "List-Unsubscribe: <https://mylocalcu.org/unsub>\n\n" + BODY)
    assert _verdict(raw) == "legitimate"


def test_spoof_that_fails_dmarc_stays_phishing():
    raw = ("From: Chase <security@chase-secure-verify.com>\nSubject: Security alert\n"
           "Authentication-Results: mx; spf=softfail; dmarc=fail "
           "header.from=chase-secure-verify.com\n\n" + BODY)
    assert _verdict(raw) == "phishing"


def test_body_only_is_unchanged():
    # No headers -> no trust evidence -> the original rule/ML verdict must stand.
    assert _verdict(BODY) == "phishing"


def test_authenticated_unknown_domain_is_capped_at_suspicious_not_cleared():
    # Authenticated but no brand match and no List-Unsubscribe: an attacker can
    # authenticate their own throwaway domain, so this is softened, not cleared.
    raw = ("From: X <x@randomshop123.com>\nSubject: verify\n"
           + _AUTH.format(d="randomshop123.com") + "\n" + BODY)
    assert _verdict(raw) == "suspicious"
