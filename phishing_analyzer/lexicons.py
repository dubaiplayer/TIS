"""
Validated lexicons + regex resources for the rule-based attributes.

Terms here were seeded by hand, then VALIDATED against real phishing samples via
`scripts/validate_lexicons.py` (document-frequency lift on Track A train). This
file reflects the keep/prune/flag decisions from that report.

Three groups:
  LEXICON             -> validated terms (lift >= ~1.3, adequate support on this
                         corpus). Fire at full weight.
  CORPUS_LIMITATION   -> semantically valid real-world phishing cues that this
                         corpus CANNOT validate (too old / corporate-only):
                         gift-card & crypto scams, modern brand impersonation,
                         raw credential words. Retained for real-world input but
                         flagged so evaluation doesn't over-trust them here.

MATCHING CONTRACT (Step 3): match case-insensitively with WORD BOUNDARIES
(`\bterm\b`), NOT naive substring. Substring matching pollutes short tokens
(e.g. "irs" matched inside "first"). Casing itself is handled by `caps_tone`.
"""

# ---------------------------------------------------------------------------
# Validated on this corpus (strong lift + support).
# ---------------------------------------------------------------------------
LEXICON = {
    "urgency": [
        "urgent", "urgently", "immediately", "immediate attention",
        "act now", "without delay", "don't delay", "do not delay",
        "within 24 hours", "within 48 hours", "within 24hrs",
        "limited time", "last warning", "final warning",
    ],
    "fear_threat": [
        "suspended", "deactivated", "unusual activity", "suspicious activity",
        "security alert", "lock your account", "will be blocked",
        "account will be closed", "breach", "permanently",
    ],
    "reward": [
        "risk free", "beneficiary", "million dollars", "jackpot", "free gift",
        "100% free", "claim your", "you won", "you have won", "inheritance",
        "compensation", "lottery",
    ],
    "curiosity": [
        "someone sent you", "pending message", "held message", "undelivered",
        "you have a new message",
    ],
    "authority": [
        "barrister", "security team", "support team", "account team",
        "mail administrator", "bank", "paypal", "government", "webmail",
        "internal revenue",
    ],
    "financial": [
        "next of kin", "beneficiary", "deposit", "routing number",
        "western union", "swift code", "account details", "wire transfer",
        "bank transfer", "account number", "funds", "usd", "transaction",
        "payment", "invoice", "transfer of funds",
    ],
    "credential": [
        "verify your account", "verify your identity", "verify now",
        "confirm now", "update your account", "confirm your account",
        "confirm your identity", "validate your", "update your information",
        "update your details", "re-confirm", "reconfirm", "account information",
        "sign in",
    ],
    "generic_greeting": [
        "dear customer", "dear user", "dear member", "dear client",
        "dear sir", "dear madam", "dear sir/madam", "dear friend",
        "dear beneficiary", "dear account holder", "dear email user",
        "dear webmail user", "dear valued customer",
    ],
}

# ---------------------------------------------------------------------------
# Valid real-world cues this corpus can't validate (too old / corporate-only).
# Retained for real input; evaluation should not lean on them here.
# ---------------------------------------------------------------------------
CORPUS_LIMITATION = {
    # Modern payment-scam rails absent from a ~2000s corpus.
    "financial": ["gift card", "itunes card", "google play card", "bitcoin",
                  "cryptocurrency", "crypto wallet", "moneygram", "money gram",
                  "cash app", "zelle", "venmo"],
    # Brand impersonation: these appear in Enron IT mail legitimately, so lift is
    # low here, but they are prime phishing impersonation targets in the wild.
    "authority": ["microsoft", "apple", "amazon", "google", "netflix",
                  "office 365", "docusign", "irs", "social security administration"],
    # Raw credential nouns: normal in corporate IT mail (so weak lift here), but
    # still relevant. The imperative phrases in LEXICON['credential'] carry the
    # real signal; these are supporting evidence only.
    "credential": ["password", "username", "login", "log in", "ssn",
                   "social security", "pin number", "one-time password", "otp"],
}

# ---------------------------------------------------------------------------
# Link / URL heuristics (regex-driven; not lift-based).
# ---------------------------------------------------------------------------
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "tiny.cc", "shorturl.at", "rb.gy",
}
# TLDs disproportionately abused for phishing/spam.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "info", "biz", "ru", "cn",
    "su", "work", "click", "link", "zip", "country", "kim", "loan",
}
CLICK_CUES = ["click here", "click below", "click the link", "follow this link",
              "log in here", "sign in here", "click here to"]

# Free/webmail providers — used by sender_domain to flag "brand claimed in body
# but sent from a freemail address".
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "yandex.com", "protonmail.com", "gmx.com", "live.com",
    "yahoo.co.uk", "msn.com", "maktoob.com", "icloud.com",
}


def all_validated_terms():
    """Flat (category, term) pairs from the validated LEXICON."""
    return [(cat, term) for cat, terms in LEXICON.items() for term in terms]
