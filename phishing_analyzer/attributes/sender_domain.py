"""Sender-domain mismatch / spoofing.

Rule-based, and only meaningful when a `sender` header is present (CEAS, Nazario,
Nigerian, SpamAssassin — absent in Enron_raw/Ling). When absent, returns score 0
with an explicit "unavailable" note so downstream can flag it rather than treat
absence as innocence.

Signals:
  - brand named in display-name but sent from a freemail address
  - display-name claims an org (Inc/Bank/Support/Team...) from freemail
  - lookalike domain: near-miss (edit distance 1-2) to a known brand domain
  - display-name itself contains a different email address (classic spoof)
"""
import re
from email.utils import parseaddr

from .base import band, Span, AttributeResult
from ..lexicons import FREEMAIL_DOMAINS

NAME = "sender_domain"

_BRANDS = {"paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
           "amazon": "amazon.com", "google": "google.com", "netflix": "netflix.com",
           "facebook": "facebook.com", "ebay": "ebay.com", "chase": "chase.com",
           "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com",
           "irs": "irs.gov", "dhl": "dhl.com", "fedex": "fedex.com"}
_ORG_WORDS = re.compile(r"\b(inc|ltd|llc|bank|support|team|service|services|security|"
                        r"help\s?desk|department|dept|admin|administrator|official)\b",
                        re.IGNORECASE)


def _levenshtein(a, b, cap=3):
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def score(text, sender=None, **_):
    if not sender:
        return AttributeResult(NAME, 0.0, "unavailable sender_domain",
                               "sender header not available; spoof check skipped", [])

    name, addr = parseaddr(sender)
    domain = addr.split("@")[-1].lower() if "@" in addr else ""
    reg = domain[4:] if domain.startswith("www.") else domain
    hits, reasons = 0.0, []
    name_l = (name or "").lower()

    # Brand in display name but freemail / non-brand domain.
    for brand, bdomain in _BRANDS.items():
        if re.search(rf"(?<!\w){re.escape(brand)}(?!\w)", name_l):
            if reg in FREEMAIL_DOMAINS or (bdomain not in reg and reg):
                hits += 1.4
                reasons.append(f"display-name claims '{brand}' but domain is '{reg or '?'}'")
            break

    # Org-sounding display name from a freemail address.
    if reg in FREEMAIL_DOMAINS and _ORG_WORDS.search(name_l):
        hits += 1.0
        reasons.append(f"organizational display-name from freemail '{reg}'")

    # Lookalike domain: near-miss to a known brand domain.
    for bdomain in set(_BRANDS.values()):
        if reg and reg != bdomain and _levenshtein(reg, bdomain, 2) <= 2:
            hits += 1.5
            reasons.append(f"lookalike domain '{reg}' ~ '{bdomain}'")
            break

    # Display name contains a second, different email address.
    m = re.search(r"[\w.+-]+@[\w.-]+\.\w+", name or "")
    if m and m.group(0).lower() != addr.lower():
        hits += 1.2
        reasons.append("display-name embeds a different email address")

    sc = 1.0 - 0.5 ** hits if hits else 0.0
    spans = [Span(sender[:120], 0, min(len(sender), 120)).__dict__] if hits else []
    expl = "; ".join(reasons) if reasons else f"sender '{addr}' — no mismatch detected"
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} sender_domain", expl, spans)
