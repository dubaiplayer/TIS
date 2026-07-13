"""
Sender-trust discount - cut false positives on GENUINE mail whose wording overlaps
with phishing (bank alerts, receipts, security notices, shipping updates).

The lexical panel and the classifier fire on words like "verify your account" or
"suspicious activity" - but those words are identical in a real bank email and a
spoof of it, so no amount of text tuning separates them. This module leans on the
signals that DO differ, all read from headers already in the pasted email:

  * sender authentication (SPF / DKIM / DMARC = pass) - proves the message really
    came from its From domain; a spoof of a brand fails these;
  * self-consistency - no link deception, obfuscation, or dangerous attachment
    (link_deception already catches lookalikes / anchor-vs-href mismatch);
  * a legitimacy marker - a known brand/bank domain, or a List-Unsubscribe header,
    which genuine bulk/transactional mail carries and phishing usually omits.

It ONLY LOWERS risk, and only with positive evidence. With no auth headers it
returns None and nothing changes - so pasted body-only text scores exactly as
before and the original rule/ML balance is untouched.

Two tiers (an attacker can authenticate their OWN throwaway domain, so authentication
alone is not a clean bill of health):
  * authenticated + consistent + (trusted brand OR List-Unsubscribe) -> cap into
    'legitimate' (the real-bank case);
  * authenticated + consistent, but an unknown domain -> cap into 'suspicious'
    (no longer 'phishing', but still flagged).
"""
import re
from email.utils import parseaddr

try:  # offline registered-domain extraction; never hits the network
    import tldextract
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

    def _regdom(host):
        r = _EXTRACT(host or "")
        return (getattr(r, "top_domain_under_public_suffix", "")
                or getattr(r, "registered_domain", "")).lower()
except Exception:  # pragma: no cover - naive fallback
    def _regdom(host):
        parts = (host or "").lower().strip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "").lower()

_DMARC = re.compile(r"\bdmarc=(\w+)", re.IGNORECASE)
_SPF = re.compile(r"\bspf=(\w+)", re.IGNORECASE)
_DKIM = re.compile(r"\bdkim=(\w+)", re.IGNORECASE)

# Structural attack signals that override any trust from authentication - including
# saas_abuse, so an authenticated sender carrying a credential-harvest link hosted on
# trusted SaaS (Google Forms / DocuSign / *.web.app) is no longer cleared.
_ATTACK = ("link_deception", "obfuscation", "attachment_risk", "html_attack",
           "saas_abuse")

# Known brands/banks whose authenticated mail should read as legitimate even with
# alarming wording. Registered domains. Extend freely - it only ever helps.
_TRUSTED = {
    # banks / payments
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com",
    "capitalone.com", "usbank.com", "pnc.com", "tdbank.com", "td.com", "ally.com",
    "discover.com", "americanexpress.com", "aexp.com", "hsbc.com", "barclays.com",
    "santander.com", "schwab.com", "fidelity.com", "vanguard.com", "paypal.com",
    "venmo.com", "stripe.com", "wise.com", "intuit.com", "coinbase.com",
    "rbc.com", "scotiabank.com", "bmo.com", "cibc.com", "natwest.com", "lloyds.com",
    # major providers / brands (their SERVICE domains, not consumer freemail - see
    # _FREEMAIL below; gmail.com/outlook.com are deliberately NOT here)
    "google.com", "microsoft.com", "office365.com",
    "apple.com", "amazon.com", "github.com", "linkedin.com",
    "dropbox.com", "slack.com", "zoom.us", "netflix.com", "adobe.com", "docusign.net",
    "atlassian.com", "atlassian.net", "salesforce.com", "notion.so", "figma.com",
    "ups.com", "fedex.com", "usps.com", "dhl.com",
}

# Consumer / freemail providers. Authentication from one of these only proves the
# sender is a real USER of that provider - NOT a trusted organization. Anyone can send
# authenticated phishing from their own account, and these domains are also decades old
# (so the domain-age check would wrongly clear them too). => NEVER apply the trust
# discount to a freemail sender; let the normal analysis judge it on its merits.
_FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk",
    "live.com", "msn.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "rocketmail.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com",
    "pm.me", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru",
    "fastmail.com", "hey.com", "tutanota.com", "qq.com", "163.com", "126.com",
}


def _addr_dom(header_value):
    _, addr = parseaddr(header_value or "")
    host = addr.split("@")[-1].lower().strip(">").strip() if "@" in addr else ""
    return _regdom(host)


def _attr(results, name):
    for r in results:
        if r.name == name:
            return r.score
    return 0.0


def _domain_age_days_safe(domain):
    """Registration age in days via RDAP, or None on any failure/timeout. Lazily
    imported so the offline core never hard-depends on the network path."""
    if not domain:
        return None
    try:
        from .link_xray import _domain_age_days
        return _domain_age_days(domain)
    except Exception:
        return None


def assess(text, sender, context, attribute_results, cfg):
    """Return {cap, tier, reasons} to discount risk, or None to leave it unchanged."""
    conf = (cfg or {}).get("sender_trust") or {}
    if not conf.get("enabled", True):
        return None
    headers = (context or {}).get("headers") or {}
    auth_blob = " ".join(filter(None, [headers.get("authentication_results"),
                                       headers.get("received_spf")]))
    if not auth_blob.strip():
        return None  # no auth headers -> can't establish trust -> behave as before

    def verdict(rx):
        m = rx.search(auth_blob)
        return m.group(1).lower() if m else None

    dmarc, spf, dkim = verdict(_DMARC), verdict(_SPF), verdict(_DKIM)
    authenticated = (dmarc == "pass") or (spf == "pass" and dkim == "pass")
    if not authenticated:
        return None  # failed / unproven auth -> no trust discount

    if any(_attr(attribute_results, n) >= 0.5 for n in _ATTACK):
        return None  # a real lookalike / attachment / obfuscation overrides trust

    passed = ", ".join(f"{k}=pass" for k, v in
                       (("DMARC", dmarc), ("SPF", spf), ("DKIM", dkim)) if v == "pass")
    reasons = [f"sender authenticated ({passed})",
               "no link/attachment/obfuscation trickery"]

    from_dom = _addr_dom(headers.get("from") or sender)
    if from_dom in _FREEMAIL:
        return None  # authenticated freemail = a real user, not a trusted org -> no discount
    trusted = from_dom in _TRUSTED
    has_unsub = bool(headers.get("list_unsubscribe"))
    if trusted:
        reasons.append(f"{from_dom} is a known brand/bank")
    if has_unsub:
        reasons.append("carries List-Unsubscribe (genuine bulk/transactional mail)")

    legit = float(conf.get("legitimate_cap", 0.2))
    if trusted or has_unsub:
        return {"cap": legit, "tier": "trusted", "reasons": reasons}

    # Established-domain trust: an authenticated, self-consistent email from a domain
    # registered years ago is a real organization (a bank, SaaS, employer) - genuine
    # verification/security/billing mail. Phishing uses freshly-registered domains or
    # fails auth, so this clears real companies without maintaining an allowlist.
    if conf.get("use_domain_age", True):
        min_age = int(conf.get("min_domain_age_days", 365))
        age = _domain_age_days_safe(from_dom)
        if age is not None and age >= min_age:
            yrs = age / 365.0
            reasons.append(f"{from_dom} is a well-established domain "
                           f"(registered ~{yrs:.0f} year(s) ago)")
            return {"cap": legit, "tier": "established", "reasons": reasons}

    reasons.append("unknown, unestablished sender domain, so capped at 'suspicious'")
    return {"cap": float(conf.get("suspicious_cap", 0.5)),
            "tier": "authenticated", "reasons": reasons}
