"""
Gmail/Outlook INBOX-ONLY false-positive guard.

Legitimate mail from big providers (e.g. a real Google security alert) uses the
exact vocabulary phishing does - "verify", "suspicious activity", "your account
was suspended", "action required" - so the lexical + ML signals light up and the
message gets miscalled phishing. The real-world discriminator is *sender
authentication*: a genuine google.com message passes DMARC aligned to google.com,
while a spoof does not. Mailboxes hand us the `Authentication-Results` header their
own server (Gmail/Outlook) stamped on receipt, so we can read that verdict directly.

This adjustment is applied ONLY to the real-inbox path (`source in {gmail, outlook}`).
The paste-in `/analyze` endpoint and the synthetic sims never call it, so their
behaviour and the ML/rule balance are completely unchanged.

It only ever REDUCES a false "phishing" call; it never escalates anything.
"""
import email as _email
import re

import tldextract

# Major senders whose *authenticated* mail must not be called phishing on wording
# alone (registrable domains). A spoof of these fails DMARC and is unaffected.
_TRUSTED = {
    "google.com", "gmail.com", "googlemail.com", "youtube.com", "microsoft.com",
    "outlook.com", "office365.com", "office.com", "live.com", "microsoftonline.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "paypal.com",
    "github.com", "gitlab.com", "linkedin.com", "facebook.com", "facebookmail.com",
    "instagram.com", "meta.com", "x.com", "twitter.com", "dropbox.com", "slack.com",
    "zoom.us", "netflix.com", "spotify.com", "adobe.com", "atlassian.com",
    "notion.so", "stripe.com", "docusign.net", "salesforce.com", "intuit.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com",
    "americanexpress.com", "capitalone.com", "discover.com", "usbank.com",
}

# Unambiguously malicious mechanics that never appear in legitimate mail - if either
# fires the message stays phishing no matter what authentication says. (Link/HTML
# checks are deliberately NOT here: legit marketing mail routinely uses redirect
# links and tracking beacons, which trip them and caused the false positives.)
_HARD_MALICIOUS = {"obfuscation", "attachment_risk"}

_ACTION = {"legitimate": "allow", "suspicious": "warn"}


def _reg_domain(addr: str) -> str:
    m = re.search(r"[\w.+-]+@([\w.-]+)", addr or "")
    host = (m.group(1) if m else "").lower().strip(".")
    ext = tldextract.extract(host)
    return ".".join(p for p in (ext.domain, ext.suffix) if p)


def _auth_results(raw: str) -> dict:
    """Read the pass/fail the receiving server recorded in Authentication-Results."""
    msg = _email.message_from_string(raw)
    blob = " ".join(msg.get_all("Authentication-Results", [])
                    + msg.get_all("ARC-Authentication-Results", [])).lower()

    def status(mech):
        m = re.search(mech + r"=(\w+)", blob)
        return m.group(1) if m else None

    return {"present": bool(blob), "spf": status("spf"),
            "dkim": status("dkim"), "dmarc": status("dmarc")}


def _hard_malicious(report) -> bool:
    return any(a.name in _HARD_MALICIOUS and a.score >= 0.5 for a in report.attributes)


def _downgrade(report, verdict: str, why: str):
    risk = 0.15 if verdict == "legitimate" else 0.45
    notes = list(report.meta.notes)
    notes.append("Inbox trust adjustment: " + why)
    return report.model_copy(update={
        "verdict": verdict,
        "risk_score": risk,
        "action": _ACTION[verdict],
        "recommendation": why,
        "summary": why,
        "meta": report.meta.model_copy(update={"notes": notes}),
    })


def adjust(report, raw: str, from_addr: str):
    """Return a possibly-downgraded copy of a report for a REAL inbox message.

    A real inbox is mostly legitimate mail, and the analyzer (trained on a phishing
    corpus) over-fires on the alarming-but-normal wording of security alerts,
    receipts, and marketing. So in the inbox we call something phishing ONLY on
    concrete evidence, not wording:
      * unambiguously malicious mechanics (hidden/homoglyph text, dangerous
        attachment) -> always phishing;
      * the sender failed authentication (DMARC/SPF fail) -> spoof, phishing;
      * otherwise, if the message is authenticated (DMARC pass) it genuinely came
        from its sender -> legitimate;
      * with no authentication signal at all, downgrade to suspicious rather than
        screaming phishing on wording alone.
    Only ever REDUCES a phishing call; never escalates."""
    if report.verdict != "phishing":
        return report
    if _hard_malicious(report):
        return report  # hidden-char / homoglyph / dangerous attachment - keep flagged

    auth = _auth_results(raw)
    if auth["dmarc"] == "fail" or auth["spf"] == "fail":
        return report  # sender failed authentication => likely spoof, keep flagged

    dom = _reg_domain(from_addr)
    if auth["dmarc"] == "pass":
        if dom in _TRUSTED:
            why = (f"Authenticated mail genuinely from {dom} (DMARC pass). "
                   "Security-alert wording is normal from this sender - not phishing.")
        else:
            why = (f"Authenticated as genuinely from {dom} (DMARC pass) with no "
                   "malicious attachment or hidden-text tricks. Flagged on wording "
                   "only - not phishing.")
        return _downgrade(report, "legitimate", why)

    return _downgrade(
        report, "suspicious",
        f"No failed authentication, dangerous attachment, or hidden-text tricks "
        f"from {dom or 'this sender'}; flagged on wording only - treat as caution.")
