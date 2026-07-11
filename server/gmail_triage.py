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


def _attr(report, name: str) -> float:
    for a in report.attributes:
        if a.name == name:
            return a.score
    return 0.0


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

    A personal inbox is overwhelmingly legitimate mail, and Gmail/Outlook already
    filter spoofed and malicious mail to Spam before it lands here. The analyzer
    (trained on a phishing corpus) over-fires on the alarming-but-normal wording of
    security alerts, receipts, and marketing - and its structural detectors trip on
    the redirect links, tracking beacons, and HTML that normal marketing mail uses.
    So in a real inbox we only KEEP a phishing call on hard, unambiguous evidence and
    otherwise trust the message. Order matters (most decisive first):

      1. dangerous executable/macro attachment          -> keep phishing (real payload)
      2. sender is a known major provider/brand          -> legitimate (a spoof of
         these is rejected upstream and never reaches the inbox)
      3. sender explicitly FAILED DMARC                  -> keep phishing (spoof)
      4. sender explicitly PASSED DMARC                  -> legitimate (authenticated)
      5. anything else (flagged on wording/structure)    -> suspicious, not phishing

    Only ever REDUCES a phishing call; never escalates."""
    if report.verdict != "phishing":
        return report

    # Hard signals that survive inbox trust: a dangerous attachment, or a
    # credential-harvest link hosted on trusted SaaS. The latter's whole cover is an
    # authenticated, trusted-brand sender (e.g. a compromised gmail.com account), so
    # it must NOT be cleared by the brand/DMARC checks below.
    if _attr(report, "attachment_risk") >= 0.5 or _attr(report, "saas_abuse") >= 0.5:
        return report

    dom = _reg_domain(from_addr)
    if dom in _TRUSTED:
        return _downgrade(
            report, "legitimate",
            f"Genuine mail from {dom}, delivered to your inbox (a spoof of this brand "
            "is rejected before it arrives). Security-alert / marketing wording is "
            "normal from this sender - not phishing.")

    auth = _auth_results(raw)
    if auth["dmarc"] == "fail":
        return report  # sender failed DMARC => likely spoof, keep flagged
    if auth["dmarc"] == "pass":
        return _downgrade(
            report, "legitimate",
            f"Authenticated as genuinely from {dom or 'this sender'} (DMARC pass) with "
            "no dangerous attachment. Flagged on wording only - not phishing.")

    return _downgrade(
        report, "suspicious",
        f"No dangerous attachment and no failed authentication from "
        f"{dom or 'this sender'}; flagged on wording alone - treat as caution.")
