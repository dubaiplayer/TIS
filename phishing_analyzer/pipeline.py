"""
End-to-end analysis: raw email (or plain text) -> structured breakdown.

analyze(text, sender) runs the 12-attribute panel + the content classifier and
combines them into the overall risk verdict. analyze_raw(raw_email) additionally
splits RFC822 headers to recover the sender and body first.

The JSON schema + CLI presentation come in Step 5; this returns plain dicts.
"""
import email

from .attributes import run_all
from . import risk
from .text_clean import build_text

_clf = None


def _classifier_prob(text, use_classifier):
    global _clf
    if not use_classifier:
        return None
    try:
        if _clf is None:
            from .classifier import PhishClassifier
            _clf = PhishClassifier()
        return _clf.proba(text)
    except FileNotFoundError:
        return None            # model not trained yet -> rules-only


def analyze(text, sender=None, use_classifier=True):
    results = run_all(text, sender=sender)
    prob = _classifier_prob(text, use_classifier)
    overall = risk.combine(results, prob)

    notes = []
    if prob is None and use_classifier:
        notes.append("classifier model not found; rules-only score")
    if not sender:
        notes.append("no sender header; sender_domain spoof check skipped")

    return {
        "overall": overall,
        "attributes": [r.to_dict() for r in results],
        "meta": {"sender_analyzed": bool(sender), "notes": notes},
    }


def analyze_raw(raw_email, use_classifier=True):
    """Parse a raw RFC822 email: recover sender + subject + body, then analyze."""
    msg = email.message_from_string(raw_email)
    sender = msg.get("From", "") or None
    subject = msg.get("Subject", "") or ""
    if msg.is_multipart():
        parts = [p.get_payload(decode=True) for p in msg.walk()
                 if p.get_content_type() == "text/plain" and not p.is_multipart()]
        body = "\n".join(p.decode("utf-8", "replace") for p in parts if p)
    else:
        payload = msg.get_payload(decode=True)
        body = payload.decode("utf-8", "replace") if payload else (msg.get_payload() or "")
    text = build_text(subject, body)
    return analyze(text, sender=sender, use_classifier=use_classifier)
