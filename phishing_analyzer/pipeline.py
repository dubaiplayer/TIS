"""
End-to-end analysis: raw email (or plain text) -> structured breakdown.

analyze(text, sender) runs the 12-attribute panel + the content classifier and
combines them into the overall risk verdict. analyze_raw(raw_email) additionally
splits RFC822 headers to recover the sender and body first.

The JSON schema + CLI presentation come in Step 5; this returns plain dicts.
"""
import email
import re

from .attributes import run_all
from . import risk
from .text_clean import build_text

_clf = None


def _classifier_detail(text, use_classifier):
    """Return {prob, phishing_terms, legit_terms, char_contribution} or None."""
    global _clf
    if not use_classifier:
        return None
    try:
        if _clf is None:
            from .classifier import PhishClassifier
            _clf = PhishClassifier()
        return _clf.explain(text)
    except Exception:
        # Missing OR corrupt/incompatible model -> degrade to rules-only, don't crash.
        return None


def _term_spans(term, text, limit=6):
    spans = []
    for m in re.finditer(rf"(?<!\w){re.escape(term)}(?!\w)", text, re.IGNORECASE):
        spans.append({"text": m.group(0), "start": m.start(), "end": m.end()})
        if len(spans) >= limit:
            break
    return spans


def _keyword_attributions(detail, text):
    """Turn signed word contributions into UI-ready records: direction, a 0..1
    intensity for sizing, and character spans for inline highlighting."""
    terms = detail["phishing_terms"] + detail["legit_terms"]
    max_abs = max((abs(w) for _, w in terms), default=1.0) or 1.0
    out = []
    for group, direction in ((detail["phishing_terms"], "phishing"),
                             (detail["legit_terms"], "legitimate")):
        for term, w in group:
            out.append({"term": term, "weight": round(w, 4), "direction": direction,
                        "intensity": round(abs(w) / max_abs, 4),
                        "spans": _term_spans(term, text)})
    return out


def analyze(text, sender=None, use_classifier=True):
    results = run_all(text, sender=sender)
    detail = _classifier_detail(text, use_classifier)
    prob = detail["prob"] if detail else None
    overall = risk.combine(results, prob)

    notes = []
    if prob is None and use_classifier:
        notes.append("classifier unavailable; rules-only score")
    if not sender:
        notes.append("no sender header; sender_domain spoof check skipped")

    classifier = {"phishing_probability": prob, "keyword_attributions": []}
    if detail:
        classifier["keyword_attributions"] = _keyword_attributions(detail, text)
        classifier["char_ngram_contribution"] = round(detail["char_contribution"], 4)

    return {
        "overall": overall,
        "attributes": [r.to_dict() for r in results],
        "classifier": classifier,
        "meta": {"sender_analyzed": bool(sender), "notes": notes},
        "analyzed_text": text,
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
