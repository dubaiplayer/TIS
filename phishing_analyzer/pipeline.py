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
from . import risk, trust
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


def analyze(text, sender=None, use_classifier=True, context=None):
    results = run_all(text, sender=sender, context=context)
    detail = _classifier_detail(text, use_classifier)
    prob = detail["prob"] if detail else None
    overall = risk.combine(results, prob)

    notes = []
    if prob is None and use_classifier:
        notes.append("classifier unavailable; rules-only score")
    if not sender:
        notes.append("no sender header; sender_domain spoof check skipped")

    # Sender-trust discount: if headers prove the mail is genuinely from its sender
    # (auth pass) and it is self-consistent, LOWER the risk so real bank/transactional
    # mail isn't flagged on shared wording. No-op without headers, so the original
    # rule/ML balance is untouched for body-only text.
    tr = trust.assess(text, sender, context, results, risk.load_weights())
    if tr and overall["risk_score"] > tr["cap"]:
        overall["risk_score"] = round(tr["cap"], 4)
        overall["verdict"] = risk.verdict_for(tr["cap"])
        overall["trust_adjusted"] = tr["tier"]
        if overall["verdict"] == "legitimate":
            overall["top_signals"] = []
        notes.append("sender-trust discount (" + tr["tier"] + "): "
                     + "; ".join(tr["reasons"]))

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


def _extract_context(msg):
    """Pull the header/HTML/attachment signals the newer attributes need
    (sender_auth, link_deception, attachment_risk). Best-effort; missing fields
    are None/empty so attributes degrade to 'unavailable' rather than crash."""
    def join(vals):
        return " | ".join(v for v in vals if v) if vals else None

    headers = {
        "from": msg.get("From"),
        "return_path": msg.get("Return-Path"),
        "reply_to": msg.get("Reply-To"),
        "authentication_results": join(msg.get_all("Authentication-Results")),
        "received_spf": join(msg.get_all("Received-SPF")),
        "dkim_signature": "present" if msg.get("DKIM-Signature") else None,
        "list_unsubscribe": msg.get("List-Unsubscribe"),
    }
    html_parts, attachments = [], []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for p in parts:
        if p.is_multipart():
            continue
        ctype = p.get_content_type()
        fname = p.get_filename()
        disp = (p.get("Content-Disposition") or "").lower()
        if fname or "attachment" in disp:
            attachments.append({"filename": fname or "", "content_type": ctype})
            continue
        if ctype == "text/html":
            payload = p.get_payload(decode=True)
            if payload:
                html_parts.append(payload.decode("utf-8", "replace"))
    return {"headers": headers, "html": "\n".join(html_parts), "attachments": attachments}


def analyze_raw(raw_email, use_classifier=True):
    """Parse a raw RFC822 email: recover sender + subject + body + context, then analyze."""
    # Parse as BYTES so 8-bit / no-transfer-encoding bodies keep their real
    # characters (zero-width, homoglyphs, non-ASCII) instead of being mangled into
    # literal \uXXXX escapes by the str payload round-trip.
    msg = (email.message_from_bytes(raw_email) if isinstance(raw_email, bytes)
           else email.message_from_bytes(raw_email.encode("utf-8", "replace")))
    sender = msg.get("From", "") or None
    subject = msg.get("Subject", "") or ""
    if msg.is_multipart():
        parts = [p.get_payload(decode=True) for p in msg.walk()
                 if p.get_content_type() == "text/plain" and not p.is_multipart()]
        body = "\n".join(p.decode("utf-8", "replace") for p in parts if p)
    else:
        payload = msg.get_payload(decode=True)
        body = payload.decode("utf-8", "replace") if payload else (msg.get_payload() or "")
    context = _extract_context(msg)
    if not body and context.get("html"):
        body = context["html"]
    text = build_text(subject, body)
    return analyze(text, sender=sender, use_classifier=use_classifier, context=context)
