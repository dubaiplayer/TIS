"""Email authentication & sender alignment.

The single highest-signal real-world phishing check that the lexical panel can't
see: whether the message passed SPF/DKIM/DMARC, and whether the visible `From`
lines up with `Return-Path` / `Reply-To`. Spoofed senders fail these.

We READ the results the receiving mail server already stamped into the headers
(Authentication-Results / Received-SPF) - no live DNS, so nothing blocks or slows
the request. When those headers are absent we fall back to From/Return-Path/
Reply-To domain alignment (works on any email). If there is nothing to check at
all, we return 'unavailable' so the combiner skips it (absence != innocence).

Needs `context["headers"]` from pipeline._extract_context.
"""
import re
from email.utils import parseaddr

from .base import band, AttributeResult

NAME = "sender_auth"

_RESULT = {"spf": re.compile(r"\bspf=(\w+)", re.IGNORECASE),
           "dkim": re.compile(r"\bdkim=(\w+)", re.IGNORECASE),
           "dmarc": re.compile(r"\bdmarc=(\w+)", re.IGNORECASE)}
_BAD = {"fail", "softfail", "permerror", "temperror", "none", "neutral"}
_HARD_BAD = {"fail", "softfail"}


def _domain(header_value):
    if not header_value:
        return ""
    _, addr = parseaddr(header_value)
    dom = addr.split("@")[-1].lower().strip(">").strip() if "@" in addr else ""
    return dom[4:] if dom.startswith("www.") else dom


def score(text, *, sender=None, context=None, **_):
    headers = (context or {}).get("headers") or {}
    auth_blob = " ".join(filter(None, [headers.get("authentication_results"),
                                       headers.get("received_spf")]))
    from_dom = _domain(headers.get("from") or sender)
    rp_dom = _domain(headers.get("return_path"))
    reply_dom = _domain(headers.get("reply_to"))

    have_auth = bool(auth_blob.strip())
    have_align = bool(from_dom and (rp_dom or reply_dom))
    if not have_auth and not have_align:
        return AttributeResult(NAME, 0.0, "unavailable sender_auth",
                               "no authentication headers and no Return-Path/Reply-To "
                               "to check alignment; sender-auth check skipped", [])

    hits, reasons = 0.0, []

    # 1) Authentication-Results / Received-SPF verdicts stamped by the receiver.
    for mech, rx in _RESULT.items():
        m = rx.search(auth_blob)
        if not m:
            continue
        verdict = m.group(1).lower()
        if verdict in _HARD_BAD:
            hits += 1.6 if mech == "dmarc" else 1.3
            reasons.append(f"{mech.upper()}={verdict}")
        elif verdict in _BAD:
            hits += 0.6
            reasons.append(f"{mech.upper()}={verdict}")

    # 2) Domain alignment (works even with no auth headers).
    if from_dom and rp_dom and from_dom != rp_dom:
        hits += 1.0
        reasons.append(f"From '{from_dom}' != Return-Path '{rp_dom}'")
    if from_dom and reply_dom and from_dom != reply_dom:
        hits += 1.1  # classic BEC: replies get redirected to the attacker
        reasons.append(f"From '{from_dom}' != Reply-To '{reply_dom}'")

    sc = 1.0 - 0.5 ** hits if hits else 0.0
    if reasons:
        expl = "authentication/alignment problems: " + "; ".join(reasons)
    else:
        expl = "sender authentication and alignment look consistent"
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} sender_auth", expl, [])
