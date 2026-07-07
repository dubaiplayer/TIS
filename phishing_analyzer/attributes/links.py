"""Suspicious links.

Extractable from this corpus: URL shorteners, abused TLDs, IP-literal hosts,
userinfo-'@' obfuscation, raw-URL count, click-cue phrases. NOT reliably
extractable: anchor-text-vs-href mismatch (HTML is pre-stripped) and live URL
reputation (out of scope). meta notes what was skipped.
"""
import re

from .base import saturating_score, band, Span, AttributeResult, build_matcher, find_spans
from ..lexicons import URL_SHORTENERS, SUSPICIOUS_TLDS, CLICK_CUES

NAME = "links"

_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'\)\]]+", re.IGNORECASE)
_IP_HOST = re.compile(r"^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)
_CLICK = build_matcher(CLICK_CUES)


def _host(url):
    u = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    return u.split("/")[0].split("?")[0].lower()


def score(text, **_):
    if not text:
        return AttributeResult(NAME, 0.0, "none links", "no text", [])

    urls = list(_URL.finditer(text))
    spans, hits, reasons = [], 0.0, []

    shorteners = tlds = iplits = userinfo = 0
    for m in urls:
        url = m.group(0)
        host = _host(url)
        flagged = False
        if any(host == s or host.endswith("." + s) for s in URL_SHORTENERS):
            shorteners += 1; flagged = True
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            tlds += 1; flagged = True
        if _IP_HOST.match(url):
            iplits += 1; flagged = True
        if "@" in url.split("//")[-1].split("/")[0]:
            userinfo += 1; flagged = True
        if flagged:
            spans.append(Span(url[:80], m.start(), m.start() + min(len(url), 80)).__dict__)

    if shorteners:
        hits += 1.0 + 0.3 * (shorteners - 1); reasons.append(f"{shorteners} shortener URL(s)")
    if tlds:
        hits += 1.0 + 0.3 * (tlds - 1); reasons.append(f"{tlds} suspicious-TLD URL(s)")
    if iplits:
        hits += 1.2 * iplits; reasons.append(f"{iplits} IP-literal URL(s)")
    if userinfo:
        hits += 1.2 * userinfo; reasons.append(f"{userinfo} '@'-obfuscated URL(s)")

    click_spans, click_seen = find_spans(text, _CLICK)
    if click_seen:
        hits += 0.5; reasons.append(f"{len(click_seen)} click-cue(s)")
        spans += [s.__dict__ for s in click_spans[:3]]

    if len(urls) >= 5:
        hits += 0.4; reasons.append(f"{len(urls)} total URLs")

    sc = saturating_score(hits)
    expl = ("; ".join(reasons) if reasons
            else (f"{len(urls)} URL(s), none flagged" if urls else "no URLs"))
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} links", expl, spans)
