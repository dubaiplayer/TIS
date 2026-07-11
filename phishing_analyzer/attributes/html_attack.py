"""HTML attack mechanics: credential-harvest forms and tracking beacons.

Uses the raw HTML (not just the visible text) to catch the actual phishing
machinery: a login/password <form> embedded in the email that posts to an
off-domain URL (a credential-harvest page delivered inside the message), and
remote tracking pixels that silently confirm the recipient's address is live.

Needs `context["html"]`. A password field or an external form action is an
unambiguous phishing tell; tracking pixels are a weak supporting signal (some
legitimate marketing mail uses them), so they contribute little on their own.
"""
from bs4 import BeautifulSoup

from .base import saturating_score, band, AttributeResult
from .link_deception import _host, _registered

NAME = "html_attack"


def score(text, *, sender=None, context=None, **_):
    html = (context or {}).get("html") or ""
    if not html:
        return AttributeResult(NAME, 0.0, "unavailable html_attack",
                               "no HTML body to inspect", [])
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return AttributeResult(NAME, 0.0, "none html_attack", "HTML unparseable", [])

    hits, reasons = 0.0, []

    pw = soup.find_all("input", attrs={"type": lambda v: v and v.lower() == "password"})
    if pw:
        hits += 1.6
        reasons.append(f"{len(pw)} password field(s) embedded in the email")

    for f in soup.find_all("form"):
        action = (f.get("action") or "").strip()
        if action.lower().startswith(("http", "www.")):
            hits += 1.0
            reasons.append(f"form submits to external site '{_registered(_host(action))}'")
            break

    px = 0
    for img in soup.find_all("img"):
        w = str(img.get("width", "")).strip()
        h = str(img.get("height", "")).strip()
        if w in ("1", "0") and h in ("1", "0"):
            px += 1
    if px:
        hits += 0.4
        reasons.append(f"{px} tracking pixel(s) (address-confirmation beacon)")

    if not reasons:
        return AttributeResult(NAME, 0.0, "none html_attack",
                               "no credential forms or tracking beacons found", [])
    sc = saturating_score(hits)
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} html_attack",
                           "; ".join(reasons[:4]), [])
