"""SaaS-hosting abuse: credential harvesters hosted on trusted cloud platforms.

Attackers increasingly skip building a fake site and instead host the phishing
"page" on a legitimate, long-lived, non-blocklisted service - a Google Form,
Microsoft Forms / SharePoint doc, DocuSign PowerForm, Typeform, or an app on
*.web.app / *.pages.dev - and send it from a real (often compromised) mailbox.
Link reputation, domain age, and blocklists all say "clean", so native filters
AND our own sender-trust discount wave it through.

This attribute flags the tell that remains: a link to a commonly-abused SaaS HOST
being used as *third-party* credential/login hosting - i.e. the link's domain is
NOT the sender's own domain (so it isn't the service emailing you about itself),
and either the host is an input-collecting form/survey or the email carries
login/authentication intent.

Reads context["html"] hrefs (BeautifulSoup) plus visible-text URLs, so HTML and
plain-text emails are both covered. Registered-domain extraction reuses the offline
tldextract helper from link_deception. No network, no new dependencies.
"""
import re
from email.utils import parseaddr

from bs4 import BeautifulSoup

from .base import saturating_score, band, Span, AttributeResult
from .link_deception import _URL, _host, _registered, _BRANDS

NAME = "saas_abuse"

# Input-collecting form/survey builders: a form IS a credential vector, so a
# third-party link to one is a signal on its own.
_FORM_HOSTS = {"forms.office.com", "forms.microsoft.com", "typeform.com",
               "jotform.com", "formstack.com", "wufoo.com", "surveymonkey.com",
               "cognitoforms.com", "gravityforms.com"}
# Doc / file share: legitimate to share, so only a tell WITH login intent.
_SHARE_HOSTS = {"docs.google.com", "drive.google.com", "sharepoint.com",
                "onedrive.live.com", "1drv.ms", "dropbox.com", "box.com",
                "docsend.com", "docusign.net", "wetransfer.com", "smallpdf.com"}
# Arbitrary page hosting - phishing-kit friendly; only a tell WITH login intent.
_APP_HOSTS = {"web.app", "firebaseapp.com", "appspot.com", "pages.dev", "workers.dev",
              "netlify.app", "vercel.app", "github.io", "glitch.me", "replit.app",
              "repl.co", "r2.dev", "blogspot.com", "weebly.com", "wixsite.com",
              "notion.site", "azurewebsites.net", "windows.net", "amazonaws.com",
              "storage.googleapis.com", "cloudfront.net", "herokuapp.com", "onrender.com"}

_LOGIN_INTENT = [
    "sign in", "signin", "log in", "login", "log on", "logon", "verify your account",
    "verify your identity", "confirm your identity", "confirm your password",
    "update your password", "reset your password", "enter your credentials",
    "enter your password", "validate your account", "authenticate", "reauthenticate",
    "re-authenticate", "review and sign", "e-sign", "esign", "session expired",
    "unusual sign-in", "access the document", "view the document",
    "you have a new document", "shared a document",
]
_INTENT_RX = re.compile(
    r"(?<!\w)(?:" + "|".join(re.escape(t) for t in
                             sorted(_LOGIN_INTENT, key=len, reverse=True)) + r")(?!\w)",
    re.IGNORECASE)


def _classify(url, host):
    """Return 'form' | 'share' | 'app' if `host`/`url` is an abused SaaS host, else ''."""
    h = (host or "").lower()
    reg = _registered(h)
    after = re.sub(r"^(?:https?://)?[^/]+", "", url or "", flags=re.IGNORECASE).lower()

    def is_(s):
        return h == s or h.endswith("." + s) or reg == s

    # Google Forms special-case: docs.google.com hosts both Docs (share) and Forms.
    if h == "forms.gle" or h.endswith(".forms.gle") or \
            (h == "docs.google.com" and "/forms/" in after):
        return "form"
    if any(is_(s) for s in _FORM_HOSTS):
        return "form"
    if any(is_(s) for s in _SHARE_HOSTS):
        return "share"
    if any(is_(s) for s in _APP_HOSTS):
        return "app"
    return ""


def _sender_reg(sender, context):
    headers = (context or {}).get("headers") or {}
    _, addr = parseaddr(headers.get("from") or sender or "")
    host = addr.split("@")[-1].lower().strip(">").strip() if "@" in addr else ""
    return _registered(host)


def _links(text, context):
    """(host, url, start|None, end|None) for every http/www link in hrefs + text."""
    out = []
    html = (context or {}).get("html") or ""
    if html:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = None
        if soup:
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.lower().startswith(("http", "www.")):
                    out.append((_host(href), href, None, None))
    for m in _URL.finditer(text or ""):
        out.append((_host(m.group(0)), m.group(0), m.start(), m.end()))
    return out


def score(text, *, sender=None, context=None, **_):
    from_reg = _sender_reg(sender, context)
    intent_spans = [Span(m.group(0), m.start(), m.end())
                    for m in _INTENT_RX.finditer(text or "")]
    has_intent = bool(intent_spans)
    low = (text or "").lower()
    brand = next((b for b in _BRANDS
                  if re.search(rf"(?<!\w){re.escape(b)}(?!\w)", low)), None)

    hits, reasons, spans, seen = 0.0, [], [], set()
    for host, url, start, end in _links(text, context):
        kind = _classify(url, host)
        if not kind or host in seen:
            continue
        seen.add(host)
        link_reg = _registered(host)
        # First-party guard: the service emailing about ITSELF is not abuse.
        if from_reg and link_reg and link_reg == from_reg:
            continue
        # Doc-share / app hosts are legitimate to link; only a tell WITH login intent.
        if kind != "form" and not has_intent:
            continue
        weight = 0.9 if kind == "form" else 0.7
        if has_intent:
            weight += 0.5
        if brand:
            weight += 0.5
        hits += weight
        reasons.append(f"credential/login link hosted on {host}"
                       + (f" while the email name-drops '{brand}'" if brand else ""))
        if start is not None:
            spans.append(Span(url[:100], start, start + min(len(url), 100)).__dict__)

    if hits <= 0:
        return AttributeResult(NAME, 0.0, "none saas_abuse",
                               "no credential/login link on an abused SaaS host", [])
    if has_intent:
        spans.append(intent_spans[0].__dict__)   # show one intent phrase as evidence
    sc = saturating_score(hits)
    shown = "; ".join(dict.fromkeys(reasons))[:300]
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} saas_abuse", shown, spans)
