"""Link deception: the classic phishing tells that need the real HTML / URLs.

The lexical panel and the old `links` attribute only see visible text, so they
miss the highest-signal link tricks:
  - anchor-text vs href mismatch  (link SAYS paypal.com, POINTS to evil.ru)
  - punycode / homograph domains  (xn--..., or 'micros0ft'/Cyrillic lookalikes)
  - brand-in-subdomain            (paypal.com.secure-login.ru)

Uses `context["html"]` (raw HTML, parsed with BeautifulSoup) when present, and
also scans visible-text URLs so plain-text emails are covered. Registered-domain
extraction uses tldextract (offline snapshot) with a naive fallback so it never
depends on the network.
"""
import re
import unicodedata

from bs4 import BeautifulSoup

from .base import saturating_score, band, Span, AttributeResult

NAME = "link_deception"

_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'\)\]]+", re.IGNORECASE)
_DOMAIN_IN_TEXT = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_BRANDS = {"paypal", "microsoft", "apple", "amazon", "google", "netflix", "facebook",
           "ebay", "chase", "wellsfargo", "bankofamerica", "irs", "dhl", "fedex",
           "instagram", "linkedin", "office365", "docusign", "coinbase", "outlook"}

try:  # offline registered-domain extraction; never hits the network
    import tldextract
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover - fallback if tldextract unavailable
    _EXTRACT = None


def _host(url):
    u = re.sub(r"^https?://", "", (url or "").strip(), flags=re.IGNORECASE)
    return u.split("/")[0].split("?")[0].split("#")[0].lower()


def _registered(host):
    host = (host or "").lower().strip().strip(".")
    if not host:
        return ""
    if _EXTRACT is not None:
        try:
            r = _EXTRACT(host)
            # 'top_domain_under_public_suffix' (tldextract >=5.3) supersedes the
            # deprecated 'registered_domain'; accept either.
            reg = getattr(r, "top_domain_under_public_suffix", None) or \
                getattr(r, "registered_domain", "")
            if reg:
                return reg
        except Exception:
            pass
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _mixed_script(s):
    scripts = set()
    for ch in s:
        if not ch.isalpha():
            continue
        if ch.isascii():
            scripts.add("LATIN")
        else:
            try:
                scripts.add(unicodedata.name(ch).split(" ")[0])
            except ValueError:
                continue
        if len(scripts) > 1:
            return True
    return False


def _host_findings(host):
    """Structural red flags on a single host."""
    out = []
    reg = _registered(host)
    if "xn--" in host:
        out.append(f"punycode/IDN host '{host}'")
    elif _mixed_script(host):
        out.append(f"homograph (mixed-script) host '{host}'")
    reg_root = reg.split(".")[0] if reg else ""
    other_labels = [l for l in host.split(".") if l and l != reg_root and l not in reg.split(".")]
    for brand in _BRANDS:
        if brand in other_labels and brand != reg_root:
            out.append(f"brand '{brand}' in subdomain but domain is '{reg or host}'")
            break
    return out


def score(text, *, sender=None, context=None, **_):
    html = (context or {}).get("html") or ""
    findings, spans, seen_hosts = [], [], set()

    # 1) HTML anchors: compare what the link SAYS vs where it POINTS.
    if html:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = None
        if soup:
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href.lower().startswith(("http", "www.")):
                    continue
                host = _host(href)
                if not host:
                    continue
                href_reg = _registered(host)
                anchor = a.get_text(" ", strip=True)
                # anchor text that itself names a different domain = deception
                for m in _DOMAIN_IN_TEXT.finditer(anchor):
                    shown_reg = _registered(m.group(0))
                    if shown_reg and href_reg and shown_reg != href_reg:
                        findings.append(f"link text says '{m.group(0)}' but points to '{href_reg}'")
                        break
                else:
                    low = anchor.lower()
                    for brand in _BRANDS:
                        if brand in low and href_reg and brand not in href_reg:
                            findings.append(f"link text mentions '{brand}' but points to '{href_reg}'")
                            break
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    findings += _host_findings(host)

    # 2) Visible-text URLs (covers plain-text emails). Also add evidence spans.
    for m in _URL.finditer(text or ""):
        host = _host(m.group(0))
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        hf = _host_findings(host)
        if hf:
            findings += hf
            spans.append(Span(m.group(0)[:80], m.start(),
                              m.start() + min(len(m.group(0)), 80)).__dict__)

    if not findings:
        label = "none link_deception"
        expl = "no link/anchor deception detected" if (html or "http" in (text or "")) \
            else "no links to inspect"
        return AttributeResult(NAME, 0.0, label, expl, [])

    # dedupe, keep order
    uniq = list(dict.fromkeys(findings))
    sc = saturating_score(len(uniq))
    shown = "; ".join(uniq[:5])
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} link_deception", shown, spans)
