"""
Link X-ray: unmask where an email's links REALLY go.

Phishing hides its destination behind shorteners and lookalike domains. This
follows each link's redirect chain to the true destination, then flags the two
strongest real-world tells that the static analyzer can't see offline:
  - domain AGE (a domain registered days ago is a huge red flag) via RDAP, and
  - presence on a public URL blocklist (best-effort, abuse.ch URLhaus).

This is NETWORK-heavy and deliberately kept OUT of /analyze (which stays fast +
deterministic). It's exposed as a separate opt-in POST /xray. Uses only the
stdlib (urllib) plus tldextract; every lookup has a short timeout and degrades
gracefully, so a slow/blocked lookup never hangs the request.
"""
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    import tldextract
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover
    _EXTRACT = None

_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'\)\]]+", re.IGNORECASE)
_UA = "Mozilla/5.0 (phishing-analyzer link-xray)"
_TIMEOUT = 8


def _registered(host):
    host = (host or "").lower().strip().strip(".")
    if _EXTRACT is not None:
        try:
            r = _EXTRACT(host)
            reg = getattr(r, "top_domain_under_public_suffix", None) or \
                getattr(r, "registered_domain", "")
            if reg:
                return reg
        except Exception:
            pass
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _host(url):
    u = re.sub(r"^https?://", "", (url or "").strip(), flags=re.IGNORECASE)
    return u.split("/")[0].split("?")[0].split("#")[0].lower()


def _unmask(url, max_hops=8):
    """Follow the redirect chain (HEAD, then GET) to the true destination.
    Returns (final_url, hops). Never downloads a page body."""
    start = url if url.lower().startswith("http") else "http://" + url
    hops, current = [], start
    for _ in range(max_hops):
        req = urllib.request.Request(current, method="HEAD", headers={"User-Agent": _UA})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                final = r.geturl()
        except urllib.error.HTTPError as e:
            # Some hosts reject HEAD; fall back to GET (headers only, no read).
            try:
                req2 = urllib.request.Request(current, headers={"User-Agent": _UA})
                with urllib.request.urlopen(req2, timeout=_TIMEOUT) as r:
                    final = r.geturl()
            except Exception:
                final = getattr(e, "url", current)
        except Exception:
            final = current
        if final == current:
            return final, hops
        hops.append(final)
        current = final
    return current, hops


def _domain_age_days(domain):
    """Registration age in days via RDAP (rdap.org bootstrap -> registry).
    None if it can't be determined."""
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{domain}",
                                     headers={"User-Agent": _UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:  # urllib follows the 302
            data = json.loads(r.read().decode("utf-8", "replace"))
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                reg = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return max(0, (datetime.now(timezone.utc) - reg).days)
    except Exception:
        pass
    return None


def _on_blocklist(url, domain):
    """Best-effort abuse.ch URLhaus check. Returns a source name or None.
    Degrades silently if the API needs a key / is unreachable."""
    try:
        body = urllib.parse.urlencode({"host": domain}).encode()
        req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/host/", data=body,
                                     headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        if data.get("query_status") == "ok" and data.get("urls"):
            return "abuse.ch URLhaus"
    except Exception:
        pass
    return None


def xray(text, max_links=5):
    """Return {links: [...], summary: str} for the URLs found in `text`."""
    socket.setdefaulttimeout(_TIMEOUT + 2)
    seen, links = set(), []
    for m in _URL.finditer(text or ""):
        raw = m.group(0).rstrip(".,);]")
        h = _host(raw)
        if not h or h in seen:
            continue
        seen.add(h)
        final, hops = _unmask(raw)
        fhost = _host(final)
        freg = _registered(fhost)
        age = _domain_age_days(freg)
        blocklist = _on_blocklist(final, freg)
        reasons = []
        if hops:
            reasons.append(f"redirects to a different site ({freg})")
        if age is not None and age <= 30:
            reasons.append(f"destination domain is only {age} day(s) old")
        if blocklist:
            reasons.append(f"listed on {blocklist}")
        links.append({
            "url": raw, "final_url": final, "redirect_hops": len(hops),
            "destination_domain": freg or fhost,
            "domain_age_days": age, "on_blocklist": bool(blocklist),
            "blocklist_source": blocklist, "suspicious_reasons": reasons,
        })
        if len(links) >= max_links:
            break
    risky = sum(1 for l in links if l["suspicious_reasons"])
    if not links:
        summary = "No links found in the email."
    elif risky:
        summary = f"{risky} of {len(links)} link(s) look risky when unmasked."
    else:
        summary = f"{len(links)} link(s) checked; none looked risky when unmasked."
    return {"links": links, "summary": summary}
