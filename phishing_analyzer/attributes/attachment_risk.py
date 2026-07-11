"""Attachment / payload risk.

Malicious attachments are a core phishing delivery vector the text panel can't
see. Flags dangerous executable/script types, double extensions ('invoice.pdf.exe'
that hide the real type), macro-enabled Office documents, HTML attachments (local
credential-harvest pages), and password-protected-style archives.

Needs `context["attachments"]` (list of {filename, content_type}) from
pipeline._extract_context. No attachments -> 'unavailable' (combiner skips it).
"""
import re

from .base import saturating_score, band, AttributeResult

NAME = "attachment_risk"

_DANGEROUS = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
              "wsf", "wsh", "hta", "jar", "msi", "ps1", "lnk", "reg", "cpl", "iso",
              "img", "vhd"}
_MACRO = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam"}
_HTML = {"html", "htm", "shtml", "svg"}
_ARCHIVE = {"zip", "rar", "7z", "gz", "cab", "ace"}
_EXT_RX = re.compile(r"\.([A-Za-z0-9]{1,5})$")
_DOUBLE_RX = re.compile(r"\.[A-Za-z0-9]{2,5}\.([A-Za-z0-9]{1,5})$")


def score(text, *, sender=None, context=None, **_):
    atts = (context or {}).get("attachments") or []
    if not atts:
        return AttributeResult(NAME, 0.0, "unavailable attachment_risk",
                               "no attachments to inspect", [])

    hits, reasons = 0.0, []
    for a in atts:
        name = (a.get("filename") or "").strip().lower()
        if not name:
            continue
        ext = (_EXT_RX.search(name).group(1) if _EXT_RX.search(name) else "")
        dbl = _DOUBLE_RX.search(name)
        if dbl and dbl.group(1) in _DANGEROUS:
            hits += 1.8
            reasons.append(f"double-extension executable '{name}'")
        elif ext in _DANGEROUS:
            hits += 1.6
            reasons.append(f"dangerous type '.{ext}' ({name})")
        elif ext in _MACRO:
            hits += 1.0
            reasons.append(f"macro-enabled document '.{ext}' ({name})")
        elif ext in _HTML:
            hits += 1.0
            reasons.append(f"HTML attachment '.{ext}' ({name})")
        elif ext in _ARCHIVE:
            hits += 0.5
            reasons.append(f"archive '.{ext}' ({name}) - may hide a payload")

    if not reasons:
        return AttributeResult(NAME, 0.0, "low attachment_risk",
                               f"{len(atts)} attachment(s), none flagged", [])
    sc = saturating_score(hits)
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} attachment_risk",
                           "; ".join(reasons[:5]), [])
