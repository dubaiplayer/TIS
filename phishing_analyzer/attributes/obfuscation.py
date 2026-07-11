"""Obfuscation / evasion: hidden characters and homoglyph tricks.

Phishers slip banned words past keyword filters by inserting invisible characters
('ver<ZWSP>ify') or swapping letters for identical-looking ones from another
alphabet ('verify' with a Cyrillic 'e'). The lexical panel matches on the surface
form and misses both. This attribute flags them - and quoting exactly what was
hidden makes a strong 'here's how they evade detection' demo beat.

Runs on the same analyzed `text` the other attributes use, so evidence offsets
line up. Detection-only: it does NOT alter the text fed to the classifier, so the
ML model's behavior is unchanged (no retrain).
"""
import re
import unicodedata

from .base import saturating_score, band, Span, AttributeResult

NAME = "obfuscation"

# Zero-width / invisible formatting characters with no business inside words.
_INVISIBLE = {
    "​": "zero-width space", "‌": "zero-width non-joiner",
    "‍": "zero-width joiner", "⁠": "word joiner",
    "﻿": "zero-width no-break space", "­": "soft hyphen",
    "᠎": "mongolian vowel separator",
}
_INVIS_RX = re.compile("[" + "".join(_INVISIBLE) + "]")
_WORD = re.compile(r"[^\W\d_]{2,}", re.UNICODE)  # letter runs, len>=2


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


def score(text, *, sender=None, context=None, **_):
    if not text:
        return AttributeResult(NAME, 0.0, "none obfuscation", "no text", [])

    findings, spans = [], []
    seen_kinds = set()

    # 1) Invisible characters embedded in the text.
    invis = list(_INVIS_RX.finditer(text))
    if invis:
        kinds = sorted({_INVISIBLE[m.group(0)] for m in invis})
        findings.append(f"{len(invis)} invisible character(s): {', '.join(kinds)}")
        seen_kinds.add("invisible")
        for m in invis[:6]:
            a = max(0, m.start() - 3)
            b = min(len(text), m.end() + 3)
            spans.append(Span(text[a:b], a, b).__dict__)

    # 2) Homoglyph words: a single word mixing alphabets (Latin + Cyrillic/Greek...).
    homoglyphs = []
    for m in _WORD.finditer(text):
        w = m.group(0)
        if _mixed_script(w):
            homoglyphs.append((w, m.start(), m.end()))
    if homoglyphs:
        shown = ", ".join(repr(w) for w, _, _ in homoglyphs[:5])
        findings.append(f"{len(homoglyphs)} homoglyph/mixed-script word(s): {shown}")
        seen_kinds.add("homoglyph")
        for w, a, b in homoglyphs[:6]:
            spans.append(Span(w, a, b).__dict__)

    if not findings:
        return AttributeResult(NAME, 0.0, "none obfuscation",
                               "no hidden characters or homoglyph tricks found", [])

    sc = saturating_score(len(seen_kinds) + 0.5 * (len(findings) - len(seen_kinds)))
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} obfuscation",
                           "evasion detected: " + "; ".join(findings), spans)
