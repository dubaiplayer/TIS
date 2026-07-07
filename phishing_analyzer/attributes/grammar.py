"""Grammar / spelling anomalies (heuristic).

Lightweight pyspellchecker misspelled-word ratio — deliberately NOT LanguageTool
(heavy Java dep, and interpretability matters). This is noisy on proper nouns /
jargon, so it's a soft signal; Step 4 validates it by correlation with the label
rather than trusting it outright. Casing matters (proper-noun heuristic), so it's
calibrated on Track B.

The SpellChecker is loaded once, lazily, and capped per email for speed.
"""
import re

from .base import saturating_score, band, Span, AttributeResult

NAME = "grammar"
MAX_WORDS = 400
_WORD = re.compile(r"[A-Za-z][A-Za-z']{2,}")
_spell = None


def _checker():
    global _spell
    if _spell is None:
        from spellchecker import SpellChecker
        _spell = SpellChecker(distance=1)  # distance=1 -> faster
    return _spell


def score(text, **_):
    if not text or len(text) < 40:
        return AttributeResult(NAME, 0.0, "none grammar", "insufficient text", [])

    # Candidate words: lowercase-only tokens (skip ALL-CAPS acronyms and
    # Capitalized tokens that are likely proper nouns) to cut false positives.
    words, positions = [], []
    for m in _WORD.finditer(text):
        w = m.group(0)
        if w[0].isupper() or w.isupper():
            continue
        words.append(w.lower())
        positions.append(m)
        if len(words) >= MAX_WORDS:
            break
    if len(words) < 20:
        return AttributeResult(NAME, 0.0, "none grammar", "too few checkable words", [])

    spell = _checker()
    unknown = spell.unknown(words)
    # unknown includes rare-but-valid words; keep it a soft ratio signal.
    n_bad = sum(1 for w in words if w in unknown)
    ratio = n_bad / len(words)

    # ~5% misspelled is unremarkable; scale so ~20%+ reads as high.
    hits = max(0.0, (ratio - 0.05) / 0.05)
    sc = saturating_score(hits)

    bad_positions = [m for w, m in zip(words, positions) if w in unknown]
    spans = [Span(m.group(0), m.start(), m.end()).__dict__ for m in bad_positions[:8]]
    expl = f"{n_bad}/{len(words)} checked words unrecognized ({ratio*100:.0f}%)"
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} grammar", expl, spans)
