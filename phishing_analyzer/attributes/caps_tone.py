"""Caps / punctuation tone: shouting and punctuation bursts.

CALIBRATION: thresholds were set against Track B (casing-preserving sources) so
the flattened Enron/Ling text does not distort them. Legit corporate baseline on
Track B sits ~9% uppercase-letter ratio and <2 '!' per 1k chars, so we key off
ALL-CAPS *words* and repeated-punctuation bursts, which are rare in normal mail.
"""
import re

from .base import saturating_score, band, Span, AttributeResult

NAME = "caps_tone"

_TOKEN = re.compile(r"\b\w[\w']*\b")
_CAPS_WORD = re.compile(r"\b[A-Z]{3,}[A-Z']*\b")      # SHOUTING words (3+ caps)
_PUNCT_BURST = re.compile(r"[!?]{2,}")                # !!!  ???  ?!?


def score(text, **_):
    if not text or len(text) < 20:
        return AttributeResult(NAME, 0.0, "none caps/tone", "insufficient text", [])

    tokens = _TOKEN.findall(text)
    n_words = max(1, sum(1 for t in tokens if any(c.isalpha() for c in t)))
    caps_words = list(_CAPS_WORD.finditer(text))
    bursts = list(_PUNCT_BURST.finditer(text))
    excl = text.count("!")

    caps_ratio = len(caps_words) / n_words
    # Effective hits: shouting ratio (scaled), punctuation bursts, exclamation load.
    hits = 0.0
    hits += min(caps_ratio / 0.05, 3.0)              # 5% caps-words -> ~1 hit, capped
    hits += min(len(bursts), 3) * 0.8
    hits += min(excl / 1000 * len(text) / 400, 2.0)  # exclamation density contribution
    sc = saturating_score(hits)

    spans = [Span(m.group(0), m.start(), m.end()).__dict__ for m in caps_words[:8]]
    spans += [Span(m.group(0), m.start(), m.end()).__dict__ for m in bursts[:4]]
    expl = (f"{len(caps_words)} all-caps word(s) ({caps_ratio*100:.0f}% of words), "
            f"{len(bursts)} punctuation burst(s), {excl} '!'")
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} caps/tone", expl, spans)
