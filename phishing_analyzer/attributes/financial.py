"""Financial-request cues (validated lexicon + modern payment rails as weak cues).

Gift-card / crypto / Zelle terms live in CORPUS_LIMITATION: absent from this
~2000s corpus but prime real-world signals. IBAN/amount regex adds structured
evidence on top of the lexicon.
"""
import re

from .base import lexical_attribute, band, Span, AttributeResult, WEAK_WEIGHT
from ..lexicons import LEXICON, CORPUS_LIMITATION

NAME = "financial"
DECAY = 0.55

_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_MONEY = re.compile(
    r"(?:US\$|USD|EUR|GBP|\$|£|€)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:million|thousand|m|k))?",
    re.IGNORECASE,
)


def score(text, **_):
    base = lexical_attribute(NAME, text, LEXICON["financial"],
                             CORPUS_LIMITATION.get("financial"), display="financial")
    if not text:
        return base

    extra_spans, extra_hits, notes = [], 0.0, []
    for rx, note in ((_IBAN, "IBAN-like account"), (_MONEY, "money amount")):
        found = list(rx.finditer(text))
        if found:
            extra_hits += WEAK_WEIGHT
            notes.append(f"{note} x{len(found)}")
            extra_spans += [Span(m.group(0), m.start(), m.end()).__dict__ for m in found[:5]]
    if extra_hits == 0:
        return base

    # Boost the lexical score by the regex evidence. Since base.score =
    # 1 - DECAY**lex_hits, multiplying the residual by DECAY**extra_hits is
    # exactly 1 - DECAY**(lex_hits + extra_hits) — no fragile log-inversion.
    combined = 1.0 - (1.0 - base.score) * (DECAY ** extra_hits)
    expl = base.explanation + ("; " + ", ".join(notes) if notes else "")
    return AttributeResult(NAME, round(combined, 4), f"{band(combined)} financial",
                           expl, base.evidence_spans + extra_spans)
