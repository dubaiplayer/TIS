"""
Shared infrastructure for attribute modules.

Every attribute returns an AttributeResult with a 0..1 score and character-offset
evidence spans into the SAME text it was given (so the UI can highlight triggers).

Matching contract: word boundaries via `(?<!\\w)...(?!\\w)`, case-insensitive.
Never naive substring (that falsely matched "irs" inside "first").
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field, asdict


@dataclass
class Span:
    text: str
    start: int
    end: int


@dataclass
class AttributeResult:
    name: str
    score: float                       # 0..1
    label: str
    explanation: str
    evidence_spans: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def build_matcher(terms):
    """Compile a single case-insensitive, word-boundary alternation for `terms`.
    Longer terms first so the most specific phrase wins."""
    if not terms:
        return None
    ordered = sorted(set(terms), key=len, reverse=True)
    alt = "|".join(re.escape(t) for t in ordered)
    return re.compile(rf"(?<!\w)(?:{alt})(?!\w)", re.IGNORECASE)


def find_spans(text, matcher):
    """Return (spans, distinct_lowercased_terms) for a compiled matcher."""
    if matcher is None or not text:
        return [], set()
    spans, seen = [], set()
    for m in matcher.finditer(text):
        spans.append(Span(m.group(0), m.start(), m.end()))
        seen.add(m.group(0).lower())
    return spans, seen


def saturating_score(effective_hits, decay=0.55):
    """Diminishing-returns map from a (possibly fractional) hit count to 0..1.
    decay=0.55 -> 1 hit≈0.45, 2≈0.70, 3≈0.83, 4≈0.91."""
    if effective_hits <= 0:
        return 0.0
    return 1.0 - decay ** effective_hits


def band(score, high=0.66, moderate=0.33):
    if score >= high:
        return "high"
    if score >= moderate:
        return "moderate"
    if score > 0:
        return "low"
    return "none"


# Weight applied to CORPUS_LIMITATION terms (valid real-world cues this corpus
# can't validate) so they contribute as softer evidence than validated terms.
WEAK_WEIGHT = 0.4


def lexical_attribute(name, text, strong_terms, weak_terms=None,
                      decay=0.55, display=None):
    """Generic scorer for a lexicon-based attribute.

    strong_terms: validated terms (full weight).
    weak_terms:   CORPUS_LIMITATION terms (WEAK_WEIGHT each).
    """
    strong_spans, strong_seen = find_spans(text, build_matcher(strong_terms))
    weak_spans, weak_seen = ([], set())
    if weak_terms:
        weak_spans, weak_seen = find_spans(text, build_matcher(weak_terms))
        weak_seen -= strong_seen  # don't double-count overlaps

    effective = len(strong_seen) + WEAK_WEIGHT * len(weak_seen)
    score = saturating_score(effective, decay)
    matched = sorted(strong_seen) + sorted(weak_seen)
    label = f"{band(score)} {display or name}".strip()
    if matched:
        shown = ", ".join(repr(t) for t in matched[:6])
        explanation = f"matched {len(matched)} {display or name} cue(s): {shown}"
    else:
        explanation = f"no {display or name} cues found"
    return AttributeResult(name, round(score, 4), label, explanation,
                           [s.__dict__ for s in (strong_spans + weak_spans)])
