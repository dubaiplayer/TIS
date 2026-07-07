"""Urgency / time-pressure cues (validated lexicon)."""
from .base import lexical_attribute
from ..lexicons import LEXICON

NAME = "urgency"


def score(text, **_):
    return lexical_attribute(NAME, text, LEXICON["urgency"], display="urgency")
