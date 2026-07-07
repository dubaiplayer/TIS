"""Emotional manipulation via curiosity bait (validated lexicon; weak on this corpus)."""
from .base import lexical_attribute
from ..lexicons import LEXICON

NAME = "curiosity"


def score(text, **_):
    return lexical_attribute(NAME, text, LEXICON["curiosity"], display="curiosity bait")
