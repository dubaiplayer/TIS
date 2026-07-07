"""Emotional manipulation via fear / threat (validated lexicon)."""
from .base import lexical_attribute
from ..lexicons import LEXICON

NAME = "fear_threat"


def score(text, **_):
    return lexical_attribute(NAME, text, LEXICON["fear_threat"], display="fear/threat")
