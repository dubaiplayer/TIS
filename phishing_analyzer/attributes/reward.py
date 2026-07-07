"""Emotional manipulation via reward / greed bait (validated lexicon)."""
from .base import lexical_attribute
from ..lexicons import LEXICON

NAME = "reward"


def score(text, **_):
    return lexical_attribute(NAME, text, LEXICON["reward"], display="reward/greed")
