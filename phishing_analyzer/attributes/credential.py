"""Credential / data-harvesting cues.

Signal lives in the imperative PHRASES (validated: "verify your account" etc.),
not the raw nouns. Raw nouns (password/login/ssn) sit in CORPUS_LIMITATION as
weak supporting evidence because Enron IT mail uses them normally.
"""
from .base import lexical_attribute
from ..lexicons import LEXICON, CORPUS_LIMITATION

NAME = "credential"


def score(text, **_):
    return lexical_attribute(NAME, text, LEXICON["credential"],
                             CORPUS_LIMITATION.get("credential"), display="credential-harvest")
