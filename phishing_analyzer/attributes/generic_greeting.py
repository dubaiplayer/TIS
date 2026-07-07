"""Generic / impersonal greeting ("Dear Customer/Friend/Sir") vs personalized."""
from .base import lexical_attribute
from ..lexicons import LEXICON

NAME = "generic_greeting"


def score(text, **_):
    return lexical_attribute(NAME, text, LEXICON["generic_greeting"], display="generic greeting")
