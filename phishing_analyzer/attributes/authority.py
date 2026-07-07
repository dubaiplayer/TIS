"""Authority impersonation (validated lexicon + brand names as weak/flagged cues).

Brand names (microsoft/apple/paypal/irs...) sit in CORPUS_LIMITATION because Enron
IT mail names them legitimately; they are softer evidence here but real
impersonation targets in the wild. sender_domain corroborates impersonation.
"""
from .base import lexical_attribute
from ..lexicons import LEXICON, CORPUS_LIMITATION

NAME = "authority"


def score(text, **_):
    return lexical_attribute(NAME, text, LEXICON["authority"],
                             CORPUS_LIMITATION.get("authority"), display="authority")
