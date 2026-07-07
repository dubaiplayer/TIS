"""Attribute registry: ordered list of (name, score_fn).

Each score_fn has signature score(text, *, sender=None) -> AttributeResult.
Import ATTRIBUTES to run the full rule-based panel.
"""
from . import (urgency, fear_threat, reward, curiosity, authority, financial,
               credential, generic_greeting, sender_domain, links, grammar, caps_tone)

ATTRIBUTES = [
    (urgency.NAME, urgency.score),
    (fear_threat.NAME, fear_threat.score),
    (reward.NAME, reward.score),
    (curiosity.NAME, curiosity.score),
    (authority.NAME, authority.score),
    (financial.NAME, financial.score),
    (credential.NAME, credential.score),
    (generic_greeting.NAME, generic_greeting.score),
    (sender_domain.NAME, sender_domain.score),
    (links.NAME, links.score),
    (grammar.NAME, grammar.score),
    (caps_tone.NAME, caps_tone.score),
]

ATTRIBUTE_NAMES = [name for name, _ in ATTRIBUTES]


def run_all(text, sender=None):
    """Run every attribute; return list[AttributeResult]."""
    return [fn(text, sender=sender) for _, fn in ATTRIBUTES]
