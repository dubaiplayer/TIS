"""
Explicit, adjustable risk combination — NOISY-OR of independent signals.

Why noisy-OR (not a weighted average): phishing evidence is disjunctive. A single
confident signal — the classifier, or one strong attribute like a spoofed sender +
wire-transfer request — should be able to drive risk high on its own. A weighted
mean drowns strong signals among the many attributes that (correctly) stay silent,
which in Step-4 testing left almost no email reaching the "phishing" verdict.

Each signal casts a "vote" = reliability * score, and:
    risk = 1 - Π (1 - vote_i)
So any one high vote pushes risk toward 1, while many zeros leave it near 0.

Reliability (0..1) comes from weights.yaml: attribute_weights are normalized by
the max weight and scaled by attribute_reliability_ceiling (so no single lexical
hit is fully trusted); the classifier gets its own classifier_reliability. Tune
everything in weights.yaml — nothing here is hidden.
"""
import math
import os

import yaml

_WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), "weights.yaml")
_cfg = None


def load_weights(path=_WEIGHTS_PATH):
    global _cfg
    if _cfg is None:
        with open(path, "r", encoding="utf-8") as f:
            _cfg = yaml.safe_load(f)
    return _cfg


def combine(attribute_results, classifier_prob=None, cfg=None):
    cfg = cfg or load_weights()
    aw = cfg["attribute_weights"]
    skip = set(cfg.get("skip_when_unavailable", []))
    ceiling = float(cfg.get("attribute_reliability_ceiling", 0.9))
    clf_reliability = float(cfg.get("classifier_reliability", 0.97))
    vote_floor = float(cfg.get("vote_floor", 0.0))
    max_w = max(aw.values()) if aw else 1.0

    log_survival = 0.0          # accumulate log(1 - vote) for numerical stability
    contributions = []

    def cast(name, score, reliability, included=True, floor=True):
        nonlocal log_survival
        vote = max(0.0, min(0.999, reliability * score))
        # Vote floor: ignore weak votes so many small attribute hits (esp. the
        # always-firing caps_tone/grammar) don't accumulate into false alarms on
        # legit corporate mail. The classifier is exempt (never floored).
        if floor and vote < vote_floor:
            vote = 0.0
        if included:
            log_survival += math.log(1.0 - vote)
        contributions.append({"name": name, "score": round(score, 4),
                              "reliability": round(reliability, 3),
                               "vote": round(vote, 4), "included": included})

    for r in attribute_results:
        w = aw.get(r.name, 1.0)
        reliability = (w / max_w) * ceiling
        if r.name in skip and r.label.startswith("unavailable"):
            cast(r.name, r.score, reliability, included=False)
        else:
            cast(r.name, r.score, reliability)

    if classifier_prob is not None:
        cast("content_classifier", classifier_prob, clf_reliability, floor=False)

    risk = 1.0 - math.exp(log_survival)
    t = cfg["verdict_thresholds"]
    if risk >= t["phishing_at_or_above"]:
        verdict = "phishing"
    elif risk < t["legitimate_below"]:
        verdict = "legitimate"
    else:
        verdict = "suspicious"

    ranked = sorted((c for c in contributions if c["included"]), key=lambda c: -c["vote"])
    top_signals = [c["name"] for c in ranked if c["vote"] >= 0.15][:4]

    return {
        "risk_score": round(risk, 4),
        "verdict": verdict,
        "top_signals": top_signals,
        "classifier_prob": (round(classifier_prob, 4) if classifier_prob is not None else None),
        "contributions": contributions,
    }
