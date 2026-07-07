"""
Explicit, adjustable risk combination.

Overall risk = normalized weighted average of attribute scores + the classifier
probability. Nothing hidden: `contributions` reports every term that went into
the number, and `top_signals` names what drove it. All weights live in
weights.yaml (see the CO-EQUAL classifier_weight note there).
"""
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

    num = den = 0.0
    contributions = []
    for r in attribute_results:
        w = aw.get(r.name, 1.0)
        unavailable = r.name in skip and r.label.startswith("unavailable")
        if unavailable:
            contributions.append({"name": r.name, "score": r.score, "weight": w,
                                   "weighted": 0.0, "included": False})
            continue
        num += w * r.score
        den += w
        contributions.append({"name": r.name, "score": r.score, "weight": w,
                               "weighted": round(w * r.score, 4), "included": True})

    if classifier_prob is not None:
        wc = float(cfg.get("classifier_weight", 0.0))
        num += wc * classifier_prob
        den += wc
        contributions.append({"name": "content_classifier", "score": round(classifier_prob, 4),
                              "weight": wc, "weighted": round(wc * classifier_prob, 4),
                               "included": True})

    risk = (num / den) if den else 0.0
    t = cfg["verdict_thresholds"]
    if risk >= t["phishing_at_or_above"]:
        verdict = "phishing"
    elif risk < t["legitimate_below"]:
        verdict = "legitimate"
    else:
        verdict = "suspicious"

    ranked = sorted((c for c in contributions if c["included"]),
                    key=lambda c: -c["weighted"])
    top_signals = [c["name"] for c in ranked if c["score"] >= 0.33][:4]

    return {
        "risk_score": round(risk, 4),
        "verdict": verdict,
        "top_signals": top_signals,
        "classifier_prob": (round(classifier_prob, 4) if classifier_prob is not None else None),
        "contributions": contributions,
    }
