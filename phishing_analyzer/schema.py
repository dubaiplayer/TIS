"""
Public JSON output schema (pydantic) + a builder from the pipeline's raw dict.

This is the stable contract a caller/UI consumes. `AnalysisReport.model_json_schema()`
emits the formal JSON Schema (see OUTPUT_SCHEMA.md).
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class EvidenceSpan(BaseModel):
    text: str = Field(description="The exact substring that triggered the signal")
    start: int = Field(description="Character offset into analyzed_text (inclusive)")
    end: int = Field(description="Character offset into analyzed_text (exclusive)")


class AttributeReport(BaseModel):
    name: str
    score: float = Field(ge=0.0, le=1.0)
    label: str = Field(description="Short human verdict, e.g. 'high financial'")
    explanation: str
    evidence: List[EvidenceSpan] = Field(default_factory=list)


class KeywordAttribution(BaseModel):
    term: str = Field(description="Word/n-gram from this email")
    weight: float = Field(description="Signed contribution to the logit "
                          "(coef*tfidf); >0 pushes phishing, <0 legitimate")
    direction: str = Field(description="phishing | legitimate")
    intensity: float = Field(ge=0.0, le=1.0,
                             description="|weight| normalized 0..1 for UI sizing/color")
    spans: List[EvidenceSpan] = Field(default_factory=list)


class ClassifierReport(BaseModel):
    phishing_probability: Optional[float] = Field(
        default=None, description="TF-IDF+LogReg P(phishing); null if model unavailable")
    keyword_attributions: List[KeywordAttribution] = Field(
        default_factory=list,
        description="Exact per-term contributions to THIS email's prediction")
    char_ngram_contribution: Optional[float] = Field(
        default=None, description="Aggregate logit contribution of character n-grams "
        "(not shown as keywords)")


class Meta(BaseModel):
    sender_analyzed: bool
    notes: List[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    verdict: str = Field(description="phishing | suspicious | legitimate")
    risk_score: float = Field(ge=0.0, le=1.0)
    action: str = Field(default="warn",
                        description="Recommended action: quarantine | warn | allow")
    recommendation: str = Field(default="",
                               description="Plain-language what-to-do for the user or agent")
    summary: str = Field(description="One-line human-readable explanation")
    top_signals: List[str]
    attributes: List[AttributeReport]
    classifier: ClassifierReport
    meta: Meta
    analyzed_text: Optional[str] = Field(
        default=None, description="Cleaned subject+body that offsets index into")


_VERDICT_BLURB = {
    "phishing": "High risk - strong phishing indicators",
    "suspicious": "Some manipulation signals present - treat with caution",
    "legitimate": "No significant phishing indicators found",
}


def _summary(verdict, top_signals):
    blurb = _VERDICT_BLURB.get(verdict, verdict)
    if top_signals:
        pretty = ", ".join(s.replace("_", " ") for s in top_signals)
        return f"{blurb}. Top signals: {pretty}."
    return f"{blurb}."


# Recommended action + plain-language guidance, derived from the verdict, so a
# caller/agent gets a decision to act on (not just a score).
_ACTION = {"phishing": "quarantine", "suspicious": "warn", "legitimate": "allow"}
_RECOMMENDATION = {
    "quarantine": "Do not click links, open attachments, or reply. Verify the sender "
                  "through a separate trusted channel and report it to your security team.",
    "warn": "Treat with caution. Do not act on any request (payment, credentials, links) "
            "until you independently verify the sender.",
    "allow": "No significant phishing indicators found. Apply normal caution.",
}


def build_report(result: dict) -> AnalysisReport:
    """Map the pipeline.analyze() dict to the validated public schema."""
    o = result["overall"]
    attrs = [
        AttributeReport(
            name=a["name"], score=a["score"], label=a["label"],
            explanation=a["explanation"],
            evidence=[EvidenceSpan(**s) for s in a.get("evidence_spans", [])],
        )
        for a in result["attributes"]
    ]
    cdict = result.get("classifier") or {}
    classifier = ClassifierReport(
        phishing_probability=cdict.get("phishing_probability", o.get("classifier_prob")),
        keyword_attributions=[KeywordAttribution(**k)
                              for k in cdict.get("keyword_attributions", [])],
        char_ngram_contribution=cdict.get("char_ngram_contribution"),
    )
    action = _ACTION.get(o["verdict"], "warn")
    return AnalysisReport(
        verdict=o["verdict"],
        risk_score=o["risk_score"],
        action=action,
        recommendation=_RECOMMENDATION[action],
        summary=_summary(o["verdict"], o["top_signals"]),
        top_signals=o["top_signals"],
        attributes=attrs,
        classifier=classifier,
        meta=Meta(**result["meta"]),
        analyzed_text=result.get("analyzed_text"),
    )
