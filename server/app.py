"""
Phishing Analyzer API — hosted HTTP service.

Wraps the local pipeline behind two endpoints so ANY caller (an AI agent, curl, a
browser) can analyze an email and receive the validated AnalysisReport JSON
(verdict, per-attribute scores + evidence, classifier keyword attributions).

Deploy (Render): start command
    uvicorn server.app:app --host 0.0.0.0 --port $PORT
Local:
    .venv/Scripts/python.exe -m server.app
"""
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from phishing_analyzer import pipeline, link_xray
from phishing_analyzer.schema import AnalysisReport, build_report

app = FastAPI(title="Phishing Analyzer API", version="1.0.0")

# Public API for agents/tools: allow all origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKILL_PATH = os.path.join(_ROOT, "SKILL.md")


class AnalyzeRequest(BaseModel):
    text: str = Field(description="Raw email text (headers + body, or just body)")
    use_classifier: bool = True


@app.get("/")
def root():
    """Human/warm-up landing: names the service and points to the docs."""
    return {
        "service": "Phishing Analyzer API",
        "description": "POST an email to /analyze to get an explainable phishing verdict.",
        "endpoints": {"health": "GET /health", "analyze": "POST /analyze",
                      "skill": "GET /skill.md", "openapi": "GET /docs"},
    }


@app.get("/health")
def health():
    """Liveness/readiness check (free-tier cold start can take 30-60s)."""
    return {"status": "ok"}


@app.get("/skill.md", response_class=PlainTextResponse)
def skill_md():
    """Serve the SKILL.md so the registry/agent can fetch it from the live URL."""
    try:
        with open(_SKILL_PATH, "r", encoding="utf-8") as f:
            return PlainTextResponse(f.read(), media_type="text/markdown")
    except FileNotFoundError:
        return PlainTextResponse("SKILL.md not found", status_code=404)


@app.post("/analyze", response_model=AnalysisReport)
def analyze(req: AnalyzeRequest) -> AnalysisReport:
    """Analyze one raw email -> structured phishing report."""
    result = pipeline.analyze_raw(req.text, use_classifier=req.use_classifier)
    return build_report(result)


@app.post("/xray")
async def xray(req: AnalyzeRequest):
    """Link X-ray: follow each link's redirect chain to its TRUE destination and
    flag domain age + blocklist hits. Network-heavy and opt-in (kept out of the
    fast/deterministic /analyze). Runs off-thread so the event loop stays free."""
    import asyncio
    return await asyncio.to_thread(link_xray.xray, req.text)


def main():
    import uvicorn
    port = int(os.environ.get("PORT", "8008"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
