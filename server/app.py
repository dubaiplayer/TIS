"""
Local analysis API for the desktop app.

Wraps the existing pipeline so the Electron renderer can POST pasted email text
and receive the validated AnalysisReport JSON (verdict, per-attribute scores +
evidence, classifier keyword attributions).

Run:  .venv/Scripts/python.exe -m uvicorn server.app:app --host 127.0.0.1 --port 8008
   or .venv/Scripts/python.exe -m server.app
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from phishing_analyzer import pipeline
from phishing_analyzer.schema import AnalysisReport, build_report

app = FastAPI(title="Phishing Analyzer API", version="1.0.0")

# Local desktop app only: the Electron renderer runs from http://localhost:5173
# (dev) or file:// (packaged), so allow all origins on loopback.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    text: str = Field(description="Raw email text (headers + body, or just body)")
    use_classifier: bool = True


@app.get("/health")
def health():
    """Cheap readiness check the app pings before enabling Analyze."""
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisReport)
def analyze(req: AnalyzeRequest) -> AnalysisReport:
    result = pipeline.analyze_raw(req.text, use_classifier=req.use_classifier)
    return build_report(result)


def main():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8008)


if __name__ == "__main__":
    main()
