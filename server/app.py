"""
Local analysis API for the desktop app.

Wraps the existing pipeline so the Electron renderer can POST pasted email text
and receive the validated AnalysisReport JSON (verdict, per-attribute scores +
evidence, classifier keyword attributions).

Run:  .venv/Scripts/python.exe -m uvicorn server.app:app --host 127.0.0.1 --port 8008
   or .venv/Scripts/python.exe -m server.app
"""
import asyncio
import json
import os
import urllib.request
import uuid
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from phishing_analyzer import pipeline
from phishing_analyzer.schema import AnalysisReport, build_report
from inbox_sim.generator import generate_inbox
from server import sim_agent

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


# ---------------------------------------------------------------------------
# Autonomous Inbox Simulator
# ---------------------------------------------------------------------------
_RUNS = {}  # run_id -> {inbox (with truth labels), use_agent}


class SimRunRequest(BaseModel):
    n: int = Field(default=8, ge=1, le=30)
    malicious_ratio: float = Field(default=0.5, ge=0.0, le=1.0)
    seed: Optional[int] = None
    use_agent: bool = True


def _predicted_label(verdict):
    # scoreboard: treat phishing OR suspicious as "flagged" (phishing side)
    return "legitimate" if verdict == "legitimate" else "phishing"


def _sse(obj):
    return f"data: {json.dumps(obj)}\n\n"


# The Inbox Simulator sends each generated email to the DEPLOYED service (the
# actual Phase-2 submission), not the local model. Override with SIM_UPSTREAM_URL.
SIM_UPSTREAM = os.environ.get("SIM_UPSTREAM_URL",
                              "https://phishing-analyzer-api-wq1v.onrender.com")


def _analyze_upstream(text, timeout=60):
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(SIM_UPSTREAM + "/analyze", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


@app.get("/sim/agent_status")
def sim_agent_status():
    """Whether the real LLM-agent mode is usable (SDK installed + API key set)."""
    return {"agent_available": sim_agent.agent_available()}


@app.post("/sim/run")
def sim_run(req: SimRunRequest):
    """Generate a labeled inbox; returns a run_id + the display list (no labels)."""
    inbox = generate_inbox(req.n, req.malicious_ratio, seed=req.seed)
    run_id = uuid.uuid4().hex
    _RUNS[run_id] = {"inbox": inbox, "use_agent": req.use_agent}
    display = [{"id": it["id"], "from": it["from"], "subject": it["subject"]} for it in inbox]
    return {"run_id": run_id, "agent_available": sim_agent.agent_available(),
            "count": len(inbox), "inbox": display}


async def _sim_events(run_id):
    run = _RUNS.get(run_id)
    if not run:
        yield _sse({"type": "error", "error": "unknown run_id"})
        return
    inbox, use_agent = run["inbox"], run["use_agent"]
    agent_on = use_agent and sim_agent.agent_available()
    # Emit an immediate event so the client's stream is alive right away, then
    # warm up the deployed service (free-tier cold start) WITHOUT blocking the loop.
    yield _sse({"type": "status", "message": "waking the deployed service…"})
    try:
        await asyncio.to_thread(
            lambda: urllib.request.urlopen(SIM_UPSTREAM + "/health", timeout=60).read())
    except Exception:
        pass
    total = correct = fp = fn = 0
    source = "hosted"
    for it in inbox:
        # Verdict comes from the DEPLOYED service; fall back to the local model
        # only if the hosted call fails, so the demo never breaks. Run the blocking
        # HTTP call in a thread so the SSE event loop keeps flowing.
        try:
            report_dict = await asyncio.to_thread(_analyze_upstream, it["raw_email"])
        except Exception:
            report_dict = build_report(pipeline.analyze_raw(it["raw_email"])).model_dump()
            source = "local (hosted unreachable)"
        verdict, risk = report_dict["verdict"], report_dict["risk_score"]
        pred, truth = _predicted_label(verdict), it["truth_label"]
        ok = pred == truth
        total += 1
        correct += ok
        fp += (not ok and pred == "phishing")
        fn += (not ok and pred == "legitimate")
        agent = (await sim_agent.analyze_email_with_agent(it["raw_email"])
                 if agent_on else {"available": False})
        yield _sse({"type": "email", "id": it["id"], "from": it["from"],
                    "subject": it["subject"], "subtype": it["subtype"],
                    "truth_label": truth, "verdict": verdict,
                    "predicted_label": pred, "risk_score": risk,
                    "correct": ok, "report": report_dict, "agent": agent,
                    "source": source})
    yield _sse({"type": "scoreboard", "total": total, "correct": correct,
                "accuracy": round(correct / total, 4) if total else 0.0,
                "false_positives": fp, "false_negatives": fn,
                "agent_used": agent_on, "source": source})


@app.get("/sim/stream/{run_id}")
def sim_stream(run_id: str):
    """SSE: one event per email as it's analyzed, then a final scoreboard event."""
    return StreamingResponse(_sim_events(run_id), media_type="text/event-stream")


@app.post("/sim/run_all")
def sim_run_all(req: SimRunRequest):
    """Synchronous batch (model-only, no agent) — fallback / quick check."""
    inbox = generate_inbox(req.n, req.malicious_ratio, seed=req.seed)
    results, correct = [], 0
    for it in inbox:
        report = build_report(pipeline.analyze_raw(it["raw_email"]))
        pred = _predicted_label(report.verdict)
        ok = pred == it["truth_label"]
        correct += ok
        results.append({"id": it["id"], "from": it["from"], "subject": it["subject"],
                        "subtype": it["subtype"], "truth_label": it["truth_label"],
                        "verdict": report.verdict, "predicted_label": pred,
                        "risk_score": report.risk_score, "correct": ok,
                        "report": report.model_dump()})
    return {"count": len(inbox), "correct": correct,
            "accuracy": round(correct / len(inbox), 4) if inbox else 0.0, "results": results}


def main():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8008)


if __name__ == "__main__":
    main()
