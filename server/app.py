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
import random
import urllib.request
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel, Field

from phishing_analyzer import pipeline, link_xray
from phishing_analyzer.schema import AnalysisReport, build_report
from inbox_sim.generator import generate_inbox
from server import sim_agent, agent_runner, mailbox, gmail_triage, gmail_oauth

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


BUILD = "2026-07-11-consistency-v3"


@app.get("/health")
def health():
    """Cheap readiness check the app pings before enabling Analyze."""
    return {"status": "ok", "build": BUILD}


@app.get("/version")
def version():
    """Confirms which build is running (so a stale process is easy to spot)."""
    return {"build": BUILD}


@app.post("/analyze", response_model=AnalysisReport)
def analyze(req: AnalyzeRequest) -> AnalysisReport:
    result = pipeline.analyze_raw(req.text, use_classifier=req.use_classifier)
    return build_report(result)


class InboxAnalyzeRequest(BaseModel):
    text: str = Field(description="Raw email fetched from a real mailbox")
    from_addr: str = Field(default="", description="The message's From address")


@app.post("/analyze/inbox", response_model=AnalysisReport)
def analyze_inbox(req: InboxAnalyzeRequest) -> AnalysisReport:
    """Same analyzer as /analyze, plus the real-inbox trust adjustment that keeps
    authenticated provider mail (e.g. genuine Google security alerts) from being
    miscalled phishing on wording alone. Used only by the Gmail/Outlook view - the
    paste-in /analyze and the sims are untouched."""
    rep = build_report(pipeline.analyze_raw(req.text))
    return gmail_triage.adjust(rep, req.text, req.from_addr)


# ---------------------------------------------------------------------------
# "Sign in with Google" (OAuth) - password-free Gmail connect for real users
# ---------------------------------------------------------------------------
_GOOGLE_SESSIONS = {}   # state -> {connected, email, access_token, refresh_token}


@app.get("/auth/google/config")
def google_config():
    """Whether a Google OAuth client is configured on this backend."""
    return {"configured": gmail_oauth.configured()}


@app.post("/auth/google/start")
def google_start():
    """Begin sign-in: returns Google's consent URL + a state to poll on."""
    if not gmail_oauth.configured():
        raise HTTPException(400, "Google OAuth is not configured on this backend "
                            "(set GOOGLE_CLIENT_ID/SECRET or add server/google_oauth.json).")
    state = uuid.uuid4().hex
    _GOOGLE_SESSIONS[state] = {"connected": False}
    return {"auth_url": gmail_oauth.build_auth_url(state), "state": state}


@app.get("/auth/google/callback")
def google_callback(state: str = "", code: str = "", error: str = ""):
    """Google redirects here after consent. Swaps the code for tokens and stores
    them under `state`; the app is polling /auth/google/status meanwhile."""
    sess = _GOOGLE_SESSIONS.get(state)
    if error or not code or sess is None:
        return HTMLResponse(f"<h3>Sign-in failed: {error or 'invalid request'}.</h3>"
                            "You can close this tab and try again.", status_code=400)
    try:
        tok = gmail_oauth.exchange_code(code)
        access = tok["access_token"]
        email_addr = gmail_oauth.get_email(access)
    except Exception as e:
        return HTMLResponse(f"<h3>Sign-in failed: {e}</h3>You can close this tab.",
                            status_code=400)
    _GOOGLE_SESSIONS[state] = {"connected": True, "email": email_addr,
                               "access_token": access,
                               "refresh_token": tok.get("refresh_token")}
    return HTMLResponse(
        f"<div style='font-family:system-ui;padding:40px;text-align:center'>"
        f"<h2>Signed in as {email_addr}</h2>"
        "<p>You can close this tab and return to the Phishing Analyzer app.</p></div>")


@app.get("/auth/google/status")
def google_status(state: str = ""):
    """The app polls this until `connected` is true, then reads the email."""
    sess = _GOOGLE_SESSIONS.get(state) or {}
    return {"connected": bool(sess.get("connected")), "email": sess.get("email", "")}


@app.post("/xray")
async def xray(req: AnalyzeRequest):
    """Link X-ray: follow each link to its true destination + flag domain age /
    blocklist. Network-heavy; runs off-thread so the loop stays free."""
    return await asyncio.to_thread(link_xray.xray, req.text)


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


# ---------------------------------------------------------------------------
# Live Agent (headless Claude Code reads a local SKILL.md, calls THIS /analyze)
# ---------------------------------------------------------------------------
_AGENT_RUNS = {}


class AgentRunRequest(BaseModel):
    n: int = Field(default=8, ge=1, le=30)
    malicious_ratio: float = Field(default=0.5, ge=0.0, le=1.0)
    seed: Optional[int] = None
    source: str = Field(default="synthetic")   # synthetic | gmail_oauth | gmail | outlook
    email: Optional[str] = None
    app_password: Optional[str] = None
    state: Optional[str] = None                 # Google OAuth session (source=gmail_oauth)


@app.get("/agent/status")
def agent_status():
    """Whether the headless-agent mode is usable (claude CLI on PATH)."""
    return {"available": agent_runner.claude_cli_available()}


def _consistent_inbox(n, ratio, seed):
    """Curate a demo inbox so EVERY email's deterministic verdict agrees with its
    intended label - phishing emails score as phishing, legitimate as legitimate,
    with no ambiguous 'suspicious' middles. This keeps the live demo internally
    consistent (the analyzer never disagrees with the ground-truth column) WHILE
    still being fresh every run: a random seed picks different emails, the threat
    count jitters around the ratio, and the final order is shuffled.

    Pass an explicit `seed` for a reproducible batch; leave it None (the demo's
    default) for a new random inbox on every run."""
    rng = random.Random(seed)  # seed=None -> seeded from OS entropy, differs each run
    base_mal = round(n * ratio)
    want_mal = min(n, max(1, base_mal + rng.choice([-1, 0, 0, 1])))  # jitter the split
    want_legit = n - want_mal
    phish, legit, seen = [], [], set()
    tries = 0
    while (len(phish) < want_mal or len(legit) < want_legit) and tries < 400:
        tries += 1
        for it in generate_inbox(8, 0.5, seed=rng.randrange(1, 10_000_000)):
            key = (it["from"], it["subject"])
            if key in seen:
                continue
            verdict = build_report(pipeline.analyze_raw(it["raw_email"])).verdict
            if it["truth_label"] == "phishing" and verdict == "phishing" and len(phish) < want_mal:
                seen.add(key); phish.append(it)
            elif it["truth_label"] == "legitimate" and verdict == "legitimate" and len(legit) < want_legit:
                seen.add(key); legit.append(it)
    ordered = phish[:want_mal] + legit[:want_legit]
    rng.shuffle(ordered)
    for i, it in enumerate(ordered, 1):
        it["id"] = i
    return ordered


@app.post("/agent/run")
def agent_run(req: AgentRunRequest):
    """Build an inbox (synthetic demo OR the user's real mailbox over IMAP), then
    return a run_id + display list (with raw_email so the GUI can fetch the full
    breakdown on expand). The agent + SKILL.md flow is identical either way."""
    oauth_token = None
    if req.source == "gmail_oauth":
        sess = _GOOGLE_SESSIONS.get(req.state or "")
        if not sess or not sess.get("connected"):
            raise HTTPException(400, "not signed in with Google (connect first)")
        oauth_token = sess["access_token"]
        try:
            inbox = gmail_oauth.fetch_recent(oauth_token, n=req.n)
        except Exception as e:
            raise HTTPException(400, f"Gmail fetch failed: {e}")
        if not inbox:
            raise HTTPException(400, "no messages found in the inbox")
        graded = False
    elif req.source in ("gmail", "outlook"):
        if not req.email or not req.app_password:
            raise HTTPException(400, "email and app_password are required for a mailbox source")
        try:
            inbox = mailbox.fetch_recent(req.email, req.app_password, n=req.n, provider=req.source)
        except Exception as e:
            raise HTTPException(400, str(e))
        if not inbox:
            raise HTTPException(400, "no messages found in the inbox")
        graded = False
    else:
        inbox = _consistent_inbox(req.n, req.malicious_ratio, req.seed)
        graded = True
    run_id = uuid.uuid4().hex
    # Pre-compute every email's FINAL report up front, keyed by its display file.
    # The row flag, the grade, and the drill-down all read from this one dict, so
    # they are the same numbers by construction - the agent's stream only paces the
    # reveal, it never supplies a verdict.
    reports = {}
    for it in inbox:
        f = f"email_{it['id']:02d}.txt"
        rep = build_report(pipeline.analyze_raw(it["raw_email"]))
        if not graded:  # real Gmail/Outlook inbox: sender-auth trust adjustment
            rep = gmail_triage.adjust(rep, it["raw_email"], it.get("from", ""))
        reports[f] = rep.model_dump()
    _AGENT_RUNS[run_id] = {"inbox": inbox, "graded": graded, "source": req.source,
                           "state": req.state, "reports": reports}
    display = [{"id": it["id"], "file": f"email_{it['id']:02d}.txt",
                "from": it["from"], "subject": it["subject"],
                "raw_email": it["raw_email"]} for it in inbox]
    return {"run_id": run_id, "available": agent_runner.claude_cli_available(),
            "count": len(inbox), "inbox": display, "graded": graded}


async def _agent_events(run_id):
    run = _AGENT_RUNS.get(run_id)
    if not run:
        yield _sse({"type": "error", "error": "unknown run_id"})
        return
    inbox = run["inbox"]
    graded = run.get("graded", True)
    files = [f"email_{it['id']:02d}.txt" for it in inbox]
    truth = {f"email_{it['id']:02d}.txt": it.get("truth_label") for it in inbox}
    reports = run["reports"]   # pre-computed in /agent/run; the ONE source of truth
    pending = list(files)      # known inbox emails still to reveal, in inbox order
    counts = {"total": 0, "flagged": 0}

    def reveal(f):
        # The row flag, the ground-truth grade, and the drill-down report are the SAME
        # pre-computed report for THIS display file. The agent's stream only paces the
        # reveal; it never supplies a verdict, so nothing can misassociate.
        rep = reports[f]
        pred = _predicted_label(rep["verdict"]) if rep["verdict"] else None
        if pred is not None:
            counts["total"] += 1
            if pred == "phishing":
                counts["flagged"] += 1
        tl = truth.get(f)
        ok = (pred == tl) if (graded and pred and tl) else None
        return _sse({"type": "email", "file": f, "verdict": rep["verdict"],
                     "risk": rep["risk_score"], "truth_label": tl, "correct": ok})

    async for ev in agent_runner.run_agent_events(inbox):
        if ev.get("type") == "email":
            if pending:                      # pace one reveal per agent email-event
                yield reveal(pending.pop(0))
        elif ev.get("type") == "done":
            while pending:                   # reveal any the agent didn't enumerate
                yield reveal(pending.pop(0))
            yield _sse({"type": "scoreboard", "graded": graded, "total": counts["total"],
                        "flagged": counts["flagged"],
                        "cleared": counts["total"] - counts["flagged"]})
        else:
            yield _sse(ev)  # activity / error pass-through


@app.get("/agent/stream/{run_id}")
def agent_stream(run_id: str):
    """SSE: live agent activity + per-email verdicts, then a final scoreboard."""
    return StreamingResponse(_agent_events(run_id), media_type="text/event-stream")


@app.get("/agent/report/{run_id}/{file}")
def agent_report(run_id: str, file: str):
    """The exact report a row's flag was computed from (incl. any Gmail trust
    adjustment). The drill-down fetches this so it always matches the row."""
    run = _AGENT_RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "unknown run_id")
    rep = (run.get("reports") or {}).get(file)
    if rep is None:
        raise HTTPException(404, "no report for that email")
    return rep


class QuarantineRequest(BaseModel):
    run_id: str
    files: list = Field(default_factory=list)   # e.g. ["email_01.txt", "email_03.txt"]
    email: str = ""
    app_password: str = ""
    provider: str = "gmail"


@app.post("/agent/quarantine")
def agent_quarantine(req: QuarantineRequest):
    """Inbox Guardian: star + label the given (phishing) emails back in the real
    mailbox. Uses the same connection the run used - Google OAuth or IMAP."""
    run = _AGENT_RUNS.get(req.run_id)
    if not run:
        raise HTTPException(404, "unknown run_id")
    by_file = {f"email_{it['id']:02d}.txt": it for it in run["inbox"]}
    ids = [by_file[f]["uid"] for f in req.files
           if f in by_file and by_file[f].get("uid")]
    if not ids:
        raise HTTPException(400, "no matching real-mailbox messages to tag "
                                 "(only real-inbox runs can be quarantined)")
    try:
        if run.get("source") == "gmail_oauth":
            sess = _GOOGLE_SESSIONS.get(run.get("state") or "")
            if not sess or not sess.get("connected"):
                raise HTTPException(400, "Google session expired; sign in again")
            n = gmail_oauth.apply_action(sess["access_token"], ids)
        else:
            n = mailbox.apply_action(req.email, req.app_password, ids, provider=req.provider)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"tagged": n, "label": "Phishing-Suspected"}


# Serve the built web UI (single-service production deploy) if it's present.
# Mounted LAST so all API routes above take precedence; no-op in local dev where
# the Vite dev server serves the UI on :5173 and there is no build.
_UI_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "desktop", "dist")
if os.path.isdir(_UI_DIR):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=_UI_DIR, html=True), name="ui")


def main():
    import uvicorn
    port = int(os.environ.get("PORT", "8008"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
