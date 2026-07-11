// Live Agent view.
//
// A real headless Claude Code agent (spawned by the local backend) reads a local
// SKILL.md and calls /analyze for every generated email. This view streams the
// agent's activity on the right, updates the inbox verdicts on the left as they
// land, and expands any email into the full analysis (including the new real-world
// detectors) fetched from the same local API.
import { useCallback, useEffect, useRef, useState } from "react";
import { agentRun, agentStreamUrl, analyzeEmail, ServerDownError } from "../api";
import RiskBanner from "./RiskBanner";
import AttributeBarChart from "./AttributeBarChart";
import KeywordHighlight from "./KeywordHighlight";
import AttributeList from "./AttributeList";

const VERDICT_COLOR = { phishing: "#ff453a", suspicious: "#ff9f0a", legitimate: "#30d158" };
const N = 6;

export default function AgentInbox() {
  const [rows, setRows] = useState([]);        // {id,file,from,subject,raw_email,...}
  const [activity, setActivity] = useState([]); // {kind,text}
  const [board, setBoard] = useState(null);
  const [available, setAvailable] = useState(true);
  const [status, setStatus] = useState("idle"); // idle | running | done | error
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const [reports, setReports] = useState({});   // file -> full report
  const esRef = useRef(null);
  const doneRef = useRef(false);
  const gotDataRef = useRef(false);
  const feedRef = useRef(null);

  const stop = () => { if (esRef.current) { esRef.current.close(); esRef.current = null; } };

  const run = useCallback(async () => {
    stop();
    doneRef.current = false; gotDataRef.current = false;
    setError(null); setBoard(null); setExpanded(null); setReports({});
    setRows([]); setActivity([]); setStatus("running");
    let info;
    try {
      info = await agentRun({ n: N });
    } catch (e) {
      setStatus("error");
      setError(e instanceof ServerDownError ? e.message : `Failed to start: ${e.message}`);
      return;
    }
    setAvailable(info.available);
    if (!info.available) {
      setStatus("error");
      setError("The 'claude' CLI wasn't found by the backend. Install Claude Code, run "
               + "'claude login', and restart the Python backend.");
      return;
    }
    setRows(info.inbox.map((m) => ({ ...m, pending: true })));

    const es = new EventSource(agentStreamUrl(info.run_id));
    esRef.current = es;
    es.onmessage = (ev) => {
      gotDataRef.current = true;
      const e = JSON.parse(ev.data);
      if (e.type === "activity") {
        setActivity((prev) => [...prev, { kind: e.kind, text: e.text }].slice(-200));
      } else if (e.type === "email") {
        setRows((prev) => prev.map((r) => (r.file === e.file
          ? { ...r, verdict: e.verdict, risk: e.risk, truth_label: e.truth_label,
              correct: e.correct, pending: false } : r)));
      } else if (e.type === "scoreboard") {
        doneRef.current = true; setBoard(e); setStatus("done"); stop();
      } else if (e.type === "error") {
        setError(e.error); setStatus("error"); stop();
      }
    };
    es.onerror = () => {
      if (doneRef.current) { stop(); return; }
      if (!gotDataRef.current) {
        setStatus("error");
        setError("Lost connection to the agent stream. Is the local backend (uvicorn on "
                 + "port 8008) running?");
      }
      stop();
    };
  }, []);

  useEffect(() => { run(); return stop; }, []); // auto-run on open

  // keep the activity feed scrolled to the newest line
  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [activity]);

  const toggle = async (r) => {
    if (r.pending) return;
    const next = expanded === r.file ? null : r.file;
    setExpanded(next);
    if (next && !reports[r.file] && r.raw_email) {
      try {
        const rep = await analyzeEmail(r.raw_email);
        setReports((prev) => ({ ...prev, [r.file]: rep }));
      } catch { /* leave unexpanded content */ }
    }
  };

  return (
    <div className="sim">
      <div className="sim-bar">
        <div className="sim-title">
          Live Agent
          <span className={`agent-pill ${available ? "on" : "off"}`}>
            {available ? "● LIVE AGENT via SKILL.md" : "● claude CLI not found"}
          </span>
        </div>
        <div className="sim-actions">
          <button className="analyze-btn" onClick={run} disabled={status === "running"}>
            {status === "running" ? "Agent running…" : "Regenerate + run"}
          </button>
        </div>
      </div>

      <div className="hosted-note">
        A real headless agent reads a <b>SKILL.md</b> and calls the analyzer itself for
        every randomly generated email — you type nothing. Its steps stream on the right;
        click any email for the full breakdown.
      </div>
      {error && <div className="error-box">{error}</div>}

      {board && (
        <div className="scoreboard">
          <div className="score-main">
            <span className="score-acc">{Math.round(board.accuracy * 100)}%</span>
            <span className="score-sub">agent accuracy · {board.correct}/{board.total} correct</span>
          </div>
          <div className="score-detail">
            <span>false positives: {board.false_positives}</span>
            <span>false negatives: {board.false_negatives}</span>
            <span>driven by: the agent + SKILL.md</span>
          </div>
        </div>
      )}

      <div className="agent-grid">
        <div className="inbox">
          {rows.map((r) => (
            <div key={r.file} className="mail">
              <div className="mail-head" onClick={() => toggle(r)}>
                <span className="mail-status">
                  {r.pending ? <span className="spinner" />
                    : <span className="verdict-dot" style={{ background: VERDICT_COLOR[r.verdict] }} />}
                </span>
                <div className="mail-meta">
                  <div className="mail-subject">{r.subject}</div>
                  <div className="mail-from">{r.from}</div>
                </div>
                <div className="mail-right">
                  {!r.pending && (
                    <>
                      <span className="verdict-tag" style={{ color: VERDICT_COLOR[r.verdict] }}>
                        {r.verdict} {r.risk != null && `· ${Math.round(r.risk * 100)}%`}
                      </span>
                      {r.truth_label && (
                        <span className="truth-mark" title={`ground truth: ${r.truth_label}`}>
                          {r.correct ? "✓" : "✗"} {r.truth_label}
                        </span>
                      )}
                    </>
                  )}
                </div>
              </div>
              {expanded === r.file && reports[r.file] && (
                <div className="mail-body">
                  <RiskBanner report={reports[r.file]} />
                  <AttributeBarChart attributes={reports[r.file].attributes} />
                  <KeywordHighlight report={reports[r.file]} />
                  <AttributeList attributes={reports[r.file].attributes} />
                </div>
              )}
            </div>
          ))}
        </div>

        <div className="agent-feed-wrap">
          <div className="agent-feed-title">Agent activity</div>
          <div className="agent-feed" ref={feedRef}>
            {activity.length === 0 && <div className="muted small">waiting for the agent…</div>}
            {activity.map((a, i) => (
              <div key={i} className={`feed-line feed-${a.kind}`}>
                <span className="feed-kind">{a.kind}</span> {a.text}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
