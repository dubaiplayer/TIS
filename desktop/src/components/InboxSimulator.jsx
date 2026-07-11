// Autonomous Inbox Simulator.
//
// On open it asks the backend to generate a labeled inbox, then streams per-email
// results (via SSE) as the analyzer/agent works through them — no user action. A
// live scoreboard grades OUR model's verdict against the generator's ground truth.
// Each row expands to the full breakdown, reusing the existing result components.
import { useCallback, useEffect, useRef, useState } from "react";
import { simRun, simStreamUrl, ServerDownError } from "../api";
import RiskBanner from "./RiskBanner";
import AttributeBarChart from "./AttributeBarChart";
import KeywordHighlight from "./KeywordHighlight";
import AttributeList from "./AttributeList";

const VERDICT_COLOR = { phishing: "#ff453a", suspicious: "#ff9f0a", legitimate: "#30d158" };
const N = 8;

export default function InboxSimulator() {
  const [rows, setRows] = useState([]);          // {id, from, subject, ...result}
  const [board, setBoard] = useState(null);
  const [agentAvailable, setAgentAvailable] = useState(false);
  const [useAgent, setUseAgent] = useState(true);
  const [status, setStatus] = useState("idle");  // idle | running | done | error
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const esRef = useRef(null);
  const doneRef = useRef(false);
  const gotDataRef = useRef(false);

  const stop = () => { if (esRef.current) { esRef.current.close(); esRef.current = null; } };

  const run = useCallback(async () => {
    stop();
    doneRef.current = false; gotDataRef.current = false;
    setError(null); setBoard(null); setExpanded(null); setRows([]); setStatus("running");
    let info;
    try {
      info = await simRun({ n: N, malicious_ratio: 0.5, use_agent: useAgent });
    } catch (e) {
      setStatus("error");
      setError(e instanceof ServerDownError ? e.message : `Failed to start: ${e.message}`);
      return;
    }
    setAgentAvailable(info.agent_available);
    setRows(info.inbox.map((m) => ({ ...m, pending: true })));

    const es = new EventSource(simStreamUrl(info.run_id));
    esRef.current = es;
    es.onmessage = (ev) => {
      gotDataRef.current = true;
      const e = JSON.parse(ev.data);
      if (e.type === "email") {
        setRows((prev) => prev.map((r) => (r.id === e.id ? { ...r, ...e, pending: false } : r)));
      } else if (e.type === "scoreboard") {
        doneRef.current = true; setBoard(e); setStatus("done"); stop();
      } else if (e.type === "error") {
        setError(e.error); setStatus("error"); stop();
      }
      // e.type === "status" (warm-up) just keeps the stream alive; ignore.
    };
    es.onerror = () => {
      // EventSource fires this on the normal end-of-stream close too. Only treat
      // it as a real failure if we never finished AND never received any data.
      if (doneRef.current) { stop(); return; }
      if (!gotDataRef.current) {
        setStatus("error");
        setError("Lost connection to the analysis stream. Is the local harness "
                 + "(uvicorn on port 8008) running? Restart it and reopen this tab.");
      }
      stop();
    };
  }, [useAgent]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { run(); return stop; }, []); // auto-run on open

  return (
    <div className="sim">
      <div className="sim-bar">
        <div className="sim-title">
          Autonomous Inbox
          <span className={`agent-pill ${agentAvailable ? "on" : "off"}`}>
            {agentAvailable ? "● LIVE AGENT" : "● model-only"}
          </span>
        </div>
        <div className="sim-actions">
          <label className="auto-toggle" title="Use the LLM agent to drive scanning (needs ANTHROPIC_API_KEY)">
            <input type="checkbox" checked={useAgent}
                   onChange={(e) => setUseAgent(e.target.checked)} /> agent
          </label>
          <button className="analyze-btn" onClick={run} disabled={status === "running"}>
            {status === "running" ? "Scanning…" : "Regenerate inbox"}
          </button>
        </div>
      </div>

      <div className="hosted-note">
        Every email is randomly generated and sent to your <b>deployed API</b> for
        analysis — fully automated, no input from you.
      </div>
      {error && <div className="error-box">{error}</div>}

      {board && (
        <div className="scoreboard">
          <div className="score-main">
            <span className="score-acc">{Math.round(board.accuracy * 100)}%</span>
            <span className="score-sub">accuracy via deployed API · {board.correct}/{board.total} correct</span>
          </div>
          <div className="score-detail">
            <span>false positives: {board.false_positives}</span>
            <span>false negatives: {board.false_negatives}</span>
            <span>analyzed via: {board.source}</span>
          </div>
        </div>
      )}

      <div className="inbox">
        {rows.map((r) => (
          <div key={r.id} className="mail">
            <div className="mail-head" onClick={() => r.report && setExpanded(expanded === r.id ? null : r.id)}>
              <span className="mail-status">
                {r.pending ? <span className="spinner" />
                  : <span className="verdict-dot" style={{ background: VERDICT_COLOR[r.verdict] }} />}
              </span>
              <div className="mail-meta">
                <div className="mail-subject">{r.subject}</div>
                <div className="mail-from">{r.from}</div>
                {r.agent && r.agent.rationale && (
                  <div className="mail-rationale">🤖 {r.agent.rationale}</div>
                )}
              </div>
              <div className="mail-right">
                {!r.pending && (
                  <>
                    <span className="verdict-tag" style={{ color: VERDICT_COLOR[r.verdict] }}>
                      {r.verdict} {r.risk_score != null && `· ${Math.round(r.risk_score * 100)}%`}
                    </span>
                    <span className="truth-mark" title={`ground truth: ${r.truth_label}`}>
                      {r.correct ? "✓" : "✗"} {r.truth_label}
                    </span>
                    {r.source && (
                      <span className="src-tag" title="analyzed by the deployed API">
                        ⬤ {r.source === "hosted" ? "hosted API" : r.source}
                      </span>
                    )}
                  </>
                )}
              </div>
            </div>
            {expanded === r.id && r.report && (
              <div className="mail-body">
                <RiskBanner report={r.report} />
                <AttributeBarChart attributes={r.report.attributes} />
                <KeywordHighlight report={r.report} />
                <AttributeList attributes={r.report.attributes} />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
