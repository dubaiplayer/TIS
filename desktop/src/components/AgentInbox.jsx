// Live Agent view.
//
// A real headless Claude Code agent (spawned by the local backend) reads a local
// SKILL.md and calls /analyze for every email. The inbox is either a synthetic
// demo batch OR the user's REAL mailbox fetched over IMAP ("My Gmail") - the
// agent + SKILL.md flow is identical either way. Activity streams on the right,
// verdicts fill in on the left, and any email expands to the full breakdown.
import { useCallback, useEffect, useRef, useState } from "react";
import { agentRun, agentReport, agentStreamUrl, analyzeEmail, analyzeInboxEmail,
  quarantine, startGoogleAuth, googleStatus, ServerDownError } from "../api";
import RiskBanner from "./RiskBanner";
import AttributeBarChart from "./AttributeBarChart";
import KeywordHighlight from "./KeywordHighlight";
import AttributeList from "./AttributeList";
import LinkXray from "./LinkXray";

const VERDICT_COLOR = { phishing: "#ff453a", suspicious: "#ff9f0a", legitimate: "#30d158" };
const N = 6;

export default function AgentInbox() {
  const [rows, setRows] = useState([]);
  const [activity, setActivity] = useState([]);
  const [board, setBoard] = useState(null);
  const [available, setAvailable] = useState(true);
  const [status, setStatus] = useState("idle");
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const [reports, setReports] = useState({});
  const [source, setSource] = useState("synthetic"); // "synthetic" | "gmail_oauth"
  const [gEmail, setGEmail] = useState("");          // connected Google account
  const [gState, setGState] = useState(null);        // OAuth session id
  const [gConnecting, setGConnecting] = useState(false);
  const [runId, setRunId] = useState(null);
  const [guardMsg, setGuardMsg] = useState(null);
  const pollRef = useRef(null);
  const esRef = useRef(null);
  const doneRef = useRef(false);
  const gotDataRef = useRef(false);
  const feedRef = useRef(null);

  const stop = () => { if (esRef.current) { esRef.current.close(); esRef.current = null; } };

  const run = useCallback(async (opts = {}) => {
    stop();
    doneRef.current = false; gotDataRef.current = false;
    setError(null); setBoard(null); setExpanded(null); setReports({});
    setRows([]); setActivity([]); setStatus("running"); setGuardMsg(null); setRunId(null);
    let info;
    try {
      info = await agentRun({ n: N, ...opts });
    } catch (e) {
      setStatus("error");
      setError(e instanceof ServerDownError ? e.message : e.message);
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
    setRunId(info.run_id);

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

  useEffect(() => { run(); return stop; }, []); // auto-run the demo on open

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [activity]);

  const toggle = async (r) => {
    if (r.pending) return;
    const next = expanded === r.file ? null : r.file;
    setExpanded(next);
    if (next && !reports[r.file] && r.raw_email) {
      try {
        // The drill-down shows the EXACT report the row flag came from - never a
        // fresh re-analysis, which is what used to diverge. For an agent run we only
        // ever read the cached report; if it's somehow missing we leave it unexpanded
        // rather than render a contradictory verdict.
        const rep = runId
          ? await agentReport(runId, r.file)
          : (source === "gmail_oauth"
              ? await analyzeInboxEmail(r.raw_email, r.from)
              : await analyzeEmail(r.raw_email));
        setReports((prev) => ({ ...prev, [r.file]: rep }));
      } catch { /* leave unexpanded content */ }
    }
  };

  const signInGoogle = async () => {
    setError(null); setGConnecting(true); setGEmail("");
    if (pollRef.current) clearInterval(pollRef.current);
    try {
      const { auth_url, state } = await startGoogleAuth();
      setGState(state);
      window.open(auth_url, "_blank", "noopener,noreferrer"); // consent in the browser
      pollRef.current = setInterval(async () => {
        const st = await googleStatus(state);
        if (st.connected) {
          clearInterval(pollRef.current); pollRef.current = null;
          setGEmail(st.email); setGConnecting(false);
        }
      }, 1500);
    } catch (e) {
      setGConnecting(false);
      setError(e.message);
    }
  };

  const runGmail = () => run({ source: "gmail_oauth", state: gState });

  const quarantinePhishing = async () => {
    const files = rows.filter((r) => r.verdict === "phishing").map((r) => r.file);
    if (!files.length) { setGuardMsg("No phishing emails to flag."); return; }
    setGuardMsg("Tagging in Gmail…");
    try {
      const res = await quarantine({ run_id: runId, files });
      setGuardMsg(`✓ Flagged ${res.tagged} email(s) in Gmail with the "${res.label}" label `
                  + "(starred + labeled — reversible, nothing deleted).");
    } catch (e) {
      setGuardMsg(`Failed: ${e.message}`);
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
          <div className="tabs">
            <button className={source === "synthetic" ? "seg on" : "seg"}
                    onClick={() => { setSource("synthetic"); run(); }}>Demo inbox</button>
            <button className={source === "gmail_oauth" ? "seg on" : "seg"}
                    onClick={() => setSource("gmail_oauth")}>My Gmail</button>
          </div>
          {source === "synthetic" && (
            <button className="analyze-btn" onClick={() => run()} disabled={status === "running"}>
              {status === "running" ? "Agent running…" : "Regenerate + run"}
            </button>
          )}
        </div>
      </div>

      {source === "gmail_oauth" && (
        <div className="connect">
          <div className="connect-row">
            {!gEmail ? (
              <button className="gsignin" onClick={signInGoogle} disabled={gConnecting}>
                <span className="gmark">G</span>
                {gConnecting ? "Waiting for Google…" : "Sign in with Google"}
              </button>
            ) : (
              <>
                <span className="connected-as">Connected as <b>{gEmail}</b></span>
                <button className="analyze-btn" onClick={runGmail} disabled={status === "running"}>
                  {status === "running" ? "Analyzing…" : "Analyze my inbox"}
                </button>
                <button className="seg" onClick={signInGoogle}>Switch account</button>
              </>
            )}
          </div>
          <div className="connect-hint">
            {gConnecting
              ? <>A Google sign-in tab opened in your browser — approve access, then come back here.</>
              : <>Secure <b>Sign in with Google</b> — no password is ever entered here. The agent reads
                 your most recent emails to triage them; the connection stays in this local app only
                 and nothing is deleted.</>}
          </div>
        </div>
      )}

      <div className="hosted-note">
        {source === "gmail_oauth"
          ? <>A real agent reads your <b>actual inbox</b> via the Gmail API and analyzes each email
             with the same SKILL.md. Its steps stream on the right; click any email for the breakdown.</>
          : <>A real headless agent reads a <b>SKILL.md</b> and calls the analyzer itself for every
             randomly generated email — you type nothing. Steps stream on the right.</>}
      </div>
      {error && <div className="error-box">{error}</div>}

      {board && (
        <div className="scoreboard">
          <div className="score-main">
            <span className="score-acc">{board.flagged}</span>
            <span className="score-sub">
              {board.flagged === 1 ? "threat" : "threats"} caught · {board.total} emails triaged live by the agent via SKILL.md
            </span>
          </div>
          <div className="score-detail">
            <span>{board.cleared} legitimate cleared</span>
            {board.graded && <span className="score-perfect">✓ every email classified correctly</span>}
            <span>driven by: the agent + SKILL.md</span>
          </div>
        </div>
      )}

      {board && source === "gmail_oauth" && (
        <div className="guardian">
          <button className="analyze-btn" onClick={quarantinePhishing}
                  disabled={!rows.some((r) => r.verdict === "phishing")}>
            🛡 Flag phishing in my Gmail
          </button>
          <span className="guardian-hint">
            Stars + labels the flagged emails "Phishing-Suspected" in your inbox — reversible, nothing deleted.
          </span>
          {guardMsg && <div className="guardian-msg">{guardMsg}</div>}
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
                  <LinkXray text={r.raw_email} />
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
