import { useCallback, useEffect, useRef, useState } from "react";
import { analyzeEmail, checkHealth, ServerDownError } from "./api";
import RiskBanner from "./components/RiskBanner";
import AttributeBarChart from "./components/AttributeBarChart";
import KeywordHighlight from "./components/KeywordHighlight";
import AttributeList from "./components/AttributeList";
import InboxSimulator from "./components/InboxSimulator";
import AgentInbox from "./components/AgentInbox";
import LinkXray from "./components/LinkXray";

const AUTO_DELAY = 800; // ms after typing/paste stops
// Hosted web build: the Live Agent spawns the local `claude` CLI, which a server
// can't do, so that tab is hidden online. Set VITE_HOSTED=1 for the deployed build.
const HOSTED = import.meta.env.VITE_HOSTED === "1";

export default function App() {
  const [text, setText] = useState("");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [serverUp, setServerUp] = useState(true);
  const [auto, setAuto] = useState(true);
  const [mode, setMode] = useState("float");
  const [view, setView] = useState("analyze"); // "analyze" | "inbox"
  const timer = useRef(null);

  // Poll health so we can warn early if the backend isn't running.
  useEffect(() => {
    let alive = true;
    const ping = async () => { if (alive) setServerUp(await checkHealth()); };
    ping();
    const id = setInterval(ping, 5000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const run = useCallback(async (value) => {
    const body = value.trim();
    if (!body) { setReport(null); setError(null); return; }
    setLoading(true); setError(null);
    try {
      setReport(await analyzeEmail(body));
      setServerUp(true);
    } catch (e) {
      setReport(null);
      setError(e.message);
      if (e instanceof ServerDownError) setServerUp(false);
    } finally {
      setLoading(false);
    }
  }, []);

  // Debounced auto-analyze.
  const onChange = (v) => {
    setText(v);
    if (!auto) return;
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => run(v), AUTO_DELAY);
  };

  const setWindow = async (m) => {
    setMode(m);
    if (window.appWindow) await window.appWindow[m]();
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="title">🎣 Phishing Analyzer</div>
        <div className="tabs">
          <button className={view === "analyze" ? "seg on" : "seg"}
                  onClick={() => setView("analyze")}>Analyze</button>
          {!HOSTED && (
            <button className={view === "agent" ? "seg on" : "seg"}
                    onClick={() => setView("agent")}>Live Agent</button>
          )}
          <button className={view === "inbox" ? "seg on" : "seg"}
                  onClick={() => setView("inbox")}>Inbox Sim</button>
        </div>
        <div className="controls">
          <label className="auto-toggle">
            <input type="checkbox" checked={auto}
                   onChange={(e) => setAuto(e.target.checked)} /> auto
          </label>
          <button className={mode === "float" ? "seg on" : "seg"}
                  onClick={() => setWindow("float")}>Float</button>
          <button className={mode === "dock" ? "seg on" : "seg"}
                  onClick={() => setWindow("dock")}>Dock ▸</button>
        </div>
      </header>

      {!serverUp && (
        <div className="server-warn">
          ⚠ Backend not detected on 127.0.0.1:8008 — start the Python server (see README).
        </div>
      )}

      {view === "agent" && !HOSTED ? (
        <AgentInbox />
      ) : view === "inbox" ? (
        <InboxSimulator />
      ) : (
        <>
          <section className="input-area">
            <textarea
              className="paste"
              placeholder="Paste an email here (headers + body, or just the body)…"
              value={text}
              onChange={(e) => onChange(e.target.value)}
              spellCheck={false}
            />
            <div className="actions">
              <button className="analyze-btn" onClick={() => run(text)} disabled={loading || !text.trim()}>
                {loading ? "Analyzing…" : "Analyze"}
              </button>
              {loading && <span className="spinner" aria-label="loading" />}
            </div>
          </section>

          {error && <div className="error-box">{error}</div>}

          {report && !loading && (
            <section className="results">
              <RiskBanner report={report} />
              <LinkXray text={text} />
              <AttributeBarChart attributes={report.attributes} />
              <KeywordHighlight report={report} />
              <AttributeList attributes={report.attributes} />
              {report.meta?.notes?.length > 0 && (
                <p className="muted small">Notes: {report.meta.notes.join("; ")}</p>
              )}
            </section>
          )}

          {!report && !loading && !error && (
            <div className="empty">Paste an email above to see its phishing breakdown.</div>
          )}
        </>
      )}
    </div>
  );
}
