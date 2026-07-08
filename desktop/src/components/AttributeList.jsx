// Expandable per-attribute rows. Click a row to reveal its explanation and the
// exact evidence snippets (spans) that triggered it — same evidence design as the
// CLI. Sorted by score; only fired attributes expand to evidence.
import { useState } from "react";

function scoreColor(s) {
  if (s >= 0.66) return "#ef4444";
  if (s >= 0.33) return "#f59e0b";
  if (s > 0) return "#eab308";
  return "#3f4956";
}

function Row({ attr }) {
  const [open, setOpen] = useState(false);
  const has = attr.evidence && attr.evidence.length > 0;
  return (
    <div className={`attr-row ${has ? "clickable" : ""}`}>
      <div className="attr-head" onClick={() => has && setOpen(!open)}>
        <span className="attr-caret">{has ? (open ? "▾" : "▸") : "·"}</span>
        <span className="attr-name">{attr.name}</span>
        <span className="attr-score-pill"
              style={{ background: scoreColor(attr.score) }}>{attr.score.toFixed(2)}</span>
        <span className="attr-label muted">{attr.label}</span>
      </div>
      {open && (
        <div className="attr-body">
          <p className="attr-expl">{attr.explanation}</p>
          {has && (
            <ul className="evidence">
              {attr.evidence.slice(0, 12).map((e, i) => (
                <li key={i}><code>{e.text}</code>
                  <span className="muted small"> @{e.start}–{e.end}</span></li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

export default function AttributeList({ attributes }) {
  const sorted = [...attributes].sort((a, b) => b.score - a.score);
  return (
    <div className="card">
      <h3>Attributes <span className="muted">(click to expand evidence)</span></h3>
      {sorted.map((a) => <Row key={a.name} attr={a} />)}
    </div>
  );
}
