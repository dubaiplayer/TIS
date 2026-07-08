// Color-coded overall verdict banner + risk meter.
const VERDICT_STYLE = {
  phishing: { bg: "#3a1416", border: "#ef4444", label: "PHISHING", fg: "#fca5a5" },
  suspicious: { bg: "#3a2f14", border: "#f59e0b", label: "SUSPICIOUS", fg: "#fcd34d" },
  legitimate: { bg: "#12301f", border: "#22c55e", label: "LEGITIMATE", fg: "#86efac" },
};

export default function RiskBanner({ report }) {
  const s = VERDICT_STYLE[report.verdict] || VERDICT_STYLE.suspicious;
  const pct = Math.round(report.risk_score * 100);
  return (
    <div className="banner" style={{ background: s.bg, borderColor: s.border }}>
      <div className="banner-head">
        <span className="banner-verdict" style={{ color: s.fg }}>{s.label}</span>
        <span className="banner-risk" style={{ color: s.fg }}>risk {pct}%</span>
      </div>
      <div className="meter">
        <div className="meter-fill" style={{ width: `${pct}%`, background: s.border }} />
      </div>
      <p className="banner-summary">{report.summary}</p>
    </div>
  );
}
