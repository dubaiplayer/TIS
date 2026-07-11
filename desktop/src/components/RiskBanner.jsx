// Color-coded overall verdict banner + risk meter.
const VERDICT_STYLE = {
  phishing: { bg: "rgba(255,69,58,0.12)", border: "#ff453a", label: "PHISHING", fg: "#ff6b6b" },
  suspicious: { bg: "rgba(255,159,10,0.12)", border: "#ff9f0a", label: "SUSPICIOUS", fg: "#ffcf70" },
  legitimate: { bg: "rgba(48,209,88,0.12)", border: "#30d158", label: "LEGITIMATE", fg: "#5be584" },
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
      {report.action && (
        <div className="banner-action">
          <span className="action-badge" style={{ color: s.fg, borderColor: s.border }}>
            {report.action}
          </span>
          {report.recommendation && <span className="action-reco">{report.recommendation}</span>}
        </div>
      )}
    </div>
  );
}
