// Link X-ray — unmask where an email's links REALLY go.
// Follows redirects to the true destination and shows domain age + blocklist hits.
import { useState } from "react";
import { xrayEmail } from "../api";

export default function LinkXray({ text }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  const run = async () => {
    setLoading(true); setErr(null);
    try { setData(await xrayEmail(text)); }
    catch (e) { setErr(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="card">
      <h3>Link X-ray <span className="muted">(unmask where links really go)</span></h3>
      {!data && !loading && (
        <button className="analyze-btn" onClick={run}>🔗 Run Link X-ray</button>
      )}
      {loading && (
        <div className="xray-loading"><span className="spinner" /> following the links…</div>
      )}
      {err && <div className="error-box">{err}</div>}
      {data && (
        <>
          <p className="xray-summary">{data.summary}</p>
          {data.links.map((l, i) => (
            <div key={i} className={`xray-link ${l.suspicious_reasons.length ? "risky" : "ok"}`}>
              <div className="xray-url">{l.url}</div>
              <div className="xray-arrow">
                ↳ {l.final_url}
                {l.redirect_hops > 0 && ` (${l.redirect_hops} redirect${l.redirect_hops > 1 ? "s" : ""})`}
              </div>
              <div className="xray-facts">
                <span>domain: {l.destination_domain}</span>
                {l.domain_age_days != null && (
                  <span className={l.domain_age_days <= 30 ? "warn-txt" : ""}>age: {l.domain_age_days}d</span>
                )}
                {l.on_blocklist && <span className="warn-txt">⚑ {l.blocklist_source}</span>}
              </div>
              {l.suspicious_reasons.length > 0 && (
                <div className="xray-reasons">⚠ {l.suspicious_reasons.join("; ")}</div>
              )}
            </div>
          ))}
        </>
      )}
    </div>
  );
}
