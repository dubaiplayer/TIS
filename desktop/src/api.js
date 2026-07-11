// Client for the local FastAPI backend. Distinguishes "server unreachable"
// (connection refused -> the Python server isn't running) from HTTP errors, so
// the UI can show a clear, actionable message instead of failing silently.
export const BASE = "http://127.0.0.1:8008";

export class ServerDownError extends Error {}

export async function checkHealth() {
  try {
    const r = await fetch(`${BASE}/health`, { method: "GET" });
    return r.ok;
  } catch {
    return false;
  }
}

export async function analyzeEmail(text) {
  let res;
  try {
    res = await fetch(`${BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
  } catch {
    // fetch throws (TypeError) on connection refused -> server not running.
    throw new ServerDownError(
      "Can't reach the analyzer server on 127.0.0.1:8008. Start the Python backend " +
      "(see run instructions) and try again."
    );
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`Analyzer error (HTTP ${res.status}). ${detail}`.trim());
  }
  return res.json();
}

// ---- Inbox Simulator ----

export async function simAgentStatus() {
  try {
    const r = await fetch(`${BASE}/sim/agent_status`);
    if (!r.ok) return { agent_available: false };
    return r.json();
  } catch {
    return { agent_available: false, unreachable: true };
  }
}

export async function simRun({ n = 8, malicious_ratio = 0.5, seed = null, use_agent = true } = {}) {
  let res;
  try {
    res = await fetch(`${BASE}/sim/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ n, malicious_ratio, seed, use_agent }),
    });
  } catch {
    throw new ServerDownError(
      "Can't reach the analyzer server on 127.0.0.1:8008. Start the Python backend first."
    );
  }
  if (!res.ok) throw new Error(`Inbox run failed (HTTP ${res.status}).`);
  return res.json();
}

// SSE URL for streaming per-email results (consume with EventSource).
export function simStreamUrl(runId) {
  return `${BASE}/sim/stream/${runId}`;
}

// ---- Live Agent (headless Claude Code reads a local SKILL.md, calls /analyze) ----

export async function agentStatus() {
  try {
    const r = await fetch(`${BASE}/agent/status`);
    return r.ok ? r.json() : { available: false };
  } catch {
    return { available: false, unreachable: true };
  }
}

export async function agentRun({
  n = 6, malicious_ratio = 0.5, seed = null,
  source = "synthetic", email = null, app_password = null,
} = {}) {
  let res;
  try {
    res = await fetch(`${BASE}/agent/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ n, malicious_ratio, seed, source, email, app_password }),
    });
  } catch {
    throw new ServerDownError(
      "Can't reach the analyzer server on 127.0.0.1:8008. Start the Python backend first."
    );
  }
  if (!res.ok) {
    let detail = "";
    try { detail = (await res.json()).detail || ""; } catch { /* ignore */ }
    throw new Error(detail || `Agent run failed (HTTP ${res.status}).`);
  }
  return res.json();
}

export function agentStreamUrl(runId) {
  return `${BASE}/agent/stream/${runId}`;
}

// ---- Inbox-aware analyze (real Gmail/Outlook messages; adds sender-auth trust) ----
export async function analyzeInboxEmail(text, from_addr = "") {
  let res;
  try {
    res = await fetch(`${BASE}/analyze/inbox`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, from_addr }),
    });
  } catch {
    throw new ServerDownError("Can't reach the analyzer server on 127.0.0.1:8008.");
  }
  if (!res.ok) throw new Error(`Analyze failed (HTTP ${res.status}).`);
  return res.json();
}

// ---- Link X-ray (unmask where links really go) ----
export async function xrayEmail(text) {
  let res;
  try {
    res = await fetch(`${BASE}/xray`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
  } catch {
    throw new ServerDownError("Can't reach the analyzer server on 127.0.0.1:8008.");
  }
  if (!res.ok) throw new Error(`Link X-ray failed (HTTP ${res.status}).`);
  return res.json();
}

// ---- Inbox Guardian (tag phishing back in the real mailbox) ----
export async function quarantine({ run_id, files, email, app_password, provider = "gmail" }) {
  let res;
  try {
    res = await fetch(`${BASE}/agent/quarantine`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run_id, files, email, app_password, provider }),
    });
  } catch {
    throw new ServerDownError("Can't reach the analyzer server on 127.0.0.1:8008.");
  }
  if (!res.ok) {
    let detail = "";
    try { detail = (await res.json()).detail || ""; } catch { /* ignore */ }
    throw new Error(detail || `Quarantine failed (HTTP ${res.status}).`);
  }
  return res.json();
}
