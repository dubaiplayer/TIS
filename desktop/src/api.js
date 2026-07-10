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
