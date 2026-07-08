// Client for the local FastAPI backend. Distinguishes "server unreachable"
// (connection refused -> the Python server isn't running) from HTTP errors, so
// the UI can show a clear, actionable message instead of failing silently.
const BASE = "http://127.0.0.1:8008";

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
