// Service worker: the only place allowed to reach the analyzer (a content script's
// fetch is blocked by Gmail's CSP/CORS). Content script -> here -> hosted API.
const DEFAULT_BASE = "https://phishing-analyzer-api-wq1v.onrender.com";
const cache = new Map(); // msgId -> report (per-session, avoids re-analyzing)

// A free-tier host spins the instance down after ~15 min idle, and the next request
// pays a 30-60s start-up. At the fetch layer that is indistinguishable from a dead
// service, so every failure is classified into a STATE the caller can act on:
//   waking    — transient, keep retrying (cold start, or a blip)
//   suspended — the host has parked the service; retrying will NOT wake it
//   offline   — this machine has no network
//   error     — the service answered, but with a real failure
const TRANSIENT = new Set([502, 503, 504]);

// Attempts are deliberately short. Aborting does not cancel a cold start already
// triggered on the host, so a quick abort + retry reaches the same instance as one
// long wait would — while leaving the service worker free between tries rather than
// parked on a single 60s fetch.
const ATTEMPT_MS = { analyze: 15000, xray: 25000, health: 8000 };

async function apiBase() {
  const { apiBase } = await chrome.storage.sync.get("apiBase");
  return (apiBase || DEFAULT_BASE).replace(/\/+$/, "");
}

function stateOf(res) {
  // Render parks a suspended service behind its edge and says so in the routing
  // header. Readable here because the host is in host_permissions — an extension's
  // fetch to a granted host is not CORS-restricted. A custom analyzer URL that
  // isn't granted reads null instead and degrades to "waking", which only costs
  // the caller its retry budget.
  if (res.status === 503 && res.headers.get("x-render-routing") === "suspend")
    return "suspended";
  return TRANSIENT.has(res.status) ? "waking" : "error";
}

async function request(path, init, timeoutMs) {
  const base = await apiBase();
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(base + path, { ...init, signal: ctrl.signal });
    if (!res.ok) return { error: `http_${res.status}`, state: stateOf(res) };
    return { data: await res.json() };
  } catch {
    // Timed out mid-cold-start and connection-refused are the same event here, so
    // assume the recoverable one unless the machine itself is offline.
    return {
      error: "unreachable",
      state: navigator.onLine === false ? "offline" : "waking",
    };
  } finally {
    clearTimeout(t);
  }
}

const postJSON = (path, body, timeoutMs) =>
  request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body), // NO credentials: wildcard CORS forbids cookies.
  }, timeoutMs);

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  // Gmail finished loading — the earliest signal that an analysis is coming. Start
  // the host's cold start now so it overlaps with the user picking a message,
  // instead of beginning when they open one.
  if (msg.type === "warm") {
    request("/health", {}, ATTEMPT_MS.health);
    sendResponse({ ok: true });
    return;
  }
  if (msg.type === "analyze") {
    if (msg.msgId && cache.has(msg.msgId)) {
      sendResponse({ data: cache.get(msg.msgId), cached: true });
      return;
    }
    postJSON("/analyze", { text: msg.text, use_classifier: true }, ATTEMPT_MS.analyze)
      .then((r) => {
        if (r.data && msg.msgId) cache.set(msg.msgId, r.data);
        sendResponse(r);
      });
    return true;
  }
  if (msg.type === "xray") {
    postJSON("/xray", { text: msg.text }, ATTEMPT_MS.xray).then(sendResponse);
    return true;
  }
  if (msg.type === "health") {
    request("/health", {}, ATTEMPT_MS.health).then((r) =>
      sendResponse({ online: !!r.data, state: r.data ? "up" : r.state }));
    return true;
  }
});
