// Service worker: the only place allowed to reach the analyzer (a content script's
// fetch is blocked by Gmail's CSP/CORS). Content script -> here -> hosted API.
const DEFAULT_BASE = "https://phishing-analyzer-api-wq1v.onrender.com";
const cache = new Map(); // msgId -> report (per-session, avoids re-analyzing)

async function apiBase() {
  const { apiBase } = await chrome.storage.sync.get("apiBase");
  return (apiBase || DEFAULT_BASE).replace(/\/+$/, "");
}

async function postJSON(path, body, timeoutMs) {
  const base = await apiBase();
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(base + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal, // NO credentials: wildcard CORS forbids cookies.
    });
    if (!res.ok) return { error: `http_${res.status}` };
    return { data: await res.json() };
  } catch {
    return { error: "offline" };
  } finally {
    clearTimeout(t);
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "analyze") {
    if (msg.msgId && cache.has(msg.msgId)) {
      sendResponse({ data: cache.get(msg.msgId), cached: true });
      return;
    }
    postJSON("/analyze", { text: msg.text, use_classifier: true }, 20000).then((r) => {
      if (r.data && msg.msgId) cache.set(msg.msgId, r.data);
      sendResponse(r);
    });
    return true;
  }
  if (msg.type === "xray") {
    postJSON("/xray", { text: msg.text }, 30000).then(sendResponse);
    return true;
  }
  if (msg.type === "health") {
    apiBase().then(async (base) => {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 8000);
      try {
        const res = await fetch(base + "/health", { signal: ctrl.signal });
        sendResponse({ online: res.ok });
      } catch {
        sendResponse({ online: false });
      } finally {
        clearTimeout(t);
      }
    });
    return true;
  }
});
