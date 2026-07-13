// Service worker: the only place allowed to reach the analyzer (a content script's
// fetch is blocked by Gmail's CSP/CORS) and the Gmail API. Content script -> here -> API.
const DEFAULT_BASE = "http://localhost:8008";
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

// ---- Gmail API (OAuth) — fetch the RAW message so headers (Authentication-Results,
// List-Unsubscribe, ...) reach the analyzer and the sender-auth / domain-age trust
// works. Optional: if OAuth isn't configured, callers fall back to DOM scraping. ----
function getToken(interactive) {
  return new Promise((resolve) => {
    try {
      chrome.identity.getAuthToken({ interactive }, (token) =>
        resolve(chrome.runtime.lastError ? null : token || null));
    } catch {
      resolve(null);
    }
  });
}

function b64urlToText(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "===".slice((b64.length + 3) % 4));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8").decode(bytes);
}

async function gmailRaw(apiMsgId, interactive) {
  let token = await getToken(interactive);
  if (!token) return { error: "no_token" };
  const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages/${apiMsgId}?format=raw`;
  let res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 401) {
    // token expired/revoked -> drop it and try once more interactively-silent
    await new Promise((r) => chrome.identity.removeCachedAuthToken({ token }, r));
    token = await getToken(false);
    if (!token) return { error: "no_token" };
    res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  }
  if (!res.ok) return { error: `gmail_${res.status}` };
  const data = await res.json();
  if (!data.raw) return { error: "no_raw" };
  return { raw: b64urlToText(data.raw) };
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "analyze") {
    if (msg.msgId && cache.has(msg.msgId)) {
      sendResponse({ data: cache.get(msg.msgId), cached: true });
      return;
    }
    postJSON("/analyze", { text: msg.text, use_classifier: true }, 15000).then((r) => {
      if (r.data && msg.msgId) cache.set(msg.msgId, r.data);
      sendResponse(r);
    });
    return true;
  }
  if (msg.type === "xray") {
    postJSON("/xray", { text: msg.text }, 30000).then(sendResponse);
    return true;
  }
  if (msg.type === "gmailRaw") {           // fetch raw message (with headers) via API
    gmailRaw(msg.apiMsgId, false).then(sendResponse);
    return true;
  }
  if (msg.type === "gmailConnect") {       // popup: interactive consent
    getToken(true).then((tok) => sendResponse({ ok: !!tok }));
    return true;
  }
  if (msg.type === "gmailStatus") {        // popup: are we already connected?
    getToken(false).then((tok) => sendResponse({ connected: !!tok }));
    return true;
  }
  if (msg.type === "health") {
    apiBase().then(async (base) => {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 4000);
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
