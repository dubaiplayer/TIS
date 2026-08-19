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

// ---- Outlook: opt-in, registered at runtime -------------------------------------
// Gmail is a static content_scripts block and is never touched here. Outlook cannot be
// declared the same way: a match pattern in the manifest is a REQUIRED host permission,
// and adding one to a published extension makes Chrome disable it for every existing
// user until each re-accepts the warning. So Outlook is an optional host permission,
// granted from the popup, and its content script is registered dynamically to match.
const OUTLOOK_ID = "outlook";
const OUTLOOK_ORIGINS = [
  "https://outlook.live.com/*",
  "https://outlook.office.com/*",
  "https://outlook.office365.com/*",
];

// Same files and timing as the Gmail block -- one adapter in content.js, two clients.
const OUTLOOK_SCRIPT = {
  id: OUTLOOK_ID,
  matches: OUTLOOK_ORIGINS,
  js: ["content.js"],
  css: ["banner.css"],
  runAt: "document_idle",
  allFrames: false,
  // On a browser restart with a restored Outlook tab, the service worker may not wake
  // before the page finishes loading. A persisted registration is already in place; a
  // non-persisted one loses that race and the user silently gets no banner on exactly
  // the tab they left open.
  persistAcrossSessions: true,
};

const outlookGranted = () => chrome.permissions.contains({ origins: OUTLOOK_ORIGINS });

async function outlookRegistered() {
  try {
    const cur = await chrome.scripting.getRegisteredContentScripts({ ids: [OUTLOOK_ID] });
    return cur.length > 0;
  } catch {
    return false;              // filtering on a never-registered id can throw
  }
}

// The permission is the source of truth; the registration is a cache of it. Every entry
// point calls this rather than assuming a direction, so grant, revoke, browser restart,
// extension update, and "revoked from chrome://extensions while the browser was closed"
// all converge on the same state.
//
// force=true also rewrites an EXISTING registration. persistAcrossSessions means a
// profile keeps whatever definition it was given at grant time, so without this a
// shipped change to matches/js/css would never reach anyone who enabled Outlook earlier.
async function reconcileOutlook(force) {
  try {
    const [granted, registered] = await Promise.all([outlookGranted(), outlookRegistered()]);
    if (granted && !registered) {
      await chrome.scripting.registerContentScripts([OUTLOOK_SCRIPT]);
    } else if (granted && registered && force) {
      await chrome.scripting.updateContentScripts([OUTLOOK_SCRIPT]);
    } else if (!granted && registered) {
      await chrome.scripting.unregisterContentScripts({ ids: [OUTLOOK_ID] });
    }
  } catch (e) {
    // Never take the worker down over this: the Gmail path must keep working.
    console.warn("[PhishingNet] Outlook reconcile failed:", e);
  }
}

// registerContentScripts does not inject into tabs that are already open, so a user who
// presses Enable while looking at their inbox would see nothing happen. Reach those tabs
// by hand. Best-effort: the popup also tells them to reload, which covers every failure.
async function injectOpenOutlookTabs() {
  let tabs;
  try {
    // No "tabs" permission -- that would add the "Read your browsing history" warning,
    // the very outcome this design exists to avoid. tabs.query's url filter is satisfied
    // by the host permission just granted; if that ever stops holding we fail closed to
    // the reload hint rather than reaching for the permission.
    tabs = await chrome.tabs.query({ url: OUTLOOK_ORIGINS });
  } catch {
    return;
  }
  for (const t of tabs) {
    if (!t.id) continue;
    try {
      await chrome.scripting.insertCSS({ target: { tabId: t.id }, files: ["banner.css"] });
      await chrome.scripting.executeScript({ target: { tabId: t.id }, files: ["content.js"] });
    } catch { /* tab closed, navigated or discarded mid-loop -- reload hint covers it */ }
  }
}

const isOutlookPerm = (p) => (p.origins || []).some((o) => OUTLOOK_ORIGINS.includes(o));

// Registered synchronously at top level: an event fired while the worker was asleep is
// only delivered if its listener was attached during the worker's first turn.
chrome.runtime.onInstalled.addListener(() => reconcileOutlook(true));
chrome.runtime.onStartup.addListener(() => reconcileOutlook(false));

chrome.permissions.onAdded.addListener((p) => {
  if (!isOutlookPerm(p)) return;
  // The worker owns this, not the popup: Chrome may tear the popup down while its own
  // confirmation dialog is on screen, so a popup-side callback is not a reliable place
  // to register anything.
  reconcileOutlook(false).then(injectOpenOutlookTabs);
});

chrome.permissions.onRemoved.addListener((p) => {
  if (isOutlookPerm(p)) reconcileOutlook(false);
});

// Also on every plain worker wake. Two reads and no writes unless the state has actually
// diverged, and it self-heals anything the events above missed -- notably a permission
// revoked from chrome://extensions while this worker was not running.
reconcileOutlook(false);
