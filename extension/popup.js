const enabledEl = document.getElementById("enabled");
const apiEl = document.getElementById("apiBase");
const dot = document.getElementById("dot");
const statusText = document.getElementById("statusText");

// The health probe doubles as a wake-up: a sleeping host starts on this request,
// so "asleep" is reported as a normal state to wait through, not a fault.
const STATUS = {
  up:        ["on",   "Analyzer online"],
  waking:    ["wake", "Analyzer asleep — starting up, ready in 30-60s"],
  suspended: ["off",  "Analyzer suspended — the hosted service isn't running"],
  offline:   ["off",  "No network connection"],
};

function checkHealth() {
  dot.className = "dot wake"; statusText.textContent = "checking…";
  chrome.runtime.sendMessage({ type: "health" }, (r) => {
    const [cls, text] = STATUS[(r && (r.online ? "up" : r.state)) || "offline"]
      || ["off", "Analyzer unreachable — check the URL above"];
    dot.className = "dot " + cls;
    statusText.textContent = text;
  });
}

chrome.storage.sync.get(["enabled", "apiBase"], (o) => {
  enabledEl.checked = o.enabled !== false;
  apiEl.value = o.apiBase || "https://phishing-analyzer-api-wq1v.onrender.com";
  checkHealth();
});

enabledEl.addEventListener("change", () =>
  chrome.storage.sync.set({ enabled: enabledEl.checked }));

apiEl.addEventListener("change", () => {
  chrome.storage.sync.set({ apiBase: apiEl.value.trim() }, checkHealth);
});

// ---- Outlook: an optional host permission, granted from here ---------------------
const OUTLOOK_ORIGINS = [
  "https://outlook.live.com/*",
  "https://outlook.office.com/*",
  "https://outlook.office365.com/*",
];
const outlookBtn = document.getElementById("outlookBtn");
const outlookHint = document.getElementById("outlookHint");

// Cached because the click handler needs the answer SYNCHRONOUSLY: permissions.request()
// only works inside a user gesture, and awaiting permissions.contains() first would spend
// the gesture before the request is made.
let outlookOn = null;

function paintOutlook(on, note) {
  outlookOn = !!on;
  outlookBtn.disabled = false;
  outlookBtn.textContent = on ? "Enabled \u2713" : "Enable";
  outlookBtn.classList.toggle("connected", !!on);
  outlookHint.textContent = note != null ? note : (on
    ? "Scanning Outlook.com and Outlook for work or school. Click to turn off."
    : "Off by default. Turn on to check email in Outlook on the web too.");
}

const refreshOutlook = () =>
  chrome.permissions.contains({ origins: OUTLOOK_ORIGINS }, (on) => paintOutlook(on));

outlookBtn.addEventListener("click", () => {
  if (outlookOn === null) return;                    // state not known yet
  if (outlookOn) {
    chrome.permissions.remove({ origins: OUTLOOK_ORIGINS }, (removed) =>
      paintOutlook(!removed, removed
        ? "Turned off. Reload any open Outlook tab to clear its banners."
        : null));
    return;
  }
  // Called directly in the gesture -- no await or callback ahead of it.
  chrome.permissions.request({ origins: OUTLOOK_ORIGINS }, (granted) => {
    // Chrome may close this popup while its own confirmation dialog is up, in which case
    // this never runs. That is fine: the service worker registers the content script off
    // permissions.onAdded, so the feature works either way. Everything here is cosmetic.
    if (chrome.runtime.lastError) {
      paintOutlook(false, "Couldn't ask Chrome for access \u2014 try again.");
      return;
    }
    paintOutlook(granted, granted
      ? "Enabled. If an Outlook tab is already open, reload it."
      : "Not enabled \u2014 Chrome access was declined.");
  });
});

// Reflect changes made outside this popup -- chrome://extensions -> Site access, or a
// grant whose confirmation dialog outlived a previous popup.
chrome.permissions.onAdded.addListener(refreshOutlook);
chrome.permissions.onRemoved.addListener(refreshOutlook);

refreshOutlook();
