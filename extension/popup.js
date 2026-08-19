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
