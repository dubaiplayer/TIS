const enabledEl = document.getElementById("enabled");
const apiEl = document.getElementById("apiBase");
const dot = document.getElementById("dot");
const statusText = document.getElementById("statusText");

function checkHealth() {
  dot.className = "dot off"; statusText.textContent = "checking…";
  chrome.runtime.sendMessage({ type: "health" }, (r) => {
    const online = r && r.online;
    dot.className = "dot " + (online ? "on" : "off");
    statusText.textContent = online ? "Analyzer online" : "Analyzer unreachable — try again shortly";
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
