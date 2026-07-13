const enabledEl = document.getElementById("enabled");
const apiEl = document.getElementById("apiBase");
const dot = document.getElementById("dot");
const statusText = document.getElementById("statusText");

function checkHealth() {
  dot.className = "dot off"; statusText.textContent = "checking…";
  chrome.runtime.sendMessage({ type: "health" }, (r) => {
    const online = r && r.online;
    dot.className = "dot " + (online ? "on" : "off");
    statusText.textContent = online ? "Backend online" : "Backend offline — start the local server";
  });
}

chrome.storage.sync.get(["enabled", "apiBase"], (o) => {
  enabledEl.checked = o.enabled !== false;
  apiEl.value = o.apiBase || "http://localhost:8008";
  checkHealth();
});

enabledEl.addEventListener("change", () =>
  chrome.storage.sync.set({ enabled: enabledEl.checked }));

apiEl.addEventListener("change", () => {
  chrome.storage.sync.set({ apiBase: apiEl.value.trim() }, checkHealth);
});
