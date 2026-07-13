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

// ---- Gmail connect (header-accurate mode) ----
const gmailBtn = document.getElementById("gmailBtn");

function renderGmail(connected) {
  gmailBtn.textContent = connected ? "✓ Gmail connected" : "Connect Gmail";
  gmailBtn.classList.toggle("connected", !!connected);
}

chrome.runtime.sendMessage({ type: "gmailStatus" }, (r) => renderGmail(r && r.connected));

gmailBtn.addEventListener("click", () => {
  gmailBtn.textContent = "Connecting…";
  chrome.runtime.sendMessage({ type: "gmailConnect" }, (r) => {
    renderGmail(r && r.ok);
    if (!r || !r.ok) gmailBtn.textContent = "Connect failed — check setup";
  });
});
