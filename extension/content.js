// Inbox Shield — reads the open Gmail message, asks the local analyzer, and drops a
// safety banner above the email body. Defensive throughout: any parse miss just means
// "no banner", never a broken page.
(() => {
  "use strict";

  const VERDICT = {
    phishing:   { label: "PHISHING",   cls: "pa-phishing",   icon: "⛔" },
    suspicious: { label: "SUSPICIOUS", cls: "pa-suspicious", icon: "⚠️" },
    legitimate: { label: "LOOKS SAFE", cls: "pa-legitimate", icon: "✓" },
  };

  let enabled = true;
  chrome.storage.sync.get("enabled", (o) => { enabled = o.enabled !== false; });
  chrome.storage.onChanged.addListener((c) => {
    if (c.enabled) {
      enabled = c.enabled.newValue !== false;
      if (!enabled) document.querySelectorAll(".pa-banner").forEach((b) => b.remove());
    }
  });

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };

  // ---- Gmail scraping (selectors are best-effort; Gmail obfuscates its DOM) ----
  function messageContainer(body) {
    let n = body;
    while (n && n !== document.body) {
      if (n.getAttribute && (n.getAttribute("data-message-id") ||
          n.getAttribute("data-legacy-message-id"))) return n;
      n = n.parentElement;
    }
    return body.closest(".adn") || body.parentElement;
  }

  function scrape(body) {
    const container = messageContainer(body);
    const msgId =
      (container && (container.getAttribute("data-message-id") ||
                     container.getAttribute("data-legacy-message-id"))) ||
      ("len:" + body.innerText.length + ":" + body.innerText.slice(0, 40));
    const senderNode = (container || document).querySelector("span[email]");
    const sender = senderNode
      ? `${senderNode.getAttribute("name") || ""} <${senderNode.getAttribute("email")}>`.trim()
      : "";
    const subject = (document.querySelector("h2.hP") || {}).innerText || "";
    const text = `From: ${sender}\nSubject: ${subject}\n\n${body.innerText}`;
    return { msgId, text, subject };
  }

  // ---- banner ----
  function chip(t) { return el("span", "pa-chip", t.replace(/_/g, " ")); }

  function buildBanner(report, text) {
    const v = VERDICT[report.verdict] || VERDICT.suspicious;
    const pct = Math.round((report.risk_score || 0) * 100);
    const wrap = el("div", `pa-banner ${v.cls}`);

    const head = el("div", "pa-head");
    head.append(el("span", "pa-icon", v.icon));
    head.append(el("span", "pa-title", `${v.label} · risk ${pct}%`));
    head.append(el("span", "pa-summary", report.summary || ""));
    const spacer = el("span", "pa-spacer"); head.append(spacer);
    const toggle = el("button", "pa-btn", "Details ▾");
    const close = el("button", "pa-btn pa-x", "✕");
    head.append(toggle, close);
    wrap.append(head);

    const body = el("div", "pa-body");
    body.style.display = "none";
    if (report.recommendation) body.append(el("div", "pa-reco", report.recommendation));

    if ((report.top_signals || []).length) {
      const sig = el("div", "pa-chips");
      sig.append(el("span", "pa-chips-label", "Signals:"));
      report.top_signals.slice(0, 5).forEach((s) => sig.append(chip(s)));
      body.append(sig);
    }
    // top 2 firing attributes with evidence-y explanation
    (report.attributes || [])
      .filter((a) => a.score >= 0.35 && a.explanation)
      .sort((a, b) => b.score - a.score)
      .slice(0, 2)
      .forEach((a) => body.append(el("div", "pa-evidence",
        `• ${a.name.replace(/_/g, " ")}: ${a.explanation}`)));

    const deep = el("button", "pa-deep", "🔗 Deep scan links (Link X-ray)");
    const deepOut = el("div", "pa-deep-out");
    deep.addEventListener("click", () => {
      deep.disabled = true; deep.textContent = "Scanning links…";
      chrome.runtime.sendMessage({ type: "xray", text }, (r) => {
        deep.remove();
        if (!r || r.error || !r.data) { deepOut.textContent = "Link scan unavailable."; return; }
        deepOut.append(el("div", "pa-deep-sum", r.data.summary || ""));
        (r.data.links || []).forEach((l) => {
          const risky = (l.suspicious_reasons || []).length > 0;
          const row = el("div", `pa-link ${risky ? "pa-link-bad" : ""}`);
          row.append(el("div", "pa-link-url", l.url));
          row.append(el("div", "pa-link-dest", `↳ ${l.destination_domain}`
            + (l.domain_age_days != null ? ` · ${l.domain_age_days}d old` : "")
            + (l.on_blocklist ? ` · ⚑ ${l.blocklist_source}` : "")));
          if (risky) row.append(el("div", "pa-link-why", "⚠ " + l.suspicious_reasons.join("; ")));
          deepOut.append(row);
        });
      });
    });
    body.append(deep, deepOut);
    wrap.append(body);

    toggle.addEventListener("click", () => {
      const open = body.style.display !== "none";
      body.style.display = open ? "none" : "block";
      toggle.textContent = open ? "Details ▾" : "Details ▴";
    });
    close.addEventListener("click", () => wrap.remove());
    return wrap;
  }

  function offlineBanner() {
    const wrap = el("div", "pa-banner pa-offline");
    const head = el("div", "pa-head");
    head.append(el("span", "pa-icon", "○"));
    head.append(el("span", "pa-title", "Analyzer offline"));
    head.append(el("span", "pa-summary",
      "Start the local Phishing Analyzer (localhost:8008) to check this email."));
    wrap.append(head);
    return wrap;
  }

  function place(body, node) {
    body.parentElement.insertBefore(node, body);
  }

  // ---- scan loop ----
  const done = new WeakSet();

  function scanOnce() {
    if (!enabled) return;
    document.querySelectorAll("div.a3s").forEach((body) => {
      if (done.has(body) || body.offsetParent === null) return;
      done.add(body);
      const info = scrape(body);
      chrome.runtime.sendMessage({ type: "analyze", text: info.text, msgId: info.msgId }, (r) => {
        if (!body.isConnected) return;
        if (!r || r.error) { place(body, offlineBanner()); return; }
        if (r.data) place(body, buildBanner(r.data, info.text));
      });
    });
  }

  let timer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(scanOnce, 400);
  });
  observer.observe(document.body, { childList: true, subtree: true });
  setTimeout(scanOnce, 1200); // initial
})();
