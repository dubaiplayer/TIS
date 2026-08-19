// Inbox Shield — reads the open Gmail message and drops a safety banner above the body.
// Scrapes the message from the DOM and, where Gmail exposes its own SPF/DKIM verdict
// ("mailed-by" / "signed-by"), forwards that as RFC822 auth headers so the analyzer's
// sender-trust discount can clear genuine transactional mail. No OAuth scope needed.
// Defensive throughout: any parse miss just means "no banner", never a broken page.
(() => {
  "use strict";

  const VERDICT = {
    phishing:   { label: "PHISHING",   cls: "pa-phishing",   icon: "⛔" },
    suspicious: { label: "SUSPICIOUS", cls: "pa-suspicious", icon: "⚠️" },
    legitimate: { label: "LOOKS SAFE", cls: "pa-legitimate", icon: "✓" },
  };

  let enabled = true;

  // Reloading or auto-updating the extension invalidates the context of content
  // scripts already injected into open tabs: chrome.runtime goes undefined while
  // this script keeps running against the page. Guard every call and stand down
  // for the life of the tab instead of throwing on each scan.
  let observer = null, timer = null;
  const alive = () => {
    try { return !!(chrome.runtime && chrome.runtime.id); } catch { return false; }
  };

  function teardown() {
    if (observer) { observer.disconnect(); observer = null; }
    clearTimeout(timer);
    enabled = false;
  }

  function send(msg, cb) {
    if (!alive()) { teardown(); cb(null); return; }
    try {
      chrome.runtime.sendMessage(msg, (r) => {
        if (chrome.runtime.lastError) { cb(null); return; }  // reading it also silences it
        cb(r);
      });
    } catch { teardown(); cb(null); }
  }

  try {
    chrome.storage.sync.get("enabled", (o) => { enabled = o.enabled !== false; });
    chrome.storage.onChanged.addListener((c) => {
      if (c.enabled) {
        enabled = c.enabled.newValue !== false;
        if (!enabled) document.querySelectorAll(".pa-banner").forEach((b) => b.remove());
      }
    });
  } catch { teardown(); }

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
    return body.closest(".adn, .h7, .gs") || body.parentElement;
  }

  function legacyId(container) {
    if (!container) return "";
    const legacy = container.getAttribute("data-legacy-message-id");
    if (legacy && /^\d+$/.test(legacy)) return legacy;
    const mid = container.getAttribute("data-message-id") || "";
    const m = mid.match(/msg-[fa]:(\d+)/);      // "#msg-f:1783..." -> decimal
    return m ? m[1] : "";
  }

  function apiIdFromLegacy(dec) {              // Gmail API id = hex of the decimal id
    try { return dec ? BigInt(dec).toString(16) : ""; } catch { return ""; }
  }

  function subjectText() {
    const h = document.querySelector("h2.hP, h2[data-thread-perm-id]");
    if (h && h.innerText.trim()) return h.innerText.trim();
    return (document.title || "").replace(/\s*-\s*[^-]+@[^-]+$/, "").trim();
  }

  // ---- sender authentication: the third signal ----
  // Gmail already ran SPF/DKIM/DMARC when the message was delivered, and renders the
  // outcome in the message details table as "mailed-by" (the SPF domain) and
  // "signed-by" (the DKIM domain). We read ITS verdict rather than re-deriving one,
  // then pass it to the analyzer as real RFC822 auth headers so the server-side
  // sender-trust discount (phishing_analyzer/trust.py) can engage. Without this the
  // analyzer sees no auth headers, returns None, and genuine transactional mail from
  // Google/Atlassian/banks scores on wording alone -> false positives.
  //
  // SECURITY: read ONLY from Gmail's own chrome (the details table). Never from the
  // message body, which is attacker-controlled and could otherwise forge a
  // "signed-by: google.com" line straight into a trust discount.

  // Match on the row LABELS ("mailed-by:", "signed-by:") rather than pinning a
  // selector to today's obfuscated class names, which Gmail churns. The row's own
  // text is label+value run together ("mailed-by:atlassian-bounces.atlassian.net"),
  // so strip the label off the front instead of guessing the cell structure.
  function readAuthRows(scope) {
    const out = {};
    scope.querySelectorAll("span, td").forEach((el) => {
      const label = el.textContent.trim().toLowerCase();
      const key = label === "mailed-by:" ? "mailedBy"
                : label === "signed-by:" ? "signedBy" : null;
      if (!key || out[key]) return;
      const row = el.closest("tr") || el.parentElement;
      if (!row) return;
      const v = row.textContent.trim()
        .replace(/^(mailed|signed)-by:\s*/i, "").trim().toLowerCase();
      if (v && !/\s/.test(v) && v.includes(".")) out[key] = v;   // a bare domain
    });
    return out;
  }

  // Gmail builds that table lazily — it does not exist until the "Show details"
  // caret is clicked. So expand, read, and collapse inside ONE synchronous task:
  // the browser cannot paint between them, so the user sees no flicker. If Gmail
  // ever defers the build, the read simply comes back empty and we fall through to
  // no-auth (today's behavior) rather than leaving the panel open.
  function gmailAuth(container) {
    if (!container) return {};
    const already = readAuthRows(container);
    if (already.mailedBy && already.signedBy) return already;   // user expanded it
    const show = container.querySelector('[aria-label="Show details"], div.ajy');
    if (!show) return already;
    let rows = already;
    try {
      show.click();
      rows = readAuthRows(container);
    } catch { /* leave rows as-is */ }
    try {
      (container.querySelector('[aria-label="Hide details"]') || show).click();
    } catch { /* never leave the panel stuck open */ }
    return rows;
  }

  const domainOf = (addr) => (String(addr).split("@")[1] || "").toLowerCase().trim();
  // Same registrable domain, or one is a subdomain of the other (po.atlassian.net
  // signed by atlassian.net is aligned; google.com signed by evil.com is not).
  const aligned = (a, b) =>
    !!a && !!b && (a === b || a.endsWith("." + b) || b.endsWith("." + a));

  function authHeaderLines(container, senderEmail) {
    const a = gmailAuth(container);
    const from = domainOf(senderEmail);
    // Require BOTH, because trust.py treats (spf=pass AND dkim=pass) as authenticated;
    // claiming it off one row would over-trust. Gmail omits these rows when auth fails.
    if (!a.mailedBy || !a.signedBy || !from) return "";
    // DKIM must align with the From domain. Otherwise an attacker spoofing
    // "From: no-reply@google.com" while signing with their OWN domain would inherit
    // google.com's place on the server's trusted-brand list.
    if (!aligned(from, a.signedBy)) return "";
    return "Authentication-Results: gmail.com; " +
             `dkim=pass header.i=@${a.signedBy}; spf=pass smtp.mailfrom=${a.mailedBy}\n` +
           `Received-SPF: pass (gmail.com: ${a.mailedBy} is a permitted sender)\n`;
  }

  function scrape(body) {
    const container = messageContainer(body);
    const dec = legacyId(container);
    const msgId = dec || ("len:" + body.innerText.length + ":" + body.innerText.slice(0, 40));
    const apiMsgId = apiIdFromLegacy(dec);
    const senderNode = (container || document).querySelector(
      "span[email], .gD[email], .go span[email]");
    const senderEmail = senderNode ? (senderNode.getAttribute("email") || "") : "";
    const sender = senderNode
      ? `${senderNode.getAttribute("name") || ""} <${senderEmail}>`.trim()
      : "";
    const auth = authHeaderLines(container, senderEmail);
    const text = `${auth}From: ${sender}\nSubject: ${subjectText()}\n\n${body.innerText}`;
    // Fold the auth state into the cache key: if the details table hadn't rendered on
    // an earlier scan, the background cache must not keep serving that unauthenticated
    // verdict for the rest of the session.
    return { msgId: msgId + (auth ? ":a" : ""), apiMsgId, text, authenticated: !!auth };
  }

  // ---- banner ----
  function chip(t) { return el("span", "pa-chip", t.replace(/_/g, " ")); }

  // Attribute score bar chart (mirrors the desktop AttributeBarChart colors).
  function attrColor(s) {
    if (s >= 0.66) return "#ef4444";
    if (s >= 0.33) return "#f59e0b";
    if (s > 0) return "#eab308";
    return "#c9ced6";
  }
  function buildBarChart(attributes) {
    const wrap = el("div", "pa-section");
    wrap.append(el("div", "pa-section-h", "Attribute scores"));
    const bars = el("div", "pa-bars");
    attributes.slice().sort((a, b) => b.score - a.score).forEach((a) => {
      const row = el("div", "pa-bar-row");
      row.append(el("span", "pa-bar-name", a.name.replace(/_/g, " ")));
      const track = el("span", "pa-bar-track");
      const fill = el("span", "pa-bar-fill");
      fill.style.width = Math.round(a.score * 100) + "%";
      fill.style.background = attrColor(a.score);
      track.append(fill);
      row.append(track, el("span", "pa-bar-val", a.score.toFixed(2)));
      bars.append(row);
    });
    wrap.append(bars);
    return wrap;
  }

  // Classifier keyword highlighting (mirrors the desktop KeywordHighlight).
  function mergeSpans(keywords) {
    const spans = [];
    keywords.filter((k) => k.direction === "phishing")
      .forEach((k) => k.spans.forEach((s) => spans.push({ ...s, intensity: k.intensity })));
    spans.sort((a, b) => a.start - b.start);
    const out = []; let lastEnd = -1;
    for (const s of spans) { if (s.start >= lastEnd) { out.push(s); lastEnd = s.end; } }
    return out;
  }
  function buildKeywords(report) {
    const kws = (report.classifier && report.classifier.keyword_attributions) || [];
    const wrap = el("div", "pa-section");
    wrap.append(el("div", "pa-section-h", "Flagged words"));
    if (!kws.length) {
      wrap.append(el("div", "pa-muted", "No classifier keywords for this email."));
      return wrap;
    }
    const cloud = el("div", "pa-cloud");
    kws.filter((k) => k.direction === "phishing").slice(0, 16).forEach((k) => {
      const c = el("span", "pa-kw pa-kw-phish", k.term);
      c.style.fontSize = (11 + 7 * k.intensity).toFixed(0) + "px";
      c.style.opacity = (0.6 + 0.4 * k.intensity).toFixed(2);
      cloud.append(c);
    });
    kws.filter((k) => k.direction === "legitimate").slice(0, 6)
      .forEach((k) => cloud.append(el("span", "pa-kw pa-kw-legit", k.term)));
    wrap.append(cloud);

    const text = report.analyzed_text || "";
    if (text) {
      const pre = el("div", "pa-hl");
      let cur = 0;
      mergeSpans(kws).forEach((s) => {
        if (s.start > cur) pre.append(document.createTextNode(text.slice(cur, s.start)));
        const m = el("mark", "pa-mark", text.slice(s.start, s.end));
        m.style.background = `rgba(239,68,68,${(0.2 + 0.5 * s.intensity).toFixed(2)})`;
        pre.append(m);
        cur = s.end;
      });
      if (cur < text.length) pre.append(document.createTextNode(text.slice(cur)));
      wrap.append(pre);
    }
    return wrap;
  }

  function buildBanner(report, text) {
    const v = VERDICT[report.verdict] || VERDICT.suspicious;
    const pct = Math.round((report.risk_score || 0) * 100);
    const wrap = el("div", `pa-banner ${v.cls}`);

    const head = el("div", "pa-head");
    head.append(el("span", "pa-icon", v.icon));
    head.append(el("span", "pa-title", `${v.label} · risk ${pct}%`));
    head.append(el("span", "pa-summary", report.summary || ""));
    head.append(el("span", "pa-spacer"));
    const toggle = el("button", "pa-btn", "Details ▾");
    const close = el("button", "pa-btn pa-x", "✕");
    head.append(toggle, close);
    wrap.append(head);

    const bodyEl = el("div", "pa-body");
    bodyEl.style.display = "none";
    if (report.recommendation) bodyEl.append(el("div", "pa-reco", report.recommendation));

    if ((report.top_signals || []).length) {
      const sig = el("div", "pa-chips");
      sig.append(el("span", "pa-chips-label", "Signals:"));
      report.top_signals.slice(0, 5).forEach((s) => sig.append(chip(s)));
      bodyEl.append(sig);
    }
    (report.attributes || [])
      .filter((a) => a.score >= 0.35 && a.explanation)
      .sort((a, b) => b.score - a.score)
      .slice(0, 2)
      .forEach((a) => bodyEl.append(el("div", "pa-evidence",
        `• ${a.name.replace(/_/g, " ")}: ${a.explanation}`)));

    if ((report.attributes || []).length) bodyEl.append(buildBarChart(report.attributes));
    bodyEl.append(buildKeywords(report));

    const deep = el("button", "pa-deep", "🔗 Deep scan links (Link X-ray)");
    const deepOut = el("div", "pa-deep-out");
    deep.addEventListener("click", () => {
      deep.disabled = true; deep.textContent = "Scanning links…";
      send({ type: "xray", text }, (r) => {
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
    bodyEl.append(deep, deepOut);
    wrap.append(bodyEl);

    toggle.addEventListener("click", () => {
      const open = bodyEl.style.display !== "none";
      bodyEl.style.display = open ? "none" : "block";
      toggle.textContent = open ? "Details ▾" : "Details ▴";
    });
    close.addEventListener("click", () => wrap.remove());
    return wrap;
  }

  // A sleeping host is not a broken one: say so, and keep the banner honest about
  // how long the wait has run so a 40s cold start doesn't read as a hang.
  function wakingBanner(startedAt) {
    const wrap = el("div", "pa-banner pa-waking");
    const head = el("div", "pa-head");
    head.append(el("span", "pa-icon pa-spin", "◐"));
    head.append(el("span", "pa-title", "WAKING ANALYZER"));
    const sum = el("span", "pa-summary", "");
    head.append(sum);
    wrap.append(head);
    const tick = () => {
      if (!wrap.isConnected) { clearInterval(iv); return; }   // replaced or closed
      const s = Math.round((Date.now() - startedAt) / 1000);
      sum.textContent =
        `The service was idle and is starting up (${s}s) — this usually takes 30-60 seconds.`;
    };
    const iv = setInterval(tick, 1000);
    tick();
    return wrap;
  }

  // Terminal failure. "suspended" is worth its own wording: retrying cannot fix it,
  // so point at what can, rather than inviting the user to wait it out.
  function failureBanner(state, onRetry) {
    const suspended = state === "suspended";
    const wrap = el("div", "pa-banner pa-offline");
    const head = el("div", "pa-head");
    head.append(el("span", "pa-icon", "○"));
    head.append(el("span", "pa-title",
      suspended ? "Analyzer suspended" : "Analyzer unavailable"));
    head.append(el("span", "pa-summary", suspended
      ? "The hosted service is suspended and can't be woken from here. Point the "
        + "extension at another analyzer URL from the toolbar popup, or restore the host."
      : state === "offline"
      ? "No network connection — the email wasn't checked."
      : "Couldn't reach the Phishing Analyzer service — please try again in a moment."));
    head.append(el("span", "pa-spacer"));
    if (!suspended) {
      const retry = el("button", "pa-btn", "Try again");
      retry.addEventListener("click", onRetry);
      head.append(retry);
    }
    wrap.append(head);
    return wrap;
  }

  function place(body, node) { body.parentElement.insertBefore(node, body); }

  // ---- scan loop ----
  const done = new WeakSet();

  // Cold starts are the common case on an idle free-tier host, so a single timeout
  // is not a verdict. Keep re-asking within this budget, showing progress, and only
  // then call it a failure.
  const WAKE_BUDGET_MS = 90000;
  const WAKE_RETRY_MS = 6000;

  function analyzeBody(body) {
    const info = scrape(body);
    let shown = null;                          // the banner we've inserted, if any

    // One banner per message: swap in place so a wake -> verdict transition doesn't
    // stack notices above the email.
    const render = (node) => {
      if (shown && shown.isConnected) shown.replaceWith(node);
      else place(body, node);
      shown = node;
    };

    const run = () => {
      const started = Date.now();
      const attempt = () => {
        send({ type: "analyze", text: info.text, msgId: info.msgId }, (r) => {
          if (!body.isConnected) return;
          if (!alive()) return;                // extension reloaded — stay silent, don't cry offline
          if (r && r.data) { render(buildBanner(r.data, info.text)); return; }
          const state = (r && r.state) || "offline";
          if (state === "waking" && Date.now() - started < WAKE_BUDGET_MS) {
            if (!(shown && shown.classList.contains("pa-waking")))
              render(wakingBanner(started));
            setTimeout(attempt, WAKE_RETRY_MS);
            return;
          }
          render(failureBanner(state, run));   // "Try again" restarts the whole budget
        });
      };
      attempt();
    };
    run();
  }

  function scanOnce() {
    if (!enabled) return;
    if (!alive()) { teardown(); return; }
    document.querySelectorAll("div.a3s").forEach((body) => {
      if (done.has(body) || body.offsetParent === null) return;
      done.add(body);
      analyzeBody(body);
    });
  }

  observer = new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(scanOnce, 400);
  });
  observer.observe(document.body, { childList: true, subtree: true });
  send({ type: "warm" }, () => {});   // overlap the host's cold start with Gmail loading
  setTimeout(scanOnce, 1200);
})();
