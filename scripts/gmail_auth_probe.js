// Paste into the Gmail tab console with a message OPEN.
// Reports whether Gmail's SPF/DKIM verdict is reachable in the DOM, and where.
(() => {
  const found = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const t = n.textContent.trim().toLowerCase();
    if (t === "mailed-by:" || t === "signed-by:" || t === "mailed-by" || t === "signed-by"
        || t.includes("mailed-by") || t.includes("signed-by")) {
      const el = n.parentElement;
      const row = el.closest("tr") || el.parentElement;
      found.push({
        label: t.slice(0, 20),
        el: el.tagName + "." + (el.className || "(none)"),
        parentTable: (el.closest("table") || {}).className || "(no table)",
        rowText: (row ? row.textContent.trim().slice(0, 80) : ""),
        visible: !!(el.offsetParent || el.getClientRects().length),
      });
    }
  }
  console.log("=== text-node matches for mailed-by / signed-by ===");
  console.table(found);
  console.log("matches:", found.length);

  // Is there a details expander we could open?
  const expanders = [
    ['img.ajz', document.querySelectorAll("img.ajz").length],
    ['[aria-label*="details" i]', document.querySelectorAll('[aria-label*="details" i]').length],
    ['.ajA', document.querySelectorAll(".ajA").length],
    ['table.cf', document.querySelectorAll("table.cf").length],
    ['table.cf.gJ', document.querySelectorAll("table.cf.gJ").length],
    ['.hb', document.querySelectorAll(".hb").length],
  ];
  console.log("=== candidate elements present ===");
  console.table(expanders.map(([sel, n]) => ({ selector: sel, count: n })));

  // Show what the show-details control looks like, if any.
  const dd = document.querySelector("img.ajz, [aria-label*='details' i]");
  console.log("show-details control:", dd ? (dd.tagName + "." + dd.className + " | aria-label=" + dd.getAttribute("aria-label")) : "(not found)");
})();
