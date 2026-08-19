// Verify the Outlook Web selectors used by extension/content.js against a real mailbox.
//
// OWA obfuscates its class names and changes them over time, so the adapter keys off ARIA
// roles and id prefixes and walks a fallback chain. This snippet reports which candidates
// actually match, so the chain can be reordered or corrected before trusting it.
//
// HOW TO RUN
//   1. Open Outlook on the web and open a message in the reading pane.
//   2. F12 -> Console -> paste this whole file -> Enter.
//   3. Run it again on: a work/school account (outlook.office.com), a pop-out message
//      window, and a conversation with several messages expanded.
//   4. Then open a DIFFERENT message WITHOUT reloading and run it once more. If "body id"
//      is unchanged, OWA recycled the node -- which is what the identity check in
//      scanOnce() exists to survive.
//
// WHAT TO REPORT BACK
//   The BODY / SUBJECT / SENDER lines, the iframe count, and whether "in iframe" is true.
//   "in iframe: true" is the one result that forces a code change (allFrames: true in the
//   registration in background.js).

(() => {
  const q = (sel) => {
    try { return [...document.querySelectorAll(sel)]; } catch { return []; }
  };

  const show = (label, sel) => {
    const n = q(sel);
    const first = n[0];
    let detail = "";
    if (first) {
      const r = first.getBoundingClientRect();
      const text = (first.innerText || "").trim().replace(/\s+/g, " ").slice(0, 60);
      detail = ` | ${Math.round(r.width)}x${Math.round(r.height)} | "${text}"`;
    }
    console.log(
      (n.length ? "  MATCH" : "  ----").padEnd(8),
      label.padEnd(8),
      String(n.length).padStart(3),
      sel + detail,
    );
  };

  console.log("=== PhishingNet selector check ===");
  console.log("host:", location.hostname, "| iframes on page:", document.querySelectorAll("iframe").length);

  console.log("\n-- message body (adapter tries these in order) --");
  show("BODY", 'div[id^="UniqueMessageBody"]');
  show("BODY", '[aria-label="Message body"]');
  show("BODY", 'div[role="document"]');

  console.log("\n-- subject --");
  show("SUBJ", '[role="heading"][aria-level="2"]');
  show("SUBJ", '[role="heading"]');

  console.log("\n-- sender (address usually lives in a title attribute) --");
  show("FROM", '[title*="@"]');

  const body =
    q('div[id^="UniqueMessageBody"]')[0] ||
    q('[aria-label="Message body"]')[0] ||
    q('div[role="document"]')[0];

  console.log("\n-- resolved body node --");
  if (!body) {
    console.log("  NONE MATCHED -- the adapter would show no banner here. Report this.");
  } else {
    const parent = body.parentElement;
    console.log("  body id      :", body.id || "(none)");
    console.log("  in iframe    :", body.ownerDocument !== document, "  <- true means allFrames is needed");
    console.log("  parent       :", parent ? parent.tagName : "(none)",
                parent ? getComputedStyle(parent).display : "",
                parent ? getComputedStyle(parent).overflow : "");
    console.log("  text length  :", (body.innerText || "").length);
    // What the adapter's container walk would scope the sender lookup to.
    const container = body.closest('[role="listitem"], [data-convid], [role="document"]');
    console.log("  container    :", container ? (container.getAttribute("role") || "data-convid") : "(fell back to parent)");
    const titled = [...(container || document).querySelectorAll('[title*="@"]')];
    const addr = titled
      .map((n) => (n.getAttribute("title") || "").match(/[^\s<>()[\]:;@,"]+@[^\s<>()[\]:;@,"]+\.[a-z]{2,}/i))
      .filter(Boolean)[0];
    console.log("  sender found :", addr ? addr[0] : "(none -- From: will carry a display name only)");
  }

  console.log("\n  document.title:", document.title);
  console.log("=== end ===");
})();
