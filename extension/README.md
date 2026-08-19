# PhishingNet — phishing safety inside Gmail and Outlook

A Chrome/Edge (Manifest V3) extension that checks every email you open and shows an
inline safety banner — like Grammarly, but for phishing. It works in **Gmail** out of
the box, and in **Outlook on the web** once you turn that on in the popup.

Email text is sent to the hosted Phishing Analyzer service
(`https://phishing-analyzer-api-wq1v.onrender.com` by default, configurable in the
popup) to be scored, and is not stored there. See `../PRIVACY.md`.

## What it does
- Open an email → a slim banner appears above the message body:
  ✓ **LOOKS SAFE** (green) · ⚠️ **SUSPICIOUS** (amber) · ⛔ **PHISHING** (red), with the risk %.
- **Details ▾** expands to the recommended action, top signals, and the evidence that fired.
- **🔗 Deep scan** runs Link X-ray on the email's links (redirects, destination domain,
  domain age, blocklist hits).
- While the analyzer is cold-starting the banner says so and keeps retrying, rather than
  reporting the service down.

## Run it unpacked
1. In Chrome/Edge open `chrome://extensions`, turn on **Developer mode** (top-right).
2. **Load unpacked** → select this `extension/` folder.
3. Open Gmail and open any email — the banner appears. Click the 🛡️ toolbar icon for
   settings (scanning on/off, analyzer URL, Outlook support, backend status).

To run against a local backend instead, start it from the project root and put its
address in the popup's **Analyzer URL** field:

```
.venv\Scripts\python.exe -m uvicorn server.app:app --host 127.0.0.1 --port 8008
```

The extension has a **fixed unpacked ID** — `oaccmpcmfggkbhbhcbohkcphllnkachp` — pinned
by the `key` field in `manifest.json`. `scripts/build_extension_zip.py` strips that field
from the store package, so the published extension has a different, store-assigned ID.

## How the two clients are wired

Gmail is a **static `content_scripts` block**. Outlook is **not**, and deliberately so: a
match pattern in the manifest is a required host permission, and adding one to a
published extension makes Chrome disable it for every existing user until each of them
re-accepts the warning. So Outlook lives in `optional_host_permissions`, is granted from
the popup, and its content script is registered at runtime by `background.js`
(`reconcileOutlook`). The permission is the source of truth; the registration mirrors it.

`content.js` serves both. Everything below its adapter block — banner building, the
cold-start retry machine — is client-agnostic; only finding, scraping and placing differ.

## Notes & limits
- **Gmail gets a sender-authentication signal; Outlook does not.** In Gmail the extension
  reads the "mailed-by" / "signed-by" values Gmail displays under *Show details* and
  forwards them as RFC822 auth headers, which lets the analyzer's sender-trust discount
  clear genuine transactional mail. Outlook on the web shows no equivalent in the reading
  pane, so the Outlook path sends message text alone — **expect more false positives on
  legitimate transactional mail in Outlook than in Gmail.**
- Both clients obfuscate their page markup and change it over time. The DOM selectors are
  best-effort; the Outlook ones key off ARIA roles and id prefixes rather than class
  names, and walk a fallback chain. A missed parse just means no banner — it never breaks
  the page.
- Outlook has no stable per-message id, so the background cache is keyed on a content
  fingerprint widened with sender and subject. Gmail uses its real message id.
- Compose-time warnings are still future work.
- `key.pem` (the private key that pins the unpacked ID) is kept locally and gitignored;
  the public half lives in `manifest.json` as `key`.
