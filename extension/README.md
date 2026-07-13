# Inbox Shield — phishing safety inside Gmail

A Chrome/Edge (Manifest V3) extension that checks every email you open in Gmail with
your **local Phishing Analyzer** and shows an inline safety banner — like Grammarly,
but for phishing. Email content is sent only to your own machine (`localhost:8008`);
nothing leaves your computer.

## What it does
- Opens an email → a slim banner appears above the message body:
  - ✓ **LOOKS SAFE** (green) · ⚠️ **SUSPICIOUS** (amber) · ⛔ **PHISHING** (red), with the risk %.
- **Details ▾** expands to the recommended action, the top signals, and the evidence
  that fired.
- **🔗 Deep scan** runs Link X-ray on the email's links (unmasks redirects, shows
  destination domain, domain age, and blocklist hits).

## Run it
1. Start the analyzer backend (from the project root):
   ```
   .venv\Scripts\python.exe -m uvicorn server.app:app --host 127.0.0.1 --port 8008
   ```
2. In Chrome/Edge go to `chrome://extensions`, turn on **Developer mode** (top right).
3. Click **Load unpacked** and select this `extension/` folder.
4. Open **Gmail** (`mail.google.com`) and open any email — the banner appears.
5. Click the toolbar 🛡️ icon for settings: on/off toggle, the analyzer URL, and a
   backend online/offline indicator.

## Notes & limits
- **Backend must be running** — the extension talks only to your local analyzer, which
  is what keeps your email on-device.
- The extension reads the message's **sender, subject, and body** from the page. It does
  NOT read the raw `Authentication-Results` headers, so the sender-authentication /
  domain-age trust discount doesn't apply here (the retrained classifier keeps
  body-only false positives low). A future version can pull the raw message (with
  headers) via the Gmail API for full accuracy.
- Gmail's page markup is obfuscated and changes over time; the scraping selectors are
  best-effort. A missed parse simply means no banner for that email — it never breaks
  the page.
- MVP targets Gmail web only. Outlook web and compose-time warnings are future work.
