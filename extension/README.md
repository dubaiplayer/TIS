# Inbox Shield — phishing safety inside Gmail

A Chrome/Edge (Manifest V3) extension that checks every email you open in Gmail with
your **local Phishing Analyzer** and shows an inline safety banner — like Grammarly,
but for phishing. Email content is sent only to your own machine (`localhost:8008`);
nothing leaves your computer.

## What it does
- Opens an email → a slim banner appears above the message body:
  ✓ **LOOKS SAFE** (green) · ⚠️ **SUSPICIOUS** (amber) · ⛔ **PHISHING** (red), with the risk %.
- **Details ▾** expands to the recommended action, top signals, and the evidence that fired.
- **🔗 Deep scan** runs Link X-ray on the email's links (redirects, destination domain,
  domain age, blocklist hits).

## Run it (basic — no Google setup)
1. Start the analyzer backend from the project root:
   ```
   .venv\Scripts\python.exe -m uvicorn server.app:app --host 127.0.0.1 --port 8008
   ```
2. In Chrome/Edge open `chrome://extensions`, turn on **Developer mode** (top-right).
3. **Load unpacked** → select this `extension/` folder.
4. Open **Gmail** and open any email — the banner appears. Click the 🛡️ toolbar icon
   for settings (on/off, analyzer URL, backend status).

In this mode the extension analyzes the **visible text** (sender, subject, body). That's
enough for most phishing, but the header-based checks (sender authentication, domain
age) can't run without the raw headers — so turn on **header-accurate mode** below.

## Header-accurate mode (optional — Gmail API via OAuth)
This lets the extension pull the **raw message including headers** (`Authentication-Results`,
`List-Unsubscribe`, …) so the sender-auth / domain-age trust discount works — the same
accuracy as pasting "Show original" into the app.

This extension has a **fixed ID**: `oaccmpcmfggkbhbhcbohkcphllnkachp` (set by the `key`
in `manifest.json`).

1. In **Google Cloud Console** (console.cloud.google.com) → the project you used before:
   - **APIs & Services → Library → Gmail API → Enable**.
   - **OAuth consent screen**: External, add the `.../auth/gmail.readonly` scope, and add
     your Gmail under **Test users**.
   - **Credentials → Create credentials → OAuth client ID → Application type: Chrome
     Extension** (older UIs: "Chrome App"). For **Item/Application ID**, paste
     `oaccmpcmfggkbhbhcbohkcphllnkachp`. Create it and copy the **Client ID**.
2. In `manifest.json`, replace `oauth2.client_id`
   (`REPLACE_WITH_YOUR_CHROME_EXTENSION_OAUTH_CLIENT_ID...`) with that Client ID.
3. Reload the extension (`chrome://extensions` → ⟳). Open the popup → **Connect Gmail**
   → approve. Banners now say "Analyzed full message incl. headers."

If you skip this, everything still works on visible-text mode; the banner just notes it.

## Notes & limits
- **Backend must be running** — the extension talks only to your local analyzer, which
  keeps your email on-device (the Gmail API call is Google → your browser only).
- Gmail's page markup is obfuscated and changes over time; the DOM selectors are
  best-effort and used to (a) find the open message and (b) fall back when
  header-accurate mode is off. A missed parse just means no banner — it never breaks
  the page.
- MVP targets Gmail web only. Outlook web and compose-time warnings are future work.
- `key.pem` (the private key that pins the extension ID) is kept locally and gitignored;
  the public half lives in `manifest.json` as `key`.
