# Releasing PhishingNet to the Chrome Web Store

The store currently has **v1.0.0**. Two releases are tagged and pushed but unpublished,
and they must ship **in this order**:

| | Version | Contents | Permission change? |
|---|---|---|---|
| 1 | `v1.1.0` | PhishingNet rename + analyzer cold-start handling | No |
| 2 | `v1.2.0` | Opt-in Outlook on the web | Yes (`scripting` + optional hosts) |

**Why two releases.** The store has no rollback — recovery from a bad release means
publishing a *higher* version containing older code. Until v1.1.0 is live and healthy,
the only rollback target is v1.0.0, which lacks the cold-start fix. Shipping v1.1.0
first also keeps v1.2.0's permission diff readable for a reviewer: one permission line
and an optional-hosts block, rather than that tangled with a rename and ~150 lines of
behavior change. A pending review blocks the next upload, so v1.2.0 cannot go up until
v1.1.0 clears.

**Can you just re-upload the zip?** For v1.1.0, effectively yes — upload and submit.
For v1.2.0, no: the package carries the code, but the **store listing description,
screenshots, and permission justifications are dashboard fields stored outside the
package**. A new permission with no justification filled in is a rejection.

Both packages are pre-built and verified in `dist/` (gitignored):

| File | Version | Upload for |
|---|---|---|
| `dist/phishingnet-1.1.0.zip` | 1.1.0 | Release 1 |
| `dist/phishingnet-1.2.0.zip` | 1.2.0 | Release 2 |

Dashboard: <https://chrome.google.com/webstore/devconsole> → select **PhishingNet**.
Section names below are by function; Google renames them periodically.

---

## Release 1 — v1.1.0

### Build (already done — only if you need to rebuild)

```bash
git checkout v1.1.0
python scripts/build_extension_zip.py     # -> inbox-shield.zip
git checkout main
```

Confirm the build prints `PhishingNet v1.1.0`, and that the zip contains
`manifest.json` at the archive root and **no** `key.pem`, `.manifest_key.txt`, or
`README.md`.

### Upload, step by step

1. Dashboard → **PhishingNet** → **Package** (or "Build") → **Upload new package**.
2. Select `dist/phishingnet-1.1.0.zip`. It must be the `.zip` itself, not the
   `extension/` folder and not a folder containing the zip.
3. If it rejects the version, the published version is already ≥ 1.1.0 — check the
   listing's current version before rebuilding.
4. Go to **Store listing**. The name now reads **PhishingNet**; update the title there
   if it still shows "Phishing Analyzer — Inbox Shield". Leave the description alone
   for this release.
5. **Privacy practices** — nothing changes. Confirm the policy URL is still
   `https://dubaiplayer.github.io/TIS/PRIVACY` and the three data-use certifications
   are still ticked. If the form shows any field as newly required, fill it now.
6. **Submit for review**, pasting the version notes below.
7. Any tab showing an incomplete-field warning blocks submission — the button greys
   out until every required field on every tab is filled.

### Test before uploading

1. `chrome://extensions` → Developer mode → **Load unpacked** → `extension/`.
   (The `key` field in the source manifest pins the unpacked ID, so this reuses the
   same storage and permission state a real upgrading user would have.)
2. Let the Render instance idle 15+ minutes, then open a Gmail message. The waking
   banner should appear, tick its counter, and **swap in place** to a verdict rather
   than stacking a second banner.
3. Check the popup's status dot reaches "Analyzer online".

### Submit

Dashboard → PhishingNet → Package → Upload new package → fill **version notes**:

> Renames the extension to PhishingNet, matching the published privacy policy. Adds
> handling for the analyzer service's cold start: a slow first response is now shown as
> a "starting up" state that retries, instead of being reported as the service being
> unavailable. No change to permissions or to what data is collected.

Nothing else on the listing changes for this release. Expect **1–3 business days**.

**Wait until it is published before starting Release 2.**

---

## Release 2 — v1.2.0

### Blocking prerequisite: verify the Outlook selectors

The OWA selectors in `content.js` were written without a live mailbox to test against.
Confirm them before shipping:

1. Open Outlook on the web, open a message in the reading pane.
2. F12 → Console → paste all of `scripts/verify_outlook_selectors.js` → Enter.
3. Repeat on: a work/school account (`outlook.office.com`), a pop-out message window,
   and a conversation with several messages expanded.
4. Then open a **different** message without reloading and run it again.

What the results mean:

| Result | Action |
|---|---|
| A `BODY` candidate matches | Good. If it isn't the first in the chain, reorder `OWA_BODY` in `content.js`. |
| No `BODY` candidate matches | Stop. The adapter would show no banner. Report the output. |
| `in iframe: true` | Set `allFrames: true` in `OUTLOOK_SCRIPT` in `background.js`. |
| `sender found: (none)` | Acceptable — `From:` carries a display name and no trust discount applies, which is already the Outlook behavior. |
| `body id` unchanged between two messages | Expected; the identity check in `scanOnce` handles it. |

### Then check the false-positive cost

Outlook sends no auth headers, so the sender-trust discount never engages there. Run
the same few transactional messages (bank, retailer, SaaS notification) through both
clients and compare verdicts. If Outlook is flagging obviously-legitimate mail as
suspicious, that is the known tradeoff showing up — decide whether to ship as-is,
soften the Outlook copy, or revisit the auth question before release.

### Verify no existing user gets disabled

This is the check that matters most, because getting it wrong disables the extension
for everyone currently using it.

1. Load the **published** tree unpacked (`git worktree add ../TIS-v1.1.0 v1.1.0`),
   open Details, and screenshot the **Permissions** and **Site access** sections.
2. Load the v1.2.0 tree and screenshot the same two sections.
3. **They must be identical.** If `scripting` appears as a user-visible line, stop.
4. In a fresh Chrome profile, load v1.2.0, touch nothing, and confirm: Gmail works as
   before; the service worker console shows only the `gmail` entry from
   `await chrome.scripting.getRegisteredContentScripts()`; and `outlook.live.com`
   injects nothing — no banner, no network call to the analyzer.

Static analysis already confirms the manifest side: no new **required** host
permissions, `content_scripts` matches unchanged, Outlook only in
`optional_host_permissions`.

### Exercise the grant/revoke lifecycle

Check `await chrome.scripting.getRegisteredContentScripts()` after each step:

- Grant with an Outlook tab **already open** → banner appears without a reload.
- Grant with no Outlook tab open, then open one → banner appears.
- Revoke from the popup → registration disappears.
- Revoke from `chrome://extensions` → Site access → registration disappears.
- Revoke while the service worker is asleep (terminate it first), then reopen the
  popup → the wake-time reconcile cleans up the registration.
- Terminate and wake the worker ~10× with the grant active → no "Duplicate script ID",
  registration count stays at 1.
- Quit Chrome entirely with an Outlook tab open, relaunch, let the tab restore →
  banner appears without a manual reload.
- Reload a granted Outlook tab repeatedly and navigate the SPA → exactly one banner
  per message.
- Sign a second Chrome profile into the same account → the popup there reads
  **Enable**, not "Enabled ✓" (permissions do not sync; nothing leaked into storage).

### Upload, step by step

Do these **in order**. Uploading the package last would mean filling justifications for
permissions the dashboard doesn't know about yet.

1. **Package → Upload new package** → `dist/phishingnet-1.2.0.zip`.
   This creates a **draft**. Nothing reaches users until you press Submit, and a draft
   can be overwritten or discarded freely.
2. **Stop and read the permissions warning.** After upload the dashboard lists the newly
   requested permissions. You should see `scripting` and the three optional Outlook
   hosts, and you should **not** see any banner saying the update requires existing
   users to re-authorize or that it will be disabled for them. If you do see one,
   discard the draft and stop — that is the failure mode this whole design exists to
   avoid, and shipping it would disable the extension for every current user.
3. **Store listing → Description.** This is a dashboard field, independent of the
   manifest — it does not update itself when you upload a package. Replace the
   Gmail-only text so it names both clients (the 128-char string above is a drop-in, or
   write longer copy; the listing field allows far more than the manifest's 132).
4. **Store listing → Screenshots.** Add at least one Outlook screenshot (banner over a
   message on `outlook.live.com`) and ideally one of the popup showing the **Enable**
   control. A description claiming Outlook with only Gmail screenshots is a recognized
   rejection reason.
5. **Privacy practices → Single purpose** — replace with the text below.
6. **Privacy practices → Permission justifications.** Two new boxes will have appeared,
   for `scripting` and for the optional host permissions. Both are required; paste the
   text below. Leave the existing `storage` and analyzer-host justifications as they
   are unless the form has cleared them.
7. **Privacy practices → Data usage.** Keep "personal communications" declared and
   re-tick the three certifications if the form reset them. Nothing about the data flow
   changed.
8. **Privacy policy URL** — unchanged and already live with the new Outlook wording.
9. **Submit for review**, pasting the reviewer version notes below.

### Listing fields to update

**Description** (already in the manifest, 128 chars):

> Phishing safety check in Gmail and Outlook. Analyzes each email you open and shows an
> inline verdict with the reasons behind it.

**Screenshots** — the listing is Gmail-only today. Claiming Outlook without an Outlook
screenshot is a recognized rejection reason. Add at least one banner-over-an-Outlook-
message shot, plus ideally the popup showing the Enable control so the opt-in is
self-evident to the reviewer.

**Privacy policy URL** — unchanged, and already live with the new content at
`https://dubaiplayer.github.io/TIS/PRIVACY`.

**Single purpose:**

> The Extension has one purpose: to warn the user about phishing in the email they are
> currently reading. Everything it does — reading the open message, sending its text to
> the analyzer for a verdict, and rendering that verdict as an inline banner — serves
> that single purpose. Support for Outlook on the web is the same feature applied to a
> second mail client; it is not an additional purpose.

**`storage` justification:**

> Stores the user's own settings: whether automatic scanning is on, and the address of
> the analysis service. No message content is stored.

**`scripting` justification (new):**

> Required to register the message-reading and banner-rendering content script on
> Outlook on the web after the user has explicitly granted the optional host permission
> for Outlook. It is never used to inject into a host the user has not granted. Gmail
> support continues to use a static content_scripts declaration and does not use this
> API.

**Optional host permissions justification (new):**

> To read the message the user currently has open in Outlook on the web and to display
> the phishing verdict banner above it — identical to the functionality already shipped
> for mail.google.com. These are declared as optional_host_permissions and are requested
> at runtime only after the user presses "Enable" in the Extension's popup. The
> Extension does not run on any Outlook page unless the user has granted this. The three
> domains are the consumer (outlook.live.com) and work/school (outlook.office.com,
> outlook.office365.com) hosts of Outlook on the web.

**Analyzer host justification** (unchanged):

> To send the text of the open email to the analysis service and receive the phishing
> verdict, risk score, and supporting evidence.

**Remote code:** No — all logic ships in the package.

**Data usage:** "Personal communications" stays declared; re-affirm the three
certifications. Nothing about the data flow changes.

**Version notes for the reviewer:**

> Adds optional support for Outlook on the web. Outlook access is declared as
> optional_host_permissions and is OFF by default; it is requested at runtime only when
> the user presses "Enable" in the popup, and can be revoked from the same button.
> Gmail support is unchanged. No change to what data is collected or where it is sent:
> the same visible message text goes to the same analyzer host. No sender-authentication
> data is read from Outlook. The privacy policy has been updated to describe the
> optional Outlook permission.

Expect **several business days to ~2 weeks** — permission changes on an extension
handling personal communications are the slowest review bucket, and justification
wording can bounce once. Do not schedule this against a hard date.

---

## If v1.2.0 misbehaves in the wild

The store has no rollback. Levers, fastest first:

| Lever | Speed | Reach |
|---|---|---|
| User revokes Outlook from the popup or `chrome://extensions` | Instant | That user, Outlook only — surgical |
| User turns off the popup's scanning toggle | Instant | That user, but kills Gmail too |
| Unpublish the listing | Hours | New installs only; existing users keep the build |
| Publish v1.2.1 with the Outlook commits reverted | Days–weeks | Everyone |

Both instant levers need *the user* to act, so they are not an operator kill switch.
The revert path is `git revert 5ac3d52 151f08c`, set version `1.2.1`, rebuild, upload —
and because v1.1.0 will be published and healthy by then, that target has real mileage
rather than being a hypothetical build.

If an operator-side switch matters to you, the cheap version is to have `/health`
return an `outlook` flag and let `reconcileOutlook` treat it as an extra condition
alongside the permission — unregistering while leaving the user's grant intact. It needs
no new permission and no review to *use* once shipped, but it has to ship *in* v1.2.0
to be available.
