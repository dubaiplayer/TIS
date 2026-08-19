# Shipping Outlook support to the Chrome Web Store

One release: **v1.2.0**, already built and verified at `dist/phishingnet-1.2.0.zip`.

**Can you just re-upload the zip?** Not quite. The package carries the code, but the
**permission justifications are dashboard fields stored outside the package**, and
v1.2.0 requests two things v1.0.0 did not (`scripting`, plus three optional Outlook
hosts). Empty justification boxes on a new permission are a rejection. The listing
description and screenshots also live outside the package and won't update themselves.

**What ships alongside Outlook.** The published build predates the analyzer cold-start
work, which lives in the same files, so it rides along in this release. That is not
scope creep you can drop — it is already in the code being packaged. It is also a fix
worth having: without it a cold analyzer is reported to the user as unavailable.

**What does NOT change.** Gmail behavior is untouched — the Outlook work moved Gmail's
scraping behind an adapter without editing any of it. And critically, no **required**
host permission is added, so existing users are not prompted and not disabled on update.

---

## Before you upload

### Already confirmed working (2026-08-19, consumer Outlook)

Verified from live captures on `outlook.live.com`:

- The OWA selectors match a real mailbox — subject, sender and body all scrape
  correctly, and the banner places above the message.
- A phishing test message scores **99% / PHISHING** with the full signal breakdown,
  attribute bars, flagged words and highlighted body all rendering.
- A benign message scores **4% / LOOKS SAFE** — so the no-auth-header tradeoff is not
  blowing up into obvious false positives on ordinary mail.
- The dark-theme CSS renders correctly against Outlook's dark reading pane.
- The grant flow works: pressing **Enable** in the popup produces banners in Outlook.

That retires what was the main pre-submission risk. What follows is what is left.

### 1. Still unverified: work/school Outlook

The manifest claims `outlook.office.com` and `outlook.office365.com`, but only consumer
Outlook has been tested. They share the OWA codebase so the adapter very likely works,
and the optional permission means nobody gets it without asking.

If you have access to a Microsoft 365 mailbox, open a message there and run
`scripts/verify_outlook_selectors.js` in the console. If you do not, **ship the three
hosts anyway** — removing them later is another review cycle, and a tenant where the
selectors miss degrades to "no banner", never a broken page.

| Result | Action |
|---|---|
| A `BODY` candidate matches | Good. If it isn't first in the chain, reorder `OWA_BODY` in `content.js`. |
| No `BODY` candidate matches | The adapter draws nothing on that host — report it. |
| `in iframe: true` | Set `allFrames: true` in `OUTLOOK_SCRIPT` in `background.js`, rebuild. |
| `sender found: (none)` | Fine. `From:` carries a display name; no trust discount applies either way. |

### 2. Finish the revoke / restart tests

The grant path is confirmed; these are the paths that are not:

- Press **Enabled ✓** in the popup to revoke → reload Outlook → no banner, and
  `await chrome.scripting.getRegisteredContentScripts()` in the service-worker console
  no longer lists `outlook`.
- Revoke instead from `chrome://extensions` → PhishingNet → **Site access** → the
  registration should disappear the same way.
- Quit Chrome entirely with an Outlook tab open, relaunch, let the tab restore → the
  banner still appears without a manual reload. This is what `persistAcrossSessions`
  buys and the only way to catch it failing.
- Confirm Gmail still banners normally with auth-backed verdicts.

### 3. Confirm no existing user gets disabled

The check that matters most, because getting it wrong disables the extension for
everyone currently using it.

```bash
git worktree add ../TIS-published v1.1.0     # closest tree to the published build
```

Load that unpacked, open **Details**, screenshot the **Permissions** and **Site access**
sections. Load the v1.2.0 tree and screenshot the same two. **They must be identical.**
If `scripting` shows up as a user-visible line, stop.

Then in a **fresh Chrome profile**: load v1.2.0, touch nothing, and confirm Gmail works,
`await chrome.scripting.getRegisteredContentScripts()` in the service-worker console
returns only the `gmail` entry, and `outlook.live.com` injects nothing at all.

### 4. Spot-check false positives on real transactional mail

Outlook sends no auth headers, so the sender-trust discount never engages there. A plain
personal email already scored 4%, but the discount exists for *transactional* mail
specifically — so open two or three real receipts or account notifications (bank,
retailer, SaaS) in Outlook and check none of them come back PHISHING. If one does, that
is the known tradeoff surfacing, and the call is whether to ship anyway or revisit it.

### 5. Screenshots — ready

`Extension Pics/store/` holds four 1280×800 PNGs: `screenshot-1` and `-2` (Gmail, from
the first publication), `screenshot-3` (Outlook, PHISHING with details expanded) and
`screenshot-4` (Outlook, LOOKS SAFE). Regenerate any capture with:

```
.venv\Scripts\python.exe scripts/make_store_screenshot.py "<capture>.png" -o "<dest>.png"
```

---

## Uploading

Dashboard: <https://chrome.google.com/webstore/devconsole> → **PhishingNet**. Section
names are by function; Google renames them periodically. Do these **in order** — the
justification boxes for the new permissions only appear once the package is uploaded.

**1. Package → Upload new package** → `dist/phishingnet-1.2.0.zip`.
Must be the `.zip` itself, not the `extension/` folder. This creates a **draft** —
nothing reaches users until you press Submit, and drafts can be overwritten or
discarded freely.

**2. Read the permissions warning before doing anything else.**
You should see `scripting` and the three Outlook hosts listed as newly requested. You
should **not** see any banner saying existing users must re-authorize, or that the
extension will be disabled for them. If you do: discard the draft and stop. That is the
exact failure this design exists to prevent.

**3. Store listing → Description.** A dashboard field, independent of the manifest — it
does not update when you upload a package. Make it name both clients. The manifest's
128-char version is a drop-in if you want it:

> Phishing safety check in Gmail and Outlook. Analyzes each email you open and shows an
> inline verdict with the reasons behind it.

**4. Store listing → Screenshots.** Add at least one Outlook screenshot (banner over a
message on `outlook.live.com`), ideally plus the popup showing the **Enable** control.
A description claiming Outlook with Gmail-only screenshots is a recognized rejection
reason.

**5. Privacy practices → Single purpose:**

> The Extension has one purpose: to warn the user about phishing in the email they are
> currently reading. Everything it does — reading the open message, sending its text to
> the analyzer for a verdict, and rendering that verdict as an inline banner — serves
> that single purpose. Support for Outlook on the web is the same feature applied to a
> second mail client; it is not an additional purpose.

**6. Privacy practices → Permission justifications.** Two new boxes appear.

`scripting`:

> Required to register the message-reading and banner-rendering content script on
> Outlook on the web after the user has explicitly granted the optional host permission
> for Outlook. It is never used to inject into a host the user has not granted. Gmail
> support continues to use a static content_scripts declaration and does not use this
> API.

Optional host permissions (`outlook.live.com`, `outlook.office.com`,
`outlook.office365.com`):

> To read the message the user currently has open in Outlook on the web and to display
> the phishing verdict banner above it — identical to the functionality already shipped
> for mail.google.com. These are declared as optional_host_permissions and are requested
> at runtime only after the user presses "Enable" in the Extension's popup. The
> Extension does not run on any Outlook page unless the user has granted this. The three
> domains are the consumer (outlook.live.com) and work/school (outlook.office.com,
> outlook.office365.com) hosts of Outlook on the web.

Leave the existing `storage` and analyzer-host justifications alone unless the form has
cleared them.

**7. Privacy practices → Data usage.** Keep "personal communications" declared and
re-tick the three certifications if the form reset them. Nothing about the data flow
changed — same text, same endpoint, same host.

**8. Privacy policy URL** — unchanged, and already live with the Outlook wording at
`https://dubaiplayer.github.io/TIS/PRIVACY`.

**9. Submit for review** with these version notes:

> Adds optional support for Outlook on the web. Outlook access is declared as
> optional_host_permissions and is OFF by default; it is requested at runtime only when
> the user presses "Enable" in the popup, and can be revoked from the same button.
> Gmail support is unchanged. Also adds handling for the analyzer service's cold start,
> so a slow first response is shown as a "starting up" state that retries rather than
> being reported as the service being unavailable. No change to what data is collected
> or where it is sent: the same visible message text goes to the same analyzer host. No
> sender-authentication data is read from Outlook. The privacy policy has been updated
> to describe the optional Outlook permission.

If **Submit** stays greyed out, walk every tab looking for a warning icon — one
incomplete required field anywhere blocks submission.

Expect **several business days to ~2 weeks**. Permission changes on an extension
handling personal communications are the slowest review bucket, and justification
wording sometimes bounces once.

---

## If it misbehaves after release

The store has no rollback. Levers, fastest first:

| Lever | Speed | Reach |
|---|---|---|
| User revokes Outlook from the popup or `chrome://extensions` | Instant | That user, Outlook only — surgical |
| User turns off the popup's scanning toggle | Instant | That user, but kills Gmail too |
| Unpublish the listing | Hours | New installs only; existing users keep the build |
| Publish v1.2.1 with the Outlook commits reverted | Days–weeks | Everyone |

Both instant levers need *the user* to act, so they are not an operator kill switch.
The revert path is `git revert 5ac3d52 151f08c` (adapter + permission plumbing), which
leaves the cold-start fix in place; set version `1.2.1`, rebuild, upload.

If you want an operator-side switch, the cheap version is to have `/health` return an
`outlook` flag and let `reconcileOutlook` treat it as an extra condition alongside the
permission — unregistering while leaving the user's grant intact. No new permission, no
review needed to *use* it — but it has to ship *in* this release to exist.
