---
layout: default
title: Privacy Policy — Inbox Shield
---

# Privacy Policy — Phishing Analyzer (Inbox Shield)

**Last updated: August 2026**

Phishing Analyzer ("Inbox Shield", the "Extension") is a browser extension that checks
the email you are viewing in Gmail for signs of phishing and shows an inline verdict
with the reasons behind it. This policy explains exactly what the Extension does and
does not do with your data.

## What the Extension accesses

When you **open an email in Gmail**, the Extension reads that single email as shown on
the page — its **sender, subject, body text, and the links it contains** — and sends
that text to the Phishing Analyzer service to be checked. It does this only for the
email you are currently viewing.

The Extension also reads the **sender-authentication result that Gmail itself displays**
for that message (the "mailed-by" and "signed-by" values shown under *Show details*), and
sends it along with the text. This is Gmail's own verification of whether the message
genuinely came from the domain it claims, and it lets the analyzer avoid wrongly flagging
legitimate mail from banks, retailers, and other services. It is read from Gmail's own
interface — the Extension does not perform any authentication check of its own, and does
not access your account to obtain it.

The Extension also stores your **settings** (whether automatic scanning is on, and the
analyzer address) in your browser's extension storage.

## What the Extension does NOT do

- It does **not** sign in to your Google account, and it does **not** use your Google
  credentials.
- It does **not** read, download, or scan your whole mailbox — only the message
  currently open on screen.
- It does **not** track your browsing, and it contains **no advertising or analytics**.
- It does **not** collect your name, contacts, or any personal profile.

## How your data is used

The email text is sent to the Phishing Analyzer service
(`https://phishing-analyzer-api-wq1v.onrender.com`) solely to compute a phishing
verdict, a risk score, and the supporting evidence, which are returned to the Extension
and displayed to you.

- Email content is analyzed **in memory** to produce the verdict and is **not stored,
  logged, or retained** after the response is returned.
- Your data is **never sold, rented, or shared** with any third party.
- The analysis is used only to provide the Extension's core function (phishing
  detection) and for no other purpose.

## Permissions and why they are needed

- **`storage`** — to save your settings (scanning on/off, analyzer address).
- **Access to `mail.google.com`** (content script) — to read the email you have open
  and to display the safety banner inside Gmail.
- **Access to the analyzer service host** — to send the email text for analysis and
  receive the verdict.

## Your choices

You can turn automatic scanning off at any time from the Extension's popup, change the
analyzer address, or remove the Extension from your browser to stop all processing.

## Children

The Extension is not directed to children under 13 and does not knowingly collect data
from them.

## Changes to this policy

This policy may be updated from time to time; the "Last updated" date above will change
accordingly.

## Contact

Questions about this policy can be sent to **guptadevesh@hotmail.com**.
