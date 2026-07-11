"""
"Sign in with Google" (OAuth 2.0) + Gmail API - the password-free, no-IMAP way for
real users to connect their inbox.

Flow (loopback redirect, the standard pattern for a local app):
  1. /auth/google/start   -> we hand back Google's consent URL + a `state`
  2. user consents in their browser
  3. Google redirects to /auth/google/callback?code=...&state=... on this backend
  4. we swap the code for tokens, remember them under `state`, and the app polls
     /auth/google/status until it sees `connected`
  5. /agent/run (source=gmail_oauth, state=...) fetches the inbox via the Gmail API

Uses the Gmail REST API directly over urllib, so no extra Python packages. Tokens
live only in this local process's memory for the session and are never written to
disk or logged. Scope is gmail.modify so the same connection can both read the inbox
and (Inbox Guardian) add a reversible label - nothing is ever deleted.
"""
import base64
import email
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from email.header import decode_header, make_header

AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URI = "https://oauth2.googleapis.com/token"
API = "https://gmail.googleapis.com/gmail/v1/users/me"
SCOPE = "https://www.googleapis.com/auth/gmail.modify"
REDIRECT_URI = "http://127.0.0.1:8008/auth/google/callback"


# --- client credentials (from env or a downloaded Google console JSON) -----------
def load_client():
    """Return (client_id, client_secret) from env vars or server/google_oauth.json
    (the file Google's console lets you download). Returns (None, None) if unset."""
    cid = os.environ.get("GOOGLE_CLIENT_ID")
    csec = os.environ.get("GOOGLE_CLIENT_SECRET")
    if cid and csec:
        return cid, csec
    path = os.path.join(os.path.dirname(__file__), "google_oauth.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        for k in ("web", "installed"):        # console download nests under these
            if k in d:
                return d[k].get("client_id"), d[k].get("client_secret")
        return d.get("client_id"), d.get("client_secret")
    return None, None


def configured():
    cid, csec = load_client()
    return bool(cid and csec)


def build_auth_url(state):
    cid, _ = load_client()
    q = urllib.parse.urlencode({
        "client_id": cid,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPE,
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": state,
    })
    return f"{AUTH_URI}?{q}"


def _post_form(url, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def exchange_code(code):
    cid, csec = load_client()
    return _post_form(TOKEN_URI, {
        "code": code, "client_id": cid, "client_secret": csec,
        "redirect_uri": REDIRECT_URI, "grant_type": "authorization_code",
    })


def _api_get(path, access_token, params=None):
    url = f"{API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def _api_post(path, access_token, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{API}{path}", data=body, method="POST",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def get_email(access_token):
    try:
        return _api_get("/profile", access_token).get("emailAddress", "")
    except Exception:
        return ""


def _decode(s):
    try:
        return str(make_header(decode_header(s or "")))
    except Exception:
        return s or ""


def fetch_recent(access_token, n=10):
    """Return the n most-recent INBOX messages as
    [{id, uid, raw_email, from, subject}] (newest first), same shape the IMAP path
    used, so the rest of the pipeline is unchanged."""
    listing = _api_get("/messages", access_token,
                       {"maxResults": max(1, n), "labelIds": "INBOX"})
    out = []
    for i, m in enumerate(listing.get("messages", []), 1):
        msg = _api_get(f"/messages/{m['id']}", access_token, {"format": "raw"})
        raw_bytes = base64.urlsafe_b64decode(msg["raw"].encode())
        parsed = email.message_from_bytes(raw_bytes)
        out.append({
            "id": i,
            "uid": m["id"],                       # Gmail message id (for modify)
            "raw_email": raw_bytes.decode("utf-8", "replace"),
            "from": _decode(parsed.get("From", "")) or "(unknown sender)",
            "subject": _decode(parsed.get("Subject", "")) or "(no subject)",
        })
    return out


def apply_action(access_token, msg_ids, label="Phishing-Suspected"):
    """Inbox Guardian via the Gmail API: STAR each message and add a reversible
    '<label>' label. Non-destructive - nothing deleted or moved. Returns the count."""
    if not msg_ids:
        return 0
    # find or create the label
    label_id = None
    for lb in _api_get("/labels", access_token).get("labels", []):
        if lb.get("name") == label:
            label_id = lb["id"]
            break
    if label_id is None:
        label_id = _api_post("/labels", access_token, {
            "name": label, "labelListVisibility": "labelShow",
            "messageListVisibility": "show"}).get("id")
    add = ["STARRED"] + ([label_id] if label_id else [])
    for mid in msg_ids:
        _api_post(f"/messages/{mid}/modify", access_token, {"addLabelIds": add})
    return len(msg_ids)
