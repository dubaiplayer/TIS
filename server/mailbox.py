"""
Fetch recent emails from a real mailbox (Gmail / Outlook) over IMAP so the Live
Agent can triage them with the same SKILL.md flow used for the synthetic demo.

The user signs in with their address + an APP PASSWORD (not their normal
password). Credentials are used ONLY for this one IMAP connection on the local
backend and are never stored, logged, or sent anywhere else.
"""
import email
import imaplib
from email.header import decode_header, make_header

# IMAP endpoints. Gmail has IMAP on by default; both require an app password
# (with 2-step verification enabled on the account).
IMAP_HOSTS = {
    "gmail": ("imap.gmail.com", 993),
    "outlook": ("outlook.office365.com", 993),
}


def _decode(s):
    try:
        return str(make_header(decode_header(s or "")))
    except Exception:
        return s or ""


def fetch_recent(address, app_password, n=10, provider="gmail"):
    """Return the n most-recent INBOX messages as
    [{id, raw_email, from, subject}] (newest first). Raises RuntimeError with a
    clear message on login/connection failure."""
    host, port = IMAP_HOSTS.get(provider, IMAP_HOSTS["gmail"])
    try:
        M = imaplib.IMAP4_SSL(host, port, timeout=20)
    except Exception as e:
        raise RuntimeError(f"Could not reach {host}: {e}") from e
    try:
        try:
            M.login(address, app_password)
        except imaplib.IMAP4.error as e:
            raise RuntimeError(
                "IMAP login failed. Use your email address and a Gmail/Outlook "
                "APP PASSWORD (2-step verification must be on) - not your normal "
                f"account password. ({e})") from e

        M.select("INBOX")
        typ, data = M.uid("search", None, "ALL")
        uids = data[0].split()
        recent = uids[-max(1, n):][::-1]  # newest first
        out = []
        for i, uid in enumerate(recent, 1):
            typ, msg_data = M.uid("fetch", uid, "(RFC822)")
            if not msg_data or not msg_data[0]:
                continue
            raw_bytes = msg_data[0][1]
            msg = email.message_from_bytes(raw_bytes)
            out.append({
                "id": i,
                "uid": uid.decode() if isinstance(uid, bytes) else str(uid),
                "raw_email": raw_bytes.decode("utf-8", "replace"),
                "from": _decode(msg.get("From", "")) or "(unknown sender)",
                "subject": _decode(msg.get("Subject", "")) or "(no subject)",
            })
        return out
    finally:
        try:
            M.logout()
        except Exception:
            pass


def apply_action(address, app_password, uids, provider="gmail", label="Phishing-Suspected"):
    """Inbox Guardian action: STAR the given INBOX message UIDs and (Gmail) add a
    reversible '<label>' label. Non-destructive - nothing is deleted or moved, so
    a false positive is trivially undone in Gmail. Returns how many were tagged."""
    if not uids:
        return 0
    host, port = IMAP_HOSTS.get(provider, IMAP_HOSTS["gmail"])
    M = imaplib.IMAP4_SSL(host, port, timeout=20)
    try:
        try:
            M.login(address, app_password)
        except imaplib.IMAP4.error as e:
            raise RuntimeError(f"IMAP login failed: {e}") from e
        M.select("INBOX")
        uidset = ",".join(str(u) for u in uids)
        M.uid("STORE", uidset, "+FLAGS", "(\\Flagged)")   # star (universally visible)
        if provider == "gmail":
            try:
                M.create(label)   # Gmail: a folder == a label; ignore if it exists
            except Exception:
                pass
            try:
                M.uid("COPY", uidset, label)   # copy-to-label applies the label
            except Exception:
                pass
        return len(uids)
    finally:
        try:
            M.logout()
        except Exception:
            pass
