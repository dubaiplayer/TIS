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
        typ, data = M.search(None, "ALL")
        ids = data[0].split()
        recent = ids[-max(1, n):][::-1]  # newest first
        out = []
        for i, num in enumerate(recent, 1):
            typ, msg_data = M.fetch(num, "(RFC822)")
            if not msg_data or not msg_data[0]:
                continue
            raw_bytes = msg_data[0][1]
            msg = email.message_from_bytes(raw_bytes)
            out.append({
                "id": i,
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
