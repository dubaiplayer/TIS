"""
Text cleaning for the phishing corpus.

Design rule: this is NOT a generic spam pipeline. We deliberately PRESERVE
casing and punctuation because they are signal here (urgency, shouting, tone).
We only remove structural noise: HTML markup, leaked email-header remnants, and
excessive whitespace.
"""

import re

from bs4 import BeautifulSoup

# Header lines that leaked into `body` fields (esp. SpamAssassin / forwarded mail).
_HEADER_LINE = re.compile(
    r"^\s*(?:Message-ID|Date|From|To|Cc|Bcc|Sent|Subject|Reply-To|Return-Path|"
    r"Content-Type|Content-Transfer-Encoding|MIME-Version|X-[\w-]+)\s*:",
    re.IGNORECASE,
)
# mbox separator and forwarding banners.
_MBOX_FROM = re.compile(r"^From \S+@\S+")
_FWD_BANNER = re.compile(
    r"^\s*-{2,}.*?(Original Message|Forwarded by|Forwarded message).*?-{2,}\s*$",
    re.IGNORECASE,
)
_TAG_HINT = re.compile(r"<\s*(html|body|div|table|td|tr|br|p|a|span|font|img)\b", re.IGNORECASE)
_WS_RUN = re.compile(r"[ \t\f\v]+")
_BLANKS = re.compile(r"\n\s*\n\s*(?:\n\s*)+")


def strip_html(text):
    """Extract visible text, but only pay the BeautifulSoup cost when the body
    actually looks like HTML."""
    if not text or not _TAG_HINT.search(text):
        return text
    try:
        return BeautifulSoup(text, "lxml").get_text(separator=" ")
    except Exception:
        return text


def strip_header_remnants(text):
    """Drop leaked header lines, mbox separators, and forwarding banners.

    Conservative: a run of header-looking lines at the START of the body (or a
    forwarding banner) is removed; ordinary prose lines are kept untouched.
    """
    if not text:
        return text
    out = []
    for line in text.splitlines():
        if _FWD_BANNER.match(line) or _MBOX_FROM.match(line):
            continue
        if _HEADER_LINE.match(line):
            continue
        out.append(line)
    return "\n".join(out)


def normalize_whitespace(text):
    """Collapse space/tab runs and 3+ blank lines, trim trailing spaces per line.
    Casing and punctuation are left exactly as-is."""
    if not text:
        return text
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _WS_RUN.sub(" ", text)
    text = "\n".join(ln.rstrip() for ln in text.split("\n"))
    text = _BLANKS.sub("\n\n", text)
    return text.strip()


def clean_body(text):
    """Full body cleaner: HTML -> header remnants -> whitespace."""
    if not isinstance(text, str):
        return ""
    return normalize_whitespace(strip_header_remnants(strip_html(text)))


def build_text(subject, body):
    """Combine subject + cleaned body into the field features run on (and that
    evidence-span offsets index into)."""
    subject = subject if isinstance(subject, str) else ""
    body = clean_body(body)
    subject = normalize_whitespace(subject)
    if subject and body:
        return f"{subject}\n\n{body}"
    return subject or body
