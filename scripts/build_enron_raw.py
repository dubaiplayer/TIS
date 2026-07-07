"""
Build Enron_raw.csv from the raw Kaggle Enron dump (wcukierski/enron-email-dataset).

Why: our previous Enron source (Enron.csv) was pre-lowercased and
punctuation-stripped, which flattened all casing/tone/urgency signal for the
legitimate class and confounded those features with source+label. This raw dump
(`emails.csv`, columns: file, message) keeps original casing/punctuation.

What this does:
  1. Streams the 1.43 GB emails.csv once (memory-safe reservoir sampling).
  2. Reservoir-samples ~15,800 messages with a FIXED seed (reproducible).
  3. Parses each raw RFC822 message -> Subject header + body (headers dropped at
     the first blank line, exactly as an email client would). Casing/punctuation
     of the body are preserved verbatim.
  4. Labels every row 0 (legitimate) -- raw Enron contains no phishing, and our
     other files use 0=legit / 1=phishing.
  5. Writes Enron_raw.csv with schema `subject,body,label` (matches the old
     Enron.csv schema, so the merge-by-column-name step just works).
"""

import csv
import email
import os
import random
import sys

DATA_DIR = r"C:\Users\15DGupta\Downloads\archive (4)"
SRC = os.path.join(DATA_DIR, "emails.csv")
OUT = os.path.join(DATA_DIR, "Enron_raw.csv")

SEED = 42
SAMPLE_N = 15_800


def raise_field_size_limit():
    """csv chokes on the long message fields at the default 128 KB limit."""
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit = int(limit // 10)


def parse_message(raw):
    """Return (subject, body) from a raw RFC822 message string.

    Uses the stdlib email parser (robust header/body split incl. the X-* Enron
    headers and MIME wrapper); falls back to a first-blank-line split if parsing
    fails. Body casing/punctuation left exactly as-is aside from trimming the
    surrounding whitespace/newlines.
    """
    try:
        msg = email.message_from_string(raw)
    except Exception:
        # Fallback: headers end at the first blank line.
        parts = raw.split("\n\n", 1)
        body = parts[1] if len(parts) == 2 else raw
        return "", body.strip()

    subject = msg.get("Subject", "") or ""

    if msg.is_multipart():
        chunks = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not part.is_multipart():
                payload = part.get_payload(decode=True)
                if payload:
                    chunks.append(payload.decode("utf-8", "replace"))
        body = "\n".join(chunks)
    else:
        payload = msg.get_payload(decode=True)
        if payload is None:
            body = msg.get_payload()
            body = body if isinstance(body, str) else ""
        else:
            body = payload.decode("utf-8", "replace")

    return subject.strip(), body.strip()


def reservoir_sample_messages(path, k, seed):
    """Algorithm R over the `message` column. One pass, O(k) memory, reproducible
    given (seed, file order). Returns a list of raw message strings and the total
    row count seen."""
    rng = random.Random(seed)
    reservoir = [None] * k
    n = 0
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        try:
            msg_idx = header.index("message")
        except ValueError:
            raise SystemExit(f"Expected a 'message' column, got header: {header}")
        for row in reader:
            if len(row) <= msg_idx:
                continue  # malformed row
            raw = row[msg_idx]
            if n < k:
                reservoir[n] = raw
            else:
                j = rng.randint(0, n)  # inclusive
                if j < k:
                    reservoir[j] = raw
            n += 1
    if n < k:
        reservoir = [r for r in reservoir if r is not None]
    return reservoir, n


def main():
    raise_field_size_limit()
    print(f"Reading {SRC}")
    print(f"Reservoir sampling {SAMPLE_N:,} messages (seed={SEED}) ...")
    sampled, total = reservoir_sample_messages(SRC, SAMPLE_N, SEED)
    print(f"  total messages in source : {total:,}")
    print(f"  sampled                  : {len(sampled):,}")

    empties = 0
    rows = []
    for raw in sampled:
        subject, body = parse_message(raw)
        if not body:
            empties += 1
        rows.append((subject, body, 0))

    with open(OUT, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["subject", "body", "label"])
        writer.writerows(rows)

    print(f"  empty-body rows          : {empties:,}")
    print(f"Wrote {OUT} ({len(rows):,} rows, schema: subject,body,label, label=0)")

    # Show a couple of parsed samples so casing/punctuation is visibly intact.
    print("\n--- sample parsed rows ---")
    for subject, body, _ in rows[:2]:
        preview = body[:280].replace("\n", " \\n ")
        print(f"SUBJECT: {subject!r}")
        print(f"BODY   : {preview}")
        print("-" * 60)


if __name__ == "__main__":
    main()
