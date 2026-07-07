"""
Step 8 — per-source casing/punctuation sanity check across the NEW merged corpus.

The merge now pulls Enron from Enron_raw.csv (raw, casing-preserved) instead of
the old flattened Enron.csv. This script recomputes the casing/punctuation
signals per source so we can confirm the Enron source no longer looks
artificially flat compared to the others before moving on to feature engineering.

For contrast it also reports the OLD Enron.csv (excluded from the merge) so the
before/after is visible in one table.

Metrics (mean per email, over the `body` field):
  upper_ratio  : uppercase letters / all letters      (flattened text -> ~0)
  caps_word%   : ALL-CAPS words / words-with-letters   (shouting / acronyms)
  !/1k         : '!' characters per 1000 chars         (exclamation density)
  ?/1k         : '?' characters per 1000 chars
  avg_len      : mean body length in chars
"""

import csv
import os
import sys

DATA_DIR = r"C:\Users\15DGupta\Downloads\archive (4)"

# (label, filename, in_merge?) -- body column is "body" in every one of these.
SOURCES = [
    ("Enron_raw (NEW)", "Enron_raw.csv", True),
    ("CEAS_08", "CEAS_08.csv", True),
    ("Ling", "Ling.csv", True),
    ("Nazario", "Nazario.csv", True),
    ("Nigerian_Fraud", "Nigerian_Fraud.csv", True),
    ("SpamAssasin", "SpamAssasin.csv", True),
    ("Enron (OLD, excluded)", "Enron.csv", False),
]


def raise_field_size_limit():
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit = int(limit // 10)


def email_stats(text):
    """Per-email casing/punctuation ratios. Returns None if there are no letters
    (can't compute a casing ratio)."""
    if not text:
        return None
    letters = upper = 0
    for ch in text:
        if ch.isalpha():
            letters += 1
            if ch.isupper():
                upper += 1
    if letters == 0:
        return None

    words_with_letters = caps_words = 0
    for tok in text.split():
        has_letter = any(c.isalpha() for c in tok)
        if not has_letter:
            continue
        words_with_letters += 1
        tok_letters = [c for c in tok if c.isalpha()]
        if len(tok_letters) >= 2 and all(c.isupper() for c in tok_letters):
            caps_words += 1

    n = len(text)
    return {
        "upper_ratio": upper / letters,
        "caps_word": (caps_words / words_with_letters) if words_with_letters else 0.0,
        "excl_1k": text.count("!") / n * 1000,
        "q_1k": text.count("?") / n * 1000,
        "len": n,
    }


def summarize(path):
    raise_field_size_limit()
    agg = {"upper_ratio": 0.0, "caps_word": 0.0, "excl_1k": 0.0, "q_1k": 0.0, "len": 0.0}
    counted = rows = 0
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if "body" not in (reader.fieldnames or []):
            raise SystemExit(f"No 'body' column in {path}: {reader.fieldnames}")
        for row in reader:
            rows += 1
            s = email_stats(row.get("body") or "")
            if s is None:
                continue
            counted += 1
            for k in agg:
                agg[k] += s[k]
    if counted:
        for k in agg:
            agg[k] /= counted
    return rows, counted, agg


def main():
    print(f"{'source':<24}{'rows':>8}{'upper_ratio':>13}{'caps_word%':>12}"
          f"{'!/1k':>8}{'?/1k':>8}{'avg_len':>9}")
    print("-" * 82)
    for label, fname, in_merge in SOURCES:
        path = os.path.join(DATA_DIR, fname)
        if not os.path.exists(path):
            print(f"{label:<24}  (missing: {fname})")
            continue
        rows, counted, a = summarize(path)
        tag = "" if in_merge else "  [excluded]"
        print(f"{label:<24}{rows:>8}{a['upper_ratio']*100:>12.2f}%"
              f"{a['caps_word']*100:>11.2f}%{a['excl_1k']:>8.2f}{a['q_1k']:>8.2f}"
              f"{a['len']:>9.0f}{tag}")

    print("\nReading upper_ratio: fraction of letters that are UPPERCASE. Normal")
    print("English prose sits a few percent; fully lowercased text reads ~0%.")


if __name__ == "__main__":
    main()
