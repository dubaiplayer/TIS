"""
STEP 1 checkpoint report.

Loads the processed Track A corpus and prints: schema, overall + per-source class
balance, per-source metadata missingness, per-source casing/punctuation metrics,
and a few sample phishing bodies per source. Run after data_prep.py.

Run:  .venv/Scripts/python.exe -m phishing_analyzer.explore
"""

import os

import pandas as pd

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed")
META_COLS = ["sender", "receiver", "date", "urls"]


def load_track_a():
    parts = [pd.read_parquet(os.path.join(OUT_DIR, f"trackA_{s}.parquet"))
             for s in ("train", "val", "test")]
    return pd.concat(parts, ignore_index=True)


def casing_stats(text):
    letters = sum(c.isalpha() for c in text)
    upper = sum(c.isupper() for c in text)
    n = len(text) or 1
    return (upper / letters if letters else 0.0), text.count("!") / n * 1000


def main():
    df = load_track_a()

    print("=" * 78)
    print("STEP 1 CHECKPOINT - merged Track A corpus")
    print("=" * 78)
    print(f"\nSchema: {list(df.columns)}")
    print(f"Total rows: {len(df):,}  |  columns carry a `source` and `split` tag")

    print("\n--- Class balance (overall) ---")
    print(f"  legit (0)   : {int((df['label']==0).sum()):,}")
    print(f"  phishing (1): {int((df['label']==1).sum()):,}")

    print("\n--- Per-source: balance, metadata missingness, casing ---")
    print(f"{'source':<16}{'rows':>7}{'legit':>7}{'phish':>7}"
          f"{'sender%':>9}{'urls%':>7}{'upper%':>8}{'!/1k':>7}")
    print("-" * 78)
    for name, grp in df.groupby("source"):
        upper_vals, excl_vals = zip(*(casing_stats(t) for t in grp["text"]))
        sender_present = (grp["sender"].str.len() > 0).mean() * 100
        urls_present = (grp["urls"].str.len() > 0).mean() * 100
        print(f"{name:<16}{len(grp):>7}{int((grp['label']==0).sum()):>7}"
              f"{int((grp['label']==1).sum()):>7}{sender_present:>8.0f}%"
              f"{urls_present:>6.0f}%{sum(upper_vals)/len(upper_vals)*100:>7.2f}%"
              f"{sum(excl_vals)/len(excl_vals):>7.2f}")

    print("\n--- Split sizes (Track A) ---")
    for split, grp in df.groupby("split"):
        print(f"  {split:<6}: {len(grp):>7,}  "
              f"(legit {int((grp['label']==0).sum()):,} / phishing {int((grp['label']==1).sum()):,})")

    print("\n--- Sample phishing bodies (per source, truncated) ---")
    phish = df[df["label"] == 1]
    for name, grp in phish.groupby("source"):
        print(f"\n[{name}] ({len(grp):,} phishing)")
        for t in grp["text"].head(2):
            preview = " ".join(t.split())[:220]
            print(f"   - {preview}")

    print("\n" + "=" * 78)
    print("Checkpoint complete. Review, then proceed to STEP 2 (feature schema).")
    print("=" * 78)


if __name__ == "__main__":
    main()
