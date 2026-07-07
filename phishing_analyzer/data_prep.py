"""
STEP 1 — Data prep.

Merge the 6 per-source files BY COLUMN NAME, clean bodies (preserving casing &
punctuation), drop near-duplicates and known noise rows, assign a stratified
70/15/15 split, and materialize the two-track corpus:

  Track A = full corpus (all 6 sources)          -> content classifier + lexicons
  Track B = Track A minus Ling (still flattened) -> casing/tone feature calibration

Outputs land in TIS/data/processed/ as both parquet and csv, plus manifest.json
and an auto-generated DATA_CARD.md. Deterministic (seed 42).

Run:  .venv/Scripts/python.exe -m phishing_analyzer.data_prep
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone

import pandas as pd

from phishing_analyzer.text_clean import build_text

SEED = 42
DATA_DIR = r"C:\Users\15DGupta\Downloads\archive (4)"
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed")

# source name -> filename. Ordered; Enron_raw replaces the old flattened Enron.
SOURCES = {
    "Enron_raw": "Enron_raw.csv",
    "CEAS_08": "CEAS_08.csv",
    "Ling": "Ling.csv",
    "Nazario": "Nazario.csv",
    "Nigerian_Fraud": "Nigerian_Fraud.csv",
    "SpamAssasin": "SpamAssasin.csv",
}
# Ling is still lowercased/punct-stripped -> excluded from the casing-sensitive track.
CASING_FLATTENED = {"Ling"}
UNIFIED_COLS = ["source", "sender", "receiver", "date", "subject", "body", "urls", "label"]

# Nazario mail-system artifacts (labeled phishing but not real emails). Match on
# apostrophe-agnostic markers — some rows use a curly apostrophe in "DON'T".
_NOISE = re.compile(r"DELETE THIS MESSAGE|FOLDER INTERNAL DATA", re.IGNORECASE)


def load_source(name, fname):
    path = os.path.join(DATA_DIR, fname)
    df = pd.read_csv(path, dtype=str, keep_default_na=False, na_values=[])
    df["source"] = name
    # Align to the unified schema; fill absent columns with empty string.
    for col in UNIFIED_COLS:
        if col not in df.columns:
            df[col] = ""
    df = df[UNIFIED_COLS].copy()
    df["label"] = pd.to_numeric(df["label"], errors="coerce").astype("Int64")
    return df


def stratified_split(df, seed=SEED):
    """70/15/15 stratified by label. Returns a 'split' Series aligned to df.index."""
    shuffled = df.sample(frac=1, random_state=seed)
    split = pd.Series("train", index=shuffled.index)
    for _, grp in shuffled.groupby("label"):
        n = len(grp)
        n_tr, n_va = int(n * 0.70), int(n * 0.15)
        idx = grp.index
        split.loc[idx[n_tr:n_tr + n_va]] = "val"
        split.loc[idx[n_tr + n_va:]] = "test"
    return split.reindex(df.index)


def _dedup_key(text):
    norm = re.sub(r"\s+", " ", (text or "").lower()).strip()
    return hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()


def save_track(df, track, out_dir):
    for split in ("train", "val", "test"):
        part = df[df["split"] == split]
        base = os.path.join(out_dir, f"{track}_{split}")
        part.to_parquet(base + ".parquet", index=False)
        part.to_csv(base + ".csv", index=False)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    frames, per_source_raw = [], {}
    for name, fname in SOURCES.items():
        df = load_source(name, fname)
        per_source_raw[name] = len(df)
        frames.append(df)
    merged = pd.concat(frames, ignore_index=True)
    n_merged = len(merged)

    # Drop rows with unusable/missing label, then known noise rows.
    merged = merged[merged["label"].notna()].copy()
    noise_mask = merged["body"].fillna("").str.contains(_NOISE)
    n_noise = int(noise_mask.sum())
    merged = merged[~noise_mask].copy()

    # Build the feature text (casing/punct preserved), drop rows that clean to empty.
    merged["text"] = [build_text(s, b) for s, b in zip(merged["subject"], merged["body"])]
    n_empty = int((merged["text"].str.len() == 0).sum())
    merged = merged[merged["text"].str.len() > 0].copy()

    # Near-duplicate dedup on normalized text (keep first).
    merged["_key"] = merged["text"].map(_dedup_key)
    before = len(merged)
    merged = merged.drop_duplicates("_key", keep="first").drop(columns="_key").reset_index(drop=True)
    n_dups = before - len(merged)

    # Stratified split, then derive the two tracks.
    merged["split"] = stratified_split(merged)
    track_a = merged
    track_b = merged[~merged["source"].isin(CASING_FLATTENED)].copy()

    save_track(track_a, "trackA", OUT_DIR)
    save_track(track_b, "trackB", OUT_DIR)

    # ---- manifest + data card ----
    def balance(df):
        return {
            "rows": int(len(df)),
            "legit": int((df["label"] == 0).sum()),
            "phishing": int((df["label"] == 1).sum()),
        }

    per_source = {
        name: {
            "rows": int((track_a["source"] == name).sum()),
            "legit": int(((track_a["source"] == name) & (track_a["label"] == 0)).sum()),
            "phishing": int(((track_a["source"] == name) & (track_a["label"] == 1)).sum()),
        }
        for name in SOURCES
    }
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "source_files": SOURCES,
        "raw_rows_per_source": per_source_raw,
        "raw_merged_rows": n_merged,
        "dropped": {"missing_label": n_merged - len(merged) - n_noise - n_dups - n_empty,
                    "noise_rows": n_noise, "empty_after_clean": n_empty, "near_duplicates": n_dups},
        "final_rows": int(len(track_a)),
        "per_source": per_source,
        "track_a": {split: balance(track_a[track_a["split"] == split]) for split in ("train", "val", "test")},
        "track_b": {split: balance(track_b[track_b["split"] == split]) for split in ("train", "val", "test")},
        "track_b_excludes": sorted(CASING_FLATTENED),
    }
    with open(os.path.join(OUT_DIR, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    write_data_card(manifest)

    print(f"Merged raw rows        : {n_merged:,}")
    print(f"Dropped noise rows     : {n_noise}")
    print(f"Dropped empty-after-clean: {n_empty}")
    print(f"Dropped near-duplicates: {n_dups:,}")
    print(f"Final Track A rows     : {len(track_a):,}  "
          f"(legit {int((track_a['label']==0).sum()):,} / "
          f"phishing {int((track_a['label']==1).sum()):,})")
    print(f"Final Track B rows     : {len(track_b):,}  (Track A minus {sorted(CASING_FLATTENED)})")
    print(f"Wrote parquet+csv, manifest.json, DATA_CARD.md -> {OUT_DIR}")


def write_data_card(m):
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "DATA_CARD.md")
    ps = m["per_source"]
    rows = "\n".join(
        f"| {name} | {d['rows']:,} | {d['legit']:,} | {d['phishing']:,} |"
        for name, d in ps.items()
    )
    ta = m["track_a"]; tb = m["track_b"]
    def line(t, s):
        b = t[s]
        return f"| {s} | {b['rows']:,} | {b['legit']:,} | {b['phishing']:,} |"
    card = f"""# Data Card — Phishing Email Corpus

*Auto-generated by `data_prep.py` on {m['created_utc']} (seed {m['seed']}).*

## Source
Combined public phishing/legitimate email corpus (Kaggle
`naserabdullahalam/phishing-email-dataset`) — CEAS_08, Ling, Nazario,
Nigerian_Fraud, SpamAssassin — **plus a raw re-download of Enron**
(`wcukierski/enron-email-dataset`, sampled to {ps['Enron_raw']['rows']:,} rows,
seed {m['seed']}) that replaces the packaged Enron file.

Files are merged **by column name** (column order differs between files). The
packaged aggregate `phishing_email.csv` and the old flattened `Enron.csv` are
**excluded** (leakage + destroyed casing/punctuation).

## Size & class balance (Track A, after cleaning/dedup)
Final rows: **{m['final_rows']:,}**. Label convention: `0 = legitimate`, `1 = phishing`.

| source | rows | legit | phishing |
|---|---|---|---|
{rows}

## Splits (stratified 70/15/15 by label, seed {m['seed']})
Track B = Track A minus {", ".join(m['track_b_excludes'])} (see bias note), same split assignments.

**Track A** | **Track B**
| split | rows | legit | phishing |
|---|---|---|---|
{line(ta,'train')}
{line(ta,'val')}
{line(ta,'test')}

Track B: train {tb['train']['rows']:,} / val {tb['val']['rows']:,} / test {tb['test']['rows']:,}.

## Cleaning applied
HTML stripped only when tags present; leaked email-header remnants, mbox
separators and forwarding banners removed; whitespace normalized. **Casing and
punctuation preserved** (they are urgency/tone signal, not noise). Dropped:
{m['dropped']['noise_rows']} noise row(s), {m['dropped']['empty_after_clean']}
empty-after-clean, {m['dropped']['near_duplicates']:,} near-duplicates.

## Known limitations & biases
- **Ling is still flattened** (lowercased/punct-stripped in the packaged data). It
  is kept in Track A but **excluded from Track B**, which is the only track used
  to calibrate casing/tone/punctuation features.
- **Enron_raw legit baseline is corporate American English (~2000–2002)** with
  signature blocks and trading acronyms — may not generalize to consumer/personal
  email. Its uppercase ratio runs slightly high for this reason (genuine, not an
  artifact).
- **Source correlates with label**: Nazario & Nigerian_Fraud are 100% phishing;
  Ling & SpamAssassin are legit-heavy. Always report per-source metrics so the
  classifier isn't just learning "corporate Enron style = legit".
- **HTML is largely pre-stripped** → anchor-text-vs-href link mismatch is mostly
  not extractable; live URL reputation is out of scope.
- The `urls` column in some sources is a has-URL 0/1 flag, **not** a label.
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(card)


if __name__ == "__main__":
    main()
