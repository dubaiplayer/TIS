"""
STEP 2 — validate seed lexicons against real phishing samples (no blind guessing).

Two analyses on Track A TRAIN (never touches val/test):
  A) SEED VALIDATION — for every seed term, document-frequency in phishing vs
     legit, the phishing rate among docs containing it, and lift vs base rate.
     Flags weak terms (low lift or thin support) as prune candidates.
  B) MINING — top discriminative unigrams/bigrams by lift (min support), to
     surface high-signal terms the seeds missed. Also prints top LEGIT-lift terms
     so source-identifying tokens (enron, names) are visible for leakage awareness.

Run:  .venv/Scripts/python.exe -m scripts.validate_lexicons
"""

import os
import re
from collections import Counter

import pandas as pd

from phishing_analyzer.lexicons import SEED

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed")
MINING_CHAR_CAP = 4000          # bound cost; phishing cues are usually early
MIN_PHISH_DF_SEED = 15          # support floor for a seed term to be "kept"
MIN_LIFT_SEED = 1.3             # lift floor for a seed term to be "kept"
MIN_PHISH_DF_MINE = 30          # support floor for a mined term
_TOK = re.compile(r"[a-z][a-z']+")


def load_train():
    return pd.read_parquet(os.path.join(OUT_DIR, "trackA_train.parquet"))


def seed_validation(texts_lower, labels):
    n_phish = int((labels == 1).sum())
    n_legit = int((labels == 0).sum())
    base = n_phish / (n_phish + n_legit)
    print("=" * 92)
    print(f"A) SEED VALIDATION on Track A train  (phish={n_phish:,} legit={n_legit:,}  "
          f"base phishing rate={base:.3f})")
    print("   lift = phish_rate / base ; KEEP if lift>=%.1f and phish_df>=%d"
          % (MIN_LIFT_SEED, MIN_PHISH_DF_SEED))
    print("=" * 92)

    phish_texts = [t for t, y in zip(texts_lower, labels) if y == 1]
    legit_texts = [t for t, y in zip(texts_lower, labels) if y == 0]

    prune = []
    for cat, terms in SEED.items():
        print(f"\n### {cat}")
        print(f"{'term':<30}{'phish_df':>9}{'legit_df':>9}{'phish_rate':>11}{'lift':>7}  verdict")
        rows = []
        for term in terms:
            pdf = sum(1 for t in phish_texts if term in t)
            ldf = sum(1 for t in legit_texts if term in t)
            tot = pdf + ldf
            rate = pdf / tot if tot else 0.0
            lift = (rate / base) if base else 0.0
            keep = pdf >= MIN_PHISH_DF_SEED and lift >= MIN_LIFT_SEED
            rows.append((term, pdf, ldf, rate, lift, keep))
            if not keep:
                prune.append((cat, term, pdf, lift))
        for term, pdf, ldf, rate, lift, keep in sorted(rows, key=lambda r: -r[4]):
            print(f"{term:<30}{pdf:>9}{ldf:>9}{rate:>10.2f} {lift:>6.2f}  "
                  f"{'KEEP' if keep else 'prune?'}")

    print("\n--- PRUNE CANDIDATES (weak lift or thin support) ---")
    for cat, term, pdf, lift in sorted(prune, key=lambda r: (r[0], r[3])):
        print(f"  [{cat}] {term!r}  (phish_df={pdf}, lift={lift:.2f})")


def mine(texts_lower, labels):
    n_phish = int((labels == 1).sum())
    n_legit = int((labels == 0).sum())
    base = n_phish / (n_phish + n_legit)

    uni_p, uni_l = Counter(), Counter()
    bi_p, bi_l = Counter(), Counter()
    for text, y in zip(texts_lower, labels):
        toks = _TOK.findall(text[:MINING_CHAR_CAP])
        uni = set(toks)
        bi = set(zip(toks, toks[1:]))
        if y == 1:
            uni_p.update(uni); bi_p.update(bi)
        else:
            uni_l.update(uni); bi_l.update(bi)

    def rank(pc, lc, min_df, joiner):
        out = []
        for term, pdf in pc.items():
            if pdf < min_df:
                continue
            ldf = lc.get(term, 0)
            rate = pdf / (pdf + ldf)
            lift = rate / base if base else 0.0
            out.append((joiner(term), pdf, ldf, rate, lift))
        return sorted(out, key=lambda r: -r[4])

    def show(title, ranked, k=30):
        print(f"\n### {title}")
        print(f"{'term':<30}{'phish_df':>9}{'legit_df':>9}{'phish_rate':>11}{'lift':>7}")
        for term, pdf, ldf, rate, lift in ranked[:k]:
            print(f"{term:<30}{pdf:>9}{ldf:>9}{rate:>10.2f} {lift:>6.2f}")

    print("\n" + "=" * 92)
    print("B) MINING — top discriminative terms (min phish_df=%d, first %d chars/doc)"
          % (MIN_PHISH_DF_MINE, MINING_CHAR_CAP))
    print("=" * 92)
    show("Top PHISHING-lift unigrams", rank(uni_p, uni_l, MIN_PHISH_DF_MINE, lambda t: t))
    show("Top PHISHING-lift bigrams", rank(bi_p, bi_l, MIN_PHISH_DF_MINE, lambda t: " ".join(t)))

    # Legit side: reveal source-identifying tokens for leakage awareness.
    def rank_legit(pc, lc, min_df):
        out = []
        for term, ldf in lc.items():
            if ldf < min_df:
                continue
            pdf = pc.get(term, 0)
            rate = ldf / (pdf + ldf)
            out.append((term, ldf, pdf, rate))
        return sorted(out, key=lambda r: -r[3])
    print("\n### Top LEGIT-lift unigrams (watch for source-identifying tokens)")
    print(f"{'term':<30}{'legit_df':>9}{'phish_df':>9}{'legit_rate':>11}")
    for term, ldf, pdf, rate in rank_legit(uni_p, uni_l, 200)[:20]:
        print(f"{term:<30}{ldf:>9}{pdf:>9}{rate:>10.2f}")


def main():
    df = load_train()
    texts_lower = df["text"].str.lower().tolist()
    labels = df["label"].to_numpy()
    seed_validation(texts_lower, labels)
    mine(texts_lower, labels)


if __name__ == "__main__":
    main()
