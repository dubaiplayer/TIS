"""
Content classifier — TF-IDF (word + char n-grams) + Logistic Regression.

The single learned model, and a CO-EQUAL signal in the risk score. Trained on
Track A train, C tuned on Track A val, saved to models/classifier.joblib.

Leakage guardrails (ML carries real weight; source correlates with label):
  - char_wb n-grams + word n-grams (obfuscation-robust, less name-memorizing).
  - after training we AUDIT top coefficients and warn on source-identifying
    tokens (enron, kaminski, ferc, ect, hpl...) so we can see if it's riding
    corporate style rather than phishing signal.
  - the classifier's weight in risk.py is adjustable in weights.yaml.

Run:  .venv/Scripts/python.exe -m phishing_analyzer.classifier
"""
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.pipeline import FeatureUnion, Pipeline

PROC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed")
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "classifier.joblib")

# Source-identifying tokens we do NOT want driving the model (leakage audit).
_SOURCE_TOKENS = {"enron", "kaminski", "ferc", "ect", "hpl", "isda", "counterparty",
                  "ees", "nom", "sitara", "hpl.", "tana", "skilling", "lavorato"}


def _features():
    word = TfidfVectorizer(sublinear_tf=True, ngram_range=(1, 2), min_df=5,
                           max_features=50000, strip_accents="unicode", lowercase=True)
    char = TfidfVectorizer(sublinear_tf=True, analyzer="char_wb", ngram_range=(3, 5),
                           min_df=5, max_features=30000, lowercase=True)
    return FeatureUnion([("word", word), ("char", char)])


def _metrics(y, p, thr=0.5):
    pred = (p >= thr).astype(int)
    return dict(precision=precision_score(y, pred), recall=recall_score(y, pred),
                f1=f1_score(y, pred), auc=roc_auc_score(y, p))


def train():
    os.makedirs(MODEL_DIR, exist_ok=True)
    tr = pd.read_parquet(os.path.join(PROC, "trackA_train.parquet"))
    va = pd.read_parquet(os.path.join(PROC, "trackA_val.parquet"))
    Xtr, ytr = tr["text"].tolist(), tr["label"].to_numpy()
    Xva, yva = va["text"].tolist(), va["label"].to_numpy()

    # Vectorize ONCE, then sweep C by refitting only the (cheap) LogReg on the
    # cached sparse matrix — far faster/lighter than refitting the char vectorizer.
    feats = _features()
    print(f"Training on {len(Xtr):,} (val {len(Xva):,}). Vectorizing once...", flush=True)
    Xtr_v = feats.fit_transform(Xtr)
    Xva_v = feats.transform(Xva)
    print(f"  feature matrix: {Xtr_v.shape[0]:,} x {Xtr_v.shape[1]:,}. Sweeping C on val F1...",
          flush=True)

    best = None
    for C in (0.3, 1.0, 3.0):
        clf = LogisticRegression(C=C, max_iter=1000, solver="liblinear").fit(Xtr_v, ytr)
        m = _metrics(yva, clf.predict_proba(Xva_v)[:, 1])
        print(f"  C={C:<4}  val  P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f} AUC={m['auc']:.4f}", flush=True)
        if best is None or m["f1"] > best[1]["f1"]:
            best = (C, m, clf)

    C, m, clf = best
    model = Pipeline([("feats", feats), ("clf", clf)])   # feats already fitted
    print(f"\nBest C={C} (val F1={m['f1']:.4f}). Saving -> {MODEL_PATH}", flush=True)
    joblib.dump({"pipeline": model, "C": C, "val_metrics": m}, MODEL_PATH)

    _audit_coefficients(model)
    return model


def _audit_coefficients(model, k=25):
    feats = model.named_steps["feats"].get_feature_names_out()
    coef = model.named_steps["clf"].coef_[0]
    order = np.argsort(coef)
    top_phish = [(feats[i], coef[i]) for i in order[::-1][:k]]
    top_legit = [(feats[i], coef[i]) for i in order[:k]]

    print("\n--- Coefficient audit (leakage check) ---")
    print("Top PHISHING-weighted features:")
    print("   " + ", ".join(f"{f.split('__',1)[-1]!r}" for f, _ in top_phish[:20]))
    print("Top LEGIT-weighted features:")
    print("   " + ", ".join(f"{f.split('__',1)[-1]!r}" for f, _ in top_legit[:20]))

    flagged = [f.split("__", 1)[-1] for f, _ in top_legit
               if any(tok in f.split("__", 1)[-1].lower() for tok in _SOURCE_TOKENS)]
    if flagged:
        print(f"\n  [!] LEAKAGE WARNING: source-identifying tokens in top legit "
              f"features: {sorted(set(flagged))}")
        print("      -> the model partly rides 'corporate Enron style = safe'. Keep the")
        print("         classifier weight in weights.yaml modest; trust per-source metrics.")
    else:
        print("\n  No obvious source-identifying tokens in the top legit features.")


class PhishClassifier:
    """Thin wrapper: load once, score a raw email string -> phishing probability."""
    _cache = None

    def __init__(self, path=MODEL_PATH):
        if PhishClassifier._cache is None:
            PhishClassifier._cache = joblib.load(path)
        self.pipeline = PhishClassifier._cache["pipeline"]

    def proba(self, text):
        return float(self.pipeline.predict_proba([text or ""])[:, 1][0])


if __name__ == "__main__":
    train()
