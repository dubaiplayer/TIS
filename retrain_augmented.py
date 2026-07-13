"""Retrain the content classifier with legit-transactional ham augmentation.

Keeps trackA_val / trackA_test UNTOUCHED so the phishing metrics are an honest,
apples-to-apples comparison. Reports baseline vs augmented on (1) the real test set
and (2) a held-out set of legitimate transactional emails (false-positive rate)."""
import os
import shutil
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score

from phishing_analyzer.classifier import _features, _metrics, MODEL_PATH, MODEL_DIR
from phishing_analyzer.text_clean import build_text
import augment_legit

PROC = os.path.join(os.path.dirname(__file__), "data", "processed")
N_AUG = 5000        # legit-transactional ham added to TRAIN only
EVAL_N = 800        # disjoint held-out legit-transactional set (FP measurement)

PROBLEM = build_text(
    "Your monthly digital statement is now available",
    "Hello Alex, Your monthly account statement for the billing cycle ending July 10, "
    "2026, is now ready to view online. To review your statement, please log in to your "
    "dashboard through our official app or visit our website directly at our standard web "
    "address. As a reminder, we will never ask you to reply to this email with your "
    "password, credit card number, or full Social Security number. Sincerely, Customer "
    "Operations Department")


def _aug_frame(n, seed):
    rows = augment_legit.generate(n, seed)
    return pd.DataFrame({"text": [build_text(e["subject"], e["body"]) for e in rows],
                         "label": [0] * n})


def _report(name, model, Xte, yte, Xev):
    proba = model.predict_proba(Xte)[:, 1]
    pred = (proba >= 0.5).astype(int)
    m = _metrics(yte, proba)
    acc = accuracy_score(yte, pred)
    ev_fp = float((model.predict_proba(Xev)[:, 1] >= 0.5).mean())  # all ham -> FP rate
    prob_email = float(model.predict_proba([PROBLEM])[:, 1][0])
    print(f"\n[{name}]")
    print(f"  TEST  acc={acc:.4f} prec={m['precision']:.4f} rec={m['recall']:.4f} "
          f"F1={m['f1']:.4f} AUC={m['auc']:.4f}")
    print(f"  legit-transactional FP rate (held-out {len(Xev)}): {ev_fp*100:.1f}%")
    print(f"  problem email P(phishing): {prob_email:.3f}  -> "
          f"{'PHISHING' if prob_email>=0.5 else 'legit'}")
    return dict(acc=acc, **m, ev_fp=ev_fp, prob=prob_email)


def main():
    tr = pd.read_parquet(os.path.join(PROC, "trackA_train.parquet"))
    va = pd.read_parquet(os.path.join(PROC, "trackA_val.parquet"))
    te = pd.read_parquet(os.path.join(PROC, "trackA_test.parquet"))
    Xte, yte = te["text"].tolist(), te["label"].to_numpy()
    ev = _aug_frame(EVAL_N, seed=2000)          # held-out legit-transactional
    Xev = ev["text"].tolist()

    print("=== BASELINE (current model) ===")
    base = joblib.load(MODEL_PATH)["pipeline"]
    r_base = _report("baseline", base, Xte, yte, Xev)

    # Back up the baseline model before overwriting.
    bak = os.path.join(MODEL_DIR, "classifier_baseline.joblib")
    if not os.path.exists(bak):
        shutil.copy(MODEL_PATH, bak)
        print(f"\nbacked up baseline -> {bak}")

    # Augmented training set (train only; val/test untouched).
    aug = _aug_frame(N_AUG, seed=1000)
    Xtr = tr["text"].tolist() + aug["text"].tolist()
    ytr = np.concatenate([tr["label"].to_numpy(), aug["label"].to_numpy()])
    Xva, yva = va["text"].tolist(), va["label"].to_numpy()
    print(f"\n=== RETRAIN on {len(Xtr):,} (orig {len(tr):,} + {N_AUG:,} legit-transactional) ===")

    feats = _features()
    Xtr_v = feats.fit_transform(Xtr)
    Xva_v = feats.transform(Xva)
    best = None
    for C in (0.3, 1.0, 3.0):
        clf = LogisticRegression(C=C, max_iter=1000, solver="liblinear").fit(Xtr_v, ytr)
        m = _metrics(yva, clf.predict_proba(Xva_v)[:, 1])
        print(f"  C={C:<4} val F1={m['f1']:.4f} AUC={m['auc']:.4f}")
        if best is None or m["f1"] > best[1]["f1"]:
            best = (C, m, clf)
    C, _m, clf = best
    model = Pipeline([("feats", feats), ("clf", clf)])
    r_new = _report("augmented", model, Xte, yte, Xev)

    # Guardrail: only save if phishing quality holds (F1 within 1pt, AUC within 0.5pt).
    ok = (r_new["f1"] >= r_base["f1"] - 0.01) and (r_new["auc"] >= r_base["auc"] - 0.005)
    print("\n=== SUMMARY ===")
    print(f"  test F1:  {r_base['f1']:.4f} -> {r_new['f1']:.4f}")
    print(f"  test AUC: {r_base['auc']:.4f} -> {r_new['auc']:.4f}")
    print(f"  legit-transactional FP: {r_base['ev_fp']*100:.1f}% -> {r_new['ev_fp']*100:.1f}%")
    print(f"  problem email P(phish): {r_base['prob']:.3f} -> {r_new['prob']:.3f}")
    if ok:
        joblib.dump({"pipeline": model, "C": C, "val_metrics": _m}, MODEL_PATH)
        print(f"\n  phishing quality preserved -> SAVED new model to {MODEL_PATH}")
    else:
        print("\n  [!] phishing quality dropped too much -> NOT saved (baseline kept).")


if __name__ == "__main__":
    main()
