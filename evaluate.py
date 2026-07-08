"""
STEP 4 — Evaluation (honest, leakage-aware).

Runs on the HELD-OUT Track A test split (never seen in training/tuning):

  1. CLASSIFIER metrics           — P/R/F1, confusion matrix, ROC-AUC.
  2. COMBINED RISK-SCORE metrics  — the full tool (12 attributes + classifier):
                                    AUC + the 3-way verdict distribution by label.
  3. PER-SOURCE breakdown         — false-positive rate per legit source and
                                    recall per phishing source. If the classifier
                                    rides "Enron = safe" leakage, Enron's FP rate
                                    is far below the other legit sources.
  4. PER-ATTRIBUTE validation     — no per-attribute ground truth, so we validate
                                    each attribute by how well its score alone
                                    separates phishing/legit (ROC-AUC) and its
                                    point-biserial correlation with the label.
  5. SPOT-CHECK export            — a stratified sample -> reports/spotcheck.csv
                                    for manual review.

Run:  .venv/Scripts/python.exe -m evaluate
"""
import json
import os

import numpy as np
import pandas as pd
from sklearn.metrics import (confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score)

from phishing_analyzer.attributes import ATTRIBUTES, ATTRIBUTE_NAMES, run_all
from phishing_analyzer import risk
from phishing_analyzer.classifier import PhishClassifier

PROC = os.path.join(os.path.dirname(__file__), "data", "processed")
REPORTS = os.path.join(os.path.dirname(__file__), "reports")


def _load_test():
    return pd.read_parquet(os.path.join(PROC, "trackA_test.parquet"))


def _confusion(y, pred, title):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    p, r, f1, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                  zero_division=0)
    print(f"\n{title}")
    print(f"  precision={p:.4f}  recall={r:.4f}  f1={f1:.4f}")
    print(f"  confusion:            pred_legit  pred_phish")
    print(f"    actual_legit  {tn:>10}  {fp:>10}   (FP rate {fp/(tn+fp):.4f})")
    print(f"    actual_phish  {fn:>10}  {tp:>10}   (recall  {tp/(tp+fn):.4f})")
    return dict(precision=p, recall=r, f1=f1, tn=int(tn), fp=int(fp), fn=int(fn), tp=int(tp))


def main():
    os.makedirs(REPORTS, exist_ok=True)
    df = _load_test()
    y = df["label"].to_numpy()
    texts = df["text"].tolist()
    senders = df["sender"].fillna("").tolist()
    sources = df["source"].to_numpy()
    n = len(df)
    print(f"Test set: {n:,} emails  (legit {int((y==0).sum()):,} / "
          f"phishing {int((y==1).sum()):,})")

    # ---- 1. classifier probabilities (vectorized) ----
    print("\nScoring classifier over test...", flush=True)
    clf = PhishClassifier()
    clf_prob = clf.pipeline.predict_proba(texts)[:, 1]

    # ---- attributes + combined risk (per-row) ----
    print("Running 12 attributes + combining risk over test "
          "(grammar spellcheck makes this the slow part)...", flush=True)
    attr_mat = np.zeros((n, len(ATTRIBUTES)))
    risk_scores = np.zeros(n)
    verdicts = np.empty(n, dtype=object)
    for i in range(n):
        results = run_all(texts[i], sender=senders[i] or None)
        for j, res in enumerate(results):
            attr_mat[i, j] = res.score
        overall = risk.combine(results, float(clf_prob[i]))
        risk_scores[i] = overall["risk_score"]
        verdicts[i] = overall["verdict"]
        if (i + 1) % 2000 == 0:
            print(f"  {i+1:,}/{n:,}", flush=True)

    report = {"n": int(n)}

    # ---- 1. classifier metrics ----
    print("\n" + "=" * 74 + "\n1) CONTENT CLASSIFIER (test)\n" + "=" * 74)
    report["classifier"] = _confusion(y, (clf_prob >= 0.5).astype(int),
                                      "TF-IDF + LogReg @ 0.5")
    report["classifier"]["auc"] = float(roc_auc_score(y, clf_prob))
    print(f"  ROC-AUC={report['classifier']['auc']:.4f}")

    # ---- 2. combined risk score ----
    print("\n" + "=" * 74 + "\n2) COMBINED RISK SCORE — full tool (test)\n" + "=" * 74)
    report["combined"] = _confusion(y, (risk_scores >= 0.5).astype(int),
                                    "Combined risk @ 0.5")
    report["combined"]["auc"] = float(roc_auc_score(y, risk_scores))
    print(f"  ROC-AUC={report['combined']['auc']:.4f}")
    print("\n  3-way verdict distribution (the tool's actual output):")
    print(f"    {'':<12}{'legitimate':>12}{'suspicious':>12}{'phishing':>12}")
    vd = {}
    for lab, name in ((0, "actual_legit"), (1, "actual_phish")):
        row = [int(((verdicts == v) & (y == lab)).sum())
               for v in ("legitimate", "suspicious", "phishing")]
        vd[name] = dict(zip(("legitimate", "suspicious", "phishing"), row))
        print(f"    {name:<12}{row[0]:>12}{row[1]:>12}{row[2]:>12}")
    report["combined"]["verdict_distribution"] = vd

    # ---- 3. per-source breakdown (leakage probe) ----
    print("\n" + "=" * 74 + "\n3) PER-SOURCE (classifier @0.5) — leakage probe\n" + "=" * 74)
    print(f"{'source':<16}{'n':>7}{'phish%':>8}{'legit_FP%':>11}{'phish_recall%':>15}")
    per_source = {}
    for src in sorted(set(sources)):
        m = sources == src
        ys, ps = y[m], (clf_prob[m] >= 0.5).astype(int)
        n_leg, n_ph = int((ys == 0).sum()), int((ys == 1).sum())
        fp = float((ps[ys == 0] == 1).mean()) if n_leg else float("nan")
        rec = float((ps[ys == 1] == 1).mean()) if n_ph else float("nan")
        per_source[src] = dict(n=int(m.sum()), legit=n_leg, phish=n_ph,
                               legit_fp_rate=fp, phish_recall=rec)
        fp_s = "   n/a" if n_leg == 0 else f"{fp*100:>10.2f}%"
        rc_s = "   n/a" if n_ph == 0 else f"{rec*100:>14.2f}%"
        print(f"{src:<16}{int(m.sum()):>7}{n_ph/(m.sum())*100:>7.0f}%{fp_s}{rc_s}")
    report["per_source"] = per_source
    _leak_note(per_source)

    # ---- 4. per-attribute validation ----
    print("\n" + "=" * 74 + "\n4) PER-ATTRIBUTE VALIDATION (no ground truth -> "
          "separation vs label)\n" + "=" * 74)
    print(f"{'attribute':<18}{'AUC':>7}{'corr':>8}{'mean_phish':>12}{'mean_legit':>12}"
          f"{'fired%':>8}")
    attrs = {}
    order = []
    for j, name in enumerate(ATTRIBUTE_NAMES):
        s = attr_mat[:, j]
        fired = float((s > 0).mean())
        mp, ml = float(s[y == 1].mean()), float(s[y == 0].mean())
        try:
            auc = float(roc_auc_score(y, s))
        except ValueError:
            auc = float("nan")
        corr = float(np.corrcoef(y, s)[0, 1]) if s.std() > 0 else float("nan")
        attrs[name] = dict(auc=auc, corr=corr, mean_phish=mp, mean_legit=ml, fired=fired)
        order.append((name, auc))
    # sender_domain is only meaningful where a sender exists — recompute on subset.
    has_sender = np.array([bool(s) for s in senders])
    if has_sender.any():
        sj = ATTRIBUTE_NAMES.index("sender_domain")
        ys2, ss2 = y[has_sender], attr_mat[has_sender, sj]
        try:
            attrs["sender_domain"]["auc_where_sender"] = float(roc_auc_score(ys2, ss2))
        except ValueError:
            attrs["sender_domain"]["auc_where_sender"] = float("nan")
    for name, _ in sorted(order, key=lambda t: (-t[1] if t[1] == t[1] else 1)):
        a = attrs[name]
        extra = ""
        if name == "sender_domain" and "auc_where_sender" in a:
            extra = f"  (AUC where sender present: {a['auc_where_sender']:.3f})"
        print(f"{name:<18}{a['auc']:>7.3f}{a['corr']:>8.3f}{a['mean_phish']:>12.3f}"
              f"{a['mean_legit']:>12.3f}{a['fired']*100:>7.1f}%{extra}")
    report["attributes"] = attrs

    # ---- 5. spot-check export ----
    spot = _export_spotcheck(df, y, clf_prob, risk_scores, verdicts, attr_mat)
    print(f"\nSpot-check sample ({len(spot)} rows) -> {os.path.join(REPORTS, 'spotcheck.csv')}")

    with open(os.path.join(REPORTS, "eval_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Metrics JSON -> {os.path.join(REPORTS, 'eval_metrics.json')}")


def _leak_note(per_source):
    legit_fp = {s: v["legit_fp_rate"] for s, v in per_source.items()
                if v["legit"] > 0 and v["legit_fp_rate"] == v["legit_fp_rate"]}
    if "Enron_raw" in legit_fp and len(legit_fp) > 1:
        enron = legit_fp["Enron_raw"]
        others = [v for s, v in legit_fp.items() if s != "Enron_raw"]
        avg_other = sum(others) / len(others)
        print(f"\n  Enron_raw legit FP rate = {enron*100:.2f}% vs other legit sources "
              f"avg = {avg_other*100:.2f}%.")
        if enron + 1e-9 < avg_other:
            print("  -> Enron is classified 'safe' more reliably than other legit mail:")
            print("     the model partly learned 'corporate Enron style = legit' (leakage).")
            print("     Real-world legit (non-corporate) will see FP closer to the higher rate.")


def _export_spotcheck(df, y, clf_prob, risk_scores, verdicts, attr_mat, per_class=20):
    rng = np.random.RandomState(42)
    idx = []
    for lab in (0, 1):
        pool = np.where(y == lab)[0]
        idx += list(rng.choice(pool, size=min(per_class, len(pool)), replace=False))
    rows = []
    for i in idx:
        r = {"source": df.iloc[i]["source"], "label": int(y[i]),
             "verdict": verdicts[i], "risk_score": round(float(risk_scores[i]), 3),
             "classifier_prob": round(float(clf_prob[i]), 3),
             "text_preview": " ".join(df.iloc[i]["text"].split())[:200]}
        for j, name in enumerate(ATTRIBUTE_NAMES):
            r[name] = round(float(attr_mat[i, j]), 3)
        rows.append(r)
    out = pd.DataFrame(rows)
    out.to_csv(os.path.join(REPORTS, "spotcheck.csv"), index=False)
    return out


if __name__ == "__main__":
    main()
