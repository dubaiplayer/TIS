"""Evaluate the trained content classifier on the held-out Track A TEST split and
render a single poster-ready validation figure (confusion matrix + ROC + metrics)."""
import os
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, roc_curve, confusion_matrix)

HERE = os.path.dirname(__file__)
TEST = os.path.join(HERE, "data", "processed", "trackA_test.parquet")
MODEL = os.path.join(HERE, "models", "classifier.joblib")
OUT = os.path.join(HERE, "validation_results.png")

df = pd.read_parquet(TEST)
X, y = df["text"].tolist(), df["label"].to_numpy()
model = joblib.load(MODEL)["pipeline"]

proba = model.predict_proba(X)[:, 1]
pred = (proba >= 0.5).astype(int)

acc = accuracy_score(y, pred)
prec = precision_score(y, pred)
rec = recall_score(y, pred)
f1 = f1_score(y, pred)
auc = roc_auc_score(y, proba)
cm = confusion_matrix(y, pred)
fpr, tpr, _ = roc_curve(y, proba)

print(f"n_test={len(y)}  phishing={int(y.sum())}  legit={int((y==0).sum())}")
print(f"Accuracy={acc:.4f} Precision={prec:.4f} Recall={rec:.4f} "
      f"F1={f1:.4f} ROC-AUC={auc:.4f}")
print("Confusion matrix [ [TN FP][FN TP] ]:", cm.tolist())

# ---- one clean 3-panel figure ----
plt.rcParams.update({"font.size": 12, "font.family": "DejaVu Sans"})
fig, ax = plt.subplots(1, 3, figsize=(16, 5))
NAVY, RED, GREEN = "#1f3b73", "#d64545", "#2e8b57"

# 1) Confusion matrix
labels = ["Legitimate", "Phishing"]
ax[0].imshow(cm, cmap="Blues")
for i in range(2):
    for j in range(2):
        ax[0].text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                   fontsize=15, fontweight="bold",
                   color="white" if cm[i, j] > cm.max() * 0.5 else "black")
ax[0].set_xticks([0, 1], labels)
ax[0].set_yticks([0, 1], labels)
ax[0].set_xlabel("Predicted")
ax[0].set_ylabel("Actual")
ax[0].set_title("Confusion Matrix", fontweight="bold")

# 2) ROC curve
ax[1].plot(fpr, tpr, color=NAVY, lw=2.5, label=f"ROC (AUC = {auc:.3f})")
ax[1].plot([0, 1], [0, 1], "--", color="gray", lw=1)
ax[1].set_xlabel("False Positive Rate")
ax[1].set_ylabel("True Positive Rate")
ax[1].set_title("ROC Curve", fontweight="bold")
ax[1].legend(loc="lower right")
ax[1].set_xlim(0, 1); ax[1].set_ylim(0, 1.02)

# 3) Metrics bar
names = ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]
vals = [acc, prec, rec, f1, auc]
ax[2].bar(names, vals, color=[NAVY, NAVY, NAVY, RED, GREEN])
ax[2].set_ylim(0.9, 1.0)
ax[2].set_ylabel("Score")
ax[2].set_title("Classifier Performance (test set)", fontweight="bold")
ax[2].tick_params(axis="x", rotation=15)

fig.suptitle(f"Model Validation — held-out test set (n = {len(y):,})",
             fontsize=15, fontweight="bold")
fig.tight_layout(rect=[0, 0, 1, 0.96])
fig.savefig(OUT, dpi=200, bbox_inches="tight")
print("saved:", OUT)
