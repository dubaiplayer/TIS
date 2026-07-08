# TIS — Phishing Email Analyzer

**"Grammarly for phishing."** Paste or open an email and get an explainable,
structured breakdown of its manipulation / phishing tactics — each attribute
scored, with the exact triggering evidence highlighted — plus one overall risk
verdict. Interpretability first: every score traces back to evidence, not a black
box, and everything runs **100% locally** (no email leaves your machine).

---

## Table of contents
- [What it is](#what-it-is)
- [Key features](#key-features)
- [How it works](#how-it-works)
- [The 12 attributes](#the-12-attributes)
- [Risk score (noisy-OR)](#risk-score-noisy-or)
- [Results](#results-held-out-test-set)
- [Project structure](#project-structure)
- [Setup](#setup)
- [Usage](#usage)
- [Output schema](#output-schema)
- [Known limitations & biases](#known-limitations--biases)
- [Roadmap](#roadmap)
- [Documentation](#documentation)

---

## What it is

TIS reads a raw email (headers + body, or just body) and returns:

- **An overall risk verdict** — `phishing` / `suspicious` / `legitimate` with a 0–1 score.
- **12 per-attribute scores** — urgency, fear/threat, reward bait, authority
  impersonation, financial requests, credential harvesting, generic greetings,
  sender-domain spoofing, suspicious links, grammar, caps/tone — each with a
  plain-English explanation and **character-offset evidence spans** for highlighting.
- **Classifier keyword attributions** — the specific words/n-grams that drove the
  ML model's prediction (exact `coef × tf-idf` contributions), with intensities.

It ships three front-ends over one Python engine: a **CLI**, a local **FastAPI
server**, and a **desktop app** (Electron + React).

## Key features

- 🔍 **Explainable** — per-attribute evidence spans + per-keyword ML attributions.
- 🧠 **Hybrid detection** — 10 rule/lexicon attributes + 2 heuristics + a TF-IDF/
  Logistic-Regression classifier, fused by a transparent, tunable **noisy-OR**.
- 🔒 **Private by design** — all inference is local; nothing is sent to the cloud.
- 🎛️ **Tunable, not magic** — weights, reliabilities, and thresholds live in an
  editable `weights.yaml`.
- 🖥️ **Desktop app** — Grammarly-style UI with a risk banner, attribute bar chart,
  inline keyword highlighting, and expandable evidence; dock/float window modes.

## How it works

```
 raw email ──► text_clean ──►  ┌───────────────────────────────┐
 (parse                        │  12 attribute scorers (rules) │──┐
  headers,                     └───────────────────────────────┘  │  noisy-OR
  clean body,                  ┌───────────────────────────────┐  ├──► risk_score
  keep casing)                 │  TF-IDF + LogReg classifier    │──┘   + verdict
                               │  (probability + keyword attr.) │
                               └───────────────────────────────┘
```

1. **Data prep** ([`data_prep.py`](phishing_analyzer/data_prep.py)) — merges 6
   public corpora (Enron, CEAS_08, Nazario, Nigerian_Fraud, SpamAssassin, Ling),
   cleans while **preserving casing/punctuation**, dedups, and makes a stratified
   train/val/test split. See [DATA_CARD.md](DATA_CARD.md).
2. **Feature schema** ([`lexicons.py`](phishing_analyzer/lexicons.py)) — lexicons
   were **validated by frequency-lift against real phishing samples**, not guessed.
   See [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md).
3. **Extraction pipeline** ([`attributes/`](phishing_analyzer/attributes/)) — each
   attribute is an independent, testable module returning
   `{score, label, explanation, evidence_spans}`.
4. **Classifier** ([`classifier.py`](phishing_analyzer/classifier.py)) — TF-IDF
   (word 1–2 grams + char 3–5 grams) → Logistic Regression, with an exact
   per-keyword attribution (`explain()`).
5. **Risk combination** ([`risk.py`](phishing_analyzer/risk.py)) — noisy-OR of all
   signals; config in [`weights.yaml`](phishing_analyzer/weights.yaml).

## The 12 attributes

| Attribute | Method | Detects |
|---|---|---|
| urgency | lexicon | time pressure ("act now", "within 24 hours") |
| fear_threat | lexicon | intimidation ("suspended", "unusual activity") |
| reward | lexicon | greed bait ("you won", "beneficiary", "million dollars") |
| curiosity | lexicon | curiosity lures ("you have a new message") |
| authority | lexicon | impersonation ("bank", "security team", brands) |
| financial | lexicon + regex | money requests ("wire transfer", IBAN/amounts) |
| credential | lexicon | harvesting phrases ("verify your account") |
| generic_greeting | lexicon | "Dear Customer/Sir/Friend" vs personalized |
| sender_domain | header parse | display-name vs domain spoof, lookalike domains |
| links | URL regex | shorteners, bad TLDs, IP-literal, obfuscation |
| grammar | spellcheck | spelling/grammar anomalies *(weak on this corpus)* |
| caps_tone | ratios | shouting / punctuation bursts *(weak on this corpus)* |

Plus the **content classifier** as a co-equal ML signal.

## Risk score (noisy-OR)

Each signal casts a vote = `reliability × score`, then
`risk = 1 − Π(1 − vote)` — so **any one confident signal drives risk high**, while
silent signals don't drag it down. A capped attribute reliability means a single
rule tops out at "suspicious"; only the classifier (or several attributes) reaches
"phishing." Verdict bands: `<0.35 legitimate`, `≥0.60 phishing`, else `suspicious`.
All values are editable in [`weights.yaml`](phishing_analyzer/weights.yaml).

## Results (held-out test set)

Test set: 10,122 emails (5,824 legit / 4,298 phishing).

| Model | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| Classifier alone | 0.9916 | 0.9907 | **0.9912** | 0.9995 |
| Combined tool | 0.9724 | 0.9919 | **0.9820** | 0.9989 |

> ⚠️ **Honest caveat:** these numbers are *in-distribution* (same sources as
> training). The classifier partially learns "corporate Enron style = safe" (a
> documented leakage the evaluation surfaces), so real-world performance on modern
> consumer phishing will be lower. Closing that gap is on the roadmap.

Full evaluation, per-source leakage probe, and per-attribute validation:
[`evaluate.py`](evaluate.py).

## Project structure

```
TIS/
├── phishing_analyzer/        # core engine
│   ├── data_prep.py          # merge/clean/split the corpora
│   ├── text_clean.py         # casing-preserving cleaner
│   ├── lexicons.py           # data-validated keyword lists
│   ├── attributes/           # 12 independent attribute modules
│   ├── classifier.py         # TF-IDF + LogReg (+ keyword attribution)
│   ├── risk.py + weights.yaml # noisy-OR risk combination (tunable)
│   ├── schema.py             # pydantic AnalysisReport (JSON contract)
│   ├── pipeline.py           # orchestrator: raw email -> report
│   └── cli.py                # terminal demo with inline highlighting
├── server/app.py             # FastAPI local API (/analyze, /health)
├── desktop/                  # Electron + React desktop app
├── evaluate.py               # test-set metrics + validation
├── scripts/                  # data build + lexicon validation utilities
├── tests/                    # pytest (attribute unit tests)
├── DATA_CARD.md / FEATURE_SCHEMA.md / OUTPUT_SCHEMA.md / CLAUDE.md
└── requirements.txt
```

> Data (`data/`), the trained model (`models/`), reports, and `node_modules/` are
> **gitignored** — they're large and regenerable from the code (see below).

## Setup

Requires **Python 3.11+** (developed on 3.14) and, for the desktop app, **Node 18+**.

```bash
# from TIS/
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# (macOS/Linux: .venv/bin/python -m pip install -r requirements.txt)

# build the processed data + train the model (one time; regenerates gitignored artifacts)
.venv/Scripts/python.exe -m scripts.build_enron_raw          # samples raw Enron
.venv/Scripts/python.exe -m phishing_analyzer.data_prep      # -> data/processed/
.venv/Scripts/python.exe -m phishing_analyzer.classifier     # -> models/classifier.joblib
```

## Usage

**CLI:**
```bash
.venv/Scripts/python.exe -m phishing_analyzer.cli --demo
.venv/Scripts/python.exe -m phishing_analyzer.cli --file email.txt --json
```

**Local API server:**
```bash
.venv/Scripts/python.exe -m uvicorn server.app:app --host 127.0.0.1 --port 8008
# GET  http://127.0.0.1:8008/health
# POST http://127.0.0.1:8008/analyze   { "text": "<raw email>" }
# docs http://127.0.0.1:8008/docs
```

**Desktop app** (needs the server running — see [desktop/README.md](desktop/README.md)):
```bash
cd desktop
npm install
npm run dev
```

**Tests:**
```bash
.venv/Scripts/python.exe -m pytest -q
```

## Output schema

Every analysis returns a validated `AnalysisReport`
([`schema.py`](phishing_analyzer/schema.py)):

```jsonc
{
  "verdict": "phishing | suspicious | legitimate",
  "risk_score": 0.0,
  "summary": "One-line explanation with top signals",
  "top_signals": ["content_classifier", "financial", "sender_domain"],
  "attributes": [
    { "name": "financial", "score": 0.98, "label": "high financial",
      "explanation": "matched 6 financial cue(s): ...",
      "evidence": [{ "text": "wire transfer", "start": 42, "end": 55 }] }
  ],
  "classifier": {
    "phishing_probability": 0.9996,
    "keyword_attributions": [
      { "term": "verify your account", "weight": 0.38,
        "direction": "phishing", "intensity": 1.0, "spans": [/* ... */] }
    ],
    "char_ngram_contribution": 4.64
  },
  "meta": { "sender_analyzed": true, "notes": [] },
  "analyzed_text": "Subject...\n\nbody..."
}
```

Full field reference: [OUTPUT_SCHEMA.md](OUTPUT_SCHEMA.md).

## Known limitations & biases

- **Corporate-only legit baseline** — Enron is ~2000s corporate email; the model
  can ride "corporate style = safe." Per-source metrics in the evaluation expose it.
- **Old corpus** — predates gift-card/crypto/brand-impersonation scams, so those
  cues are retained but flagged as unvalidated on this data.
- **grammar & caps_tone are weak here** — grammar flags corporate jargon as
  "misspellings"; caps_tone doesn't separate on this corpus. Both kept at low
  reliability and documented.
- **No ground truth for individual attributes** — validated indirectly (AUC/
  correlation vs the phishing label + manual spot-check).
- **Requires the local server running** for the desktop app / API.

## Roadmap

- **Browser extension** for webmail (Gmail/Outlook) — one-click "Scan this email"
  with an in-page results panel, reusing the local API. *(planned)*
- Modern/held-out phishing evaluation to quantify real-world generalization.
- Optional bundling of the Python backend with the desktop app.

## Documentation

| Doc | What's in it |
|---|---|
| [CLAUDE.md](CLAUDE.md) | Project context, decisions, and gotchas (authoritative) |
| [DATA_CARD.md](DATA_CARD.md) | Dataset sources, sizes, splits, biases |
| [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md) | The 12 attributes + validation findings |
| [OUTPUT_SCHEMA.md](OUTPUT_SCHEMA.md) | JSON output contract + CLI usage |
| [desktop/README.md](desktop/README.md) | Desktop app run instructions |

---

*Built as an educational, defensive security tool. Detection quality is
demonstrated on a public research corpus; validate before relying on it for
real-world protection.*
