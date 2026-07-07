# CLAUDE.md — Phishing Email Analysis Tool

Project context for Claude Code. Read this first.

## What we're building

A "Grammarly for phishing": read raw email text and return a **structured,
explainable breakdown** of manipulation/phishing attributes — each with a score
and **highlighted evidence spans** — plus an overall risk score/verdict. Priority
is interpretability (every score traceable to evidence), not a black-box classifier.

## Current status (2026-07-07)

- **Step 1 (data prep): DONE.** `data_prep.py` merges 6 sources by name, cleans
  (casing preserved), dedups, two-track stratified split → `data/processed/`
  (parquet+csv) + `manifest.json` + `DATA_CARD.md`. Track A = 67,472 rows
  (38,822 legit / 28,650 phish). `explore.py` prints the checkpoint report.
- **Step 2 (feature schema): DONE.** Lexicons seeded then VALIDATED by
  frequency-lift on Track A train (`scripts/validate_lexicons.py`). Finalized in
  `phishing_analyzer/lexicons.py` (LEXICON = validated; CORPUS_LIMITATION =
  modern cues the old corpus can't validate). Full schema in `FEATURE_SCHEMA.md`.
  Key finding: blind mining is dominated by campaign/source artifacts →
  confirms the co-equal-ML leakage guardrails.
- **Step 3 (extraction pipeline): DONE.** 12 attribute modules under
  `phishing_analyzer/attributes/` (word-boundary matching, saturating scores,
  evidence spans); TF-IDF(word+char)+LogReg trained (`classifier.py`, val
  F1=0.989, AUC=0.999, saved to `models/classifier.joblib`); risk combination in
  `risk.py`+`weights.yaml` (classifier CO-EQUAL, weight 13). `pipeline.py`
  orchestrates. 15/15 unit tests pass; `scripts/smoke_demo.py` verifies E2E.
  **Leakage confirmed live:** classifier's top legit features include `enron`,
  `re:`, `thanks`, `>` — it rides corporate style. Step 4 MUST report per-source
  metrics and we may dial `classifier_weight` down.
- **Next up:** Step 4 — evaluation (test-set P/R/F1, confusion matrix, per-source
  metrics, attribute-vs-label correlation, spot-check sample).
- Scripts done: `build_enron_raw.py`, `casing_check.py`, `validate_lexicons.py`,
  `smoke_demo.py`.

## Environment

- Python **3.14.5**, system-wide. No scientific libraries installed yet.
- Data-prep scripts so far are **stdlib-only** (csv, email, random) — this keeps
  the 1.43 GB raw Enron read memory-safe and avoids install risk.
- When ML work starts: create a **venv inside `TIS/`** and install
  `pandas scikit-learn numpy pyarrow beautifulsoup4 lxml pyyaml pydantic
  tldextract pyspellchecker matplotlib pytest`. Verify Python-3.14 wheels on
  install; pin or fall back (e.g. csv-only if pyarrow fails).
- Code lives in this repo (`TIS/`). Add `data/`, venv, `__pycache__` to `.gitignore`.

## Dataset

Location: `C:\Users\15DGupta\Downloads\archive (4)`. We use **6 per-source files**,
merged **by column name** (column order differs between files — never merge by index).

| Source | Rows | Labels | Casing | In merge |
|---|---|---|---|---|
| `Enron_raw.csv` (NEW) | 15,800 | 0 only (legit) | preserved | ✅ |
| `CEAS_08.csv` | 39,154 | 0 + 1 | preserved | ✅ |
| `Ling.csv` | 2,859 | 0 + 1 | **flattened (lowercased)** | ✅ |
| `Nazario.csv` | 1,565 | 1 only | preserved | ✅ |
| `Nigerian_Fraud.csv` | 3,332 | 1 only | preserved | ✅ |
| `SpamAssasin.csv` | 5,809 | 0 + 1 | preserved | ✅ |
| ~~`Enron.csv`~~ (old) | 29,767 | 0+1 | flattened | ❌ excluded |
| ~~`phishing_email.csv`~~ | 82,486 | 0+1 | flattened | ❌ excluded |

Labels: `0 = legitimate`, `1 = phishing`. Text column is `body` (+ `subject`); some
files also have `sender/receiver/date/urls`. **`urls` is a has-URL 0/1 flag, NOT a label.**

### Why Enron was re-sourced (key decision)
The originally packaged `Enron.csv` was **pre-lowercased and punctuation-stripped**,
which flattened all casing/tone/urgency signal for the legit class and confounded
those features with source+label. We re-downloaded the **raw** Kaggle Enron dump
(`emails.csv`, wcukierski), parsed headers→body, sampled 15,800 (seed 42), labeled
0, and saved `Enron_raw.csv` with schema `subject,body,label`.

**Verified fix** (`scripts/casing_check.py`, mean uppercase-letter ratio):
old Enron `0.00%` → `Enron_raw` `11.78%` — now in the band of the other
casing-preserving sources (CEAS 8.84%, Nazario 9.18%, SpamAssassin 8.94%).

### Residual dataset caveats (keep in the data card)
- **Ling is still flattened** (0.00% uppercase). We only re-sourced Enron. So the
  casing confound now lives entirely in Ling → **exclude Ling (only) from
  casing-sensitive feature calibration** (Track B, below).
- **Enron_raw runs slightly high on uppercase (11.78%)** due to corporate
  signature blocks and trading acronyms (SWAP, ETA, EB). Genuine casing, not an
  artifact — but the corporate-signature style is baked into the legit baseline.
- **Corporate-English-only legit baseline.** Enron is ~2000–2002 corporate mail;
  may not generalize to consumer/personal phishing. A raw re-download cannot fix
  this — inherent to the corpus.
- **Nazario + Nigerian are 100% phishing**; Ling + SpamAssassin are legit-heavy.
  Source correlates with label — report per-source metrics to expose this.
- **HTML mostly pre-stripped** → anchor-text-vs-href link mismatch is largely
  not extractable. Live URL reputation is out of scope.

## Two-track corpus (core methodology)

- **Track A — full corpus** (all 6 sources, both labels): TF-IDF + LogisticRegression
  content classifier and content-lexicon validation (casing-insensitive words).
- **Track B — casing-preserving subset** (all 6 **except Ling**): the ONLY track
  used to calibrate/validate casing/tone/punctuation features (ALL-CAPS, `!!!`,
  urgency intensity). Enron_raw now belongs here (this changed after the re-source).
- Both tracks carry a `source` column for per-source evaluation.

## Planned repo layout

```
TIS/
  requirements.txt, README.md, DATA_CARD.md
  data/processed/                  # versioned cleaned outputs (parquet + csv) + manifest.json
  scripts/
    build_enron_raw.py             # DONE — builds Enron_raw.csv
    casing_check.py                # DONE — per-source casing/punctuation report
  phishing_analyzer/
    data_prep.py                   # merge (by name) + two-track split + save
    explore.py                     # Step-1 checkpoint report
    text_clean.py                  # HTML strip / header-remnant strip / whitespace (preserve casing+punct)
    lexicons/                      # seed lexicons, data-validated by frequency lift
    attributes/                    # one module per attribute (below), each ->
                                   #   AttributeResult{score, label, explanation, evidence_spans}
    classifier.py                  # TF-IDF + LogisticRegression
    risk.py + weights.yaml         # explicit, adjustable score combination
    schema.py                      # pydantic JSON output models
    cli.py                         # demo: raw email -> JSON + highlighted terminal view
  evaluate.py                      # metrics + attribute validation
  tests/                           # pytest per attribute
```

## Attribute schema (Step 2 — finalized after Step-1 checkpoint)

Each attribute is an independently testable module returning
`AttributeResult{score∈[0,1], label, explanation, evidence_spans:[{text,start,end}]}`.
`evidence_spans` are character offsets into the original text (drive the highlight UI).

| Attribute | Method | Track |
|---|---|---|
| Urgency / time pressure | Lexicon + regex (deadlines, "act now") | A phrases, B caps intensity |
| Emotional manipulation (fear/threat/reward/curiosity) | Sub-lexicons per emotion | A |
| Authority impersonation | Lexicon (bank/IT/gov/exec) + sender cross-check | A + sender |
| Financial request | Lexicon (wire, gift card, invoice) + IBAN/BTC regex | A |
| Credential/data harvesting | Lexicon (verify/login/SSN/password) + URL/form cues | A + links |
| Generic vs personalized greeting | Regex ("Dear customer" vs a name) | A |
| Sender-domain mismatch / spoofing | Parse display-name vs domain; freemail-as-brand; lookalike (tldextract + edit distance) | sender-present sources only |
| Suspicious links | Shorteners, odd TLDs, IP-literal, raw-URL count; anchor/href only if HTML present | A |
| Grammar/spelling anomalies | pyspellchecker ratio + heuristics | B (casing matters) |
| Caps/punctuation tone | CAPS ratio, `!`/`?` bursts | **B only** |
| Content classifier | TF-IDF + LogisticRegression | A |

Lexicons: seed by hand, then **validate against real phishing samples** (per-term
phishing-vs-legit frequency lift on Track A); drop no-lift terms, surface missed
high-lift terms. No blind keyword guessing.

## Risk combination (Step 3)

**Decision: the TF-IDF + LogReg classifier is a CO-EQUAL signal** with the
rule-based attributes in the final risk score (not optional, not merely a
backstop). Explicit, adjustable weighted aggregation of attribute scores +
classifier probability, weights in `weights.yaml`. Two modes: (a) transparent
hand-set weights; (b) optional meta-LogisticRegression over attribute scores +
classifier prob (still interpretable via coefficients). Always output
contributing signals + the classifier's top contributing n-grams — never a fully
opaque number.

**Leakage guardrails (because ML now carries real weight):** source correlates
hard with label here (Enron=100% legit), so the classifier could inflate accuracy
by learning "corporate Enron style = safe". Mitigations: (1) report per-source
metrics in Step 4 and specifically inspect Enron false-negative behavior;
(2) prefer char+word n-grams and inspect top coefficients for source-identifying
tokens (names, "enron", signature artifacts) — down-weight/blocklist if found;
(3) keep the classifier weight adjustable in `weights.yaml` so it can be dialed
back if evaluation shows it's riding source rather than phishing signal.

## Evaluation (Step 4)

- Overall classification on Track A test: precision/recall/F1, confusion matrix,
  ROC-AUC. **Report per-source metrics** to expose the corporate-tone bias
  (expect near-perfect Enron separation — flag as partly artifact).
- Attribute validation (no per-attribute ground truth): per-attribute AUC /
  point-biserial correlation vs label; phishing-vs-legit score distributions;
  manual spot-check of ~40 stratified emails to a review CSV. Caps/tone attributes
  validated on **Track B** only.

## Output format (Step 5)

```json
{
  "overall": {"risk_score": 0.0, "verdict": "phishing|suspicious|legitimate",
              "top_signals": ["urgency", "financial_request"]},
  "attributes": [
    {"name": "urgency", "score": 0.0, "label": "...", "explanation": "...",
     "evidence_spans": [{"text": "act now", "start": 42, "end": 49}]}
  ],
  "meta": {"sender_analyzed": true, "notes": ["no HTML -> anchor/href check skipped"]}
}
```
CLI demo (`cli.py`): raw email from `--file`/stdin → JSON + highlighted terminal view.

## Conventions / gotchas for anyone editing

- **Merge sources by column name, never index** (order differs across files).
- **Never reintroduce `phishing_email.csv` or the old `Enron.csv`** — flattened
  text + leakage (the aggregate contains the per-source rows).
- Raw Enron reads need `csv.field_size_limit` raised (long message fields).
- Preserve **casing and punctuation** in body cleaning — they are signal here, not
  noise. Do not lowercase/strip-punct the way generic spam pipelines do.
- Reproducibility: fixed seeds (Enron sample uses seed 42). Stratify splits by label.
- Stop for user review at the Step-1 checkpoint before finalizing features.

## How to run (so far)

```bash
python scripts/build_enron_raw.py   # -> archive (4)/Enron_raw.csv  (seed 42, 15,800 rows)
python scripts/casing_check.py      # per-source casing/punctuation report
```
