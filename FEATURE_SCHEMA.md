# Feature / Attribute Schema (Step 2 — finalized)

Every attribute is its own module returning:

```python
AttributeResult(
    score: float,            # 0..1, calibrated per attribute
    label: str,              # short human verdict, e.g. "high urgency"
    explanation: str,        # one line naming what fired
    evidence_spans: list,    # [{text, start, end}] char offsets into `text`
)
```

`evidence_spans` are character offsets into the cleaned `text` field (subject +
body) produced by `data_prep.py`, so the UI can highlight the exact trigger.

**Matching contract:** lexicon terms match **case-insensitively with word
boundaries** (`\bterm\b`), never naive substring (substring matching falsely hit
`irs` inside `first`). Casing is a *separate* signal (see `caps_tone`).

**How lexicons were built:** seeded by hand, then validated by document-frequency
**lift** on Track A train (`scripts/validate_lexicons.py`). Base phishing rate =
0.425, so lift = P(phish | term contains) / 0.425; lift 2.36 is the ceiling
(100% phishing). Terms kept at lift ≥ ~1.3 with adequate support; weak/normal-
office terms pruned; valid-but-unverifiable modern cues retained under
`CORPUS_LIMITATION` and flagged.

---

## Attributes

| # | Attribute | Method | Track | Validated signal strength (this corpus) |
|---|---|---|---|---|
| 1 | Urgency / time pressure | Lexicon (`\b`) + intensity from caps | A (phrases) + B (caps) | Strong: `urgent` 2.14, `urgently` 2.22, `without delay` 2.27 |
| 2 | Emotional — fear/threat | Lexicon | A | Mixed: `unusual activity` 2.21, `suspended` 1.90; many threat words weak (see notes) |
| 3 | Emotional — reward/greed | Lexicon | A | Strong: `beneficiary` 2.33, `million dollars` 2.19, `risk free` 2.33 |
| 4 | Emotional — curiosity bait | Lexicon | A | Weak on this corpus (office `fax`/`see attached` are normal) |
| 5 | Authority impersonation | Lexicon + sender cross-check | A + sender | Partial: `barrister` 2.34, `bank` 1.62; brands weak here (flagged) |
| 6 | Financial request | Lexicon + IBAN/amount regex | A | Strongest: `next of kin` 2.36, `deposit` 2.16, `wire transfer` 1.93 |
| 7 | Credential / data harvesting | Lexicon (imperative phrases) + link cues | A + links | Phrases strong (`verify your account` 2.36); raw words weak (flagged) |
| 8 | Generic vs personalized greeting | Regex/lexicon | A | Strong: `dear sir` 2.28, `dear friend` 2.26, `dear customer` 2.21 |
| 9 | Sender-domain mismatch / spoofing | Parse `sender`: display-name vs domain, freemail-as-brand, lookalike (edit distance) | sender-present sources only | Rule-based; coverage limited (see notes) |
| 10 | Suspicious links | Regex over URLs: shorteners, odd TLDs, IP-literal, raw-URL count, click-cues | A | Rule-based; anchor/href mismatch mostly N/A (HTML pre-stripped) |
| 11 | Grammar / spelling anomalies | pyspellchecker ratio + heuristics | B (casing) | Heuristic; validate by correlation in Step 4 |
| 12 | Caps / punctuation tone | Ratio features (CAPS ratio, `!`/`?` bursts) | **B only** | Calibrated on casing-preserving sources (Enron flattening handled) |
| — | Content classifier | TF-IDF + LogReg | A | **Co-equal signal** in risk score (with leakage guardrails) |

**Rule/lexicon vs ML — the split and the tradeoff.** Attributes 1–10 are
rule/lexicon-based: fully interpretable, every hit maps to a highlighted span,
tunable without retraining — at the cost of only catching anticipated patterns.
Attributes 11–12 are heuristic ratios. The one learned model (TF-IDF + LogReg)
is the generalization backstop and, per the project decision, a **co-equal**
contributor to the risk score. We deliberately avoid embeddings/transformers/RNNs
unless Step 4 shows the linear model underperforms — interpretability is the
product.

---

## What the validation changed (evidence-driven, not guessed)

- **Kept (generalizable):** financial/419, reward, generic-greeting, and core
  urgency phrases are strongly discriminative and validated with high support.
- **Pruned (non-discriminative *here*):** `deadline` (lift 0.05 — 1059 legit),
  `expire*`, `asap`, `see attached`, `fax`, `voicemail`, plus most raw threat
  words (`terminated`, `unauthorized`, `violation`) — all ordinary in corporate
  mail. Kept out of the default lexicon so they don't fire on benign email.
- **Flagged, retained (`CORPUS_LIMITATION`):**
  - Modern payment rails — `gift card`, `itunes card`, `bitcoin`,
    `cryptocurrency`, `zelle`/`venmo` — ≈0 lift because the corpus predates them.
  - Brand impersonation — `microsoft`, `apple`, `amazon`, `paypal`, `irs` —
    weak lift because Enron IT mail names these legitimately.
  - Raw credential nouns — `password`, `login`, `ssn` — *lower* phishing rate
    than base here; the signal lives in the imperative phrase, not the noun.
  These fire on real-world input but Step 4 won't over-credit them on this data.

## Bias flags carried into feature engineering

1. **Mining is dominated by memorized campaign/source tokens** (`whitedone`,
   `livefilestore`, `karadzic`, `dailytop`, and legit-side `enron's`, `kaminski`,
   `ferc`). Confirms the TF-IDF classifier will exploit source/campaign leakage →
   enforce the Step-3 guardrails (char+word n-grams, coefficient audit for
   source tokens, adjustable classifier weight, per-source Step-4 metrics).
2. **Corporate-only legit baseline** makes credential/urgency *nouns* look benign
   and suppresses modern-scam vocabulary. Lexicon compensates via phrases +
   `CORPUS_LIMITATION`; caps/tone stays on Track B.
3. **Sender coverage is partial** — `sender` present in CEAS/Nazario/Nigerian/
   SpamAssassin (100/100/90/100%), absent in Enron_raw/Ling. Attribute 9 runs
   only where sender exists; output `meta` notes when it's skipped. Legit-with-
   sender still exists (CEAS/SpamAssassin), so the attribute has both classes.
4. **HTML pre-stripped** → anchor-text-vs-href mismatch largely not extractable;
   link attribute focuses on shorteners/TLDs/IP-literals/raw-URL count. Live URL
   reputation is out of scope.

## Scoring & combination (implemented in Step 3)

Each attribute maps its raw hit-count/ratio to a 0..1 score via a saturating
function (diminishing returns; tuned per attribute). The overall risk score is an
explicit, adjustable weighted blend of attribute scores + the classifier
probability (weights in `weights.yaml`), with contributing signals always
emitted. See `CLAUDE.md` → "Risk combination" for the co-equal-ML guardrails.
