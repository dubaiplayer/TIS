# Output Schema & CLI (Step 5)

The tool emits one JSON object per analyzed email, defined and validated by the
pydantic models in [`phishing_analyzer/schema.py`](phishing_analyzer/schema.py).
`AnalysisReport.model_json_schema()` produces the formal JSON Schema.

## Structure

```jsonc
{
  "verdict": "phishing | suspicious | legitimate",
  "risk_score": 0.0,              // 0..1 overall risk (noisy-OR of all signals)
  "summary": "One-line human-readable explanation with top signals",
  "top_signals": ["content_classifier", "financial", "sender_domain"],
  "attributes": [                 // all 12, whether or not they fired
    {
      "name": "financial",
      "score": 0.98,              // 0..1 for this attribute
      "label": "high financial",
      "explanation": "matched 6 financial cue(s): 'beneficiary', ...",
      "evidence": [               // char offsets into analyzed_text -> UI highlights
        {"text": "wire transfer", "start": 42, "end": 55}
      ]
    }
  ],
  "classifier": { "phishing_probability": 0.9996 },  // null if model unavailable
  "meta": {
    "sender_analyzed": true,
    "notes": ["no sender header; sender_domain spoof check skipped"]
  },
  "analyzed_text": "Subject...\n\nbody..."          // what offsets index into
}
```

### Field notes
- **verdict** — banded from `risk_score` via `weights.yaml` thresholds
  (`legitimate` < 0.35, `phishing` ≥ 0.60, else `suspicious`).
- **attributes[].evidence** — `start`/`end` are character offsets into
  `analyzed_text` (inclusive/exclusive), enabling Grammarly-style highlighting.
- **classifier.phishing_probability** — the co-equal TF-IDF+LogReg signal;
  `null` when the model isn't trained/available (tool falls back to rules-only).
- **meta.notes** — surfaces skipped checks (e.g. no sender header, no HTML).

## Example (phishing)

```json
{
  "verdict": "phishing",
  "risk_score": 0.9976,
  "summary": "High risk - strong phishing indicators. Top signals: content classifier, credential, fear threat, sender domain.",
  "top_signals": ["content_classifier", "credential", "fear_threat", "sender_domain"],
  "classifier": {"phishing_probability": 1.0},
  "attributes": [
    {"name": "credential", "score": 0.8336, "label": "high credential-harvest",
     "explanation": "matched 3 credential-harvest cue(s): 'confirm your identity', 'sign in', 'verify your account'",
     "evidence": [{"text": "verify your account", "start": 120, "end": 139}]},
    {"name": "sender_domain", "score": 0.6211, "label": "moderate sender_domain",
     "explanation": "display-name claims 'paypal' but domain is 'account-verify.gmail.com'",
     "evidence": [{"text": "PayPal Security <service@account-verify.gmail.com>", "start": 0, "end": 49}]}
  ],
  "meta": {"sender_analyzed": true, "notes": []}
}
```

## CLI usage

```bash
# Pretty terminal view (verdict, ranked signals, inline-highlighted email)
.venv/Scripts/python.exe -m phishing_analyzer.cli --demo
.venv/Scripts/python.exe -m phishing_analyzer.cli --file suspicious_email.txt

# JSON output (the schema above)
.venv/Scripts/python.exe -m phishing_analyzer.cli --file email.txt --json

# Pipe raw email via stdin; rules-only (no ML); no color
cat email.txt | .venv/Scripts/python.exe -m phishing_analyzer.cli --no-color --no-classifier
```

Input is a raw email (headers + body); the CLI parses the `From:` header to run
the sender-spoofing check. Plain body text also works (sender check is then
skipped and noted in `meta`).
```
