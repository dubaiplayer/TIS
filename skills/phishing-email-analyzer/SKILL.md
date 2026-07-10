---
name: phishing-email-analyzer
description: >-
  Analyze an email for phishing / social-engineering manipulation. Use when asked
  whether an email is phishing or a scam, to scan/triage an email for red flags, or
  to explain the manipulation tactics in an email. Runs a LOCAL, explainable
  analyzer (rule attributes + a trained classifier) and returns a structured JSON
  verdict with per-attribute evidence. The verdict comes from the local model, not
  from your own judgment — report what the tool returns.
---

# Phishing Email Analyzer

A local, explainable phishing detector. Given raw email text it returns a verdict
(`phishing` / `suspicious` / `legitimate`), a 0–1 risk score, 12 per-attribute
scores with highlighted evidence, and the classifier's keyword attributions.

**Important:** the analysis is done by the local model + rules. Do not decide
phishing yourself — always run the tool and relay its result.

**Portable:** this skill works in Claude Code and OpenClaw, on Windows/macOS/Linux.
It ships a self-locating launcher (`analyze.py`) that finds the project and its
Python automatically — you do not need to know the venv path or the working
directory.

## How to analyze an email (preferred — portable)

Run the bundled `analyze.py` in THIS skill's folder, piping the raw email to stdin.
It auto-locates the project root and re-runs itself with the project's virtualenv
Python, so any `python` on PATH works:

```bash
printf '%s' "$EMAIL_TEXT" | python "<skill_dir>/analyze.py" --json
# or:  python "<skill_dir>/analyze.py" --file path/to/email.txt --json
```

`<skill_dir>` is the directory this SKILL.md lives in (the runtime provides it).
Read **stdout only** — it prints exactly one JSON object; logs go to stderr.
Exit code `0` = success; non-zero = failure and stdout is
`{"error": "...", "error_type": "..."}` — surface that instead of guessing.

## Alternative (when the shell is already at the project root)

```bash
printf '%s' "$EMAIL_TEXT" | python -m phishing_analyzer.cli --json
```

## One-time setup (only if the tool reports it's needed)

If a run returns `{"error": "...", "error_type": "SetupError"}` (dependencies not
installed / project not found), run once from the project root:

```bash
python -m scripts.setup
```

It installs dependencies and ensures the trained model exists. If it prints
`DEGRADED`, the analyzer still works in rules-only mode (no ML signal) and says so
in the report's `meta.notes`.

## Input contract
Raw email text. Include `From:` and `Subject:` headers when available so the
sender-spoofing check runs; a bare body also works (that check is then skipped).

## Output contract (the JSON to read)
See `OUTPUT_SCHEMA.md` in the project root. Key fields:
- `verdict` — `phishing` | `suspicious` | `legitimate`
- `risk_score` — 0..1
- `summary` — one-line explanation
- `top_signals` — the strongest contributing signals
- `attributes[]` — `{name, score, label, explanation, evidence[{text,start,end}]}`
- `classifier.phishing_probability` (null if model absent) and
  `classifier.keyword_attributions[]` — the words that drove the ML prediction
- `meta.notes` — e.g. "rules-only" when the model isn't available

## How to report back
Lead with the **verdict + risk %**, then the top 2–4 firing attributes and a short
evidence snippet from each. If `meta.notes` mentions rules-only, say the ML signal
was unavailable. Keep it to what the tool returned.

## Constraints / honesty
- Local + English email only. Trained on a public, corporate-biased research corpus
  → be cautious on modern/targeted phishing; do not present as definitive protection.
- Deterministic: the same email yields the same verdict.
- The skill orchestrates the local project — it requires the `phishing_analyzer`
  repo present alongside it (the skill folder ships inside that repo).

## Example
Input (stdin):
```
From: PayPal Security <svc@account-verify.gmail.com>
Subject: URGENT: verify your account

Dear Customer, unusual activity was detected. Verify your account within 24 hours
or it will be suspended: http://bit.ly/verify
```
Output (abridged): `verdict: "phishing"`, `risk_score: ~0.99`, top signals include
`sender_domain` ("claims 'paypal' but domain is account-verify.gmail.com"),
`credential`, `urgency`, `links`.
