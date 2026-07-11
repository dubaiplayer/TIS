# Phishing Email Analyzer API

An HTTP service that analyzes a raw email and returns an explainable phishing verdict — an overall risk score, 16 per-attribute manipulation/threat scores with the exact evidence text, and the classifier keywords that drove the decision. Any agent handling email can call it to answer "is this email phishing, and why?"

Beyond the language-manipulation attributes, it inspects real-world phishing vectors: **sender authentication** (SPF/DKIM/DMARC results + From/Reply-To/Return-Path alignment), **link deception** (link-text-vs-destination mismatch, punycode/homograph domains, brand-in-subdomain), **obfuscation** (hidden zero-width characters and homoglyph tricks), and **attachment risk** (dangerous types, double extensions, macro documents). Pass the full raw email — headers, HTML, and MIME parts included — to get these signals.

Base URL:
https://phishing-analyzer-api-wq1v.onrender.com

Note: this is a free-tier host that sleeps when idle. The first request after a quiet period can take 30–60 seconds while it wakes. Send a `GET /health` first to warm it up, then call `/analyze`.

## Endpoints

### GET /health
Liveness check. Returns `{"status":"ok"}`. Use it to warm up the service before analyzing.

Example call:
```
curl https://phishing-analyzer-api-wq1v.onrender.com/health
```
Example response:
```json
{"status": "ok"}
```

### POST /analyze
Analyze one email. Send a JSON body with a single field `text` containing the raw email (headers + body, or just the body). Returns the structured phishing report. Including the `From:` and `Subject:` headers improves accuracy (it enables the sender-spoofing check).

Example call:
```
curl -X POST https://phishing-analyzer-api-wq1v.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "From: PayPal Security <service@account-verify.gmail.com>\nSubject: URGENT: verify your account\n\nDear Customer, unusual activity was detected and your account was suspended. Verify your account within 24 hours or it will be permanently blocked: http://bit.ly/verify-now"}'
```
Example response (abridged — the real response also includes every attribute, evidence character-offset spans, and keyword attributions):
```json
{
  "verdict": "phishing",
  "risk_score": 0.995,
  "summary": "High risk - strong phishing indicators. Top signals: content classifier, fear threat, sender domain, credential.",
  "top_signals": ["content_classifier", "fear_threat", "sender_domain", "credential"],
  "attributes": [
    {"name": "fear_threat", "score": 0.8336,
     "explanation": "matched 3 fear/threat cue(s): 'permanently', 'suspended', 'unusual activity'"},
    {"name": "urgency", "score": 0.6975,
     "explanation": "matched 2 urgency cue(s): 'urgent', 'within 24 hours'"},
    {"name": "credential", "score": 0.45,
     "explanation": "matched 1 credential-harvest cue(s): 'verify your account'"}
  ],
  "classifier": {"phishing_probability": 0.9998}
}
```

Response fields:
- `verdict` — one of `"phishing"`, `"suspicious"`, `"legitimate"`.
- `risk_score` — number from 0.0 to 1.0.
- `summary` — one-line human-readable explanation.
- `top_signals` — the strongest contributing signals, most important first.
- `attributes` — array of all 16 attributes, each with `name`, `score` (0.0–1.0), `label`, `explanation`, and `evidence` (array of `{text, start, end}` character spans). Includes the language attributes (urgency, fear_threat, reward, curiosity, authority, financial, credential, generic_greeting, sender_domain, links, grammar, caps_tone) and the real-world detectors (sender_auth, link_deception, obfuscation, attachment_risk). Detectors that need data not present in the email report `label` starting with `"unavailable"`.
- `classifier.phishing_probability` — the ML model's probability (0.0–1.0); `null` if the model is unavailable.
- `meta.notes` — notes such as when a check was skipped.

### GET /skill.md
Returns this document as `text/markdown` (so an agent or the registry can fetch the instructions from the live URL).

Example call:
```
curl https://phishing-analyzer-api-wq1v.onrender.com/skill.md
```

## How the agent should use this

1. Warm up: send `GET /health`. If it does not return `{"status":"ok"}` within ~60 seconds, wait and retry once (free-tier cold start).
2. To analyze an email, send `POST /analyze` with a JSON body `{"text": "<the full raw email as a string>"}` and header `Content-Type: application/json`. Include the `From:` and `Subject:` headers in the text when you have them.
3. Read the response: `verdict` is the decision, `risk_score` (0–1) is the confidence, `top_signals` names the strongest red flags, and `attributes[]` gives per-tactic scores with `explanation` and `evidence` text you can quote.
4. Report back to the user: state the `verdict` and `risk_score`, then list the top 2–4 firing attributes with a short evidence snippet from each. If `classifier.phishing_probability` is `null` or `meta.notes` mentions rules-only, say the ML signal was unavailable.

## Notes and constraints
- The verdict is produced by the service's own model + rules; treat the JSON as the source of truth and report it — do not override it with your own judgment.
- Deterministic: the same email text always returns the same verdict.
- English-language email; the model was trained on a public research corpus, so treat it as a strong triage signal, not a guarantee.
- No authentication required. Send `text/*` email content only; no attachments are processed.
