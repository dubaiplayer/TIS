"""
Phishing email analyzer — CLI demo.

Reads a raw email (headers + body) from a file, --text, or stdin, runs the full
pipeline, and prints either the JSON report or a "Grammarly-style" terminal view
with the manipulation cues highlighted inline.

Examples:
  .venv/Scripts/python.exe -m phishing_analyzer.cli --file email.txt
  .venv/Scripts/python.exe -m phishing_analyzer.cli --demo
  echo "URGENT verify your account" | .venv/Scripts/python.exe -m phishing_analyzer.cli
  .venv/Scripts/python.exe -m phishing_analyzer.cli --file email.txt --json
"""
import argparse
import sys

from . import pipeline
from .schema import build_report

# ANSI
_C = {"red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
      "dim": "\033[2m", "bold": "\033[1m", "hl": "\033[43m\033[30m", "reset": "\033[0m"}
_VERDICT_COLOR = {"phishing": "red", "suspicious": "yellow", "legitimate": "green"}

DEMO_EMAIL = """From: PayPal Security <service@account-verify.gmail.com>
Subject: URGENT: Your account has been suspended

Dear Customer,

URGENT!!! We detected unusual activity and your account has been suspended.
You must verify your account within 24 hours or it will be permanently blocked.
Click here to sign in and confirm your identity: http://bit.ly/pp-verify-now

PayPal Security Team
"""


def _paint(s, color, on):
    return f"{_C[color]}{s}{_C['reset']}" if on else s


def _bar(score, width=24):
    filled = int(round(score * width))
    return "[" + "#" * filled + "-" * (width - filled) + f"] {score:.2f}"


def _merge_spans(spans):
    spans = sorted(((s["start"], s["end"]) for s in spans if s["end"] > s["start"]))
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def _highlight(text, spans, on, cap=1600):
    ranges = _merge_spans(spans)
    out, cur = [], 0
    for a, b in ranges:
        if a >= cap:
            break
        out.append(text[cur:a])
        out.append(_paint(text[a:min(b, cap)], "hl", on))
        cur = min(b, cap)
    out.append(text[cur:cap])
    tail = "  …(truncated)" if len(text) > cap else ""
    return "".join(out) + tail


def render(report, color=True):
    v = report.verdict
    vc = _VERDICT_COLOR.get(v, "bold")
    print()
    print(_paint(f"  VERDICT: {v.upper()}", vc, color) + f"    risk {_bar(report.risk_score)}")
    print(f"  {report.summary}")
    if report.classifier.phishing_probability is not None:
        print(_paint(f"  classifier P(phishing) = {report.classifier.phishing_probability:.3f}",
                     "dim", color))
    print()

    fired = sorted([a for a in report.attributes if a.score > 0], key=lambda a: -a.score)
    if fired:
        print(_paint("  Signals detected:", "bold", color))
        for a in fired:
            print(f"    {_paint(a.label, vc, color):<28} {a.score:.2f}  "
                  f"{_paint(a.explanation, 'dim', color)}")
    else:
        print(_paint("  No manipulation signals detected.", "dim", color))

    kws = report.classifier.keyword_attributions
    if kws:
        print("\n  " + _paint("Classifier keyword attributions "
                              "(coef x tf-idf, this email):", "bold", color))
        for k in [k for k in kws if k.direction == "phishing"][:10]:
            print(f"    {_paint('+'+format(k.weight,'.3f'), 'red', color)}  "
                  f"{k.term}  {_paint('('+format(k.intensity,'.2f')+')', 'dim', color)}")
        for k in [k for k in kws if k.direction == "legitimate"][:4]:
            print(f"    {_paint(format(k.weight,'.3f'), 'green', color)}  "
                  f"{k.term}  {_paint('(pushes legit)', 'dim', color)}")

    all_spans = [s.model_dump() for a in report.attributes for s in a.evidence]
    if all_spans and report.analyzed_text:
        print("\n  " + _paint("Email with evidence highlighted:", "bold", color))
        body = _highlight(report.analyzed_text, all_spans, color)
        for line in body.splitlines():
            print("    " + line)
    if report.meta.notes:
        print("\n  " + _paint("Notes: " + "; ".join(report.meta.notes), "dim", color))
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Phishing email analyzer")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--file", help="path to a raw email file")
    src.add_argument("--text", help="raw email text inline")
    src.add_argument("--demo", action="store_true", help="analyze a built-in sample")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of the pretty view")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI color")
    ap.add_argument("--no-classifier", action="store_true", help="rules only (skip the ML model)")
    args = ap.parse_args(argv)

    if args.demo:
        raw = DEMO_EMAIL
    elif args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    elif args.text:
        raw = args.text
    else:
        raw = sys.stdin.read()
    if not raw.strip():
        ap.error("no input (use --file, --text, --demo, or pipe via stdin)")

    result = pipeline.analyze_raw(raw, use_classifier=not args.no_classifier)
    report = build_report(result)

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        render(report, color=not args.no_color)


if __name__ == "__main__":
    main()
