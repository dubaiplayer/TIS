#!/usr/bin/env python3
"""
Portable launcher for the phishing-email-analyzer skill.

Makes the skill work regardless of OS, current working directory, or which Python
the agent invokes:
  - self-locates the project root by walking up from this file until it finds
    `phishing_analyzer/pipeline.py` (works from .claude/skills/ or skills/),
  - re-executes itself with the project's venv Python if one exists (so the ML
    dependencies are available even when called by system `python`),
  - reads a raw email from stdin, --file, or --text and prints the AnalysisReport
    JSON to stdout (nothing else); on failure prints a JSON error + non-zero exit.

Usage:
    <raw email> | python analyze.py --json
    python analyze.py --file email.txt --json
    python analyze.py --text "From: ...\\nSubject: ...\\n\\nbody"
"""
import argparse
import json
import os
import subprocess
import sys


def find_root(start):
    d = os.path.abspath(start)
    for _ in range(10):
        if os.path.isfile(os.path.join(d, "phishing_analyzer", "pipeline.py")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
    return None


def venv_python(root):
    for c in (os.path.join(root, ".venv", "Scripts", "python.exe"),  # Windows
              os.path.join(root, ".venv", "bin", "python")):          # macOS/Linux
        if os.path.isfile(c):
            return c
    return None


def _fail(msg, kind, as_json):
    if as_json:
        print(json.dumps({"error": msg, "error_type": kind}))
    else:
        print("Error: " + msg, file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="Portable phishing-email analyzer")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--file")
    g.add_argument("--text")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args, _ = ap.parse_known_args()
    as_json = args.json

    root = find_root(os.path.dirname(os.path.abspath(__file__)))
    if not root:
        _fail("could not locate the phishing_analyzer project from the skill folder; "
              "the skill needs the project repo present alongside it.", "SetupError", as_json)

    # Re-run under the project's venv Python so ML deps resolve (no-op if already it).
    vp = venv_python(root)
    if vp and os.path.realpath(vp) != os.path.realpath(sys.executable):
        try:
            return sys.exit(subprocess.run([vp, os.path.abspath(__file__)] + sys.argv[1:]).returncode)
        except Exception:
            pass  # fall through: try with the current interpreter

    sys.path.insert(0, root)
    try:
        from phishing_analyzer import pipeline
        from phishing_analyzer.schema import build_report
    except Exception as e:
        _fail(f"dependencies not available ({type(e).__name__}: {e}). "
              f"Run once from the project root: python -m scripts.setup", "SetupError", as_json)

    try:
        if args.file:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
        elif args.text:
            raw = args.text
        else:
            raw = sys.stdin.read()
        if not raw.strip():
            raise ValueError("no input (pipe an email via stdin, or use --file/--text)")
        report = build_report(pipeline.analyze_raw(raw))
    except Exception as e:
        _fail(str(e), type(e).__name__, as_json)

    if as_json:
        print(report.model_dump_json(indent=2))
    else:
        from phishing_analyzer.cli import render
        render(report, color=not args.no_color)


if __name__ == "__main__":
    main()
