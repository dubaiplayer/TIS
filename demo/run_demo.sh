#!/usr/bin/env bash
# run_demo.sh — completely-automatic agent demo (Git-Bash / macOS / Linux parity).
# Same as run_demo.ps1: fresh random inbox -> warm service -> headless agent.
# Uses your Claude subscription login (claude login) — no ANTHROPIC_API_KEY needed.
#
# Usage:  ./demo/run_demo.sh [N] [SEED]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVC="https://phishing-analyzer-api-wq1v.onrender.com"
N="${1:-6}"
SEED="${2:-}"

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  echo "[note] ANTHROPIC_API_KEY is set — the agent will use that key, not your subscription."
fi
command -v claude >/dev/null 2>&1 || { echo "The 'claude' CLI is not on PATH. Install Claude Code and run 'claude login'."; exit 1; }

echo "[1/3] Generating $N random emails..."
if [ -n "$SEED" ]; then python "$HERE/make_inbox.py" "$N" --seed "$SEED"; else python "$HERE/make_inbox.py" "$N"; fi

echo; echo "[2/3] Warming the service (cold start can take 30-60s)..."
curl -s "$SVC/health" || true; echo

echo; echo "[3/3] Launching the agent (headless, no prompts)..."
cd "$HERE"
claude -p "$(cat "$HERE/PROMPT.txt")" \
  --allowedTools "Read,Glob,Bash(curl *),Bash(curl.exe *),Bash(python *),Bash(python3 *)" \
  --verbose

echo; echo "Done."
