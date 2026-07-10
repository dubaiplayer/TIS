# Phishing Analyzer — Desktop App

Electron + React (Vite) desktop UI for the phishing analyzer. It calls the local
FastAPI backend (which wraps the Python pipeline) and renders a Grammarly-style
breakdown: overall verdict, per-attribute score chart, classifier keyword
highlighting, and expandable per-attribute evidence.

Two window modes (top-right toggle): **Float** (normal window) and **Dock ▸**
(docked to the right screen edge, always-on-top).

## Two views (top tabs)
- **Analyze** — paste an email; it's analyzed (auto after ~0.8s or via the button).
- **Inbox Sim** — the **autonomous demo**: on open it generates a labeled inbox of
  synthetic emails (malicious ↔ benign) and works through every one with no user
  input, streaming a verdict + expandable breakdown per email and a live
  **scoreboard** (your model's accuracy vs the known labels).
  - Detection is always **your model** (deterministic). The optional **LLM agent**
    (Claude Agent SDK, via the `phishing-email-analyzer` skill) only replaces the
    human "click Analyze" step and narrates an action per email.
  - Agent mode needs `ANTHROPIC_API_KEY` set in the environment that runs the
    backend, plus `pip install claude-agent-sdk`. Without it, the view shows a
    clear banner and runs model-only (verdicts unchanged).
  - Emails are **synthetic templates** — a pipeline demo, not a real-world benchmark.

## Prerequisites
- Python venv set up at repo root with backend deps:
  `.venv/Scripts/python.exe -m pip install -r ../requirements.txt`
- The trained model at `../models/classifier.joblib`
  (run `.venv/Scripts/python.exe -m phishing_analyzer.classifier` once if missing).
- Node.js 18+ and npm.

## Run it (two terminals)

**Terminal 1 — backend API** (from the repo root `TIS/`):
```bash
.venv/Scripts/python.exe -m uvicorn server.app:app --host 127.0.0.1 --port 8008
```
Health check: open http://127.0.0.1:8008/health → `{"status":"ok"}`.
API docs (FastAPI auto): http://127.0.0.1:8008/docs

**Terminal 2 — desktop app** (from `TIS/desktop/`):
```bash
npm install        # first time only
npm run dev        # starts Vite (5173) then launches Electron
```
The Electron window opens automatically. Paste an email and it analyzes
(auto after ~0.8 s, or click **Analyze**).

If the backend isn't running you'll see a clear banner
("Backend not detected on 127.0.0.1:8008") rather than a silent failure.

## Package a distributable (optional)
```bash
npm run dist       # builds the renderer + electron-builder installer -> release/
```
Note: packaging bundles only the Electron app. The Python backend still runs
separately (a future step could bundle it via PyInstaller and spawn it from the
Electron main process).

## Layout
```
desktop/
  electron/main.cjs      window + dock/float toggle (IPC)
  electron/preload.cjs   safe contextBridge (window controls only)
  src/api.js             backend client (server-down detection)
  src/App.jsx            input, debounced auto-analyze, wiring, error states
  src/components/        RiskBanner, AttributeBarChart, KeywordHighlight, AttributeList
```
