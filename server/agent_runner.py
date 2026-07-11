"""
Live-agent runner for the GUI.

Spawns headless Claude Code (`claude -p ... --output-format stream-json`) in a
throwaway folder that contains ONLY a local SKILL.md + the generated inbox. The
agent reads the skill and calls THIS backend's /analyze for every email; we parse
its stream-json events and relay compact activity + per-email results to the GUI.

Auth: the Claude subscription login (claude login) - no ANTHROPIC_API_KEY.
The agent's network calls only hit the local analyzer (127.0.0.1), so it works
fully offline from any external service.
"""
import asyncio
import json
import os
import shutil
import tempfile

LOCAL_BASE = os.environ.get("AGENT_LOCAL_BASE", "http://127.0.0.1:8008")
ALLOWED = "Read,Glob,Bash(curl *),Bash(curl.exe *),Bash(python *),Bash(python3 *)"

_SKILL_TMPL = """# Phishing Email Analyzer API (local)

Base URL:
{base}

## POST /analyze
Send a JSON body {{"text": "<the full raw email as a string>"}} with header
Content-Type: application/json. Read the response:
- `verdict` - "phishing" | "suspicious" | "legitimate"
- `risk_score` - number 0..1
- `top_signals` - strongest red flags
- `attributes` - all 16 detectors incl. sender_auth, link_deception, obfuscation,
  attachment_risk, each with score + explanation + evidence.

Example:
curl -s -X POST {base}/analyze -H "Content-Type: application/json" -d "{{\\"text\\": \\"...\\"}}"

## GET /health -> {{"status": "ok"}}
"""

_PROMPT = """Read SKILL.md in this folder and follow it exactly. Do everything automatically, without asking anything.

1. For every .txt file in the inbox/ folder, read the file and POST its FULL contents to the API's /analyze endpoint (use curl or python for the HTTP call). Take `verdict` and `risk_score` from the JSON response. Do NOT decide phishing yourself - the verdict must come only from the API.
2. Immediately after you get each email's result, output ONE line, exactly this shape and nothing else on the line:
RESULT {"file": "email_0X.txt", "verdict": "<the verdict>", "risk": <the risk_score>}
3. After all emails are done, output a final line: DONE
"""


def claude_cli_available():
    return shutil.which("claude") is not None


def _write_run_folder(inbox):
    d = tempfile.mkdtemp(prefix="agentdemo_")
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(_SKILL_TMPL.format(base=LOCAL_BASE))
    with open(os.path.join(d, "PROMPT.txt"), "w", encoding="utf-8") as f:
        f.write(_PROMPT)
    inbox_dir = os.path.join(d, "inbox")
    os.makedirs(inbox_dir)
    for it in inbox:
        with open(os.path.join(inbox_dir, f"email_{it['id']:02d}.txt"), "w",
                  encoding="utf-8") as f:
            f.write(it["raw_email"])
    return d


def _short(s, n=100):
    s = " ".join(str(s).split())
    return s[:n] + ("…" if len(s) > n else "")


def _parse_event(ev):
    """Map one stream-json event to zero or more GUI dicts."""
    t = ev.get("type")
    outs = []
    if t == "system" and ev.get("subtype") == "init":
        outs.append({"type": "activity", "kind": "system",
                     "text": f"agent ready (model {ev.get('model', 'claude')})"})
    elif t == "assistant":
        for b in ev.get("message", {}).get("content", []):
            bt = b.get("type")
            if bt == "tool_use":
                name, inp = b.get("name"), (b.get("input") or {})
                if name == "Read":
                    outs.append({"type": "activity", "kind": "read",
                                 "text": f"reading {os.path.basename(str(inp.get('file_path', '')))}"})
                elif name == "Glob":
                    outs.append({"type": "activity", "kind": "glob",
                                 "text": f"listing files ({inp.get('pattern', '')})"})
                elif name == "Bash":
                    outs.append({"type": "activity", "kind": "bash",
                                 "text": _short(inp.get("command", ""))})
                else:
                    outs.append({"type": "activity", "kind": "tool", "text": str(name)})
            elif bt == "text":
                for ln in (b.get("text") or "").splitlines():
                    ln = ln.strip()
                    if ln.startswith("RESULT "):
                        try:
                            rec = json.loads(ln[len("RESULT "):])
                            outs.append({"type": "email", "file": rec.get("file"),
                                         "verdict": rec.get("verdict"), "risk": rec.get("risk")})
                        except Exception:
                            pass
                    elif ln and ln != "DONE":
                        outs.append({"type": "activity", "kind": "text", "text": ln[:200]})
    return outs


async def run_agent_events(inbox):
    """Async generator: activity / email / error / done dicts as the agent works."""
    claude = shutil.which("claude")
    if not claude:
        yield {"type": "error", "error": "The 'claude' CLI was not found on PATH. "
               "Install Claude Code and run 'claude login', then restart the backend."}
        return

    folder = _write_run_folder(inbox)
    argv = [claude, "-p", _PROMPT, "--output-format", "stream-json", "--verbose",
            "--allowedTools", ALLOWED]
    yield {"type": "activity", "kind": "start", "text": "launching the agent (headless)…"}
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=folder,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except Exception as e:
        shutil.rmtree(folder, ignore_errors=True)
        yield {"type": "error", "error": f"could not launch the agent: {type(e).__name__}: {e}. "
               f"claude path: {claude}"}
        return

    try:
        async for line in proc.stdout:
            s = line.decode("utf-8", "replace").strip()
            if not s:
                continue
            try:
                ev = json.loads(s)
            except Exception:
                continue
            for out in _parse_event(ev):
                yield out
        await proc.wait()
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    yield {"type": "done"}
