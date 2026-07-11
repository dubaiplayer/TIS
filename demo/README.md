# Agent Demo — a real agent using only the hosted SKILL.md

This folder is the **video demo**. **One command** launches a real Claude Code
agent that, on its own, reads `SKILL.md`, analyzes a folder of **random emails**
through the live hosted API, and prints a graded scoreboard. No prompt typed, no
Anthropic API key — it uses your Claude subscription login.

**Why this satisfies the hackathon:** the scored bar is "a stock agent succeeds
using only your SKILL.md." The agent runs inside this folder, which contains
**only** `SKILL.md`, the random `inbox/` emails, and `labels.json` — no repo, no
model, no code. It has nothing to fall back on, so every verdict must come from
your live API, driven purely by `SKILL.md`.

## Prerequisites (one-time)
- Claude Code installed and logged in: `claude login` (Pro/Max subscription).
- `ANTHROPIC_API_KEY` **unset**, so the agent uses your subscription (not a key):
  - PowerShell: `$env:ANTHROPIC_API_KEY = ''`
- Python on PATH (only to generate the random emails).

## Run it (the whole demo)
From the repo root (`...\Autonomus Agent Version\project\TIS`):

```powershell
.\demo\run_demo.ps1              # 6 fresh random emails
.\demo\run_demo.ps1 -N 8         # more emails
.\demo\run_demo.ps1 -N 6 -Seed 1 # reproducible take
```

(Git-Bash / macOS / Linux: `./demo/run_demo.sh 6` — optional second arg is the seed.)

The launcher does three things automatically:
1. generates a fresh random inbox (`inbox/email_0X.txt` + `labels.json`),
2. warms the free-tier service (absorbs the 30–60s cold start),
3. runs the agent headless (`claude -p ... --allowedTools "Read,Glob,Bash(curl *),Bash(python *)" --verbose`).

You then watch the agent read `SKILL.md`, call the live API once per email, and
print the verdict table + accuracy — all by itself.

## Suggested shot list + on-screen captions
1. **The empty-handed agent.** Show this folder — only `SKILL.md`, `inbox/`,
   `labels.json`, and the small helper scripts.
   > *"The agent gets ONLY my SKILL.md and a folder of emails — no code, no model."*
2. **One command.** Run `.\demo\run_demo.ps1`.
   > *"One command. Everything after this is the agent."*
3. **Fresh random inbox.** The launcher generates new random emails.
   > *"Every email is randomly generated — nothing hand-picked."*
4. **The agent works, unattended.** It reads SKILL.md, warms up, and calls the LIVE
   API per email (visible via `--verbose`).
   > *"It reads my SKILL.md and calls my hosted API on its own — no key, no typing."*
5. **Scoreboard.** Final verdict table + accuracy.
   > *"A stock agent succeeded using only my SKILL.md."*

## Files
- `run_demo.ps1` / `run_demo.sh` — the one-command launcher.
- `SKILL.md` — the hosted skill the agent reads (copy of the deployed one; refresh
  if the Render URL ever changes).
- `make_inbox.py` — generates the random inbox + ground truth (reuses
  `inbox_sim/generator.py`).
- `PROMPT.txt` — the instruction the launcher feeds the agent.
- `grade.py` — optional fallback scoreboard.
- `inbox/`, `labels.json` — generated each run; git-ignored.

## Troubleshooting
- **Do one rehearsal run before filming.** Run `.\demo\run_demo.ps1` in your normal
  terminal (NOT inside a Claude Code session — nesting sandboxes the network) and
  confirm the agent reaches the API and prints the table.
- **A permission prompt appears / agent aborts on a tool:** the launcher already
  allowlists `curl`, `curl.exe`, and `python`. If the agent still picks another
  command and prompts, either approve it once on camera, or (safe here — synthetic
  folder, public read-only API, no secrets) add `--dangerously-skip-permissions` to
  the `claude` call in `run_demo.ps1` for a guaranteed no-prompt take. That flag
  turns off approval gates for the run, so only use it in this throwaway demo folder.
- **Agent invents a verdict instead of calling the API:** `PROMPT.txt` forbids it;
  re-run and confirm each row has a matching `/analyze` call.
- **`--verbose` too noisy on camera:** drop it — the agent still prints its progress
  and final table.
- **Cold-start stall:** the launcher warms `/health` first; if the service was
  asleep, give it a few seconds before it responds.

## Manual fallback (if you'd rather drive it yourself)
Skip the launcher and run any agent by hand:
1. Generate the inbox: `python demo/make_inbox.py 6`.
2. Open the `demo/` folder in Cursor (or `cd demo` + start Claude Code).
3. Paste the contents of `PROMPT.txt` and send. Same result, but you typed the prompt.
