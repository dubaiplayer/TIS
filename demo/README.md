# Agent Demo — a real agent using only the hosted SKILL.md

This folder is the **video demo**. It shows a real coding agent (Cursor **or**
Claude Code) reading `SKILL.md` and, from a single instruction, autonomously
analyzing a folder of **random emails** through the live hosted API — then printing
a graded scoreboard. No Anthropic API key needed: the agent uses Cursor's / Claude
Code's own model.

**Why this satisfies the hackathon:** the scored bar is "a stock agent succeeds
using only your SKILL.md." Here the agent is opened in a folder that contains
**only** the `SKILL.md`, the random `inbox/` emails, and `labels.json` — no repo,
no model, no code. It has nothing to fall back on, so every verdict must come from
your live API, driven purely by the instructions in `SKILL.md`.

## Files
- `SKILL.md` — the hosted skill the agent reads (copy of the deployed one; refresh
  if the Render URL ever changes).
- `make_inbox.py` — generates a fresh random inbox (`inbox/email_0X.txt`) + ground
  truth (`labels.json`). Reuses the project's `inbox_sim/generator.py`.
- `PROMPT.txt` — the single instruction you paste into the agent.
- `grade.py` — optional fallback scoreboard (only if you don't want the agent to
  self-grade on camera).
- `inbox/`, `labels.json` — generated each run; git-ignored.

## Setup (once, right before recording)
From the repo root (`...\Autonomus Agent Version\project\TIS`):

```
python demo/make_inbox.py 6            # 6 fresh random emails
# or, for a repeatable take:
python demo/make_inbox.py 6 --seed 1
```

Warm the free-tier service so the first call in the video is fast:
```
curl https://phishing-analyzer-api-wq1v.onrender.com/health
```
(Wait for `{"status":"ok"}` — the first hit after idle can take 30–60s.)

## Record — Option A: Claude Code
1. `cd demo`
2. Start Claude Code in this folder.
3. Paste the contents of `PROMPT.txt` and send.
4. Record: it reads `SKILL.md`, calls `/health`, then `/analyze` once per email
   against the live URL, and prints the verdict table + accuracy.

## Record — Option B: Cursor
1. Open the `demo/` folder in Cursor (File → Open Folder → this folder).
2. Open the agent chat (Composer / Agent mode).
3. Paste the contents of `PROMPT.txt` and send.
4. Record the same flow — the agent's tool calls (terminal `curl` / HTTP) are
   visible as it works through the inbox.

Try both; keep whichever looks cleaner on screen.

## Suggested shot list + on-screen captions
1. **The empty-handed agent.** Show the `demo/` folder contents (just `SKILL.md`,
   `inbox/`, `labels.json`).
   > Caption: *"The agent gets ONLY my SKILL.md and a folder of emails — no code, no model."*
2. **Fresh random inbox.** Run `python demo/make_inbox.py 6` on camera.
   > Caption: *"Every email is randomly generated — nothing hand-picked."*
3. **One instruction.** Paste `PROMPT.txt` into the agent.
   > Caption: *"I give it one instruction. Everything after this is the agent."*
4. **The agent works.** Show it reading SKILL.md, warming up, and calling the LIVE
   API once per email.
   > Caption: *"It reads my SKILL.md and calls my hosted API on its own — fully automatic."*
5. **Scoreboard.** Show the final verdict table + accuracy.
   > Caption: *"A stock agent succeeded using only my SKILL.md."*

## Notes
- If the agent tries to guess verdicts instead of calling the API, the prompt
  forbids it ("do NOT decide phishing yourself") — re-run; verify each row has a
  matching `/analyze` call.
- Keep `n` small (6) for a tight demo; scale up only if it runs smoothly.
- The service must be awake and reachable during recording (see Setup).
