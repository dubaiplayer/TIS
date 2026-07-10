"""
Claude Agent SDK runner for the Inbox Simulator.

An autonomous LLM agent that, per email, invokes the local `phishing-email-analyzer`
SKILL (which runs our CLI/model) and returns a compact decision + rationale. This
provides the *autonomy* (it decides to scan each email and narrates an action); the
authoritative verdict for the scoreboard still comes from our model, computed
directly by the endpoint.

Degrades gracefully: if the SDK isn't installed or ANTHROPIC_API_KEY is unset,
`agent_available()` is False and the endpoint shows model verdicts without agent
narration (clear banner, no silent hang).
"""
import json
import os
import re

# Repo root = parent of server/ ; the .claude/skills live here.
CWD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_PROMPT = """You are an autonomous email-security triage agent. Analyze the email \
below by invoking the `phishing-email-analyzer` skill (run the skill / its CLI — do \
NOT judge phishing yourself; rely on the tool's verdict).

Email:
<<<
{email}
>>>

After running the skill, reply with ONLY a single-line JSON object, no other prose:
{{"verdict":"phishing|suspicious|legitimate","risk_score":<0..1>,"action":"quarantine|flag|allow","rationale":"<one short sentence>"}}"""


def agent_available():
    """True only if the SDK is importable AND an API key is present."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import claude_agent_sdk  # noqa: F401
        return True
    except Exception:
        return False


def _extract_json(text):
    if not text:
        return None
    # last {...} block in the agent's final message
    matches = re.findall(r"\{.*\}", text, re.DOTALL)
    for m in reversed(matches):
        try:
            return json.loads(m)
        except Exception:
            continue
    return None


async def analyze_email_with_agent(raw_email, timeout_s=90):
    """Run the agent on one email. Returns
    {available, verdict, action, rationale, error}."""
    if not agent_available():
        return {"available": False, "error": "agent unavailable "
                "(no ANTHROPIC_API_KEY or claude-agent-sdk not installed)"}
    try:
        from claude_agent_sdk import query, ClaudeAgentOptions
    except Exception as e:
        return {"available": False, "error": f"SDK import failed: {e}"}

    options = ClaudeAgentOptions(
        cwd=CWD,
        setting_sources=["project"],       # load .claude/skills from this repo
        skills="all",                      # enable the phishing-email-analyzer skill
        allowed_tools=["Bash", "Skill"],   # scan via the skill/CLI only
        permission_mode="bypassPermissions",
    )

    final_text = ""
    try:
        async for message in query(prompt=_PROMPT.format(email=raw_email), options=options):
            # ResultMessage carries the final text; be tolerant of SDK message shapes.
            result = getattr(message, "result", None)
            if isinstance(result, str) and result.strip():
                final_text = result
            else:
                for block in getattr(message, "content", []) or []:
                    t = getattr(block, "text", None)
                    if t:
                        final_text = t
    except Exception as e:
        return {"available": True, "error": f"agent run failed: {type(e).__name__}: {e}"}

    parsed = _extract_json(final_text) or {}
    return {
        "available": True,
        "verdict": parsed.get("verdict"),
        "action": parsed.get("action"),
        "rationale": parsed.get("rationale") or (final_text[:160] if final_text else None),
        "error": None if parsed else "could not parse agent output",
    }
