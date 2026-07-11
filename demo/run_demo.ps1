<#
  run_demo.ps1  -  completely-automatic agent demo (one command, no typing, no key)

  Generates a fresh random inbox, warms the hosted service, then runs the Claude
  Code agent unattended. The agent reads SKILL.md in this folder and calls the live
  hosted API for every email, then prints a graded scoreboard. It authenticates with
  your Claude subscription login (claude login) - no ANTHROPIC_API_KEY needed.

  Usage:
    .\demo\run_demo.ps1                 # 6 fresh random emails
    .\demo\run_demo.ps1 -N 8            # 8 emails
    .\demo\run_demo.ps1 -N 6 -Seed 1   # reproducible take
#>
param(
    [int]$N = 6,
    [int]$Seed = 0
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$svc  = "https://phishing-analyzer-api-wq1v.onrender.com"

# --- 0. Auth sanity: we WANT the subscription login, not a key ---
if ($env:ANTHROPIC_API_KEY) {
    Write-Host "[note] ANTHROPIC_API_KEY is set - the agent will use that key, not your subscription." -ForegroundColor Yellow
    Write-Host '       For the no-key demo, clear it first:  $env:ANTHROPIC_API_KEY = ""' -ForegroundColor Yellow
}
if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
    throw "The 'claude' CLI was not found on PATH. Install Claude Code and run 'claude login' first."
}

# --- 1. Fresh random inbox ---
Write-Host "[1/3] Generating $N random emails..." -ForegroundColor Cyan
if ($Seed -ne 0) {
    python "$here\make_inbox.py" $N --seed $Seed
} else {
    python "$here\make_inbox.py" $N
}

# --- 2. Warm the free-tier service (absorbs the cold start) ---
Write-Host "`n[2/3] Warming the service (first hit after idle can take 30-60s)..." -ForegroundColor Cyan
try { curl.exe -s "$svc/health" | Out-Host } catch { Write-Host "  (warm-up note: $_)" }

# --- 3. Run the agent unattended from THIS folder ---
Write-Host "`n[3/3] Launching the agent (headless)..." -ForegroundColor Cyan
Write-Host "      It reads SKILL.md here and calls the live API on its own.`n" -ForegroundColor DarkGray

Push-Location $here
try {
    $prompt = Get-Content "$here\PROMPT.txt" -Raw
    # The allowlist lets the agent run curl/python unattended (no permission prompts).
    # If it still prompts, approve once - or see README 'Troubleshooting' for a
    # zero-prompt option (safe only in this throwaway synthetic demo folder).
    $claudeArgs = @(
        '-p', $prompt,
        '--allowedTools', 'Read,Glob,Bash(curl *),Bash(curl.exe *),Bash(python *),Bash(python3 *)',
        '--verbose'
    )
    claude @claudeArgs
} finally {
    Pop-Location
}

Write-Host "`nDone." -ForegroundColor Green
