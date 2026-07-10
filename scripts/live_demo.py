"""
Live demo for the video: generate RANDOM emails (not hand-picked) and send each
one to the HOSTED service, then show a running accuracy scoreboard vs the known
labels. Nothing is hardcoded — a fresh random inbox every run — and it exercises
the actual deployed API (the Phase 2 submission), not the local model.

Run:  .venv/Scripts/python.exe -m scripts.live_demo
Options (env): N (default 10), URL (default the deployed service).
"""
import json
import os
import time
import urllib.request

from inbox_sim.generator import generate_inbox

URL = os.environ.get("URL", "https://phishing-analyzer-api-wq1v.onrender.com")
N = int(os.environ.get("N", "10"))


def call_analyze(text, timeout=60):
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(URL + "/analyze", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    print(f"Service: {URL}")
    print("Warming up (free tier can take 30-60s on first call)...", flush=True)
    try:
        urllib.request.urlopen(URL + "/health", timeout=90).read()
    except Exception as e:
        print(f"  warm-up note: {e}")

    inbox = generate_inbox(N, malicious_ratio=0.5)  # fresh RANDOM inbox each run
    print(f"\nGenerated {len(inbox)} random emails. Sending each to the LIVE service...\n")
    print(f"{'#':>2}  {'ground truth':<12}{'service verdict':<16}{'risk':>6}  result  subject")
    print("-" * 78)

    correct = 0
    for it in inbox:
        try:
            d = call_analyze(it["raw_email"])
            verdict = d["verdict"]
            risk = d["risk_score"]
        except Exception as e:
            print(f"{it['id']:>2}  ERROR: {e}")
            continue
        predicted = "legitimate" if verdict == "legitimate" else "phishing"
        ok = predicted == it["truth_label"]
        correct += ok
        mark = "OK  " if ok else "MISS"
        print(f"{it['id']:>2}  {it['truth_label']:<12}{verdict:<16}{risk:>6.2f}  {mark}    "
              f"{it['subject'][:38]}")
        time.sleep(0.2)

    print("-" * 78)
    print(f"ACCURACY: {correct}/{len(inbox)} = {correct/len(inbox)*100:.0f}%  "
          f"(random emails, graded against their known labels, via the live API)")


if __name__ == "__main__":
    main()
