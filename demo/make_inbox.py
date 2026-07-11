"""
Generate a fresh, self-contained demo inbox for the agent video.

Writes N random labeled emails into demo/inbox/email_0X.txt and the ground-truth
demo/labels.json. Re-run for a brand-new random inbox each recording. The agent is
pointed at THIS demo/ folder (SKILL.md + inbox/ + labels.json) with nothing else,
so it must call the hosted API for every verdict — there is no local model here.

Run:  python demo/make_inbox.py 6            (6 emails, random each run)
      python demo/make_inbox.py 6 --seed 1   (reproducible take)
      python demo/make_inbox.py 8 --ratio 0.5
"""
import argparse
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)          # repo root holds inbox_sim/
sys.path.insert(0, ROOT)

from inbox_sim.generator import generate_inbox  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Generate a random demo inbox for the agent.")
    ap.add_argument("n", nargs="?", type=int, default=6, help="number of emails (default 6)")
    ap.add_argument("--seed", type=int, default=None,
                    help="fix the RNG for a reproducible inbox (omit for fresh random)")
    ap.add_argument("--ratio", type=float, default=0.5, help="malicious fraction 0..1 (default 0.5)")
    args = ap.parse_args()

    inbox_dir = os.path.join(HERE, "inbox")
    if os.path.isdir(inbox_dir):
        shutil.rmtree(inbox_dir)      # clear old run so files don't accumulate
    os.makedirs(inbox_dir)

    emails = generate_inbox(args.n, malicious_ratio=args.ratio, seed=args.seed)
    labels = {}
    for it in emails:
        fname = f"email_{it['id']:02d}.txt"
        with open(os.path.join(inbox_dir, fname), "w", encoding="utf-8") as f:
            f.write(it["raw_email"])
        labels[fname] = it["truth_label"]

    with open(os.path.join(HERE, "labels.json"), "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2)

    print(f"Wrote {len(emails)} emails -> {inbox_dir}")
    print(f"Wrote ground truth  -> {os.path.join(HERE, 'labels.json')}")
    print("\nGround truth (the agent gets the verdict from the API; labels only grade it):")
    for fname, label in labels.items():
        print(f"  {fname}: {label}")


if __name__ == "__main__":
    main()
