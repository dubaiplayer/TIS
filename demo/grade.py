"""
Fallback scoreboard (optional).

Use this only if the agent's on-screen self-grading looks messy and you'd rather
grade separately. Provide the agent's verdicts as demo/verdicts.json:

    { "email_01.txt": "phishing", "email_02.txt": "legitimate", ... }

Then:  python demo/grade.py

It compares those verdicts against demo/labels.json and prints accuracy. This does
NOT call the API or analyze anything — it only tallies verdicts the agent produced.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def _norm(v):
    # ground truth is phishing/legitimate; collapse suspicious -> phishing side.
    return "legitimate" if str(v).lower() == "legitimate" else "phishing"


def main():
    with open(os.path.join(HERE, "labels.json"), encoding="utf-8") as f:
        labels = json.load(f)
    vpath = os.path.join(HERE, "verdicts.json")
    if not os.path.exists(vpath):
        raise SystemExit("No verdicts.json found. Paste the agent's verdicts into "
                         "demo/verdicts.json as {filename: verdict}, then rerun.")
    with open(vpath, encoding="utf-8") as f:
        verdicts = json.load(f)

    print(f"{'file':<16}{'agent':<13}{'truth':<13}{'ok'}")
    print("-" * 46)
    correct = 0
    for fname, truth in sorted(labels.items()):
        got = verdicts.get(fname, "?")
        ok = _norm(got) == _norm(truth)
        correct += ok
        print(f"{fname:<16}{str(got):<13}{truth:<13}{'YES' if ok else 'no'}")
    print("-" * 46)
    print(f"ACCURACY: {correct}/{len(labels)} = {correct/len(labels)*100:.0f}%")


if __name__ == "__main__":
    main()
