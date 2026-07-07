"""
Step 3 smoke test: run the full pipeline (rules + trained classifier) on a few
crafted emails and print the structured breakdown. Not the final CLI (that's
Step 5) — just a sanity check that everything wires together.

Run:  .venv/Scripts/python.exe -m scripts.smoke_demo
"""
import json

from phishing_analyzer import pipeline

SAMPLES = [
    ("Nigerian-419 phish", "James Ngola <james_ngola2002@maktoob.com>",
     "URGENT BUSINESS ASSISTANCE\n\nDear Friend, I am Dr. James Ngola. I need your "
     "urgent help to transfer of funds of USD $25,000,000. You will be the beneficiary "
     "as next of kin. Please send your bank account number and account details "
     "immediately. This is 100% risk free."),
    ("Credential-harvest phish", "PayPal Security <service@account-verify.gmail.com>",
     "Dear Customer,\n\nURGENT!!! Your account was suspended due to unusual activity. "
     "You must verify your account within 24 hours or it will be permanently blocked. "
     "Click here to sign in: http://bit.ly/pp-verify"),
    ("Legit corporate", "Dave Allen <dave.allen@enron.com>",
     "Hi John,\n\nAttached is the quarterly gas nomination report for your review. "
     "Let me know if the volumes look right before Thursday's meeting. Thanks, Dave"),
]


def main():
    for title, sender, body in SAMPLES:
        text = body if body.lower().startswith(("subject",)) else body
        res = pipeline.analyze(text, sender=sender)
        o = res["overall"]
        print("=" * 78)
        print(f"{title}   |  sender: {sender}")
        print(f"  VERDICT: {o['verdict'].upper()}   risk={o['risk_score']}   "
              f"classifier_prob={o['classifier_prob']}")
        print(f"  top signals: {o['top_signals']}")
        fired = [(a['name'], a['score'], a['explanation']) for a in res["attributes"]
                 if a['score'] > 0]
        for name, sc, expl in sorted(fired, key=lambda x: -x[1]):
            print(f"    - {name:<16} {sc:>5}  {expl[:80]}")
        if res["meta"]["notes"]:
            print(f"  notes: {res['meta']['notes']}")
    print("=" * 78)


if __name__ == "__main__":
    main()
