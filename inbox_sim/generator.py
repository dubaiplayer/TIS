"""
Template-based synthetic email generator for the autonomous Inbox Simulator.

Produces a labeled mix of malicious and benign emails. Each email carries a
ground-truth label (so the UI scoreboard can grade the analyzer). Malicious
templates embed real phishing cues our lexicons/model detect (urgent + verify +
freemail/lookalike sender + shortener links + 419 language); benign templates use
ordinary correspondence and clean sender domains.

NOTE: these are SYNTHETIC demo emails, not real threats — a pipeline demo, not a
real-world benchmark.

Public API:
    generate_inbox(n=8, malicious_ratio=0.5, seed=None) -> list[dict]
      each: {id, raw_email, truth_label ("phishing"|"legitimate"), subtype, from, subject}
"""
import random
from email.utils import parseaddr

FIRST = ["James", "Mary", "David", "Sarah", "Michael", "Linda", "Robert", "Emma",
         "John", "Grace", "Daniel", "Aisha", "Tunde", "Chen", "Olga", "Ben"]
LAST = ["Okafor", "Smith", "Johnson", "Williams", "Adeyemi", "Brown", "Garcia",
        "Muller", "Chen", "Ivanov", "Suleman", "Dosumu", "Parker", "Reyes"]
COMPANIES = ["Northwind Logistics", "Acme Corp", "BluePeak Analytics", "Globex",
             "Meridian Bank", "Contoso Ltd", "Vertex Energy", "Pinecone Media"]
FREEMAIL = ["gmail.com", "yahoo.com", "maktoob.com", "hotmail.com", "outlook.com"]
LOOKALIKE = ["paypa1.com", "micros0ft-secure.com", "account-verify.gmail.com",
             "secure-appleid.net", "amaz0n-support.com", "netflix-billing.info"]
SHORTENERS = ["http://bit.ly/{c}", "http://tinyurl.com/{c}", "http://ow.ly/{c}",
              "http://rb.gy/{c}"]


def _code(rng, n=6):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def _name(rng):
    return f"{rng.choice(FIRST)} {rng.choice(LAST)}"


def _amount(rng):
    return f"${rng.randint(2, 45)},{rng.randint(100,999)},{rng.randint(100,999)}"


# ---- malicious templates: return (from_header, subject, body) ----

def _t_419(rng):
    name = _name(rng)
    frm = f"Barrister {name} <{name.split()[0].lower()}{rng.randint(1,99)}@{rng.choice(FREEMAIL)}>"
    subj = rng.choice(["URGENT BUSINESS ASSISTANCE", "CONFIDENTIAL PROPOSAL",
                       "Compensation / Next of Kin"])
    body = (f"Dear Friend,\n\nI am Barrister {name}, personal attorney to a late client. "
            f"I am contacting you regarding an inheritance of {_amount(rng)} USD. As the "
            f"next of kin, you are entitled to these funds. This is 100% risk free. "
            f"Please urgently send your bank details and account number so the transfer "
            f"of funds can proceed immediately.\n\nRegards,\nBarrister {name}")
    return frm, subj, body


def _t_credential(rng):
    brand = rng.choice(["PayPal", "Microsoft", "Apple", "Amazon", "Netflix"])
    frm = f"{brand} Security <security@{rng.choice(LOOKALIKE)}>"
    subj = rng.choice([f"URGENT: verify your {brand} account",
                       "Unusual sign-in activity detected",
                       "Action required: confirm your identity"])
    evil = rng.choice(LOOKALIKE)
    # HTML body: the link TEXT names the real brand domain, the href points elsewhere
    # (fires link_deception on top of the credential/fear/urgency language).
    body = (f"<html><body>"
            f"<p>Dear Customer,</p>"
            f"<p>We detected unusual activity on your {brand} account. For your security "
            f"it has been temporarily suspended. You must verify your account within 24 "
            f"hours or it will be permanently blocked.</p>"
            f'<p><a href="http://{evil}/login">Sign in to {brand.lower()}.com to confirm '
            f"your identity</a></p>"
            f"<p>{brand} Security Team</p></body></html>")
    return frm, subj, body


def _t_invoice(rng):
    co = rng.choice(COMPANIES)
    frm = f"Accounts Payable <billing@{rng.choice(LOOKALIKE)}>"
    subj = rng.choice(["Overdue Invoice - Immediate Payment Required",
                       f"Final notice: invoice #{rng.randint(1000,9999)}"])
    link = rng.choice(SHORTENERS).format(c=_code(rng))
    body = (f"Dear Customer,\n\nOur records show an overdue balance for {co}. To avoid "
            f"penalty, an immediate wire transfer of {_amount(rng)} is required today. "
            f"Review the invoice and submit payment here: {link}\n\nDo not delay - this "
            f"is your final notice.\n\nAccounts Payable")
    return frm, subj, body


def _t_prize(rng):
    frm = f"Award Notification <claims{rng.randint(1,99)}@{rng.choice(FREEMAIL)}>"
    subj = rng.choice(["Congratulations! You have won", "Final Winner Notification"])
    link = rng.choice(SHORTENERS).format(c=_code(rng))
    body = (f"Dear Winner,\n\nYou won the lottery! Your email was selected and you are "
            f"entitled to a cash prize of {_amount(rng)}. To claim your prize, urgently "
            f"confirm your details here: {link}\n\nThis is a limited time offer.")
    return frm, subj, body


def _t_suspension(rng):
    bank = rng.choice(["Meridian Bank", "First National", "Chase"])
    frm = f"{bank} Alerts <alerts@{rng.choice(LOOKALIKE)}>"
    subj = "Your account has been suspended"
    link = rng.choice(SHORTENERS).format(c=_code(rng))
    body = (f"Dear Customer,\n\nYour {bank} account has been suspended due to suspicious "
            f"activity. To restore access you must verify your account and confirm your "
            f"password immediately: {link}\n\nFailure to act within 24 hours will result "
            f"in permanent closure.\n\n{bank} Security")
    return frm, subj, body


def _t_bec(rng):
    exec_name = _name(rng)
    co = rng.choice(COMPANIES)
    dom = co.lower().split()[0] + ".com"
    frm = (f"{exec_name} (CEO) <{exec_name.split()[0].lower()}."
           f"{exec_name.split()[1].lower()}@{dom}>")
    subj = rng.choice(["Urgent request", "Are you available?", "Quick task", "Confidential"])
    ask = rng.choice([
        f"process an urgent wire transfer of {_amount(rng)} to a new vendor",
        "purchase five $200 gift cards for a client and send me the codes",
        "update the direct deposit details for our next payroll run",
    ])
    body = (f"Hi,\n\nAre you available? I need you to {ask} right away. This is time "
            f"sensitive and must be handled today. Please keep this strictly confidential "
            f"until it is done - I am in back-to-back meetings and can only be reached by "
            f"email.\n\nThanks,\n{exec_name}\nCEO, {co}")
    return frm, subj, body


def _t_html_login(rng):
    brand = rng.choice(["Microsoft 365", "Okta", "Google Workspace", "PayPal"])
    frm = f"{brand} Support <no-reply@{rng.choice(LOOKALIKE)}>"
    subj = rng.choice([f"Action required: re-authenticate your {brand} account",
                       "Your password expires today", "Verify your mailbox to avoid suspension"])
    evil = rng.choice(LOOKALIKE)
    body = (f"<html><body><p>Dear user,</p>"
            f"<p>Your {brand} session has expired. Sign in below to keep your access. "
            f"Failure to verify within 24 hours will suspend your account.</p>"
            f'<form action="http://{evil}/login" method="post">'
            f'Email: <input type="text" name="email"><br>'
            f'Password: <input type="password" name="password"><br>'
            f'<button type="submit">Sign in</button></form>'
            f'<img src="http://{evil}/o.gif" width="1" height="1">'
            f"<p>{brand} Security Team</p></body></html>")
    return frm, subj, body


MALICIOUS = [("nigerian_419", _t_419), ("credential_harvest", _t_credential),
             ("fake_invoice", _t_invoice), ("prize_lottery", _t_prize),
             ("account_suspension", _t_suspension), ("bec_wire_fraud", _t_bec),
             ("html_login_form", _t_html_login)]


# ---- benign templates ----

def _t_work(rng):
    a, b = _name(rng), _name(rng)
    co = rng.choice(COMPANIES)
    dom = co.lower().split()[0] + ".com"
    frm = f"{a} <{a.split()[0].lower()}.{a.split()[1].lower()}@{dom}>"
    subj = rng.choice(["Q3 report draft", "Re: Thursday meeting", "Updated project plan"])
    body = (f"Hi {b.split()[0]},\n\nAttached is the latest draft of the {rng.choice(['Q3','budget','roadmap'])} "
            f"document for your review. Could you take a look before our meeting on "
            f"{rng.choice(['Tuesday','Thursday','Monday'])}? Let me know if the numbers "
            f"look right.\n\nThanks,\n{a.split()[0]}")
    return frm, subj, body


def _t_newsletter(rng):
    co = rng.choice(COMPANIES)
    dom = co.lower().split()[0] + ".com"
    frm = f"{co} News <newsletter@{dom}>"
    subj = f"{co} Monthly - {rng.choice(['product updates','what is new','team highlights'])}"
    body = (f"Hello,\n\nHere is what is new at {co} this month: three product improvements, "
            f"a customer story, and upcoming events. Read more on our blog. You can update "
            f"your preferences or unsubscribe at any time from the link in the footer.\n\n"
            f"The {co} Team")
    return frm, subj, body


def _t_receipt(rng):
    co = rng.choice(COMPANIES)
    dom = co.lower().split()[0] + ".com"
    frm = f"{co} Orders <orders@{dom}>"
    order = rng.randint(100000, 999999)
    subj = f"Your order #{order} has shipped"
    body = (f"Hi {rng.choice(FIRST)},\n\nThanks for your order. Order #{order} has shipped "
            f"and should arrive in {rng.randint(2,6)} business days. You can view tracking "
            f"in your account. Order total: ${rng.randint(20,240)}.{rng.randint(10,99)}.\n\n"
            f"Thanks for shopping with {co}.")
    return frm, subj, body


def _t_calendar(rng):
    a = _name(rng)
    dom = rng.choice(COMPANIES).lower().split()[0] + ".com"
    frm = f"{a} <{a.split()[0].lower()}@{dom}>"
    subj = rng.choice(["Invitation: Design sync", "Meeting: sprint planning"])
    body = (f"Hi team,\n\nYou are invited to {subj.split(': ')[-1]} on "
            f"{rng.choice(['Mon','Wed','Fri'])} at {rng.randint(1,4)}pm. Agenda: review "
            f"progress and next steps. Please accept or propose a new time.\n\n{a.split()[0]}")
    return frm, subj, body


def _t_personal(rng):
    a = _name(rng)
    frm = f"{a} <{a.split()[0].lower()}.{a.split()[1].lower()}@{rng.choice(FREEMAIL)}>"
    subj = rng.choice(["Dinner this weekend?", "Photos from the trip", "Quick question"])
    body = (f"Hey!\n\nHope you are doing well. Are you free this weekend to grab dinner? "
            f"I also wanted to share the photos from last month. Let me know what works "
            f"for you.\n\nCheers,\n{a.split()[0]}")
    return frm, subj, body


BENIGN = [("work_thread", _t_work), ("newsletter", _t_newsletter),
          ("receipt", _t_receipt), ("calendar_invite", _t_calendar),
          ("personal_note", _t_personal)]


def generate_inbox(n=8, malicious_ratio=0.5, seed=None):
    rng = random.Random(seed)
    n_mal = max(0, min(n, round(n * malicious_ratio)))
    n_ben = n - n_mal

    items = []
    def make(pool, label):
        subtype, fn = rng.choice(pool)
        frm, subj, body = fn(rng)
        _, addr = parseaddr(frm)
        hdrs = [f"From: {frm}"]
        if label == "phishing":
            # spoofed: failing auth + replies/bounces redirected to the attacker
            atk = f"recovery{rng.randint(1, 99)}@{rng.choice(LOOKALIKE + FREEMAIL)}"
            hdrs.append(f"Reply-To: <{atk}>")
            hdrs.append(f"Return-Path: <bounce@{rng.choice(LOOKALIKE)}>")
            res = rng.choice(["spf=fail; dkim=fail; dmarc=fail",
                              "spf=softfail; dkim=none; dmarc=fail",
                              "spf=fail; dkim=pass; dmarc=fail"])
            hdrs.append(f"Authentication-Results: mx.google.com; {res}")
        else:
            hdrs.append(f"Return-Path: <{addr}>")
            hdrs.append("Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass")
        hdrs.append(f"Subject: {subj}")
        if body.lstrip().startswith("<"):
            hdrs.append("Content-Type: text/html")
        raw = "\n".join(hdrs) + "\n\n" + body
        return {"raw_email": raw, "truth_label": label, "subtype": subtype,
                "from": frm, "subject": subj}

    items += [make(MALICIOUS, "phishing") for _ in range(n_mal)]
    items += [make(BENIGN, "legitimate") for _ in range(n_ben)]
    rng.shuffle(items)
    for i, it in enumerate(items):
        it["id"] = i + 1
    return items


if __name__ == "__main__":
    for it in generate_inbox(6, 0.5, seed=1):
        print(f"[{it['id']}] {it['truth_label']:<11} {it['subtype']:<18} {it['subject']}")
