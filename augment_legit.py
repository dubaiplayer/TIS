"""Generate diverse LEGITIMATE transactional / security-advisory emails to augment
the classifier's ham. The training corpus (Enron + phishing sets) is thin on modern
account-statement / receipt / subscription / security-notice mail, so the model
over-associates that vocabulary ("statement, billing, password, credit card, SSN,
log in") with phishing. These examples teach it the same words in LEGITIMATE,
protective/informational contexts. Heavy combinatorial variety so the model learns
the language, not the templates. Deterministic given a seed."""
import random

_COMPANIES = [
    ("Northwind Bank", "northwindbank.com"), ("Acme Utilities", "acmeutilities.com"),
    ("Brightpay", "brightpay.com"), ("Cloudline", "cloudline.io"),
    ("Summit Wireless", "summitwireless.com"), ("Evergreen Insurance", "evergreenins.com"),
    ("Harbor Credit Union", "harborcu.org"), ("Nimbus Storage", "nimbusstorage.com"),
    ("Vertex Energy", "vertexenergy.com"), ("Loom", "atlassian.net"),
    ("Meridian Health", "meridianhealth.com"), ("Parcelly", "parcelly.com"),
    ("Streamly", "streamly.tv"), ("Booknest", "booknest.com"), ("Foodly", "foodly.com"),
    ("Orbit Mobile", "orbitmobile.com"), ("Ledgerly", "ledgerly.com"),
    ("Trailhead Gear", "trailheadgear.com"), ("Quill Software", "quillsoftware.com"),
    ("Coastal Airlines", "coastalair.com"), ("Bloom Grocery", "bloomgrocery.com"),
    ("Fintrust", "fintrust.com"), ("Pixelworks", "pixelworks.app"),
]
_NAMES = ["Alex", "Sam", "Jordan", "Taylor", "Morgan", "Priya", "Wei", "Diego",
          "Fatima", "Liam", "Noah", "Emma", "Olivia", "Devesh", "Chen", "Aisha",
          "Marcus", "Sofia", "Hiro", "Lena", "Omar", "Grace", "Ravi", "Nadia"]
_MONTHS = ["January", "February", "March", "April", "May", "June", "July",
           "August", "September", "October", "November", "December"]

# Protective / anti-phishing reassurance lines - the hallmark of legit security &
# account mail, and almost never present in phishing (which wants your credentials).
_PROTECT = [
    "As a reminder, we will never ask you to reply to this email with your password, credit card number, or full Social Security number.",
    "For your security, {co} will never request your password or one-time code by email.",
    "We will never call or email to ask for your full card number, PIN, or online banking password.",
    "Always log in directly through our official app or website rather than following links in an email.",
    "{co} will never ask you to move money to keep it safe.",
    "Never share your one-time passcode with anyone, including someone claiming to be from {co}.",
]
_HELP = [
    "If you have any questions, our support team is happy to help.",
    "If you did not request this, please contact us through the help center in your account.",
    "Need a hand? Visit the Help section after signing in to your account.",
    "You can manage your preferences anytime from your account settings.",
]
_SIGNOFF = ["Thank you,", "Sincerely,", "Best regards,", "Warm regards,", "Kind regards,"]
_DEPT = ["Customer Operations", "Account Services", "the {co} Team", "Billing Support",
         "Member Services", "the Security Team", "Customer Care"]


def _amt(rng):
    return f"${rng.randint(4, 480)}.{rng.randint(0, 99):02d}"


def _date(rng):
    return f"{rng.choice(_MONTHS)} {rng.randint(1, 28)}, 2026"


def _statement(rng, co, name):
    subj = rng.choice([
        f"Your monthly statement from {co} is now available",
        f"Your {co} account statement is ready to view",
        "Your monthly digital statement is now available",
        f"{co}: your billing statement for this cycle is ready",
    ])
    lines = [f"Hello {name},",
             rng.choice([
                 f"Your monthly account statement for the billing cycle ending {_date(rng)} is now ready to view online.",
                 f"Your latest statement from {co} is available. The balance for this period is {_amt(rng)}.",
                 f"A new statement has been posted to your account for the period ending {_date(rng)}."]),
             rng.choice([
                 "To review your statement, please log in to your dashboard through our official app or visit our website directly.",
                 "You can view the full details after signing in to your account.",
                 "Sign in to your account to download a PDF copy for your records."])]
    return subj, lines


def _receipt(rng, co, name):
    subj = rng.choice([f"Your receipt from {co}", f"Payment received - thank you",
                       f"Your {co} payment confirmation", "Receipt for your recent payment"])
    lines = [f"Hi {name},",
             rng.choice([
                 f"Thanks for your payment of {_amt(rng)} to {co}. This message confirms your transaction was successful.",
                 f"We have received your payment of {_amt(rng)}. Your account is now up to date.",
                 f"Your payment of {_amt(rng)} was processed on {_date(rng)}. No further action is needed."]),
             rng.choice(["A copy of your receipt is available in your account.",
                         "You can view or print this receipt anytime from your billing history."])]
    return subj, lines


def _order(rng, co, name):
    oid = f"{rng.randint(10000, 99999)}"
    subj = rng.choice([f"Your {co} order #{oid} is confirmed",
                       f"Order confirmation - #{oid}", f"We've received your order (#{oid})",
                       f"Your order has shipped - #{oid}"])
    lines = [f"Hello {name},",
             rng.choice([
                 f"Thanks for your order! Order #{oid} totaling {_amt(rng)} has been confirmed and is being prepared.",
                 f"Good news - your order #{oid} has shipped and is on its way. Estimated delivery is {_date(rng)}.",
                 f"Your order #{oid} is confirmed. We'll email you again when it ships."]),
             rng.choice(["You can track the status from the Orders page in your account.",
                         "View your order details anytime by signing in to your account."])]
    return subj, lines


def _subscription(rng, co, name):
    subj = rng.choice([f"Your {co} trial has started", f"Welcome to {co}",
                       f"Your {co} subscription is active", f"Your {co} plan renews soon"])
    lines = [f"Hi {name},",
             rng.choice([
                 f"You're now on a free 14-day trial of {co}. Your trial ends on {_date(rng)}.",
                 f"Your {co} subscription is active. Your plan renews automatically on {_date(rng)} for {_amt(rng)}.",
                 f"Thanks for subscribing to {co}. To avoid interruption, add your payment details before {_date(rng)}."]),
             rng.choice(["You can view or change your plan from your billing settings.",
                         "Manage your subscription anytime from the account dashboard."])]
    return subj, lines


def _security(rng, co, name):
    subj = rng.choice([f"Security tips for your {co} account", "Keeping your account secure",
                       f"An important security reminder from {co}", "Protect your account"])
    lines = [f"Dear {name},",
             rng.choice([
                 f"We're committed to keeping your {co} account safe. Here are a few reminders to protect your information.",
                 "Your account security matters to us. Please review these reminders to stay protected online."]),
             rng.choice(_PROTECT).format(co=co),
             "If you ever receive a message asking for this information, do not respond and report it to us."]
    return subj, lines


def _signin(rng, co, name):
    dev = rng.choice(["a new device", "a Windows computer", "an iPhone", "a new browser",
                      "an Android phone", "a Mac"])
    subj = rng.choice([f"New sign-in to your {co} account", "We noticed a new sign-in",
                       f"Your {co} account was accessed from {dev}"])
    lines = [f"Hi {name},",
             f"Your {co} account was just signed in to from {dev} on {_date(rng)}.",
             rng.choice([
                 "If this was you, no action is needed and you can ignore this message.",
                 "If this was you, you're all set. If not, please review your recent activity after signing in."]),
             rng.choice(_PROTECT).format(co=co)]
    return subj, lines


def _password_changed(rng, co, name):
    subj = rng.choice([f"Your {co} password was changed", "Your password has been updated",
                       "Confirmation: your password was reset"])
    lines = [f"Hello {name},",
             f"This is a confirmation that the password for your {co} account was changed on {_date(rng)}.",
             rng.choice([
                 "If you made this change, no further action is required.",
                 "If you did not make this change, please secure your account and contact support."]),
             rng.choice(_PROTECT).format(co=co)]
    return subj, lines


def _invoice(rng, co, name):
    inv = f"INV-{rng.randint(1000, 9999)}"
    subj = rng.choice([f"Invoice {inv} from {co}", f"Your {co} invoice is ready",
                       f"New invoice available: {inv}"])
    lines = [f"Hi {name},",
             f"Invoice {inv} for {_amt(rng)} is now available and is due on {_date(rng)}.",
             rng.choice(["You can view and pay it from the billing section of your account.",
                         "Sign in to your account to review the line items and payment options."])]
    return subj, lines


def _reminder(rng, co, name):
    subj = rng.choice([f"Reminder: your appointment with {co}", "Upcoming appointment reminder",
                       f"Your {co} renewal is coming up", "A quick reminder"])
    lines = [f"Hello {name},",
             rng.choice([
                 f"This is a friendly reminder of your upcoming appointment on {_date(rng)}.",
                 f"Your {co} membership renews on {_date(rng)}. No action is needed if you'd like to continue."]),
             rng.choice(_HELP).format(co=co)]
    return subj, lines


def _newsletter(rng, co, name):
    subj = rng.choice([f"What's new at {co} this month", f"{co} product updates",
                       f"Your {co} monthly digest", f"News from {co}"])
    lines = [f"Hi {name},",
             f"Here's a look at what's new at {co} this month, plus a few tips to get the most out of your account.",
             "We've shipped several improvements based on your feedback - thank you for being a member.",
             "You can unsubscribe from these updates at any time from your email preferences."]
    return subj, lines


_BUILDERS = [_statement, _statement, _receipt, _order, _subscription, _subscription,
             _security, _security, _signin, _password_changed, _invoice, _reminder,
             _newsletter]


def generate(n, seed):
    """Return a list of {'subject', 'body'} legitimate transactional/security emails."""
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        co, _dom = rng.choice(_COMPANIES)
        name = rng.choice(_NAMES)
        subj, lines = rng.choice(_BUILDERS)(rng, co, name)
        # optional protective + help footer for extra variety and coverage
        if rng.random() < 0.5:
            lines.append(rng.choice(_PROTECT).format(co=co))
        if rng.random() < 0.6:
            lines.append(rng.choice(_HELP).format(co=co))
        dept = rng.choice(_DEPT).format(co=co)
        lines.append(rng.choice(_SIGNOFF))
        lines.append(f"{dept} Department" if "Team" not in dept else dept)
        out.append({"subject": subj, "body": "\n".join(lines)})
    return out


if __name__ == "__main__":
    for e in generate(3, 42):
        print("SUBJECT:", e["subject"]); print(e["body"]); print("-" * 60)
