"""Business Email Compromise (BEC) / wire-fraud detector.

The highest-dollar phishing has no links and no malware: someone posing as an
executive pressures an employee to move money - a wire transfer, gift cards, a
payroll/bank-detail change. Keyword and URL detectors miss it because there's
nothing overtly "phishy" in it. This composite fires on the classic BEC pattern:
a money-movement request combined with pressure/authority/secrecy, and especially
a Reply-To that quietly redirects replies away from the real sender.

To keep false positives low it requires a money-movement cue AND at least one
other BEC factor (a bare invoice mention alone does not fire); gift-card asks are
treated as BEC on their own (they are essentially always a scam).
"""
from email.utils import parseaddr

from .base import band, AttributeResult, build_matcher, find_spans

NAME = "bec"

_PAYMENT = ["wire transfer", "bank transfer", "direct deposit", "routing number",
            "bank details", "account details", "swift code", "western union",
            "moneygram", "outstanding invoice", "make a payment", "process the payment",
            "process this payment", "pay the invoice", "update my banking",
            "change my direct deposit", "banking information"]
_GIFTCARD = ["gift card", "gift cards", "itunes card", "google play card", "steam card",
             "apple card", "amazon card", "prepaid card"]
_AUTHORITY = ["ceo", "cfo", "coo", "chief executive", "chief financial", "director",
              "president", "vice president", "on behalf of", "the board", "chairman",
              "managing director", "head of finance", "your manager"]
_URGENCY = ["urgent", "urgently", "immediately", "asap", "as soon as possible",
            "right away", "before end of day", "by eod", "time sensitive",
            "time-sensitive", "within the hour", "at your earliest"]
_REQUEST = ["are you available", "i need you to", "i need a favor", "quick favor",
            "can you handle", "please handle", "kindly process", "i need your help",
            "are you at your desk", "let me know when you get this"]
_SECRECY = ["confidential", "keep this between us", "do not discuss", "don't tell",
            "keep it discreet", "handle it quietly", "keep this quiet"]

_M_PAY = build_matcher(_PAYMENT)
_M_GIFT = build_matcher(_GIFTCARD)
_M_AUTH = build_matcher(_AUTHORITY)
_M_URG = build_matcher(_URGENCY)
_M_REQ = build_matcher(_REQUEST)
_M_SEC = build_matcher(_SECRECY)


def _domain(v):
    if not v:
        return ""
    _, addr = parseaddr(v)
    d = addr.split("@")[-1].lower().strip(">").strip() if "@" in addr else ""
    return d[4:] if d.startswith("www.") else d


def score(text, *, sender=None, context=None, **_):
    headers = (context or {}).get("headers") or {}
    from_dom = _domain(headers.get("from") or sender)
    reply_dom = _domain(headers.get("reply_to"))
    reply_mismatch = bool(from_dom and reply_dom and from_dom != reply_dom)

    pay_sp, pay = find_spans(text, _M_PAY)
    gift_sp, gift = find_spans(text, _M_GIFT)
    auth_sp, auth = find_spans(text, _M_AUTH)
    urg_sp, urg = find_spans(text, _M_URG)
    req_sp, req = find_spans(text, _M_REQ)
    sec_sp, sec = find_spans(text, _M_SEC)

    factors = []
    if auth:
        factors.append("authority/executive framing")
    if urg:
        factors.append("urgency/pressure")
    if req:
        factors.append("action-request framing")
    if sec:
        factors.append("secrecy request")
    if reply_mismatch:
        factors.append(f"Reply-To redirects to '{reply_dom}'")

    # BEC requires money movement AND at least one pressure factor; gift-card asks
    # are treated as BEC on their own.
    if gift:
        hits = 1.4 + 0.6 * len(factors)
        money = "gift-card purchase request"
    elif pay and factors:
        hits = 1.0 + 0.6 * len(factors)
        money = "money-movement request"
    else:
        return AttributeResult(NAME, 0.0, "none bec",
                               "no business-email-compromise pattern", [])

    if reply_mismatch:
        hits += 0.4  # the single strongest structural BEC tell
    sc = 1.0 - 0.5 ** hits
    spans = [s.__dict__ for s in (pay_sp + gift_sp + auth_sp + urg_sp + req_sp + sec_sp)[:8]]
    expl = f"BEC pattern - {money}" + (": " + "; ".join(factors) if factors else "")
    return AttributeResult(NAME, round(sc, 4), f"{band(sc)} bec", expl, spans)
