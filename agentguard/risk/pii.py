"""Personal data detection. Validated with checksums where formats have them, to keep
false positives low: Luhn for card numbers, ISO 7064 mod 97 for IBANs, issuance rules for
US Social Security numbers.
"""

import re

EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}\b"
)
# International (+CC ...) or North American (xxx) xxx-xxxx / xxx-xxx-xxxx forms only.
PHONE = re.compile(
    r"(?<![\w+])(?:\+[1-9]\d{0,2}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{2,4}){2,4}"
    r"|\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\b\d{3}[.-]\d{3}[.-]\d{4})\b"
)
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
CARD_PREFIX = re.compile(
    r"^(?:4|5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720)|3[47]|6(?:011|5)|3(?:0[0-5]|[68])|35)"
)

# Categories that are redacted in audit logs and notifications. Email addresses and phone
# numbers are often the legitimate subject of an action (a recipient), so they are kept.
REDACTED = ("credit_card", "ssn", "iban")


def luhn(digits):
    total = 0
    for index, digit in enumerate(reversed(digits)):
        value = int(digit)
        if index % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def iban_valid(value):
    compact = value.replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    number = "".join(str(int(c, 36)) for c in rearranged)
    return int(number) % 97 == 1


def find_pii(text):
    """[(category, start, end)] for personal data in ``text``."""
    if not text:
        return []
    found = [("email", m.start(), m.end()) for m in EMAIL.finditer(text)]
    found += [("ssn", m.start(), m.end()) for m in SSN.finditer(text)]
    for match in CARD.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and CARD_PREFIX.match(digits) and luhn(digits):
            found.append(("credit_card", match.start(), match.end()))
    found += [("iban", m.start(), m.end()) for m in IBAN.finditer(text) if iban_valid(m.group(0))]
    taken = [(s, e) for _, s, e in found]
    for match in PHONE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        overlaps = any(s < match.end() and match.start() < e for s, e in taken)
        if 10 <= len(digits) <= 15 and not overlaps:
            found.append(("phone", match.start(), match.end()))
    return sorted(found, key=lambda item: item[1])
