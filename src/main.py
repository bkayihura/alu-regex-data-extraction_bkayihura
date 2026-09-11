#!/usr/bin/env python3
# ALU Regex Data Extraction & Secure Validation assignment
# Pulls emails, credit cards, phone numbers, URLs, hashtags, currency
# amounts, HTML tags and times out of a messy block of text using regex,
# checks that what it finds is actually valid, and tries not to trust
# anything that looks like an attack.
#
# Run with: python src/main.py
# Reads from input/raw-text.txt, writes to output/sample-output.json

import re
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_PATH = os.path.join(BASE_DIR, "input", "raw-text.txt")
OUTPUT_PATH = os.path.join(BASE_DIR, "output", "sample-output.json")

# --- security stuff -----------------------------------------------------
# The text we get isn't guaranteed to be safe just because it came from
# an API. Before we extract anything we scan every line for common
# injection signatures (script tags, SQL keywords, path traversal, that
# kind of thing). If a line matches one of these it gets skipped
# entirely during extraction, so nothing "hostile" can sneak through
# just because it happens to also look like an email or a phone number.
INJECTION_PATTERNS = [
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    re.compile(r"\binsert\s+into\b", re.IGNORECASE),
    re.compile(r"--\s*$"),
    re.compile(r"\.\./\.\./"),
    re.compile(r"\$\{jndi:", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
]


def scan_for_threats(raw_text):
    # returns a list of warnings: which line, which pattern matched, and
    # a short snippet (not the whole line -- no reason to keep a full
    # copy of an attack string sitting around in the output)
    warnings = []
    for line_no, line in enumerate(raw_text.splitlines(), start=1):
        for pattern in INJECTION_PATTERNS:
            if pattern.search(line):
                snippet = line.strip()[:40]
                if len(line.strip()) > 40:
                    snippet += "..."
                warnings.append({
                    "line": line_no,
                    "pattern": pattern.pattern,
                    "snippet": snippet,
                })
    return warnings


def is_line_flagged(line_no, warnings):
    for w in warnings:
        if w["line"] == line_no:
            return True
    return False


# --- the actual regex patterns ------------------------------------------
# Quantifiers are capped (e.g. {0,62} instead of just +) instead of left
# open-ended. Partly this matches real limits (an email local-part can't
# really be longer than 64 chars per the RFC) and partly it just avoids
# the regex engine going nuts on a huge adversarial input.

PATTERNS = {
    "email": re.compile(
        r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?"
        r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){1,5}\b"
    ),

    # Visa/MC/Discover are 4-4-4-4, Amex is 4-6-5. Separators can be a
    # space, a dash, or nothing at all.
    "credit_card": re.compile(
        r"\b(?:\d{4}[ -]?\d{6}[ -]?\d{5}"
        r"|\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4})\b"
    ),

    "phone": re.compile(
        r"(?<!\d)(?:\+?\d{1,3}[-.\s]?)?"
        r"(?:\(\d{2,4}\)|\d{2,4})[-.\s]\d{3,4}[-.\s]?\d{3,4}"
        r"(?:\s?(?:ext\.?|x)\s?\d{1,5})?(?!\d)"
    ),

    "url": re.compile(
        r"\bhttps?://[^\s<>\"')]{1,500}"
        r"|\bwww\.[^\s<>\"')]{1,500}"
    ),

    # domain mentioned without http:// or www. in front, e.g. "visit
    # alueducation.com for more info"
    "bare_domain": re.compile(
        r"\b(?<![@/.\w])[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"\.(?:com|org|net|edu|co\.uk|co)\b"
    ),

    "hashtag": re.compile(r"(?<!&)#[A-Za-z][A-Za-z0-9_]{1,49}\b"),

    "currency": re.compile(
        r"(?:\$|€|£|KES|USD|EUR|GBP)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?"
    ),

    "html_tag": re.compile(
        r"</?[a-zA-Z][a-zA-Z0-9]{0,20}"
        r"(?:\s+[a-zA-Z-]{1,30}(?:=(?:\"[^\"]{0,200}\"|'[^']{0,200}'|[^\s>]{1,100}))?){0,10}"
        r"\s*/?>"
    ),

    "time_12h": re.compile(r"\b(?:0?[1-9]|1[0-2]):[0-5]\d\s?[APap][Mm]\b"),
    "time_24h": re.compile(r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\b"),
}

# ALU-specific email checks. Since "@" only shows up once in an email,
# the domain has to come immediately after it -- so a subdomain address
# like someone@alumni.alueducation.com can never accidentally match the
# plain @alueducation.com pattern below. No need for lookbehind tricks.
ALU_PATTERNS = {
    "alu_official": re.compile(r"^[A-Za-z0-9._%+-]+@alueducation\.com$", re.IGNORECASE),
    "alu_alumni": re.compile(r"^[A-Za-z0-9._%+-]+@alumni\.alueducation\.com$", re.IGNORECASE),
    "alu_si": re.compile(r"^[A-Za-z0-9._%+-]+@si\.alueducation\.com$", re.IGNORECASE),
}


def luhn_is_valid(card_number):
    # standard Luhn check -- this catches things that are shaped like a
    # card number but aren't actually a valid one
    digits = [int(d) for d in re.sub(r"[ -]", "", card_number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def classify_email(email):
    for label, pattern in ALU_PATTERNS.items():
        if pattern.match(email):
            return label
    return "general"


# emails and card numbers are the two things the brief specifically
# calls sensitive, so we don't print or save them in full anywhere --
# just a masked version like j***a@gmail.com or ****6467
def mask_email(email):
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return masked_local + "@" + domain


def mask_card(number):
    digits = re.sub(r"[ -]", "", number)
    return "*" * (len(digits) - 4) + digits[-4:]


def extract_all(raw_text, threats):

    def line_of(match_start):
        return raw_text.count("\n", 0, match_start) + 1

    def safe_matches(pattern):
        # only yield matches that weren't on a line we flagged as hostile
        for m in pattern.finditer(raw_text):
            if not is_line_flagged(line_of(m.start()), threats):
                yield m.group().strip()

    results = {}

    seen_emails = set()
    email_list = []
    for email in safe_matches(PATTERNS["email"]):
        key = email.lower()
        if key in seen_emails:
            continue
        seen_emails.add(key)
        email_list.append({
            "masked": mask_email(email),
            "alu_category": classify_email(email),
        })
    results["emails"] = email_list

    seen_cards = set()
    card_list = []
    for raw_card in safe_matches(PATTERNS["credit_card"]):
        digits = re.sub(r"[ -]", "", raw_card)
        if digits in seen_cards:
            continue
        seen_cards.add(digits)
        card_list.append({
            "masked": mask_card(raw_card),
            "luhn_valid": luhn_is_valid(raw_card),
        })
    results["credit_cards"] = card_list

    # the rest isn't sensitive so it's fine to keep in full
    results["phone_numbers"] = sorted(set(safe_matches(PATTERNS["phone"])))
    results["urls"] = sorted(set(safe_matches(PATTERNS["url"])))
    results["bare_domains"] = sorted(set(safe_matches(PATTERNS["bare_domain"])))
    results["hashtags"] = sorted(set(safe_matches(PATTERNS["hashtag"])))
    results["currency_amounts"] = sorted(set(safe_matches(PATTERNS["currency"])))
    results["html_tags"] = sorted(set(safe_matches(PATTERNS["html_tag"])))
    results["times"] = sorted(set(
        list(safe_matches(PATTERNS["time_12h"])) + list(safe_matches(PATTERNS["time_24h"]))
    ))

    return results


def main():
    if not os.path.isfile(INPUT_PATH):
        print("Input file not found: " + INPUT_PATH, file=sys.stderr)
        sys.exit(1)

    with open(INPUT_PATH, "r", encoding="utf-8", errors="replace") as f:
        raw_text = f.read()

    # scan first, extract second -- don't trust the input before checking it
    threats = scan_for_threats(raw_text)
    results = extract_all(raw_text, threats)

    output = {
        "security": {
            "threats_detected": len(threats),
            "flagged_lines": [w["line"] for w in threats],
            "details": threats,
        },
        "extracted": results,
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("=== Extraction Summary ===")
    print(f"Security warnings raised : {len(threats)} (see output JSON for details)")
    print(f"Emails found              : {len(results['emails'])}")
    for e in results["emails"]:
        print(f"   - {e['masked']}  [{e['alu_category']}]")
    print(f"Credit cards found        : {len(results['credit_cards'])}")
    for c in results["credit_cards"]:
        status = "VALID (Luhn)" if c["luhn_valid"] else "INVALID (Luhn check failed)"
        print(f"   - {c['masked']}  [{status}]")
    print(f"Phone numbers found       : {len(results['phone_numbers'])}")
    print(f"URLs found                : {len(results['urls'])}")
    print(f"Bare domains found        : {len(results['bare_domains'])}")
    print(f"Hashtags found            : {len(results['hashtags'])}")
    print(f"Currency amounts found    : {len(results['currency_amounts'])}")
    print(f"HTML tags found           : {len(results['html_tags'])}")
    print(f"Time values found         : {len(results['times'])}")
    print(f"\nFull results written to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
