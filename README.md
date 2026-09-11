# ALU Regex Data Extraction & Secure Validation

A regex-based program that extracts structured data from raw, messy,
production-style text (like a support-ticket export), validates what
it finds, and defends against hostile or malformed input.

## Project structure

```
alu-regex-data-extraction_yourusername/
├── input/
│   └── raw-text.txt        # Realistic sample input (support ticket log)
├── src/
│   └── main.py              # All extraction / validation / security logic
├── output/
│   └── sample-output.json   # Generated results from the sample input
└── README.md
```

> Rename the top-level folder to `alu-regex-data-extraction_<your-github-username>`
> before submitting.

## How to run

Requires Python 3.8+, no external dependencies.

```bash
python src/main.py
```

This reads `input/raw-text.txt`, prints a masked console summary, and
writes the full results to `output/sample-output.json`.

## Data types extracted

| Type | Notes |
|---|---|
| **Emails** (required) | Includes general validation and separate ALU-specific classification into `alu_official` (`@alueducation.com`), `alu_alumni` (`@alumni.alueducation.com`), and `alu_si` (`@si.alueducation.com`). |
| **Credit card numbers** (required) | Matches Visa/Mastercard/Discover (4-4-4-4) and Amex (4-6-5) shapes, then runs each match through a **Luhn checksum** so a string that merely looks like a card number isn't reported as a real one. |
| Phone numbers | Handles country codes, parentheses, dashes/dots/spaces, and extensions (`ext.`/`x`). |
| URLs | `http(s)://` and bare `www.` forms. |
| Bare domains | Domain mentions with no protocol/`www` prefix (e.g. "visit alueducation.com"). |
| Hashtags | Excludes HTML numeric entities like `&#123;`. |
| Currency amounts | `$`, `€`, `£`, and `USD`/`EUR`/`GBP`/`KES` codes, with thousands separators. |
| HTML tags | Opening/closing/self-closing tags with attributes. |
| Time (12h & 24h) | `9:15 AM`, `14:32`, `17:45:00`, etc. |

That's 9 categories in total (the assignment required a minimum of 4,
including emails and credit cards specifically).

## Why the regex patterns are shaped this way

- **Bounded quantifiers everywhere** (`{0,63}` instead of open-ended `*`
  or `+`) instead of unbounded repetition. This mirrors real protocol
  limits (e.g. RFC 5321 caps an email local-part at 64 characters) and
  also protects against **ReDoS** (catastrophic backtracking) if an
  attacker feeds in a very long adversarial string.
- **ALU domain matching relies on the fact that `@` appears once.**
  `@alueducation\.com$` can never accidentally match
  `user@alumni.alueducation.com`, because the text immediately after
  `@` must be `alueducation.com`, not `alumni.alueducation.com`. This
  keeps the three ALU categories mutually exclusive without needing
  lookbehind tricks.
- **Credit card matching is deliberately two-stage:** a regex finds
  things *shaped* like a card number, and a separate Luhn checksum
  decides if it's *plausible*. The sample input includes one number
  that is the right shape but fails Luhn on purpose, to show the
  validator rejecting it rather than trusting the regex alone.

## Security considerations

The brief for this assignment explicitly says not to treat all input
as trustworthy just because it comes from an external API. This
program takes that seriously in a few concrete ways:

1. **Pre-scan before extraction.** Before any data extraction runs,
   every line of the input is checked against a list of known
   injection signatures — `<script>` tags, SQL keywords
   (`DROP TABLE`, `UNION SELECT`, ...), path traversal (`../../`),
   `${jndi:...}`-style lookups, and prompt-injection phrases like
   "ignore all previous instructions". Any line that matches is
   **flagged and excluded from extraction entirely**, so a malicious
   payload can never be reported as if it were legitimate data, even
   if it happens to contain something regex-shaped.
2. **Sensitive fields are masked, never exposed raw.** Emails and
   credit card numbers are the two categories the assignment calls
   out specifically. Neither is ever printed to the console or written
   to the output file in full — only a masked form (e.g.
   `j*******a@gmail.com`, `************6467`) plus a short one-way
   SHA-256 fingerprint (for de-duplication without storing the raw
   value). A real production system would go further and keep raw
   values only in an encrypted store with strict access control; this
   demo shows the masking pattern that store would sit behind.
3. **Threat log stores short snippets, not full payloads.** When a
   line is flagged, the log keeps only the first ~40 characters of
   that line — enough to identify and audit the issue without the log
   file itself becoming a second copy of the attack string or of
   whatever sensitive data happened to be nearby.
4. **No `eval`, no dynamic code execution, no shell-outs** on any part
   of the input — everything is treated strictly as data for pattern
   matching, never as instructions.

**Known trade-off:** the SQL-comment pattern (`--\s*$`) is intentionally
broad and will also flag an ordinary `---` divider line as a false
positive (visible in `sample-output.json`). This is a deliberate
"fail cautious" choice — for a security check, an occasional false
positive on harmless input is preferable to missing a real SQL
injection attempt.

## Sample output

See `output/sample-output.json` for the full run against
`input/raw-text.txt`, including the security scan results and every
extracted category.
