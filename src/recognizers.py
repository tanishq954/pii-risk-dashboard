"""Custom Microsoft Presidio recognizers for Indian PII.

Each recognizer combines three layers, which is how production PII
classifiers keep false positives down:

1. A regular expression that finds candidate strings.
2. Context words (e.g. "aadhaar", "account") that raise confidence, or
   are *required* for weak patterns such as a bare 9-18 digit number.
3. Validation logic, such as the Verhoeff checksum for Aadhaar or the
   holder-type letter for PAN.

Presidio compiles patterns case-insensitively by default, so patterns
that must be upper case use the scoped flag ``(?-i:...)``.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult

# ---------------------------------------------------------------------------
# Verhoeff checksum (used by UIDAI for the 12th digit of every Aadhaar)
# ---------------------------------------------------------------------------
# Multiplication table of the dihedral group D5
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
# Permutation table applied based on digit position
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
# Inverse table used to compute a check digit
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_checksum(number: str) -> int:
    """Return the Verhoeff checksum of a digit string (0 means valid)."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c


def verhoeff_validate(number: str) -> bool:
    """True if the digit string (including its check digit) is Verhoeff-valid."""
    return number.isdigit() and verhoeff_checksum(number) == 0


def verhoeff_generate_check_digit(number: str) -> str:
    """Return the check digit that makes ``number + digit`` Verhoeff-valid."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])


# ---------------------------------------------------------------------------
# Context helper
# ---------------------------------------------------------------------------
def has_context(text: str, start: int, end: int, words: Iterable[str],
                prefix_chars: int = 60, suffix_chars: int = 30) -> bool:
    """True if any context word appears within the character window around a match.

    ``words`` are regular-expression fragments matched on word boundaries,
    case-insensitively (e.g. ``a/c`` or ``acc(?:ount)?``).
    """
    window = text[max(0, start - prefix_chars):start] + " " + text[end:end + suffix_chars]
    return any(re.search(rf"(?<![a-z]){w}(?![a-z])", window, flags=re.IGNORECASE) for w in words)


class ContextRequiredRecognizer(PatternRecognizer):
    """A PatternRecognizer that drops matches with no required context word nearby.

    Used for weak patterns (a long number, a currency amount) that are only
    PII when the surrounding text says what they are.
    """

    def __init__(self, *args, required_context: List[str], prefix_chars: int = 60,
                 suffix_chars: int = 30, **kwargs):
        super().__init__(*args, **kwargs)
        self.required_context = required_context
        self.prefix_chars = prefix_chars
        self.suffix_chars = suffix_chars

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None) -> List[RecognizerResult]:
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)
        return [r for r in results
                if has_context(text, r.start, r.end, self.required_context, self.prefix_chars, self.suffix_chars)]


# ---------------------------------------------------------------------------
# IN_AADHAAR
# ---------------------------------------------------------------------------
AADHAAR_CONTEXT = ["aadhaar", "aadhar", "adhaar", "uid", "uidai", "enrolment", "e-kyc", "ekyc", "kyc"]


class AadhaarRecognizer(PatternRecognizer):
    """12-digit Aadhaar number: first digit 2-9, optional 4-4-4 spacing, Verhoeff-valid.

    A random 12-digit number passes Verhoeff 1 time in 10, so an
    *unformatted* number with no Aadhaar context is kept at a reduced
    score (0.6). That lets a 12-digit bank account next to the word
    "account" win the overlap instead.
    """

    def __init__(self):
        patterns = [
            Pattern("aadhaar_spaced", r"(?<![\d-])[2-9]\d{3}([ -])\d{4}\1\d{4}(?![\d-])", 0.5),
            Pattern("aadhaar_plain", r"(?<!\d)[2-9]\d{11}(?!\d)", 0.3),
        ]
        super().__init__(supported_entity="IN_AADHAAR", name="InAadhaarRecognizer",
                         patterns=patterns, context=AADHAAR_CONTEXT)

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        digits = re.sub(r"\D", "", pattern_text)
        if len(digits) != 12 or len(set(digits)) == 1:
            return False
        return verhoeff_validate(digits)

    def analyze(self, text, entities, nlp_artifacts=None, regex_flags=None):
        results = super().analyze(text, entities, nlp_artifacts, regex_flags)
        for r in results:
            if not text[r.start:r.end].isdigit():
                continue  # 4-4-4 formatting is itself strong evidence of an Aadhaar
            prefix = text[max(0, r.start - 60):r.start].lower()
            aadhaar_pos = _last_position(prefix, AADHAAR_CONTEXT)
            bank_pos = _last_position(prefix, BANK_CONTEXT)
            # "Nearest label wins": no Aadhaar label, or a closer banking label
            # ("... | Account No: 123456789012"), means it is probably not an Aadhaar.
            if aadhaar_pos < 0 or bank_pos > aadhaar_pos:
                r.score = min(r.score, 0.6)
        return results


def _last_position(window: str, words: Iterable[str]) -> int:
    """Index of the last context word found in ``window`` (-1 if none)."""
    best = -1
    for w in words:
        for m in re.finditer(rf"(?<![a-z]){w}(?![a-z])", window):
            best = max(best, m.start())
    return best


# ---------------------------------------------------------------------------
# IN_PAN
# ---------------------------------------------------------------------------
# 4th character of a PAN encodes the holder type:
# P person, C company, H HUF, F firm, A AOP, T trust, B BOI, L local authority,
# J artificial juridical person, G government.
PAN_HOLDER_TYPES = "PCHFATBLJG"


class PanRecognizer(PatternRecognizer):
    """Permanent Account Number: AAAAA9999A with a valid holder-type letter."""

    def __init__(self):
        patterns = [Pattern("pan", rf"\b(?-i:[A-Z]{{3}}[{PAN_HOLDER_TYPES}][A-Z]\d{{4}}[A-Z])\b", 0.7)]
        super().__init__(supported_entity="IN_PAN", name="InPanRecognizer", patterns=patterns,
                         context=["pan", "permanent account number", "income tax", "tax", "itr", "tds", "kyc"])

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        return len(pattern_text) == 10 and pattern_text[3] in PAN_HOLDER_TYPES


# ---------------------------------------------------------------------------
# IN_IFSC
# ---------------------------------------------------------------------------
class IfscRecognizer(PatternRecognizer):
    """Indian Financial System Code: 4 letters (bank), a zero, 6 alphanumerics (branch)."""

    def __init__(self):
        patterns = [Pattern("ifsc", r"\b(?-i:[A-Z]{4}0[A-Z0-9]{6})\b", 0.6)]
        super().__init__(supported_entity="IN_IFSC", name="InIfscRecognizer", patterns=patterns,
                         context=["ifsc", "branch", "bank", "neft", "rtgs", "imps"])


# ---------------------------------------------------------------------------
# IN_PHONE
# ---------------------------------------------------------------------------
class IndianPhoneRecognizer(PatternRecognizer):
    """Indian mobile numbers: optional +91 / 0091 / 0 prefix, 10 digits starting 6-9."""

    def __init__(self):
        patterns = [Pattern(
            "in_mobile",
            r"(?<![\d+])(?:(?:\+|00)91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)",
            0.55,
        )]
        super().__init__(supported_entity="IN_PHONE", name="InPhoneRecognizer", patterns=patterns,
                         context=["phone", "mobile", "mob", "cell", "contact", "call", "whatsapp", "tel", "ph"])


# ---------------------------------------------------------------------------
# IN_UPI
# ---------------------------------------------------------------------------
# Restricting to known UPI handles is what separates "name@okaxis" (a UPI ID)
# from "name@company.com" (an e-mail address).
UPI_HANDLES = [
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "paytm", "upi", "apl",
    "ptyes", "ptsbi", "pthdfc", "ptaxis", "axisbank", "icici", "hdfcbank", "sbi", "kotak",
    "yesbank", "jupiteraxis", "fbl", "waaxis", "wahdfcbank", "waicici", "wasbi", "ikwik",
    "freecharge", "airtel", "jio", "slc", "abfspay", "idfcbank", "pingpay", "axisb", "rbl",
]


class UpiRecognizer(PatternRecognizer):
    """UPI virtual payment address such as ``priya.s@okaxis``."""

    def __init__(self):
        handles = "|".join(UPI_HANDLES)
        patterns = [Pattern(
            "upi",
            rf"(?<![\w.-])[a-z0-9][a-z0-9._-]{{1,63}}@(?:{handles})(?![\w-])(?!\.[a-z])",
            0.7,
        )]
        super().__init__(supported_entity="IN_UPI", name="InUpiRecognizer", patterns=patterns,
                         context=["upi", "vpa", "gpay", "google pay", "phonepe", "paytm", "bhim"])


# ---------------------------------------------------------------------------
# BANK_ACCOUNT
# ---------------------------------------------------------------------------
BANK_CONTEXT = ["account", "acc", "a/c", "acct", "ac no", "bank", "savings", "current a/c", "beneficiary"]


class BankAccountRecognizer(ContextRequiredRecognizer):
    """9-18 digit account numbers, only when banking context words are nearby."""

    def __init__(self):
        patterns = [Pattern("bank_account", r"(?<![\d-])\d{9,18}(?![\d-])", 0.6)]
        super().__init__(supported_entity="BANK_ACCOUNT", name="BankAccountRecognizer",
                         patterns=patterns, context=BANK_CONTEXT,
                         required_context=BANK_CONTEXT, prefix_chars=40, suffix_chars=0)


# ---------------------------------------------------------------------------
# SALARY
# ---------------------------------------------------------------------------
SALARY_CONTEXT = ["salary", "salaries", "ctc", "compensation", "pay", "payslip", "pay slip", "payroll",
                  "bonus", "package", "wage", "wages", "remuneration", "stipend", "gross", "net pay",
                  "earnings", "increment", "appraisal", "basic", "hra", "take-home", "take home"]


class SalaryRecognizer(ContextRequiredRecognizer):
    """Currency amounts (INR/USD, lakh, LPA, CTC) that sit near salary vocabulary."""

    def __init__(self):
        num = r"\d{1,3}(?:[,\d]*\d)?(?:\.\d{1,2})?"
        unit = r"(?:\s*(?:lakhs?|lacs?|crores?|lpa|k)\b)?"
        patterns = [
            # ₹85,000 / Rs. 85,000 / INR 12,00,000 / (INR): 85000 / $120,000 / USD 5000
            Pattern("salary_currency_prefix",
                    rf"(?:₹|(?<![a-z])rs\.?|(?<![a-z])inr|(?<![a-z])usd|\$)\)?\s*[:=\-]?\s*{num}{unit}", 0.55),
            # 12 LPA / 18.5 lakh / 1.2 crore
            Pattern("salary_units", rf"(?<![\d.,]){num}\s*(?:lpa|lakhs?|lacs?|crores?)\b", 0.55),
            # 85,000 INR / 5000 rupees
            Pattern("salary_currency_suffix", rf"(?<![\d.,]){num}\s*(?:inr|rupees|usd)\b", 0.55),
        ]
        super().__init__(supported_entity="SALARY", name="SalaryRecognizer", patterns=patterns,
                         context=SALARY_CONTEXT, required_context=SALARY_CONTEXT,
                         prefix_chars=60, suffix_chars=40)

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        # Reject bare currency symbols or amounts of zero; otherwise keep the
        # pattern score (None) so confidence comes from context, not a checksum.
        digits = re.sub(r"\D", "", pattern_text)
        return None if digits and int(digits) > 0 else False


# ---------------------------------------------------------------------------
# HEALTH_INFO
# ---------------------------------------------------------------------------
HEALTH_TERMS = [
    r"diagnos(?:is|ed|es)", r"prescription", r"prescribed", r"hospitali[sz](?:ed|ation)", r"hospital",
    r"surgery", r"surgical", r"diabet(?:es|ic)", r"hypertension", r"pregnan(?:cy|t)", r"maternity leave",
    r"miscarriage", r"cancer", r"chemotherapy", r"tumou?r", r"asthma", r"dengue", r"typhoid", r"malaria",
    r"tuberculosis", r"hiv", r"covid-19 positive", r"fracture[sd]?", r"clinical depression",
    r"depression", r"anxiety disorder", r"thyroid", r"blood pressure", r"medical certificate",
    r"medical leave", r"physiotherapy", r"cardiac", r"angioplasty", r"dialysis", r"mri scan",
    r"blood test", r"insulin", r"migraine", r"jaundice", r"appendicitis", r"psychiatri(?:st|c)",
]


class HealthInfoRecognizer(PatternRecognizer):
    """Health/medical vocabulary. Health data is special-category data under GDPR Art. 9."""

    def __init__(self):
        terms = "|".join(HEALTH_TERMS)
        patterns = [Pattern("health_terms", rf"\b(?:{terms})\b", 0.55)]
        super().__init__(supported_entity="HEALTH_INFO", name="HealthInfoRecognizer", patterns=patterns,
                         context=["patient", "doctor", "dr", "treatment", "medical", "clinic", "leave",
                                  "diagnosed", "suffering", "recovering", "admitted"])


# ---------------------------------------------------------------------------
# PERSON (name cues) - complements spaCy NER
# ---------------------------------------------------------------------------
# spaCy's English models miss many Indian names ("Faqid Kibe"). Business text
# usually introduces a person with a cue word, so a Capitalised Two-Word
# phrase right after "Dear", "Mr.", "Customer", "Name:" etc. is a strong signal.
# Salutations / role words: a good hint (0.6)
NAME_CUES = [r"dear", r"hi", r"hello", r"mr\.?", r"mrs\.?", r"ms\.?", r"dr\.?", r"shri", r"smt\.?",
             r"customer", r"candidate", r"employee", r"regards,\s*\n", r"sincerely,\s*\n"]
# Explicit field labels ("Employee Name: ...") are near-certain (0.9), so they
# win over spaCy when it mislabels a name such as "Harini Mall" as a LOCATION.
NAME_LABELS = [r"name", r"employee name", r"customer name", r"candidate name", r"beneficiary name",
               r"traveller \d", r"employee", r"patient name"]
NAME_STOPWORDS = {"team", "care", "customer", "support", "accounts", "account", "desk", "sir", "madam", "all",
                  "travel", "operations", "acquisition", "talent", "hr", "manager", "department", "services",
                  "name", "id", "bank", "office", "the", "and", "policy", "notes", "limited", "ltd", "pvt"}


class NameCueRecognizer(PatternRecognizer):
    """Capitalised 2-3 word names that follow a salutation or a name label."""

    def __init__(self):
        cues, labels = "|".join(NAME_CUES), "|".join(NAME_LABELS)
        name = r"(?-i:[A-Z][a-z]+(?:[ ][A-Z][a-z]+){1,2})\b"
        patterns = [
            Pattern("name_after_label", rf"(?<=(?:^|[^a-z])(?:{labels})[ \t]*:[ \t]*){name}", 0.9),
            Pattern("name_after_cue", rf"(?<=(?:^|[^a-z])(?:{cues})[ \t]+){name}", 0.6),
        ]
        super().__init__(supported_entity="PERSON", name="NameCueRecognizer", patterns=patterns)

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        words = pattern_text.lower().split()
        return False if any(w in NAME_STOPWORDS for w in words) else None


def get_custom_recognizers() -> List[PatternRecognizer]:
    """All custom Indian-PII recognizers, ready to add to a Presidio registry."""
    return [
        AadhaarRecognizer(),
        PanRecognizer(),
        IfscRecognizer(),
        IndianPhoneRecognizer(),
        UpiRecognizer(),
        BankAccountRecognizer(),
        SalaryRecognizer(),
        HealthInfoRecognizer(),
        NameCueRecognizer(),
    ]


CUSTOM_ENTITIES = ["IN_AADHAAR", "IN_PAN", "IN_IFSC", "IN_PHONE", "IN_UPI", "BANK_ACCOUNT", "SALARY", "HEALTH_INFO"]
