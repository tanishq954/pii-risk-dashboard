"""File-level risk scoring.

Score = sum(weight x confidence) over every scored finding
        + volume bonus (many sensitive records in one file)
        capped at 100.

Then:
* **Toxic combination** - a person or identifier together with health,
  salary or financial data is raised to at least the High threshold,
  because that combination is what makes a breach harmful to an individual.
* Levels: High >= 40, Medium >= 15, Low > 0, Clean = no scored findings.
  (DATE_TIME and LOCATION are stored but not scored - too noisy.)

All weights and thresholds come from config.yaml.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional

from . import load_config

# Plain-English names used in the "reason" text, as (singular, plural).
FRIENDLY_NAMES = {
    "IN_AADHAAR": ("Aadhaar number", "Aadhaar numbers"),
    "IN_PAN": ("PAN", "PANs"),
    "IN_IFSC": ("IFSC code", "IFSC codes"),
    "IN_PHONE": ("Indian mobile number", "Indian mobile numbers"),
    "IN_UPI": ("UPI ID", "UPI IDs"),
    "BANK_ACCOUNT": ("bank account number", "bank account numbers"),
    "SALARY": ("salary amount", "salary amounts"),
    "HEALTH_INFO": ("health reference", "health references"),
    "PERSON": ("person name", "person names"),
    "EMAIL_ADDRESS": ("email address", "email addresses"),
    "PHONE_NUMBER": ("phone number", "phone numbers"),
    "CREDIT_CARD": ("credit card number", "credit card numbers"),
    "US_SSN": ("US SSN", "US SSNs"),
    "IBAN_CODE": ("IBAN", "IBANs"),
    "IP_ADDRESS": ("IP address", "IP addresses"),
    "LOCATION": ("location", "locations"),
    "DATE_TIME": ("date", "dates"),
}

RISK_LEVELS = ["High", "Medium", "Low", "Clean"]
RISK_COLORS = {"High": "#d03b3b", "Medium": "#fab219", "Low": "#0ca30c", "Clean": "#9aa0a6"}


def friendly(entity_type: str, n: int = 1) -> str:
    single, plural = FRIENDLY_NAMES.get(entity_type, (entity_type, entity_type))
    return single if n == 1 else plural


def volume_bonus(sensitive_records: int, tiers: List[List[int]]) -> int:
    """Largest bonus whose record threshold is met (tiers are [min_records, points])."""
    bonus = 0
    for min_records, points in sorted(tiers):
        if sensitive_records >= min_records:
            bonus = points
    return bonus


def score_document(findings: List[Dict[str, Any]], cfg: Optional[dict] = None) -> Dict[str, Any]:
    """Score one document's findings.

    Returns ``risk_score`` (0-100), ``risk_level``, ``reason`` and
    ``toxic`` (whether the toxic-combination rule fired).
    """
    rcfg = (cfg or load_config())["risk"]
    weights: Dict[str, float] = rcfg["weights"]
    excluded = set(rcfg["excluded_from_scoring"])
    high, medium = rcfg["thresholds"]["high"], rcfg["thresholds"]["medium"]
    cap = rcfg["max_score"]

    scored = [f for f in findings if f["entity_type"] not in excluded]
    if not scored:
        return {"risk_score": 0.0, "risk_level": "Clean", "reason": "No personal data detected", "toxic": False}

    base = sum(weights.get(f["entity_type"], 1) * f["confidence"] for f in scored)
    vb = rcfg["volume_bonus"]
    sensitive_records = sum(1 for f in scored if weights.get(f["entity_type"], 0) >= vb["sensitive_weight_min"])
    bonus = volume_bonus(sensitive_records, vb["tiers"])
    score = min(cap, base + bonus)

    types = {f["entity_type"] for f in scored}
    tc = rcfg["toxic_combination"]
    identity = types & set(tc["identity_entities"])
    sensitive = types & set(tc["sensitive_entities"])
    toxic = bool(identity and sensitive)
    if toxic:
        score = max(score, high)

    level = "High" if score >= high else "Medium" if score >= medium else "Low"
    return {"risk_score": round(score, 1), "risk_level": level,
            "reason": build_reason(scored, weights, identity, sensitive, toxic, sensitive_records, bonus),
            "toxic": toxic}


def build_reason(scored, weights, identity, sensitive, toxic, sensitive_records, bonus) -> str:
    """Short human-readable explanation, e.g.
    '3 Aadhaar numbers + 2 salary amounts; salary details linked to a named person'."""
    counts = Counter(f["entity_type"] for f in scored)
    # Most sensitive types first, at most four in the sentence
    ordered = sorted(counts.items(), key=lambda kv: (weights.get(kv[0], 0), kv[1]), reverse=True)
    parts = [f"{n} {friendly(t, n)}" for t, n in ordered[:4]]
    if len(ordered) > 4:
        parts.append(f"{len(ordered) - 4} other type(s)")
    reason = " + ".join(parts)

    if toxic:
        what = []
        if "HEALTH_INFO" in sensitive:
            what.append("health data")
        if "SALARY" in sensitive:
            what.append("salary details")
        if sensitive & {"BANK_ACCOUNT", "CREDIT_CARD", "IN_UPI", "IBAN_CODE"}:
            what.append("financial account data")
        who = "a named person" if "PERSON" in identity else "a personal identifier"
        reason += f"; {' and '.join(what)} linked to {who} (toxic combination)"
    if bonus:
        reason += f"; bulk file with {sensitive_records} sensitive records (+{bonus} volume bonus)"
    return reason
