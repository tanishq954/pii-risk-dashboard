"""Regulatory mapping and illustrative exposure estimates (DPDP Act 2023, GDPR).

IMPORTANT: every figure produced here is an *illustrative ceiling for
demonstration*, not a prediction of a fine and not legal advice. Penalty
figures live in config.yaml so they can be updated.

* DPDP Act 2023 does not define a separate "sensitive personal data"
  category (unlike the old SPDI Rules), so every entity is "personal data";
  we additionally flag identity, financial and health data as *higher risk*.
* GDPR distinguishes ordinary personal data from Article 9 "special
  category" data (health, among others).
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from . import load_config

# entity -> (DPDP category, DPDP higher-risk?, GDPR category, Financial tag?)
ENTITY_REGULATORY_MAP: Dict[str, Dict[str, Any]] = {
    "IN_AADHAAR":    {"dpdp": "Personal data (national ID)", "dpdp_higher_risk": True,  "gdpr": "Personal data (national identifier, Art. 87)", "financial": False},
    "IN_PAN":        {"dpdp": "Personal data (tax ID)",      "dpdp_higher_risk": True,  "gdpr": "Personal data (national identifier)",   "financial": True},
    "IN_IFSC":       {"dpdp": "Personal data when linked to an account", "dpdp_higher_risk": False, "gdpr": "Personal data when linked", "financial": True},
    "IN_PHONE":      {"dpdp": "Personal data (contact)",     "dpdp_higher_risk": False, "gdpr": "Personal data",                         "financial": False},
    "IN_UPI":        {"dpdp": "Personal data (financial)",   "dpdp_higher_risk": True,  "gdpr": "Personal data (financial)",             "financial": True},
    "BANK_ACCOUNT":  {"dpdp": "Personal data (financial)",   "dpdp_higher_risk": True,  "gdpr": "Personal data (financial)",             "financial": True},
    "SALARY":        {"dpdp": "Personal data (financial)",   "dpdp_higher_risk": True,  "gdpr": "Personal data (financial)",             "financial": True},
    "HEALTH_INFO":   {"dpdp": "Personal data (health)",      "dpdp_higher_risk": True,  "gdpr": "Special category data (Art. 9 - health)", "financial": False},
    "CREDIT_CARD":   {"dpdp": "Personal data (financial)",   "dpdp_higher_risk": True,  "gdpr": "Personal data (financial)",             "financial": True},
    "IBAN_CODE":     {"dpdp": "Personal data (financial)",   "dpdp_higher_risk": True,  "gdpr": "Personal data (financial)",             "financial": True},
    "US_SSN":        {"dpdp": "Personal data (national ID)", "dpdp_higher_risk": True,  "gdpr": "Personal data (national identifier)",   "financial": False},
    "PERSON":        {"dpdp": "Personal data",               "dpdp_higher_risk": False, "gdpr": "Personal data",                         "financial": False},
    "EMAIL_ADDRESS": {"dpdp": "Personal data (contact)",     "dpdp_higher_risk": False, "gdpr": "Personal data",                         "financial": False},
    "PHONE_NUMBER":  {"dpdp": "Personal data (contact)",     "dpdp_higher_risk": False, "gdpr": "Personal data",                         "financial": False},
    "IP_ADDRESS":    {"dpdp": "Personal data (online identifier)", "dpdp_higher_risk": False, "gdpr": "Personal data (online identifier, Recital 30)", "financial": False},
    "LOCATION":      {"dpdp": "Personal data when linked",   "dpdp_higher_risk": False, "gdpr": "Personal data when linked",             "financial": False},
    "DATE_TIME":     {"dpdp": "Personal data when linked (e.g. DOB)", "dpdp_higher_risk": False, "gdpr": "Personal data when linked", "financial": False},
}


def regulatory_row(entity_type: str) -> Dict[str, Any]:
    m = ENTITY_REGULATORY_MAP.get(entity_type, {"dpdp": "Personal data", "dpdp_higher_risk": False,
                                                "gdpr": "Personal data", "financial": False})
    return {"entity_type": entity_type, "dpdp_category": m["dpdp"],
            "dpdp_higher_risk": "Yes" if m["dpdp_higher_risk"] else "No",
            "gdpr_category": m["gdpr"],
            "gdpr_special_category": "Yes" if m["gdpr"].startswith("Special") else "No",
            "financial": "Yes" if m["financial"] else "No"}


def gdpr_max_fine_eur(annual_turnover_eur: float, cfg: Optional[dict] = None) -> float:
    """Art. 83(5) ceiling: the higher of EUR 20m or 4% of worldwide annual turnover."""
    g = (cfg or load_config())["compliance"]["gdpr"]
    return max(float(g["fixed_cap_eur"]), float(annual_turnover_eur) * g["turnover_pct"] / 100.0)


def dpdp_max_penalty_inr(cfg: Optional[dict] = None) -> float:
    """DPDP ceiling for failing to take reasonable security safeguards (INR)."""
    crore = (cfg or load_config())["compliance"]["dpdp"]["max_penalty_security_safeguards_crore"]
    return float(crore) * 1e7


def exposure_index(unique_individuals: int, docs_high: int, docs_medium: int, docs_with_pii: int,
                   cfg: Optional[dict] = None) -> Dict[str, Any]:
    """Combine *how many people* and *how severe* into a 0-100 index.

    * Scale (0-60): log-scaled number of unique individuals relative to a
      reference population (100,000 by default). Log scale because the
      jump from 10 to 1,000 people matters as much as 1,000 to 100,000.
    * Severity (0-40): share of PII-bearing documents that are High risk
      (Medium counts half).
    """
    e = (cfg or load_config())["compliance"]["exposure_index"]
    ref = e["reference_individuals"]
    scale = e["scale_weight"] * min(1.0, math.log10(1 + max(0, unique_individuals)) / math.log10(1 + ref))
    severity = e["severity_weight"] * ((docs_high + 0.5 * docs_medium) / docs_with_pii) if docs_with_pii else 0.0
    value = round(scale + severity, 1)
    band = "Critical" if value >= 75 else "High" if value >= 50 else "Moderate" if value >= 25 else "Low"
    return {"index": value, "band": band, "scale_component": round(scale, 1),
            "severity_component": round(severity, 1)}


def estimate_unique_individuals(unique_by_type: Dict[str, int]) -> int:
    """Conservative (lower-bound) estimate of affected people.

    One person may appear with an Aadhaar, a phone and an email, so adding
    the counts would triple-count them. The largest unique count of any
    single identifier type is a defensible lower bound.
    """
    return max(unique_by_type.values()) if unique_by_type else 0


def format_inr(amount: float) -> str:
    """Indian-style short format: 250 crore, 4.5 lakh."""
    if amount >= 1e7:
        return f"INR {amount / 1e7:,.0f} crore"
    if amount >= 1e5:
        return f"INR {amount / 1e5:,.1f} lakh"
    return f"INR {amount:,.0f}"


def format_eur(amount: float) -> str:
    if amount >= 1e9:
        return f"EUR {amount / 1e9:,.2f} bn"
    if amount >= 1e6:
        return f"EUR {amount / 1e6:,.1f} m"
    return f"EUR {amount:,.0f}"


def compliance_table(entity_types: List[str]) -> List[Dict[str, Any]]:
    return [regulatory_row(t) for t in entity_types]


# ---------------------------------------------------------------------------
# Remediation recommendations (rule-based, generated from the actual findings)
# ---------------------------------------------------------------------------
def _top_folder(path: str, root: str) -> str:
    """First folder under the scan root (e.g. 'hr', 'support', 'enron/allen-p')."""
    from pathlib import PurePath

    try:
        rel = PurePath(path).relative_to(PurePath(root))
        return rel.parts[0] if len(rel.parts) > 1 else "(root folder)"
    except ValueError:
        parts = PurePath(path).parts
        return "/".join(parts[:2]) if len(parts) > 2 else (parts[0] if parts else "")


def remediation_actions(documents, findings, scan_root: str = "", scan_date: Optional[str] = None,
                        cfg: Optional[dict] = None) -> List[Dict[str, Any]]:
    """Turn scan results into a prioritised action list.

    ``documents`` and ``findings`` are pandas DataFrames as stored in SQLite.
    Every number in the text is computed from the scan - nothing is hardcoded.
    """
    import pandas as pd

    cfg = cfg or load_config()
    actions: List[Dict[str, Any]] = []
    if documents is None or documents.empty:
        return actions
    docs = documents.copy()
    docs["folder"] = docs["path"].map(lambda p: _top_folder(str(p), scan_root))
    types_by_doc = findings.groupby("doc_id")["entity_type"].agg(set) if not findings.empty else pd.Series(dtype=object)
    has = lambda t: docs["doc_id"].map(lambda d: t in types_by_doc.get(d, set()))

    def where(mask) -> str:
        top = docs.loc[mask, "folder"].value_counts()
        if top.empty:
            return ""
        return f" (mostly in '{top.index[0]}': {int(top.iloc[0])})"

    def add(priority, action, count, why):
        if count:
            actions.append({"priority": priority, "action": action, "documents": int(count), "why": why})

    sheets = docs["file_type"].isin(["csv", "xlsx"]) & (docs["risk_level"] == "High")
    add("P1", f"Restrict access to {int(sheets.sum())} spreadsheets holding bulk personal records{where(sheets)}",
        sheets.sum(), "Bulk exports (payroll, KYC) expose many people at once; limit to named owners and encrypt.")

    toxic = docs["toxic"].astype(bool)
    add("P1", f"Review {int(toxic.sum())} 'toxic combination' files first",
        toxic.sum(), "Identity + health/salary/financial data together causes the most harm if breached.")

    aad = has("IN_AADHAAR")
    add("P1", f"Redact or mask Aadhaar numbers in {int(aad.sum())} documents{where(aad)}",
        aad.sum(), "Keep only the last 4 digits; full Aadhaar numbers should not sit in email or shared files.")

    health = has("HEALTH_INFO")
    add("P1", f"Move {int(health.sum())} documents with health information to a restricted HR-medical store{where(health)}",
        health.sum(), "Health data is special-category data under GDPR Art. 9 and high-risk under DPDP.")

    fin = has("BANK_ACCOUNT") | has("CREDIT_CARD") | has("IN_UPI") | has("IBAN_CODE")
    add("P2", f"Vault or tokenise financial account details found in {int(fin.sum())} documents{where(fin)}",
        fin.sum(), "Bank, card and UPI details enable fraud; card numbers must never travel by email (PCI DSS).")

    sal = has("SALARY")
    add("P2", f"Limit {int(sal.sum())} documents with salary details to HR/Payroll{where(sal)}",
        sal.sum(), "Compensation data is confidential and should not live on shared drives or broad mailboxes.")

    pan = has("IN_PAN") & ~aad
    add("P2", f"Mask PAN numbers in {int(pan.sum())} further documents{where(pan)}",
        pan.sum(), "PAN links a person to their tax records.")

    risky_mail = docs[docs["risk_level"].isin(["High", "Medium"]) & (docs["sender"].fillna("") != "")]
    if not risky_mail.empty:
        top_sender = risky_mail["sender"].value_counts()
        s_name, s_n = top_sender.index[0], int(top_sender.iloc[0])
        add("P2", f"Apply a retention policy and DLP rule to the mailbox '{s_name}' ({s_n} high/medium-risk emails)",
            s_n, "The mailboxes that send the most sensitive data are the best place to start data-loss prevention.")

    years = cfg["remediation"]["retention_years"]
    dates = pd.to_datetime(docs["date"], errors="coerce", utc=True)
    ref = pd.to_datetime(scan_date, utc=True) if scan_date else pd.Timestamp.now(tz="UTC")
    old = (dates < ref - pd.DateOffset(years=years)) & (docs["risk_level"] != "Clean")
    add("P3", f"Review {int(old.sum())} documents with personal data older than {years} years for deletion",
        old.sum(), "DPDP requires erasure once the purpose is served; a retention schedule shrinks exposure.")

    clean = docs["risk_level"] == "Clean"
    add("P3", f"{int(clean.sum())} documents contain no detected PII: candidates for standard retention and AI/analytics use",
        clean.sum(), "Classifying clean content is what makes it safe to feed into search or GenAI tools (after spot checks).")

    order = {"P1": 0, "P2": 1, "P3": 2}
    return sorted(actions, key=lambda a: (order[a["priority"]], -a["documents"]))
