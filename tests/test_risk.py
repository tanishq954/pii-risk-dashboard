"""Tests for risk scoring, thresholds, the toxic-combination rule and the 100 cap."""
from src import load_config
from src.compliance import exposure_index, gdpr_max_fine_eur
from src.risk import score_document, volume_bonus

CFG = load_config()
W = CFG["risk"]["weights"]
HIGH, MED = CFG["risk"]["thresholds"]["high"], CFG["risk"]["thresholds"]["medium"]


def f(entity, conf=1.0):
    return {"entity_type": entity, "confidence": conf, "start": 0, "end": 1, "masked_value": "X"}


def test_no_findings_is_clean():
    r = score_document([])
    assert r["risk_level"] == "Clean" and r["risk_score"] == 0


def test_only_unscored_entities_is_clean():
    r = score_document([f("DATE_TIME"), f("LOCATION")])
    assert r["risk_level"] == "Clean"


def test_score_is_weight_times_confidence():
    r = score_document([f("IN_AADHAAR", 0.9), f("EMAIL_ADDRESS", 0.5)])
    assert r["risk_score"] == round(W["IN_AADHAAR"] * 0.9 + W["EMAIL_ADDRESS"] * 0.5, 1)


def test_thresholds():
    assert score_document([f("PERSON")])["risk_level"] == "Low"                         # 1
    assert score_document([f("IN_AADHAAR"), f("IN_PHONE"), f("PERSON")])["risk_level"] == "Medium"  # 15
    assert score_document([f("IN_AADHAAR")] * 4)["risk_level"] == "High"               # 40
    assert score_document([f("IN_AADHAAR"), f("IN_PHONE")])["risk_level"] == "Low"     # 14 < 15


def test_toxic_combination_forces_high():
    r = score_document([f("PERSON"), f("HEALTH_INFO", 0.55)])
    assert r["toxic"] and r["risk_level"] == "High" and r["risk_score"] >= HIGH
    assert "toxic combination" in r["reason"]
    r = score_document([f("IN_PAN"), f("BANK_ACCOUNT")])
    assert r["toxic"] and r["risk_level"] == "High"


def test_sensitive_without_identity_is_not_toxic():
    r = score_document([f("HEALTH_INFO", 0.55)])
    assert not r["toxic"] and r["risk_level"] == "Low"


def test_volume_bonus_and_cap():
    assert volume_bonus(9, [[10, 10], [50, 20]]) == 0
    assert volume_bonus(10, [[10, 10], [50, 20]]) == 10
    assert volume_bonus(75, [[10, 10], [50, 20]]) == 20
    r = score_document([f("IN_AADHAAR")] * 200)
    assert r["risk_score"] == CFG["risk"]["max_score"] == 100
    assert "volume bonus" in r["reason"]


def test_bulk_file_scores_higher_than_single_record():
    one = score_document([f("IN_PHONE"), f("PERSON")])["risk_score"]
    many = score_document([f("IN_PHONE"), f("PERSON")] * 3)["risk_score"]
    assert many > one


def test_reason_is_human_readable():
    r = score_document([f("IN_AADHAAR")] * 3 + [f("SALARY"), f("PERSON")])
    assert r["reason"].startswith("3 Aadhaar numbers")
    assert "salary details linked to a named person" in r["reason"]


def test_gdpr_ceiling_is_higher_of_fixed_or_percent():
    assert gdpr_max_fine_eur(100_000_000) == 20_000_000         # 4% = 4m < 20m
    assert gdpr_max_fine_eur(1_000_000_000) == 40_000_000       # 4% = 40m


def test_exposure_index_bounds():
    assert exposure_index(0, 0, 0, 0)["index"] == 0
    top = exposure_index(10**7, 100, 0, 100)
    assert top["index"] == 100 and top["band"] == "Critical"
