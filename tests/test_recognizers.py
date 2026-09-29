"""Tests for the custom Indian PII recognizers (run through the full Presidio pipeline)."""
import random

from src.detector import mask_value
from src.recognizers import verhoeff_generate_check_digit, verhoeff_validate


def make_aadhaar(seed: int = 1) -> str:
    rng = random.Random(seed)
    body = str(rng.randint(2, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(10))
    return body + verhoeff_generate_check_digit(body)


def invalid_aadhaar(valid: str) -> str:
    """Change the check digit so the Verhoeff checksum fails."""
    return valid[:-1] + str((int(valid[-1]) + 1) % 10)


# --- Verhoeff ---------------------------------------------------------------
def test_verhoeff_known_values():
    assert verhoeff_generate_check_digit("236") == "3"      # textbook example: 2363 is valid
    assert verhoeff_validate("2363")
    assert not verhoeff_validate("2364")


def test_verhoeff_detects_every_single_digit_error():
    num = make_aadhaar(7)
    assert verhoeff_validate(num)
    for pos in range(len(num)):
        for d in "0123456789":
            if d != num[pos]:
                assert not verhoeff_validate(num[:pos] + d + num[pos + 1:])


# --- Aadhaar ----------------------------------------------------------------
def test_valid_aadhaar_detected_spaced_and_plain(detect):
    a = make_aadhaar(3)
    spaced = f"{a[:4]} {a[4:8]} {a[8:]}"
    assert detect(f"Customer Aadhaar number: {spaced}").get("IN_AADHAAR") == [spaced]
    assert detect(f"Aadhaar: {a}").get("IN_AADHAAR") == [a]


def test_invalid_checksum_aadhaar_rejected(detect):
    bad = invalid_aadhaar(make_aadhaar(3))
    assert "IN_AADHAAR" not in detect(f"Aadhaar number: {bad[:4]} {bad[4:8]} {bad[8:]}")


def test_aadhaar_cannot_start_with_0_or_1(detect):
    for first in "01":
        body = first + "2345678901"
        num = body + verhoeff_generate_check_digit(body)
        assert "IN_AADHAAR" not in detect(f"Aadhaar: {num[:4]} {num[4:8]} {num[8:]}")


def test_plain_12_digits_next_to_account_label_is_bank_account(detect):
    a = make_aadhaar(11)  # Verhoeff-valid, but labelled as an account number
    found = detect(f"Account No: {a}")
    assert found.get("BANK_ACCOUNT") == [a]
    assert "IN_AADHAAR" not in found


# --- PAN --------------------------------------------------------------------
def test_valid_pan(detect):
    assert detect("PAN: ABCPK1234F").get("IN_PAN") == ["ABCPK1234F"]


def test_pan_invalid_holder_type_or_format(detect):
    assert "IN_PAN" not in detect("PAN: ABCXK1234F")   # X is not a valid holder type
    assert "IN_PAN" not in detect("PAN: ABCP1234FK")   # wrong shape
    assert "IN_PAN" not in detect("pan: abcpk1234f")   # PAN is always upper case


# --- IFSC -------------------------------------------------------------------
def test_ifsc_valid_and_invalid(detect):
    assert detect("IFSC Code: HDFC0001234").get("IN_IFSC") == ["HDFC0001234"]
    assert "IN_IFSC" not in detect("IFSC Code: HDFC1001234")   # 5th character must be 0
    assert "IN_IFSC" not in detect("IFSC Code: HDF00001234")   # first 4 must be letters


# --- UPI vs email -----------------------------------------------------------
def test_upi_detected_but_normal_email_is_not_upi(detect):
    found = detect("Pay me on UPI rahul.k@okaxis or write to rahul.k@gmail.com")
    assert found.get("IN_UPI") == ["rahul.k@okaxis"]
    assert found.get("EMAIL_ADDRESS") == ["rahul.k@gmail.com"]


def test_known_handle_as_email_domain_is_not_upi(detect):
    found = detect("Contact priya@paytm.com for the invoice")
    assert "IN_UPI" not in found
    assert found.get("EMAIL_ADDRESS") == ["priya@paytm.com"]


def test_unknown_handle_not_upi(detect):
    assert "IN_UPI" not in detect("Send to rahul@notabank")


# --- Phone ------------------------------------------------------------------
def test_indian_mobile_formats(detect):
    for phone in ["+91 98765 43210", "+91-9876543210", "9876543210", "09876543210"]:
        assert detect(f"Mobile: {phone}").get("IN_PHONE") == [phone], phone


def test_not_a_mobile(detect):
    assert "IN_PHONE" not in detect("Mobile: 5876543210")  # Indian mobiles start 6-9


# --- Bank account (context required) ----------------------------------------
def test_bank_account_with_context(detect):
    assert detect("Please credit A/c No 12345678901 today").get("BANK_ACCOUNT") == ["12345678901"]
    assert detect("Bank account number: 501002345678").get("BANK_ACCOUNT") == ["501002345678"]


def test_bank_account_without_context(detect):
    found = detect("The shipment reference is 12345678901 for your records")
    assert "BANK_ACCOUNT" not in found


# --- Salary (context required) ----------------------------------------------
def test_salary_with_context(detect):
    assert "SALARY" in detect("Your monthly salary is ₹85,000 from April")
    assert "SALARY" in detect("The offered CTC is 18 LPA")
    assert "SALARY" in detect("Net Salary (INR): 85000")


def test_salary_without_context(detect):
    assert "SALARY" not in detect("Team lunch budget is Rs 600 per head")
    assert "SALARY" not in detect("Invoice value for the milestone is INR 4,50,000")


# --- Health -----------------------------------------------------------------
def test_health_info(detect):
    assert "HEALTH_INFO" in detect("The employee was diagnosed with diabetes and needs insulin")
    assert "HEALTH_INFO" not in detect("The quarterly review is on Thursday")


# --- Credit card vs bank account --------------------------------------------
def test_credit_card_with_card_context(detect):
    assert "CREDIT_CARD" in detect("Charged on my credit card 4111 1111 1111 1111")


# --- Masking never reveals the full value -----------------------------------
def test_masking():
    assert mask_value("2345 6789 0124", "IN_AADHAAR") == "XXXX XXXX 0124"
    assert mask_value("ABCPK1234F", "IN_PAN") == "XXXXXX234F"
    assert mask_value("rahul.k@gmail.com", "EMAIL_ADDRESS") == "r******@gmail.com"
    assert mask_value("₹85,000", "SALARY") == "₹XX,XXX"
    assert mask_value("Rahul Mehta", "PERSON") == "R**** M****"
    for value, et in [("2345 6789 0124", "IN_AADHAAR"), ("12345678901", "BANK_ACCOUNT"), ("9876543210", "IN_PHONE")]:
        assert mask_value(value, et) != value
