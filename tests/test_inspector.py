"""
Tests for the PIIInspector — detection accuracy and mask/unmask correctness.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from gateway.inspector import PIIInspector


@pytest.fixture
def inspector():
    return PIIInspector()


# ---------------------------------------------------------------------------
# SSN
# ---------------------------------------------------------------------------

class TestSSNDetection:
    def test_basic_ssn(self, inspector):
        text = "My SSN is 123-45-6789."
        masked, entities = inspector.mask(text)
        assert "[SSN_REDACTED]" in masked
        assert any(e.entity_type == "SSN" for e in entities)

    def test_ssn_not_in_masked(self, inspector):
        text = "SSN: 987-65-4321"
        masked, _ = inspector.mask(text)
        assert "987-65-4321" not in masked

    def test_multiple_ssns(self, inspector):
        text = "Primary: 123-45-6789. Secondary: 987-65-4321."
        masked, entities = inspector.mask(text)
        ssn_entities = [e for e in entities if e.entity_type == "SSN"]
        assert len(ssn_entities) == 2
        assert "123-45-6789" not in masked
        assert "987-65-4321" not in masked

    def test_no_false_positive_partial(self, inspector):
        # Number without proper SSN format should not match
        text = "The code is 123-456-789."
        _, entities = inspector.mask(text)
        ssn_entities = [e for e in entities if e.entity_type == "SSN"]
        assert len(ssn_entities) == 0

    def test_ssn_unmask(self, inspector):
        original = "Patient SSN: 555-44-3333"
        masked, entities = inspector.mask(original)
        restored = inspector.unmask(masked, entities)
        assert restored == original


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

class TestEmailDetection:
    def test_simple_email(self, inspector):
        text = "Contact us at support@example.com for help."
        masked, entities = inspector.mask(text)
        assert "[EMAIL_REDACTED]" in masked
        assert any(e.entity_type == "EMAIL" for e in entities)

    def test_email_with_subdomain(self, inspector):
        text = "Send to john.doe@mail.company.org"
        masked, entities = inspector.mask(text)
        assert "john.doe@mail.company.org" not in masked

    def test_multiple_emails(self, inspector):
        text = "From: alice@foo.com, To: bob@bar.net"
        masked, entities = inspector.mask(text)
        email_entities = [e for e in entities if e.entity_type == "EMAIL"]
        assert len(email_entities) == 2

    def test_email_unmask(self, inspector):
        original = "Reply to user@domain.com please."
        masked, entities = inspector.mask(original)
        restored = inspector.unmask(masked, entities)
        assert restored == original

    def test_no_email_false_positive(self, inspector):
        text = "Visit our site at www.example.com for details."
        _, entities = inspector.mask(text)
        email_entities = [e for e in entities if e.entity_type == "EMAIL"]
        assert len(email_entities) == 0


# ---------------------------------------------------------------------------
# Credit card (Luhn-valid)
# ---------------------------------------------------------------------------

class TestCreditCardDetection:
    def test_valid_visa(self, inspector):
        # 4111111111111111 — standard Luhn-valid test number
        text = "My Visa card is 4111111111111111."
        masked, entities = inspector.mask(text)
        assert "[CC_REDACTED]" in masked
        assert any(e.entity_type == "CREDIT_CARD" for e in entities)

    def test_valid_mastercard(self, inspector):
        text = "Pay with 5500005555555559."
        masked, entities = inspector.mask(text)
        assert any(e.entity_type == "CREDIT_CARD" for e in entities)

    def test_invalid_luhn_not_detected(self, inspector):
        # 1234567890123456 fails Luhn
        text = "The number 1234567890123456 appears here."
        _, entities = inspector.mask(text)
        cc_entities = [e for e in entities if e.entity_type == "CREDIT_CARD"]
        assert len(cc_entities) == 0

    def test_card_with_dashes(self, inspector):
        text = "Card: 4111-1111-1111-1111"
        masked, entities = inspector.mask(text)
        assert any(e.entity_type == "CREDIT_CARD" for e in entities)

    def test_card_unmask(self, inspector):
        original = "Charge to 4111111111111111 for the order."
        masked, entities = inspector.mask(original)
        restored = inspector.unmask(masked, entities)
        assert restored == original


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

class TestAPIKeyDetection:
    def test_openai_sk_key(self, inspector):
        text = "My OpenAI key is sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD"
        masked, entities = inspector.mask(text)
        assert "[API_KEY_REDACTED]" in masked

    def test_bearer_token(self, inspector):
        text = "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9abc123"
        masked, entities = inspector.mask(text)
        assert any(e.entity_type == "API_KEY" for e in entities)

    def test_google_api_key(self, inspector):
        text = "key=AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        masked, entities = inspector.mask(text)
        assert any(e.entity_type == "API_KEY" for e in entities)

    def test_github_pat(self, inspector):
        text = "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890ab"
        masked, entities = inspector.mask(text)
        assert any(e.entity_type == "API_KEY" for e in entities)

    def test_api_key_unmask(self, inspector):
        original = "Use key sk-TestKeyABCDEFGHIJKLMNOPQRSTUVWXYZ1234 for access."
        masked, entities = inspector.mask(original)
        restored = inspector.unmask(masked, entities)
        assert restored == original


# ---------------------------------------------------------------------------
# IP address
# ---------------------------------------------------------------------------

class TestIPAddressDetection:
    def test_ipv4(self, inspector):
        text = "Server at 192.168.1.100 is down."
        masked, entities = inspector.mask(text)
        assert "[IP_REDACTED]" in masked

    def test_public_ip(self, inspector):
        text = "Origin: 203.0.113.42"
        masked, entities = inspector.mask(text)
        assert any(e.entity_type == "IP_ADDRESS" for e in entities)

    def test_no_false_positive_version(self, inspector):
        # "3.14.15" could match — IP regex requires valid octets
        text = "Running Python 3.11.0 on the server."
        _, entities = inspector.mask(text)
        ip_entities = [e for e in entities if e.entity_type == "IP_ADDRESS"]
        # 3.11.0 is only 3 octets — should not match
        assert len(ip_entities) == 0


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

class TestPhoneDetection:
    def test_us_phone_dashes(self, inspector):
        text = "Call me at 555-867-5309."
        masked, entities = inspector.mask(text)
        assert any(e.entity_type == "PHONE" for e in entities)

    def test_us_phone_parens(self, inspector):
        text = "Reach us at (800) 555-0199."
        masked, entities = inspector.mask(text)
        assert any(e.entity_type == "PHONE" for e in entities)

    def test_us_phone_plain(self, inspector):
        text = "My number is 4155552671."
        masked, entities = inspector.mask(text)
        assert any(e.entity_type == "PHONE" for e in entities)


# ---------------------------------------------------------------------------
# Scan only
# ---------------------------------------------------------------------------

class TestScanOnly:
    def test_scan_does_not_modify(self, inspector):
        text = "Email: foo@bar.com, SSN: 123-45-6789"
        report = inspector.scan_only(text)
        assert report.original_text == text
        assert report.entity_count == 2
        assert "EMAIL" in report.entity_types
        assert "SSN" in report.entity_types

    def test_scan_risk_score(self, inspector):
        text = "foo@bar.com"
        report = inspector.scan_only(text)
        assert 0 < report.risk_score <= 1.0

    def test_scan_empty_clean(self, inspector):
        text = "No sensitive data here."
        report = inspector.scan_only(text)
        assert report.entity_count == 0
        assert report.risk_score == 0.0


# ---------------------------------------------------------------------------
# Mixed PII unmask round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_multi_entity_round_trip(self, inspector):
        original = (
            "Name: Jane Doe, Email: jane@corp.com, "
            "SSN: 321-54-9876, Card: 4111111111111111"
        )
        masked, entities = inspector.mask(original)
        assert original not in masked  # some PII was replaced
        restored = inspector.unmask(masked, entities)
        assert restored == original

    def test_no_pii_round_trip(self, inspector):
        original = "This message contains nothing sensitive."
        masked, entities = inspector.mask(original)
        assert masked == original
        assert entities == []
