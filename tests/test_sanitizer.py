"""Tests for Sanitizer Pipeline."""

from app.sanitizer.pipeline import SanitizerPipeline, SanitizeResult


def test_sanitize_emails():
    pipe = SanitizerPipeline()
    result = pipe.sanitize("Contact admin@example.com for help")
    assert "[REDACTED_EMAIL]" in result.sanitized_text
    assert result.redaction_count >= 1
    assert result.redaction_types.get("email", 0) >= 1


def test_sanitize_private_ips():
    pipe = SanitizerPipeline()
    result = pipe.sanitize("Server 192.168.1.100 and 10.0.0.5 are internal")
    assert "192.168.1.100" not in result.sanitized_text
    assert "10.0.0.5" not in result.sanitized_text
    assert result.redaction_types.get("private_ip", 0) >= 2


def test_sanitize_preserves_public_ips():
    pipe = SanitizerPipeline()
    result = pipe.sanitize("Attack from 8.8.8.8 targeted 1.1.1.1")
    assert "8.8.8.8" in result.sanitized_text
    assert "1.1.1.1" in result.sanitized_text


def test_sanitize_passwords():
    pipe = SanitizerPipeline()
    result = pipe.sanitize("password: secret123 and api_key=abcdef")
    assert "secret123" not in result.sanitized_text
    assert "abcdef" not in result.sanitized_text
    assert "[REDACTED]" in result.sanitized_text
    assert result.redaction_types.get("credential", 0) >= 2


def test_sanitize_ssn():
    pipe = SanitizerPipeline()
    result = pipe.sanitize("SSN: 123-45-6789")
    assert "123-45-6789" not in result.sanitized_text
    assert "[REDACTED_SSN]" in result.sanitized_text


def test_sanitize_credit_card():
    pipe = SanitizerPipeline()
    result = pipe.sanitize("Card: 4111 1111 1111 1111")
    assert "4111" not in result.sanitized_text
    assert "[REDACTED_CC]" in result.sanitized_text


def test_sanitize_no_op():
    pipe = SanitizerPipeline()
    text = "This is a clean text with no sensitive data"
    result = pipe.sanitize(text)
    assert result.sanitized_text == text
    assert result.redaction_count == 0


def test_sanitize_multiple_types():
    pipe = SanitizerPipeline()
    text = "User admin@test.com from 192.168.1.1 password=hunter2"
    result = pipe.sanitize(text)
    assert result.redaction_count >= 3
    assert "admin@test.com" not in result.sanitized_text
    assert "192.168.1.1" not in result.sanitized_text
    assert "hunter2" not in result.sanitized_text


def test_sanitize_result_lengths():
    pipe = SanitizerPipeline()
    result = pipe.sanitize("Test 10.0.0.1 data")
    assert result.original_length > 0
    assert result.sanitized_length > 0


def test_sanitize_json_like():
    pipe = SanitizerPipeline()
    text = '{"ip": "192.168.1.1", "email": "a@b.com", "data": "normal"}'
    result = pipe.sanitize(text)
    assert "192.168.1.1" not in result.sanitized_text
    assert "a@b.com" not in result.sanitized_text
    assert "normal" in result.sanitized_text
