"""
Unit tests for cookie security reviewer in SecureScan.
"""

import pytest
from scanner.cookie_checks import analyze_cookies


class TestCookieChecks:
    """Tests for analyze_cookies function and secret redaction."""

    def test_no_cookies_handled_gracefully(self):
        res = analyze_cookies([], is_https=True)
        assert res["has_cookies"] is False
        assert res["cookie_count"] == 0
        assert len(res["findings"]) == 0

    def test_secure_cookie_passes_without_issues(self):
        headers = ["session_id=supersecrettoken12345; Path=/; Secure; HttpOnly; SameSite=Strict"]
        res = analyze_cookies(headers, is_https=True)
        assert res["has_cookies"] is True
        assert res["cookie_count"] == 1
        assert len(res["findings"]) == 0

        cookie = res["cookies"][0]
        assert cookie["name"] == "session_id"
        assert cookie["secure"] is True
        assert cookie["httponly"] is True
        assert cookie["samesite"] == "strict"
        # Verify secret token is REDACTED
        assert cookie["value"] == "[REDACTED_FOR_SECURITY]"
        assert "supersecrettoken12345" not in str(res)

    def test_missing_secure_flag_flagged(self):
        headers = ["user_id=1234; Path=/; HttpOnly; SameSite=Lax"]
        res = analyze_cookies(headers, is_https=True)
        assert any("Missing 'Secure' Attribute" in f["title"] for f in res["findings"])

    def test_missing_httponly_flag_flagged(self):
        headers = ["auth_token=secretjwt; Path=/; Secure; SameSite=Lax"]
        res = analyze_cookies(headers, is_https=True)
        assert any("Missing 'HttpOnly' Attribute" in f["title"] for f in res["findings"])

    def test_samesite_none_without_secure_flags_high(self):
        headers = ["cross_cookie=val; Path=/; SameSite=None"]
        res = analyze_cookies(headers, is_https=True)
        assert any("SameSite=None Without Secure" in f["title"] and f["severity"] == "High" for f in res["findings"])

    def test_confidential_values_never_leaked_in_evidence(self):
        secret_password = "very_sensitive_password_12345"
        headers = [f"login_token={secret_password}; Path=/"]
        res = analyze_cookies(headers, is_https=False)
        # Ensure raw secret is not in any finding evidence, explanation, or title
        dumped = str(res)
        assert secret_password not in dumped
