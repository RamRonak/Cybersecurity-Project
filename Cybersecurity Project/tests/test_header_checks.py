"""
Unit tests for HTTP security headers analyzer in SecureScan.
"""

import pytest
from scanner.header_checks import analyze_security_headers


class TestHeaderChecks:
    """Tests for analyze_security_headers function."""

    def test_all_recommended_headers_present(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' https://trusted.cdn; frame-ancestors 'none';",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=()",
        }
        res = analyze_security_headers(headers, is_https=True)

        assert res["Content-Security-Policy"]["status"] == "Present"
        assert res["Content-Security-Policy"]["severity"] == "Informational"

        assert res["Strict-Transport-Security"]["status"] == "Present"
        assert res["Strict-Transport-Security"]["include_subdomains"] is True
        assert res["Strict-Transport-Security"]["preload"] is True

        assert res["X-Content-Type-Options"]["status"] == "Present"
        assert res["X-Frame-Options"]["status"] == "Present"
        assert res["Referrer-Policy"]["status"] == "Present"
        assert res["Permissions-Policy"]["status"] == "Present"

    def test_missing_all_headers(self):
        headers = {"Content-Type": "text/html"}
        res = analyze_security_headers(headers, is_https=True)

        assert res["Content-Security-Policy"]["status"] == "Missing"
        assert res["Strict-Transport-Security"]["status"] == "Missing"
        assert res["X-Content-Type-Options"]["status"] == "Missing"
        assert res["X-Frame-Options"]["status"] == "Missing"
        assert res["Referrer-Policy"]["status"] == "Missing"
        assert res["Permissions-Policy"]["status"] == "Missing"

    def test_csp_with_unsafe_directives(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';",
        }
        res = analyze_security_headers(headers, is_https=True)
        assert res["Content-Security-Policy"]["status"] == "Review Recommended"
        assert any("unsafe-inline" in issue for issue in res["Content-Security-Policy"]["issues"])
        assert any("unsafe-eval" in issue for issue in res["Content-Security-Policy"]["issues"])

    def test_hsts_not_applicable_on_http(self):
        headers = {"Strict-Transport-Security": "max-age=31536000"}
        res = analyze_security_headers(headers, is_https=False)
        assert res["Strict-Transport-Security"]["status"] == "Not Applicable"

    def test_hsts_short_max_age(self):
        headers = {"Strict-Transport-Security": "max-age=300"}
        res = analyze_security_headers(headers, is_https=True)
        assert res["Strict-Transport-Security"]["status"] == "Review Recommended"
        assert any("shorter than" in issue for issue in res["Strict-Transport-Security"]["issues"])

    def test_xfo_compensated_by_csp_frame_ancestors(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self';",
        }
        res = analyze_security_headers(headers, is_https=True)
        # X-Frame-Options is not flagged as Missing Medium risk if CSP frame-ancestors is present
        assert res["X-Frame-Options"]["status"] == "Not Applicable"
        assert res["X-Frame-Options"]["severity"] == "Informational"

    def test_referrer_policy_unsafe_url_flagged(self):
        headers = {"Referrer-Policy": "unsafe-url"}
        res = analyze_security_headers(headers, is_https=True)
        assert res["Referrer-Policy"]["status"] == "Review Recommended"
        assert res["Referrer-Policy"]["severity"] == "Medium"
