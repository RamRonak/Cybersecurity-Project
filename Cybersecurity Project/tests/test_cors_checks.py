"""
Unit tests for CORS configuration analyzer in SecureScan.
"""

import pytest
from scanner.cors_checks import analyze_cors_configuration


class TestCorsChecks:
    """Tests for analyze_cors_configuration."""

    def test_no_cors_headers_returns_not_configured(self):
        headers = {"Content-Type": "text/html"}
        res = analyze_cors_configuration(headers)
        assert res["has_cors_headers"] is False
        assert res["status"] == "Not Configured"
        assert len(res["findings"]) == 0

    def test_wildcard_origin_with_credentials_flags_high_severity(self):
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        res = analyze_cors_configuration(headers)
        assert res["has_cors_headers"] is True
        assert res["risk_level"] == "High"
        assert any(f["id"] == "SEC-CORS-001" and f["severity"] == "High" for f in res["findings"])

    def test_wildcard_origin_alone_flags_low_severity(self):
        headers = {
            "Access-Control-Allow-Origin": "*",
        }
        res = analyze_cors_configuration(headers)
        assert res["risk_level"] == "Low"
        assert any(f["id"] == "SEC-CORS-002" and f["severity"] == "Low" for f in res["findings"])

    def test_risky_methods_flagged(self):
        headers = {
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, PUT",
        }
        res = analyze_cors_configuration(headers)
        assert any("SEC-CORS-003" == f["id"] for f in res["findings"])
        assert any("DELETE" in f["title"] for f in res["findings"])

    def test_wildcard_headers_flagged(self):
        headers = {
            "Access-Control-Allow-Origin": "https://trusted.example.com",
            "Access-Control-Allow-Headers": "*",
        }
        res = analyze_cors_configuration(headers)
        assert any("SEC-CORS-004" == f["id"] for f in res["findings"])
