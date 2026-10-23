"""
Unit tests for findings classification and scoring engine in SecureScan.
"""

import pytest
from scanner.findings import compile_scan_findings


class TestFindingsEngine:
    """Tests for compile_scan_findings function."""

    def test_clean_scan_produces_grade_a(self):
        conn = {"final_url": "https://example.com/"}
        tls = {"is_https_initial": True, "is_https_final": True, "certificate_valid": True, "days_remaining": 90}
        headers = {
            "Content-Security-Policy": {"status": "Present", "severity": "Informational"},
            "Strict-Transport-Security": {"status": "Present", "severity": "Informational"},
            "X-Content-Type-Options": {"status": "Present", "severity": "Informational"},
            "X-Frame-Options": {"status": "Present", "severity": "Informational"},
            "Referrer-Policy": {"status": "Present", "severity": "Informational"},
            "Permissions-Policy": {"status": "Present", "severity": "Informational"},
        }
        cors = {"findings": []}
        cookies = {"findings": []}

        findings, summary = compile_scan_findings(conn, tls, headers, cors, cookies)
        assert summary["total_findings"] == 0
        assert summary["high_count"] == 0
        assert summary["security_score"] == 100
        assert summary["grade"] == "A"

    def test_insecure_transport_creates_high_finding(self):
        conn = {"final_url": "http://example.com/"}
        tls = {"is_https_initial": False, "is_https_final": False, "certificate_valid": "Not assessed"}
        headers = {}
        cors = {"findings": []}
        cookies = {"findings": []}

        findings, summary = compile_scan_findings(conn, tls, headers, cors, cookies)
        assert any(f["id"] == "SEC-TLS-NO-HTTPS" and f["severity"] == "High" for f in findings)
        assert summary["high_count"] >= 1
        assert summary["security_score"] <= 75

    def test_expired_certificate_creates_high_finding(self):
        conn = {"final_url": "https://expired.example.com/"}
        tls = {
            "is_https_initial": True,
            "is_https_final": True,
            "certificate_valid": True,
            "days_remaining": -5,
            "valid_until": "2026-01-01",
            "hostname": "expired.example.com",
        }
        headers = {}
        cors = {"findings": []}
        cookies = {"findings": []}

        findings, summary = compile_scan_findings(conn, tls, headers, cors, cookies)
        assert any(f["id"] == "SEC-TLS-CERT-EXPIRED" and f["severity"] == "High" for f in findings)

    def test_deduction_and_grade_f_on_multiple_criticals(self):
        conn = {"final_url": "http://insecure.example.com/"}
        tls = {"is_https_initial": False, "is_https_final": False}
        headers = {
            "Content-Security-Policy": {"status": "Missing", "severity": "Medium", "description": "", "issues": []},
            "X-Frame-Options": {"status": "Missing", "severity": "Medium", "description": "", "issues": []},
        }
        cors = {
            "findings": [
                {"id": "SEC-CORS-001", "title": "Wildcard Origin with Credentials", "severity": "High", "evidence": "", "explanation": "", "impact": "", "remediation": ""}
            ]
        }
        cookies = {
            "findings": [
                {"id": "SEC-CK-01", "title": "Insecure cookie", "severity": "High", "evidence": "", "explanation": "", "impact": "", "remediation": ""}
            ]
        }

        findings, summary = compile_scan_findings(conn, tls, headers, cors, cookies)
        # High count is 3 (TLS, CORS, Cookie) -> 3 * 25 = 75 deduction
        # Medium count is 2 -> 2 * 10 = 20 deduction -> Score <= 100 - 95 = 5
        assert summary["grade"] == "F"
        assert summary["security_score"] < 40
