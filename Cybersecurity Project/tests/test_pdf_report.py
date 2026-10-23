"""
Unit tests for ReportLab PDF report generation in SecureScan.
"""

import pytest
from reports.pdf_generator import generate_security_pdf
from scanner.demo_fixtures import run_demo_fixture_scan


class TestPdfReport:
    """Tests for generate_security_pdf function."""

    def test_pdf_generation_from_hardened_scan(self):
        scan_data = run_demo_fixture_scan("hardened")
        pdf_bytes = generate_security_pdf(scan_data)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 2000
        # Valid PDF begins with %PDF-
        assert pdf_bytes.startswith(b"%PDF-")

    def test_pdf_generation_from_legacy_scan_with_findings(self):
        scan_data = run_demo_fixture_scan("legacy")
        pdf_bytes = generate_security_pdf(scan_data)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 2000
        assert pdf_bytes.startswith(b"%PDF-")

    def test_pdf_generation_safely_escapes_xml_special_characters(self):
        # Ensure injected characters like <>&" do not break the ReportLab XML parser
        scan_data = run_demo_fixture_scan("hardened")
        scan_data["findings"].append({
            "id": "SEC-TEST-ESC",
            "title": "Test <script>alert(1)</script> & Entity 'Escaping' \"Quotes\"",
            "category": "Test Category <>&",
            "severity": "Low",
            "affected_component": "Test <Component>",
            "evidence": "Value = <abc> & 123",
            "explanation": "Testing <xml> tags & safe formatting",
            "impact": "No injection into PDF parser <tag>",
            "remediation": "Escape <all> input",
            "references": ["https://example.com?a=1&b=2"],
        })

        pdf_bytes = generate_security_pdf(scan_data)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
