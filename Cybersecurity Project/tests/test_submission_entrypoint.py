"""
Tests for the consolidated submission entry-point: RonakRam_SecureScan.py
Verifies that the standalone submission deliverable functions correctly.
"""

import os
import tempfile
import pytest

import RonakRam_SecureScan as submission


class TestSubmissionEntrypoint:
    """Test suite validating RonakRam_SecureScan.py core functionality."""

    def test_url_validation_consolidated(self):
        """Ensures URL validation works within the consolidated module."""
        is_valid, err, meta = submission.validate_target_url("https://example.com/api")
        assert is_valid is True
        assert meta["hostname"] == "example.com"
        assert meta["scheme"] == "https"

        # Insecure schemes rejected
        is_valid, err, _ = submission.validate_target_url("ftp://example.com")
        assert is_valid is False
        assert "Unsupported scheme" in err

        # Localhost rejected
        is_valid, err, _ = submission.validate_target_url("http://localhost:8080")
        assert is_valid is False
        assert "localhost" in err

    def test_ssrf_safety_consolidated(self):
        """Ensures SSRF detection blocks private and loopback IPs."""
        import ipaddress
        is_safe, _ = submission.is_safe_public_ip(ipaddress.ip_address("127.0.0.1"))
        assert is_safe is False

        is_safe, _ = submission.is_safe_public_ip(ipaddress.ip_address("192.168.1.1"))
        assert is_safe is False

        is_safe, _ = submission.is_safe_public_ip(ipaddress.ip_address("169.254.169.254"))
        assert is_safe is False

        is_safe, _ = submission.is_safe_public_ip(ipaddress.ip_address("93.184.216.34"))
        assert is_safe is True

    def test_offline_demo_hardened_scan(self):
        """Verifies that offline hardened scenario completes with Grade A."""
        result = submission.run_demo_fixture_scan("hardened")
        assert result["success"] is True
        assert result["status"] == "COMPLETED"
        assert result["summary"]["grade"] == "A"
        assert result["summary"]["security_score"] == 100
        assert len(result["findings"]) == 0

    def test_offline_demo_legacy_scan(self):
        """Verifies that offline legacy scenario detects weaknesses and downgrades score."""
        result = submission.run_demo_fixture_scan("legacy")
        assert result["success"] is True
        assert result["status"] == "COMPLETED"
        assert result["summary"]["grade"] in ("D", "F")
        assert len(result["findings"]) > 0

    def test_pdf_generation_from_consolidated(self):
        """Verifies that PDF generation functions cleanly and returns binary PDF bytes."""
        demo_res = submission.run_demo_fixture_scan("hardened")
        pdf_bytes = submission.generate_security_pdf(demo_res)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 1000

    def test_web_app_factory_routes(self):
        """Verifies that create_app factory from submission produces a working Flask app."""
        app = submission.create_app()
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/")
        assert resp.status_code == 200

        resp_demo = client.get("/demo")
        assert resp_demo.status_code == 200

        resp_about = client.get("/about")
        assert resp_about.status_code == 200
