"""
Unit tests for URL validation module in SecureScan.
"""

import pytest
from scanner.url_validation import validate_target_url


class TestURLValidation:
    """Tests for validate_target_url."""

    def test_valid_https_url(self):
        valid, err, meta = validate_target_url("https://example.com")
        assert valid is True
        assert err == ""
        assert meta["scheme"] == "https"
        assert meta["hostname"] == "example.com"
        assert meta["port"] == 443
        assert meta["normalized_url"] == "https://example.com/"

    def test_valid_http_with_path_and_query(self):
        valid, err, meta = validate_target_url("http://example.com/api/v1/test?debug=0")
        assert valid is True
        assert meta["scheme"] == "http"
        assert meta["path"] == "/api/v1/test"
        assert meta["query"] == "debug=0"
        assert meta["port"] == 80

    def test_valid_custom_web_port(self):
        valid, err, meta = validate_target_url("https://example.com:8443/status")
        assert valid is True
        assert meta["port"] == 8443
        assert "example.com:8443" in meta["normalized_url"]

    def test_rejects_empty_and_whitespace(self):
        valid, err, _ = validate_target_url("")
        assert valid is False
        assert "empty" in err.lower()

        valid, err, _ = validate_target_url("https://exa mple.com")
        assert valid is False
        assert "whitespace" in err.lower()

    def test_rejects_missing_scheme(self):
        valid, err, _ = validate_target_url("example.com")
        assert valid is False
        assert "explicit scheme" in err.lower()

    def test_rejects_unsupported_schemes(self):
        for bad_scheme in ["ftp://ftp.example.com", "file:///etc/passwd", "gopher://evil.com", "javascript:alert(1)"]:
            valid, err, _ = validate_target_url(bad_scheme)
            assert valid is False
            assert "unsupported" in err.lower() or "scheme" in err.lower()

    def test_rejects_embedded_credentials(self):
        valid, err, _ = validate_target_url("https://admin:secret@example.com/admin")
        assert valid is False
        assert "credentials" in err.lower()

        valid, err, _ = validate_target_url("http://root@example.com/")
        assert valid is False
        assert "credentials" in err.lower()

    def test_rejects_localhost_labels(self):
        for host in ["http://localhost", "https://localhost:8080", "http://app.localhost"]:
            valid, err, _ = validate_target_url(host)
            assert valid is False
            assert "localhost" in err.lower()

    def test_rejects_out_of_range_ports(self):
        valid, err, _ = validate_target_url("http://example.com:70000")
        assert valid is False
        assert "range" in err.lower()
