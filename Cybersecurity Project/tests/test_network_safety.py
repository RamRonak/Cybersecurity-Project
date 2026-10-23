"""
Unit tests for network safety and SSRF defense module in SecureScan.
"""

import ipaddress
import socket
from unittest.mock import patch
import pytest

from scanner.network_safety import (
    is_safe_public_ip,
    resolve_and_validate_hostname,
    validate_redirect_target,
)


class TestNetworkSafety:
    """Tests for IP address filtering and SSRF defense."""

    def test_loopback_ips_blocked(self):
        for ip_str in ["127.0.0.1", "127.0.1.1", "127.255.255.254", "::1"]:
            ip = ipaddress.ip_address(ip_str)
            safe, reason = is_safe_public_ip(ip)
            assert safe is False
            assert "loopback" in reason.lower()

    def test_private_rfc1918_ips_blocked(self):
        for ip_str in ["10.0.0.1", "10.254.1.5", "172.16.0.1", "172.31.255.254", "192.168.1.1", "192.168.100.50"]:
            ip = ipaddress.ip_address(ip_str)
            safe, reason = is_safe_public_ip(ip)
            assert safe is False
            assert "private" in reason.lower()

    def test_link_local_and_cloud_metadata_blocked(self):
        # AWS / GCP / Azure metadata endpoint: 169.254.169.254
        metadata_ip = ipaddress.ip_address("169.254.169.254")
        safe, reason = is_safe_public_ip(metadata_ip)
        assert safe is False
        assert "link-local" in reason.lower() or "blocked" in reason.lower()

        ipv6_link_local = ipaddress.ip_address("fe80::1")
        safe, reason = is_safe_public_ip(ipv6_link_local)
        assert safe is False

    def test_ipv4_mapped_ipv6_blocked(self):
        # IPv4-mapped IPv6 loopback and private
        mapped_loopback = ipaddress.ip_address("::ffff:127.0.0.1")
        safe, reason = is_safe_public_ip(mapped_loopback)
        assert safe is False

        mapped_private = ipaddress.ip_address("::ffff:192.168.1.100")
        safe, reason = is_safe_public_ip(mapped_private)
        assert safe is False

    def test_public_ips_permitted(self):
        for ip_str in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"]:
            ip = ipaddress.ip_address(ip_str)
            safe, reason = is_safe_public_ip(ip)
            assert safe is True
            assert "authorized" in reason.lower()

    def test_dns_resolution_private_ip_rejected(self):
        # Mock DNS resolving to a private IP
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0))
            ]
            valid, err, ips = resolve_and_validate_hostname("internal-service.local")
            assert valid is False
            assert "prohibited" in err.lower() or "private" in err.lower()

    def test_dns_rebinding_mixed_ips_rejected(self):
        # Mock DNS resolving to both a public and a private IP
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            ]
            valid, err, ips = resolve_and_validate_hostname("rebind.example.com")
            assert valid is False
            assert "prohibited" in err.lower()

    def test_dns_resolution_failure_handled(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
            valid, err, ips = resolve_and_validate_hostname("nonexistent-domain-xyz123.org")
            assert valid is False
            assert "dns resolution failed" in err.lower()

    def test_redirect_validation_safe(self):
        with patch("scanner.network_safety.resolve_and_validate_hostname") as mock_res:
            mock_res.return_value = (True, "", ["93.184.216.34"])
            safe, err, target = validate_redirect_target("https://example.com/start", "/dashboard")
            assert safe is True
            assert target == "https://example.com/dashboard"

    def test_redirect_to_internal_metadata_blocked(self):
        safe, err, target = validate_redirect_target(
            "https://example.com/path",
            "http://169.254.169.254/latest/meta-data/"
        )
        assert safe is False
        assert "ssrf" in err.lower() or "blocked" in err.lower()
