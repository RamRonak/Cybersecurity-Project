"""
===============================================================================
SecureScan — Automated Web Security Scanner & Configuration Assessment Framework
===============================================================================
Author: Ronak Ram
Project: SecureScan — Defensive Web Application Security Scanner
Submission for: IBM SkillsBuild Cyber Security BootCamp 2026 conducted by BharatCares
Date: October 2026

Description:
    SecureScan is a defensive, non-destructive web security scanning framework
    developed to audit web application transport security, HTTP security response
    headers, Cross-Origin Resource Sharing (CORS) configurations, and cookie
    security flags. It enforces strict Server-Side Request Forgery (SSRF) defenses,
    performs multi-IP DNS resolution, redacts sensitive session secrets, and
    compiles publication-ready PDF security reports.

Usage:
    Web Dashboard:
        python RonakRam_SecureScan.py
        python RonakRam_SecureScan.py --web --port 5000

    Offline Demonstration Scenarios (No network access required):
        python RonakRam_SecureScan.py --demo hardened --pdf report_hardened.pdf
        python RonakRam_SecureScan.py --demo legacy
        python RonakRam_SecureScan.py --demo permissive_cors
        python RonakRam_SecureScan.py --demo vulnerable_cookies
        python RonakRam_SecureScan.py --demo timeout_error
        python RonakRam_SecureScan.py --list-demos

    Authorized Target Scan:
        python RonakRam_SecureScan.py --url https://example.com --auth --pdf audit_report.pdf
===============================================================================
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from io import BytesIO
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
import uuid
import xml.sax.saxutils as saxutils

# Third-party dependencies
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# =============================================================================
# 1. APPLICATION & SECURITY CONFIGURATION
# =============================================================================

class Config:
    """Core application and security configuration settings."""

    # Security: Secret key for session management and CSRF tokens
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    # Flask session cookies hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"

    # Scanner network limits
    DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("DEFAULT_TIMEOUT_SECONDS", "6"))
    MIN_TIMEOUT_SECONDS = 2
    MAX_TIMEOUT_SECONDS = 10

    # Defense-in-depth: limit redirects to prevent infinite loops / redirection chains
    MAX_REDIRECTS = int(os.environ.get("MAX_REDIRECTS", "4"))

    # Response body cutoff (1MB) to protect server memory against payload bloat
    MAX_RESPONSE_BYTES = int(os.environ.get("MAX_RESPONSE_BYTES", str(1024 * 1024)))

    # Maximum recent scans to hold in memory
    MAX_HISTORY_ENTRIES = int(os.environ.get("MAX_HISTORY_ENTRIES", "30"))

    # Ethical User-Agent identifying the scanner as a defensive security assessment tool
    SCANNER_USER_AGENT = (
        "SecureScan-Auditor/1.0 (+Defensive Web Security Scanner; IBM SkillsBuild Bootcamp Assessment)"
    )

    # Allowed URL schemes
    ALLOWED_SCHEMES = {"http", "https"}

    # Permitted assessment ports
    ALLOWED_PORTS = {80, 443, 8080, 8443}


# =============================================================================
# 2. URL VALIDATION MODULE
# =============================================================================

class URLValidationError(ValueError):
    """Raised when a URL violates security or formatting policies."""
    pass


PERMITTED_SCHEMES = {"http", "https"}
PERMITTED_PORTS = {80, 443, 8080, 8443}


def validate_target_url(raw_url: str, allow_custom_ports: bool = True) -> tuple[bool, str, dict[str, Any]]:
    """
    Validates and canonicalizes a user-supplied target URL.

    Args:
        raw_url: The raw input URL string from user input.
        allow_custom_ports: Whether to permit non-standard web ports (8080, 8443).

    Returns:
        tuple (is_valid, error_message, metadata_dict)
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "Target URL cannot be empty.", {}

    cleaned = raw_url.strip()
    if len(cleaned) > 2048:
        return False, "URL exceeds maximum permitted length (2048 characters).", {}

    # Check for whitespace inside URL
    if any(char in cleaned for char in (" ", "\t", "\r", "\n")):
        return False, "URL must not contain whitespace characters.", {}

    # Must explicitly start with http:// or https://
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", cleaned)
    if not scheme_match:
        return (
            False,
            "URL must include an explicit scheme (e.g., 'https://example.com').",
            {},
        )

    scheme = scheme_match.group(1).lower()
    if scheme not in PERMITTED_SCHEMES:
        return (
            False,
            f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted for security assessment.",
            {},
        )

    try:
        parsed = urlsplit(cleaned)
    except Exception as exc:
        return False, f"Malformed URL syntax: {exc}", {}

    # Enforce no embedded credentials (e.g., http://admin:pass@example.com)
    if parsed.username or parsed.password:
        return (
            False,
            "Embedded user credentials (username/password in URL) are prohibited for security reasons.",
            {},
        )

    # Netloc check
    netloc = parsed.netloc
    if not netloc:
        return False, "URL does not contain a valid network location (hostname).", {}

    # Extract hostname and port
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        return False, f"Invalid hostname or port in URL: {exc}", {}

    if not hostname:
        return False, "URL host component cannot be empty.", {}

    hostname = hostname.lower()

    # Reject localhost keyword or loopback labels
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        return False, "Scanning 'localhost' or local domain targets is forbidden in remote mode.", {}

    # Port validation
    effective_port = port if port is not None else (443 if scheme == "https" else 80)

    if port is not None:
        if port < 1 or port > 65535:
            return False, f"Port '{port}' is out of the valid TCP range (1-65535).", {}
        if not allow_custom_ports and port not in PERMITTED_PORTS:
            return (
                False,
                f"Port '{port}' is not in the allowed assessment ports list (80, 443, 8080, 8443).",
                {},
            )

    # Reconstruct normalized URL (standardize default ports, preserve path/query)
    if (scheme == "http" and effective_port == 80) or (scheme == "https" and effective_port == 443):
        normalized_netloc = hostname
    else:
        normalized_netloc = f"{hostname}:{effective_port}"

    normalized_path = parsed.path if parsed.path else "/"
    normalized_url = urlunsplit((
        scheme,
        normalized_netloc,
        normalized_path,
        parsed.query,
        "",  # Fragments are stripped as they are not sent over HTTP
    ))

    metadata = {
        "raw_url": raw_url,
        "normalized_url": normalized_url,
        "scheme": scheme,
        "hostname": hostname,
        "port": effective_port,
        "path": normalized_path,
        "query": parsed.query,
    }

    return True, "", metadata


# =============================================================================
# 3. NETWORK SAFETY & SSRF DEFENSE MODULE
# =============================================================================

BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # Private-Use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-Use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast (RFC 3068)
    ipaddress.ip_network("192.168.0.0/16"),     # Private-Use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for Future Use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast (RFC 919)
]

BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("64:ff9b:1::/48"),     # Local-Use IPv4/IPv6 Translation
    ipaddress.ip_network("100::/64"),           # Discard-Only Prefix (RFC 6666)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address ULA (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
]


def is_safe_public_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """
    Determines if an IP address belongs to the routable public Internet.
    Blocks private networks, cloud metadata endpoints, loopback, multicast, and reserved ranges.
    """
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.is_loopback:
        return False, f"IP address {ip_obj} is a loopback address (disallowed for remote scans)."

    if ip_obj.is_link_local:
        return False, f"IP address {ip_obj} is a link-local address (potential cloud metadata risk)."

    if ip_obj.is_private:
        return False, f"IP address {ip_obj} is in a private network range (RFC 1918 / RFC 4193)."

    if ip_obj.is_multicast:
        return False, f"IP address {ip_obj} is a multicast address."

    if ip_obj.is_reserved:
        return False, f"IP address {ip_obj} is in an IETF reserved address range."

    if ip_obj.is_unspecified:
        return False, f"IP address {ip_obj} is an unspecified network address."

    if isinstance(ip_obj, ipaddress.IPv4Address):
        for network in BLOCKED_IPV4_NETWORKS:
            if ip_obj in network:
                return False, f"IP address {ip_obj} falls within blocked network {network}."

    if isinstance(ip_obj, ipaddress.IPv6Address):
        for network in BLOCKED_IPV6_NETWORKS:
            if ip_obj in network:
                return False, f"IP address {ip_obj} falls within blocked IPv6 network {network}."

    return True, "IP address is an authorized public routable destination."


def resolve_and_validate_hostname(hostname: str) -> tuple[bool, str, list[str]]:
    """
    Performs safe DNS resolution and validates every returned IP address.
    If ANY resolved IP is private, internal, or reserved, the hostname is rejected (SSRF Rebinding defense).
    """
    try:
        direct_ip = ipaddress.ip_address(hostname)
        is_safe, reason = is_safe_public_ip(direct_ip)
        if not is_safe:
            return False, reason, [str(direct_ip)]
        return True, "", [str(direct_ip)]
    except ValueError:
        pass

    resolved_ips: list[str] = []
    try:
        addr_info = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        return False, f"DNS resolution failed for hostname '{hostname}': {exc}", []
    except Exception as exc:
        return False, f"Unexpected error during DNS resolution for '{hostname}': {exc}", []

    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        return False, f"DNS query for '{hostname}' returned no IP addresses.", []

    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address format received from DNS: '{ip_str}'", []

        is_safe, reason = is_safe_public_ip(ip_obj)
        if not is_safe:
            return (
                False,
                f"Destination '{hostname}' resolved to prohibited address ({ip_str}): {reason}",
                resolved_ips,
            )

    return True, "", resolved_ips


def validate_redirect_target(base_url: str, target_location: str) -> tuple[bool, str, str]:
    """
    Validates a redirection target header (HTTP 3xx Location) before following it.
    Resolves relative URLs against base_url, validates the protocol, and enforces SSRF boundaries.
    """
    if not target_location or not target_location.strip():
        return False, "Empty Location header in redirect response.", ""

    try:
        absolute_target = urljoin(base_url, target_location.strip())
    except Exception as exc:
        return False, f"Failed to construct redirect destination: {exc}", ""

    is_valid, err_msg, meta = validate_target_url(absolute_target)
    if not is_valid:
        return False, f"Redirect to invalid destination: {err_msg}", absolute_target

    is_safe, net_err, _ = resolve_and_validate_hostname(meta["hostname"])
    if not is_safe:
        return False, f"Redirect target blocked by SSRF policy: {net_err}", absolute_target

    return True, "", meta["normalized_url"]


# =============================================================================
# 4. SAFE HTTP CLIENT MODULE
# =============================================================================

class SafeHttpClient:
    """Defensive HTTP client enforcing strict security constraints."""

    def __init__(
        self,
        timeout: int = Config.DEFAULT_TIMEOUT_SECONDS,
        max_redirects: int = Config.MAX_REDIRECTS,
        max_bytes: int = Config.MAX_RESPONSE_BYTES,
    ):
        self.timeout = max(
            Config.MIN_TIMEOUT_SECONDS,
            min(timeout, Config.MAX_TIMEOUT_SECONDS),
        )
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": Config.SCANNER_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.session.trust_env = False

    def request_target(self, target_url: str) -> dict[str, Any]:
        """
        Executes a safe GET request to the target URL, verifying DNS and SSRF
        at each step and re-validating any HTTP redirects manually.
        """
        current_url = target_url
        redirect_history: list[dict[str, Any]] = []
        hop_count = 0

        parsed = urlsplit(current_url)
        initial_hostname = parsed.hostname or ""

        is_safe, ssrf_err, resolved_ips = resolve_and_validate_hostname(initial_hostname)
        if not is_safe:
            return {
                "success": False,
                "error_type": "SSRF_BLOCKED",
                "error_message": f"Security policy blocked connection: {ssrf_err}",
                "initial_url": target_url,
                "final_url": current_url,
                "status_code": None,
                "headers": {},
                "cookies": [],
                "response_time_ms": 0.0,
                "content_type": "",
                "redirect_history": [],
                "resolved_ips": resolved_ips,
            }

        start_time = time.perf_counter()

        while True:
            try:
                resp = self.session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                )
            except requests.exceptions.SSLError as exc:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return {
                    "success": False,
                    "error_type": "TLS_VERIFICATION_FAILED",
                    "error_message": (
                        f"TLS verification failed: {exc}. The remote server presented an untrusted, "
                        "expired, self-signed, or invalid certificate."
                    ),
                    "initial_url": target_url,
                    "final_url": current_url,
                    "status_code": None,
                    "headers": {},
                    "cookies": [],
                    "response_time_ms": round(elapsed_ms, 2),
                    "content_type": "",
                    "redirect_history": redirect_history,
                    "resolved_ips": resolved_ips,
                }
            except requests.exceptions.Timeout:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return {
                    "success": False,
                    "error_type": "TIMEOUT",
                    "error_message": (
                        f"Request timed out after {self.timeout} seconds. The target server was unresponsive."
                    ),
                    "initial_url": target_url,
                    "final_url": current_url,
                    "status_code": None,
                    "headers": {},
                    "cookies": [],
                    "response_time_ms": round(elapsed_ms, 2),
                    "content_type": "",
                    "redirect_history": redirect_history,
                    "resolved_ips": resolved_ips,
                }
            except requests.exceptions.ConnectionError as exc:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return {
                    "success": False,
                    "error_type": "CONNECTION_FAILED",
                    "error_message": f"Failed to establish connection to target: {exc}",
                    "initial_url": target_url,
                    "final_url": current_url,
                    "status_code": None,
                    "headers": {},
                    "cookies": [],
                    "response_time_ms": round(elapsed_ms, 2),
                    "content_type": "",
                    "redirect_history": redirect_history,
                    "resolved_ips": resolved_ips,
                }
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return {
                    "success": False,
                    "error_type": "UNEXPECTED_ERROR",
                    "error_message": f"An unexpected network error occurred: {exc}",
                    "initial_url": target_url,
                    "final_url": current_url,
                    "status_code": None,
                    "headers": {},
                    "cookies": [],
                    "response_time_ms": round(elapsed_ms, 2),
                    "content_type": "",
                    "redirect_history": redirect_history,
                    "resolved_ips": resolved_ips,
                }

            if resp.is_redirect or resp.status_code in {301, 302, 303, 307, 308}:
                location = resp.headers.get("Location")
                redirect_history.append({
                    "hop": hop_count + 1,
                    "from_url": current_url,
                    "status_code": resp.status_code,
                    "location_header": location,
                })

                if not location:
                    break

                hop_count += 1
                if hop_count > self.max_redirects:
                    resp.close()
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    return {
                        "success": False,
                        "error_type": "TOO_MANY_REDIRECTS",
                        "error_message": (
                            f"Redirect limit exceeded ({self.max_redirects} hops). "
                            "Aborted to prevent redirection loops."
                        ),
                        "initial_url": target_url,
                        "final_url": current_url,
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                        "cookies": [cookie.name for cookie in resp.cookies],
                        "response_time_ms": round(elapsed_ms, 2),
                        "content_type": resp.headers.get("Content-Type", ""),
                        "redirect_history": redirect_history,
                        "resolved_ips": resolved_ips,
                    }

                is_safe_redir, redir_err, next_url = validate_redirect_target(current_url, location)
                if not is_safe_redir:
                    resp.close()
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    return {
                        "success": False,
                        "error_type": "REDIRECT_BLOCKED_BY_POLICY",
                        "error_message": f"Redirect blocked by security boundary: {redir_err}",
                        "initial_url": target_url,
                        "final_url": next_url,
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                        "cookies": [cookie.name for cookie in resp.cookies],
                        "response_time_ms": round(elapsed_ms, 2),
                        "content_type": resp.headers.get("Content-Type", ""),
                        "redirect_history": redirect_history,
                        "resolved_ips": resolved_ips,
                    }

                resp.close()
                current_url = next_url
                continue

            break

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        raw_content = b""
        try:
            for chunk in resp.iter_content(chunk_size=4096):
                raw_content += chunk
                if len(raw_content) >= self.max_bytes:
                    break
        except Exception:
            pass
        finally:
            resp.close()

        raw_cookie_headers = []
        if "Set-Cookie" in resp.headers:
            raw_cookie_headers.append(resp.headers["Set-Cookie"])
        if hasattr(resp.raw, "headers") and resp.raw.headers:
            for k, v in resp.raw.headers.items():
                if k.lower() == "set-cookie" and v not in raw_cookie_headers:
                    raw_cookie_headers.append(v)

        return {
            "success": True,
            "error_type": None,
            "error_message": "",
            "initial_url": target_url,
            "final_url": current_url,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "cookies": [c.name for c in resp.cookies],
            "raw_cookie_headers": raw_cookie_headers,
            "response_time_ms": round(elapsed_ms, 2),
            "content_type": resp.headers.get("Content-Type", "Not specified"),
            "redirect_history": redirect_history,
            "resolved_ips": resolved_ips,
            "content_length": len(raw_content),
        }


# =============================================================================
# 5. TLS & HTTPS ASSESSMENT MODULE
# =============================================================================

def assess_tls_configuration(
    initial_url: str,
    final_url: str,
    redirect_history: list[dict[str, Any]],
    timeout: int = 5,
) -> dict[str, Any]:
    """
    Evaluates TLS enforcement, HTTPS adoption, and retrieves certificate validity details.
    """
    parsed_initial = urlsplit(initial_url)
    parsed_final = urlsplit(final_url)

    is_https_initial = parsed_initial.scheme.lower() == "https"
    is_https_final = parsed_final.scheme.lower() == "https"

    http_to_https_redirect = False
    if not is_https_initial and is_https_final:
        http_to_https_redirect = True
    elif not is_https_initial and redirect_history:
        for hop in redirect_history:
            loc = hop.get("location_header", "")
            if loc.lower().startswith("https://"):
                http_to_https_redirect = True
                break

    target_hostname = parsed_final.hostname or parsed_initial.hostname or ""
    effective_port = parsed_final.port or (443 if is_https_final else 80)

    if not is_https_final:
        return {
            "is_https_initial": is_https_initial,
            "is_https_final": is_https_final,
            "http_to_https_redirect": False,
            "certificate_assessed": False,
            "certificate_valid": "Not assessed",
            "tls_protocol": "Not assessed",
            "cipher_suite": "Not assessed",
            "hostname": target_hostname,
            "port": effective_port,
            "days_remaining": None,
            "valid_from": None,
            "valid_until": None,
            "issuer": "Not assessed",
            "subject": "Not assessed",
            "error_detail": "Target terminated on plain HTTP. Transport encryption is not configured.",
        }

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    cert_assessed = False
    cert_valid = False
    tls_protocol = "Not assessed"
    cipher_suite = "Not assessed"
    days_remaining = None
    valid_from_str = None
    valid_until_str = None
    issuer_str = "Not assessed"
    subject_str = "Not assessed"
    error_detail = ""

    try:
        with socket.create_connection((target_hostname, effective_port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target_hostname) as sslobj:
                cert_assessed = True
                cert_valid = True
                tls_protocol = sslobj.version() or "TLS (unknown version)"
                cipher_info = sslobj.cipher()
                cipher_suite = cipher_info[0] if cipher_info else "Not assessed"

                cert = sslobj.getpeercert()
                if cert:
                    subject_parts = []
                    for item in cert.get("subject", ()):
                        for key, value in item:
                            if key == "commonName":
                                subject_parts.append(f"CN={value}")
                    subject_str = ", ".join(subject_parts) if subject_parts else target_hostname

                    issuer_parts = []
                    for item in cert.get("issuer", ()):
                        for key, value in item:
                            if key in ("commonName", "organizationName"):
                                issuer_parts.append(f"{key}={value}")
                    issuer_str = ", ".join(issuer_parts) if issuer_parts else "Unknown Issuer"

                    not_after = cert.get("notAfter")
                    not_before = cert.get("notBefore")

                    if not_after:
                        try:
                            expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                                tzinfo=timezone.utc
                            )
                            valid_until_str = expire_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                            now = datetime.now(timezone.utc)
                            delta = expire_dt - now
                            days_remaining = delta.days
                        except Exception:
                            valid_until_str = not_after

                    if not_before:
                        try:
                            start_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(
                                tzinfo=timezone.utc
                            )
                            valid_from_str = start_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                        except Exception:
                            valid_from_str = not_before

    except ssl.SSLCertVerificationError as exc:
        cert_assessed = True
        cert_valid = False
        error_detail = f"Certificate verification failed: {exc.verify_message}"
    except ssl.SSLError as exc:
        cert_assessed = True
        cert_valid = False
        error_detail = f"TLS handshake failure: {exc}"
    except (socket.timeout, TimeoutError):
        cert_assessed = False
        cert_valid = "Not assessed"
        error_detail = f"TLS handshake timed out after {timeout} seconds."
    except Exception as exc:
        cert_assessed = False
        cert_valid = "Not assessed"
        error_detail = f"Unable to establish TLS connection: {exc}"

    return {
        "is_https_initial": is_https_initial,
        "is_https_final": is_https_final,
        "http_to_https_redirect": http_to_https_redirect,
        "certificate_assessed": cert_assessed,
        "certificate_valid": cert_valid,
        "tls_protocol": tls_protocol,
        "cipher_suite": cipher_suite,
        "hostname": target_hostname,
        "port": effective_port,
        "days_remaining": days_remaining,
        "valid_from": valid_from_str,
        "valid_until": valid_until_str,
        "issuer": issuer_str,
        "subject": subject_str,
        "error_detail": error_detail,
    }


# =============================================================================
# 6. HTTP SECURITY HEADER ANALYZER MODULE
# =============================================================================

def analyze_security_headers(headers: dict[str, str], is_https: bool = True) -> dict[str, Any]:
    """
    Analyzes HTTP response headers against modern security configuration standards.
    """
    normalized = {k.lower(): v for k, v in headers.items()}
    results: dict[str, Any] = {}

    # 1. Content-Security-Policy (CSP)
    csp_val = normalized.get("content-security-policy")
    if csp_val:
        issues = []
        if "'unsafe-inline'" in csp_val:
            issues.append("Contains 'unsafe-inline' which weakens XSS defenses.")
        if "'unsafe-eval'" in csp_val:
            issues.append("Contains 'unsafe-eval' permitting runtime string evaluation.")
        if "http:" in csp_val and is_https:
            issues.append("Permits insecure HTTP resources within an HTTPS context.")
        if not re.search(r"\b(default-src|script-src)\b", csp_val):
            issues.append("Missing essential fallback directives ('default-src' or 'script-src').")

        has_frame_ancestors = "frame-ancestors" in csp_val

        if issues:
            status = "Review Recommended"
            details = "CSP is implemented but contains permissive directives: " + " ".join(issues)
            severity = "Low"
        else:
            status = "Present"
            details = "Robust Content-Security-Policy is defined with restrictive directives."
            severity = "Informational"

        results["Content-Security-Policy"] = {
            "name": "Content-Security-Policy",
            "status": status,
            "value": csp_val,
            "has_frame_ancestors": has_frame_ancestors,
            "issues": issues,
            "severity": severity,
            "description": "Defines authorized sources of executable scripts, stylesheets, and resources to mitigate XSS and data injection.",
            "impact": "A weak or absent CSP permits unauthorized script execution, increasing vulnerability to Cross-Site Scripting (XSS).",
            "remediation": "Define a restrictive CSP starting with `default-src 'self'` and avoid `'unsafe-inline'` or `'unsafe-eval'`.",
        }
    else:
        results["Content-Security-Policy"] = {
            "name": "Content-Security-Policy",
            "status": "Missing",
            "value": None,
            "has_frame_ancestors": False,
            "issues": ["Header is absent from the HTTP response."],
            "severity": "Medium",
            "description": "Defines authorized sources of executable content to mitigate Cross-Site Scripting (XSS).",
            "impact": "Without CSP, the browser has no origin enforcement rules for dynamically injected scripts, increasing XSS risk.",
            "remediation": "Deploy a Content-Security-Policy header (e.g., `default-src 'self'; script-src 'self'`).",
        }

    # 2. Strict-Transport-Security (HSTS)
    hsts_val = normalized.get("strict-transport-security")
    if not is_https:
        results["Strict-Transport-Security"] = {
            "name": "Strict-Transport-Security",
            "status": "Not Applicable",
            "value": hsts_val,
            "issues": ["HSTS is only applicable and evaluated over secure HTTPS connections."],
            "severity": "Informational",
            "description": "Forces browsers to communicate exclusively over HTTPS to prevent SSL stripping.",
            "impact": "Not applicable on plain HTTP responses. Browsers strictly ignore HSTS headers received over HTTP.",
            "remediation": "Enable HTTPS on the target server and configure HSTS.",
        }
    elif hsts_val:
        issues = []
        max_age_match = re.search(r"max-age=(\d+)", hsts_val)
        include_subdomains = "includesubdomains" in hsts_val.lower()
        preload = "preload" in hsts_val.lower()

        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age == 0:
                issues.append("max-age is set to 0, which disables HSTS caching.")
            elif max_age < 15724800:
                issues.append(f"max-age ({max_age}s) is shorter than the recommended minimum of 6 months (15724800s).")
        else:
            issues.append("HSTS header does not define a valid 'max-age' directive.")

        if not include_subdomains:
            issues.append("Does not include 'includeSubDomains' directive.")

        if issues:
            status = "Review Recommended"
            details = "HSTS is present but has sub-optimal parameters: " + " ".join(issues)
            severity = "Low"
        else:
            status = "Present"
            details = "HSTS is configured with adequate duration and subdomains protection."
            severity = "Informational"

        results["Strict-Transport-Security"] = {
            "name": "Strict-Transport-Security",
            "status": status,
            "value": hsts_val,
            "issues": issues,
            "severity": severity,
            "include_subdomains": include_subdomains,
            "preload": preload,
            "description": "Instructs web browsers to interact with the domain exclusively over secure HTTPS channels.",
            "impact": "Short duration or missing subdomains allows adversary-in-the-middle downgrade attacks against subdomains.",
            "remediation": "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
        }
    else:
        results["Strict-Transport-Security"] = {
            "name": "Strict-Transport-Security",
            "status": "Missing",
            "value": None,
            "issues": ["Header is absent from HTTPS response."],
            "severity": "Medium",
            "description": "Instructs web browsers to interact exclusively over HTTPS.",
            "impact": "Users connecting via initial HTTP links or insecure Wi-Fi are vulnerable to SSL-stripping man-in-the-middle attacks.",
            "remediation": "Configure your web server to return `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
        }

    # 3. X-Content-Type-Options
    xcto_val = normalized.get("x-content-type-options")
    if xcto_val:
        if xcto_val.strip().lower() == "nosniff":
            status = "Present"
            severity = "Informational"
            issues = []
        else:
            status = "Review Recommended"
            severity = "Low"
            issues = [f"Observed value '{xcto_val}' is invalid; must be 'nosniff'."]

        results["X-Content-Type-Options"] = {
            "name": "X-Content-Type-Options",
            "status": status,
            "value": xcto_val,
            "issues": issues,
            "severity": severity,
            "description": "Prevents MIME-type sniffing by browsers, forcing them to adhere strictly to the declared Content-Type.",
            "impact": "Without 'nosniff', browsers may execute malicious scripts uploaded as benign image or text files.",
            "remediation": "Add `X-Content-Type-Options: nosniff` to all HTTP responses.",
        }
    else:
        results["X-Content-Type-Options"] = {
            "name": "X-Content-Type-Options",
            "status": "Missing",
            "value": None,
            "issues": ["Header is absent from HTTP response."],
            "severity": "Low",
            "description": "Prevents browsers from interpreting files as a different MIME type than declared.",
            "impact": "Increases exposure to MIME confusion attacks where untrusted user-uploaded content is parsed as executable scripts.",
            "remediation": "Add `X-Content-Type-Options: nosniff` to your server response headers.",
        }

    # 4. X-Frame-Options
    xfo_val = normalized.get("x-frame-options")
    csp_has_fa = results.get("Content-Security-Policy", {}).get("has_frame_ancestors", False)

    if xfo_val:
        xfo_upper = xfo_val.strip().upper()
        if xfo_upper in ("DENY", "SAMEORIGIN"):
            status = "Present"
            severity = "Informational"
            issues = []
        elif xfo_upper.startswith("ALLOW-FROM"):
            status = "Review Recommended"
            severity = "Low"
            issues = ["'ALLOW-FROM' is obsolete and unsupported in modern browsers; use CSP frame-ancestors instead."]
        else:
            status = "Review Recommended"
            severity = "Low"
            issues = [f"Unrecognized X-Frame-Options directive: '{xfo_val}'."]

        results["X-Frame-Options"] = {
            "name": "X-Frame-Options",
            "status": status,
            "value": xfo_val,
            "issues": issues,
            "severity": severity,
            "description": "Protects users against Clickjacking by controlling whether the site can be embedded in an <iframe>.",
            "impact": "If misconfigured, malicious sites can embed this page in a transparent frame and hijack user clicks.",
            "remediation": "Set `X-Frame-Options: SAMEORIGIN` or `DENY`, or utilize CSP `frame-ancestors`.",
        }
    else:
        if csp_has_fa:
            results["X-Frame-Options"] = {
                "name": "X-Frame-Options",
                "status": "Not Applicable",
                "value": None,
                "issues": ["Header absent, but compensated by modern CSP 'frame-ancestors' directive."],
                "severity": "Informational",
                "description": "Controls iframe embedding to prevent clickjacking.",
                "impact": "Legacy browsers lacking CSP support may still be vulnerable to framing.",
                "remediation": "Consider adding `X-Frame-Options: SAMEORIGIN` for defense-in-depth on legacy user agents.",
            }
        else:
            results["X-Frame-Options"] = {
                "name": "X-Frame-Options",
                "status": "Missing",
                "value": None,
                "issues": ["Header is absent and no CSP 'frame-ancestors' directive was found."],
                "severity": "Medium",
                "description": "Protects against UI redress and Clickjacking attacks.",
                "impact": "Attackers can embed your site into malicious frames, tricking authenticated users into performing unintended actions.",
                "remediation": "Set `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`.",
            }

    # 5. Referrer-Policy
    rp_val = normalized.get("referrer-policy")
    if rp_val:
        safe_policies = {
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        }
        val_clean = rp_val.strip().lower()
        if val_clean == "unsafe-url":
            status = "Review Recommended"
            severity = "Medium"
            issues = ["'unsafe-url' leaks full URL paths and query parameters to third-party referrers."]
        elif any(p in val_clean for p in safe_policies):
            status = "Present"
            severity = "Informational"
            issues = []
        else:
            status = "Review Recommended"
            severity = "Low"
            issues = [f"Unrecognized policy '{rp_val}'."]

        results["Referrer-Policy"] = {
            "name": "Referrer-Policy",
            "status": status,
            "value": rp_val,
            "issues": issues,
            "severity": severity,
            "description": "Controls how much referral information (URL, query params) is sent when navigating to external origins.",
            "impact": "Permissive policies leak sensitive query parameters or URL tokens in Referer headers.",
            "remediation": "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
        }
    else:
        results["Referrer-Policy"] = {
            "name": "Referrer-Policy",
            "status": "Missing",
            "value": None,
            "issues": ["Header is absent from HTTP response."],
            "severity": "Low",
            "description": "Regulates the transmission of HTTP Referer headers to outbound destinations.",
            "impact": "Browser default behavior may expose path or query parameter contents to third-party endpoints.",
            "remediation": "Configure `Referrer-Policy: strict-origin-when-cross-origin`.",
        }

    # 6. Permissions-Policy
    pp_val = normalized.get("permissions-policy")
    if pp_val:
        results["Permissions-Policy"] = {
            "name": "Permissions-Policy",
            "status": "Present",
            "value": pp_val,
            "issues": [],
            "severity": "Informational",
            "description": "Allows a site to selectively enable or disable browser hardware features (camera, microphone, geolocation).",
            "impact": "Restricts unauthorized hardware API access in embedded frames or compromised scripts.",
            "remediation": "Regularly audit policy directives to maintain minimum necessary privileges.",
        }
    else:
        results["Permissions-Policy"] = {
            "name": "Permissions-Policy",
            "status": "Missing",
            "value": None,
            "issues": ["Header is absent from HTTP response."],
            "severity": "Low",
            "description": "Controls browser feature APIs like geolocation, camera, microphone, and payment.",
            "impact": "Embedded frames or compromised third-party scripts could potentially request access to sensitive browser features.",
            "remediation": "Add `Permissions-Policy: geolocation=(), camera=(), microphone=()` to restrict unneeded device APIs.",
        }

    return results


# =============================================================================
# 7. CORS CONFIGURATION ANALYZER MODULE
# =============================================================================

def analyze_cors_configuration(headers: dict[str, str]) -> dict[str, Any]:
    """
    Evaluates observed CORS response headers against defensive security practices.
    """
    normalized = {k.lower(): v for k, v in headers.items()}

    acao = normalized.get("access-control-allow-origin")
    acac = normalized.get("access-control-allow-credentials")
    acam = normalized.get("access-control-allow-methods")
    acah = normalized.get("access-control-allow-headers")
    aceh = normalized.get("access-control-expose-headers")

    has_cors = any([acao, acac, acam, acah, aceh])

    if not has_cors:
        return {
            "has_cors_headers": False,
            "status": "Not Configured",
            "summary": "No CORS response headers were observed in the HTTP response.",
            "acao": None,
            "acac": None,
            "acam": None,
            "acah": None,
            "aceh": None,
            "findings": [],
            "risk_level": "None",
        }

    findings = []
    risk_level = "Informational"

    is_wildcard_origin = acao == "*"
    is_credentials_allowed = str(acac).lower() == "true" if acac else False

    if is_wildcard_origin and is_credentials_allowed:
        findings.append({
            "id": "SEC-CORS-001",
            "title": "Invalid Insecure CORS Configuration: Wildcard Origin with Credentials",
            "severity": "High",
            "evidence": f"Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}",
            "explanation": (
                "The server attempts to permit credentials (cookies, HTTP auth) while using a wildcard '*' origin. "
                "Although modern web standards reject this combination in standard browsers, this signals an insecure "
                "architectural intent that may be exploited in non-browser clients or custom implementations."
            ),
            "impact": "Potential cross-origin data exposure if misconfigured middleware allows arbitrary origin reflection.",
            "remediation": "Do not combine credentials with wildcard origins. Explicitly specify trusted, verified domain origins.",
        })
        risk_level = "High"

    elif is_wildcard_origin:
        findings.append({
            "id": "SEC-CORS-002",
            "title": "Permissive Wildcard CORS Origin Allowed",
            "severity": "Low",
            "evidence": f"Access-Control-Allow-Origin: {acao}",
            "explanation": (
                "The endpoint permits any external domain ('*') to read responses. While normal for public CDNs, "
                "fonts, and public APIs, it should not be applied to private or authenticated internal data."
            ),
            "impact": "Any web origin can access responses from this endpoint via client-side JavaScript requests.",
            "remediation": "If this endpoint serves authenticated or sensitive data, restrict origin to approved domains.",
        })
        if risk_level != "High":
            risk_level = "Low"

    if acam:
        methods_list = [m.strip().upper() for m in acam.split(",")]
        risky_methods = [m for m in methods_list if m in ("DELETE", "PUT", "PATCH", "*")]
        if risky_methods:
            findings.append({
                "id": "SEC-CORS-003",
                "title": f"Broad Cross-Origin HTTP Methods Permitted: {', '.join(risky_methods)}",
                "severity": "Low",
                "evidence": f"Access-Control-Allow-Methods: {acam}",
                "explanation": (
                    f"The server allows state-modifying HTTP methods ({', '.join(risky_methods)}) across origins. "
                    "Ensure these actions enforce proper authorization and anti-CSRF protections."
                ),
                "impact": "Cross-origin requests may execute state-modifying actions if authentication is not strictly scoped.",
                "remediation": "Limit Access-Control-Allow-Methods to only the specific HTTP verbs required by client integrations.",
            })

    if acah and "*" in acah:
        findings.append({
            "id": "SEC-CORS-004",
            "title": "Wildcard Allowed Headers in CORS Configuration",
            "severity": "Informational",
            "evidence": f"Access-Control-Allow-Headers: {acah}",
            "explanation": "Access-Control-Allow-Headers uses a wildcard '*', permitting any custom HTTP header from cross-origin requests.",
            "impact": "Broad header allowances bypass fine-grained request header restrictions.",
            "remediation": "Enumerate only necessary application request headers instead of using a wildcard.",
        })

    return {
        "has_cors_headers": True,
        "status": "Configured",
        "summary": f"Observed CORS headers: Origin={acao or 'Not set'}, Credentials={acac or 'Not set'}.",
        "acao": acao,
        "acac": acac,
        "acam": acam,
        "acah": acah,
        "aceh": aceh,
        "findings": findings,
        "risk_level": risk_level,
    }


# =============================================================================
# 8. COOKIE SECURITY REVIEWER MODULE (WITH SECRET REDACTION)
# =============================================================================

def analyze_cookies(
    raw_cookie_headers: list[str],
    is_https: bool = True,
) -> dict[str, Any]:
    """
    Parses and audits Set-Cookie headers for security attributes.
    CRITICAL PRIVACY CONTROL: Strictly redacts all raw cookie values.
    """
    if not raw_cookie_headers:
        return {
            "has_cookies": False,
            "cookie_count": 0,
            "cookies": [],
            "findings": [],
            "summary": "No Set-Cookie headers were returned in the HTTP response.",
        }

    audited_cookies: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for raw_header in raw_cookie_headers:
        cookie_parts = re.split(r",\s*(?=[a-zA-Z0-9_\-.]+=)", raw_header)

        for part in cookie_parts:
            part = part.strip()
            if not part:
                continue

            cookie_parser = SimpleCookie()
            try:
                cookie_parser.load(part)
            except Exception:
                pass

            if cookie_parser:
                for name, morsel in cookie_parser.items():
                    has_secure = bool(morsel.get("secure"))
                    has_httponly = bool(morsel.get("httponly"))
                    samesite_raw = morsel.get("samesite")
                    samesite = samesite_raw.lower() if samesite_raw else None
                    path = morsel.get("path", "/")

                    cookie_info = {
                        "name": name,
                        "value": "[REDACTED_FOR_SECURITY]",
                        "secure": has_secure,
                        "httponly": has_httponly,
                        "samesite": samesite or "Not Set",
                        "path": path,
                        "domain": morsel.get("domain", "Host-only"),
                        "issues": [],
                    }

                    if not has_secure:
                        cookie_info["issues"].append("Missing 'Secure' flag.")
                        findings.append({
                            "id": f"SEC-CK-SEC-{name[:8]}",
                            "title": f"Cookie '{name}' Missing 'Secure' Attribute",
                            "severity": "Medium" if is_https else "Low",
                            "category": "Cookie Security",
                            "affected": f"Set-Cookie: {name}",
                            "evidence": f"Cookie '{name}' was issued without the Secure flag.",
                            "explanation": (
                                f"The cookie '{name}' lacks the 'Secure' directive. Browsers may transmit this "
                                "cookie over unencrypted HTTP channels during cleartext navigation or link clicks."
                            ),
                            "impact": "Credentials or session identifiers may be intercepted by an adversary-in-the-middle on insecure networks.",
                            "remediation": f"Append the `; Secure` attribute to Set-Cookie for '{name}'.",
                        })

                    if not has_httponly:
                        cookie_info["issues"].append("Missing 'HttpOnly' flag.")
                        findings.append({
                            "id": f"SEC-CK-HTTP-{name[:8]}",
                            "title": f"Cookie '{name}' Missing 'HttpOnly' Attribute",
                            "severity": "Medium",
                            "category": "Cookie Security",
                            "affected": f"Set-Cookie: {name}",
                            "evidence": f"Cookie '{name}' was issued without the HttpOnly flag.",
                            "explanation": (
                                f"The cookie '{name}' is accessible via client-side JavaScript (`document.cookie`). "
                                "If an attacker executes a Cross-Site Scripting (XSS) exploit, this cookie can be exfiltrated."
                            ),
                            "impact": "Increased risk of session hijacking and credential theft in the event of XSS vulnerabilities.",
                            "remediation": f"Append the `; HttpOnly` attribute to Set-Cookie for '{name}'.",
                        })

                    if not samesite or samesite == "not set":
                        cookie_info["issues"].append("Missing 'SameSite' attribute.")
                        findings.append({
                            "id": f"SEC-CK-SS-{name[:8]}",
                            "title": f"Cookie '{name}' Missing Explicit 'SameSite' Attribute",
                            "severity": "Low",
                            "category": "Cookie Security",
                            "affected": f"Set-Cookie: {name}",
                            "evidence": f"Cookie '{name}' does not specify a SameSite policy.",
                            "explanation": (
                                f"The cookie '{name}' does not declare an explicit SameSite attribute. While modern browsers "
                                "default to 'SameSite=Lax', explicit configuration ensures consistent behavior across all user agents."
                            ),
                            "impact": "Exposure to Cross-Site Request Forgery (CSRF) in older browsers or non-standard user agents.",
                            "remediation": f"Explicitly specify `; SameSite=Lax` or `; SameSite=Strict` on Set-Cookie for '{name}'.",
                        })
                    elif samesite == "none" and not has_secure:
                        cookie_info["issues"].append("SameSite=None without Secure flag.")
                        findings.append({
                            "id": f"SEC-CK-SSN-{name[:8]}",
                            "title": f"Cookie '{name}' Uses SameSite=None Without Secure Flag",
                            "severity": "High",
                            "category": "Cookie Security",
                            "affected": f"Set-Cookie: {name}",
                            "evidence": f"Cookie '{name}' specifies SameSite=None but omits the Secure directive.",
                            "explanation": (
                                "Modern browser specifications mandate that any cookie using `SameSite=None` MUST also "
                                "have the `Secure` flag. Browsers will reject or insecurely handle this cookie."
                            ),
                            "impact": "Cookie rejection by modern browsers or transmission across unencrypted connections.",
                            "remediation": f"Add the `; Secure` attribute whenever using `; SameSite=None`.",
                        })

                    audited_cookies.append(cookie_info)

    return {
        "has_cookies": len(audited_cookies) > 0,
        "cookie_count": len(audited_cookies),
        "cookies": audited_cookies,
        "findings": findings,
        "summary": f"Audited {len(audited_cookies)} cookie(s). All cookie values redacted.",
    }


# =============================================================================
# 9. FINDINGS AND RISK CLASSIFICATION ENGINE
# =============================================================================

@dataclass
class Finding:
    """Standardized representation of a detected security weakness or configuration item."""

    id: str
    title: str
    category: str
    severity: str
    affected_component: str
    evidence: str
    explanation: str
    impact: str
    remediation: str
    references: list[str]
    confidence: str = "High"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compile_scan_findings(
    connectivity_data: dict[str, Any],
    tls_data: dict[str, Any],
    header_data: dict[str, Any],
    cors_data: dict[str, Any],
    cookie_data: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Compiles and scores all findings across scanner sub-modules into a unified list.
    """
    findings: list[Finding] = []

    # 1. TLS & Transport Security Findings
    if not tls_data.get("is_https_final"):
        findings.append(Finding(
            id="SEC-TLS-NO-HTTPS",
            title="Insecure Transport: Plaintext HTTP in Use",
            category="HTTPS & TLS",
            severity="High",
            affected_component="Network Transport / Scheme",
            evidence=f"Final URL uses unencrypted protocol: {connectivity_data.get('final_url')}",
            explanation=(
                "The target application responds over plaintext HTTP without enforcing transport encryption (TLS/HTTPS). "
                "All communication, including authentication tokens, cookies, and sensitive data, travels unencrypted."
            ),
            impact="Adversaries on the same network or path can intercept, sniff, or tamper with user traffic in transit.",
            remediation="Enforce HTTPS across the entire application and configure automatic 301 redirects from HTTP to HTTPS.",
            references=[
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
            ],
        ))
    elif not tls_data.get("is_https_initial") and not tls_data.get("http_to_https_redirect"):
        findings.append(Finding(
            id="SEC-TLS-NO-REDIRECT",
            title="HTTP Does Not Automatically Upgrade to HTTPS",
            category="HTTPS & TLS",
            severity="Medium",
            affected_component="HTTP 301/302 Redirect",
            evidence="Initial request to HTTP did not redirect to HTTPS.",
            explanation="The server did not automatically upgrade cleartext HTTP requests to secure HTTPS.",
            impact="Users typing URLs without explicit https:// remain on plaintext connections.",
            remediation="Implement automatic HTTP to HTTPS redirection using status code 301 (Permanent Redirect).",
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security",
            ],
        ))

    # Certificate validity findings
    if tls_data.get("is_https_final"):
        cert_valid = tls_data.get("certificate_valid")
        if cert_valid is False:
            findings.append(Finding(
                id="SEC-TLS-CERT-INVALID",
                title="TLS Certificate Validation Failed",
                category="HTTPS & TLS",
                severity="High",
                affected_component=f"TLS Certificate for {tls_data.get('hostname')}",
                evidence=tls_data.get("error_detail", "Certificate validation failed."),
                explanation="The TLS certificate presented by the server is untrusted, self-signed, host-mismatched, or expired.",
                impact="Browsers display security warnings, and traffic can be intercepted via adversary-in-the-middle attacks.",
                remediation="Install a valid, unexpired TLS certificate from a trusted public Certificate Authority (e.g., Let's Encrypt).",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                ],
            ))
        elif isinstance(tls_data.get("days_remaining"), int):
            days = tls_data["days_remaining"]
            if days <= 0:
                findings.append(Finding(
                    id="SEC-TLS-CERT-EXPIRED",
                    title="TLS Certificate Is Expired",
                    category="HTTPS & TLS",
                    severity="High",
                    affected_component=f"TLS Certificate ({tls_data.get('hostname')})",
                    evidence=f"Certificate expired on {tls_data.get('valid_until')} ({days} days remaining).",
                    explanation="The server TLS certificate is no longer valid due to passing its expiration date.",
                    impact="Connections will trigger browser security warnings and break client integrations.",
                    remediation="Renew and re-deploy the TLS certificate immediately.",
                    references=["https://letsencrypt.org/docs/"],
                ))
            elif days <= 30:
                findings.append(Finding(
                    id="SEC-TLS-CERT-EXPIRING-SOON",
                    title="TLS Certificate Expiring Soon",
                    category="HTTPS & TLS",
                    severity="Low",
                    affected_component=f"TLS Certificate ({tls_data.get('hostname')})",
                    evidence=f"Certificate expires in {days} days on {tls_data.get('valid_until')}.",
                    explanation="The current TLS certificate is valid but expires within 30 days.",
                    impact="Failure to renew in time will cause certificate warnings and service interruption.",
                    remediation="Schedule automated certificate renewal via ACME / Certbot prior to expiration.",
                    references=["https://letsencrypt.org/docs/automated-renewals/"],
                ))

    # 2. HTTP Security Header Findings
    for hdr_name, hdr_info in header_data.items():
        status = hdr_info.get("status")
        if status in ("Missing", "Review Recommended"):
            sev = hdr_info.get("severity", "Low")
            slug = (
                hdr_name.replace("Content-Security-Policy", "CSP")
                .replace("Strict-Transport-Security", "HSTS")
                .replace("X-Content-Type-Options", "XCTO")
                .replace("X-Frame-Options", "XFO")
                .replace("Referrer-Policy", "RP")
                .replace("Permissions-Policy", "PP")
            )
            evidence_text = (
                f"Observed header value: '{hdr_info.get('value')}'"
                if hdr_info.get("value")
                else "Header was not returned in HTTP response headers."
            )

            findings.append(Finding(
                id=f"SEC-HDR-{slug}",
                title=f"{'Missing' if status == 'Missing' else 'Review Recommended:'} {hdr_name}",
                category="HTTP Security Headers",
                severity=sev,
                affected_component=f"HTTP Header: {hdr_name}",
                evidence=evidence_text,
                explanation=hdr_info.get("description", "") + " " + " ".join(hdr_info.get("issues", [])),
                impact=hdr_info.get("impact", "Weakened browser-enforced security boundaries."),
                remediation=hdr_info.get("remediation", f"Configure the {hdr_name} response header with secure parameters."),
                references=[
                    "https://owasp.org/www-project-secure-headers/",
                    f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{hdr_name}",
                ],
            ))

    # 3. CORS Findings
    for cors_finding in cors_data.get("findings", []):
        findings.append(Finding(
            id=cors_finding["id"],
            title=cors_finding["title"],
            category="CORS Configuration",
            severity=cors_finding["severity"],
            affected_component="Cross-Origin Resource Sharing (CORS) Headers",
            evidence=cors_finding["evidence"],
            explanation=cors_finding["explanation"],
            impact=cors_finding["impact"],
            remediation=cors_finding["remediation"],
            references=[
                "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            ],
        ))

    # 4. Cookie Findings
    for ck_finding in cookie_data.get("findings", []):
        findings.append(Finding(
            id=ck_finding["id"],
            title=ck_finding["title"],
            category="Cookie Security",
            severity=ck_finding["severity"],
            affected_component=ck_finding.get("affected", "Set-Cookie Header"),
            evidence=ck_finding["evidence"],
            explanation=ck_finding["explanation"],
            impact=ck_finding["impact"],
            remediation=ck_finding["remediation"],
            references=[
                "https://owasp.org/www-community/controls/SecureCookieAttribute",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
            ],
        ))

    total = len(findings)
    high = sum(1 for f in findings if f.severity == "High")
    medium = sum(1 for f in findings if f.severity == "Medium")
    low = sum(1 for f in findings if f.severity == "Low")
    info = sum(1 for f in findings if f.severity == "Informational")

    raw_score = 100 - (high * 25 + medium * 10 + low * 4)
    security_score = max(0, min(100, raw_score))

    if security_score >= 90:
        grade = "A"
        grade_label = "Strong Security Posture"
    elif security_score >= 75:
        grade = "B"
        grade_label = "Good (Minor Recommendations)"
    elif security_score >= 60:
        grade = "C"
        grade_label = "Fair (Hardening Recommended)"
    elif security_score >= 40:
        grade = "D"
        grade_label = "Poor (Multiple Weaknesses)"
    else:
        grade = "F"
        grade_label = "Critical Weaknesses Detected"

    summary = {
        "total_findings": total,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "info_count": info,
        "security_score": security_score,
        "grade": grade,
        "grade_label": grade_label,
    }

    serialized_findings = [f.to_dict() for f in findings]
    return serialized_findings, summary


# =============================================================================
# 10. SAFE LOCAL DEMONSTRATION FIXTURES
# =============================================================================

DEMO_SCENARIOS = {
    "hardened": {
        "id": "hardened",
        "name": "Hardened Enterprise Web Application (Optimal Security Posture)",
        "simulated_target": "https://secure-demo.internal/app",
        "description": "Simulates a fully-hardened modern web application with strict Content-Security-Policy, HSTS preloading, secure cookies, and minimal CORS.",
        "status_code": 200,
        "is_https": True,
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' https://fonts.googleapis.com; frame-ancestors 'none'; object-src 'none';",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
            "Access-Control-Allow-Origin": "https://trusted-partner.example.com",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        },
        "raw_cookies": [
            "session_id=s%3A2948194; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600",
            "csrf_token=9a8b7c6d5e; Path=/; Secure; HttpOnly; SameSite=Strict",
        ],
        "tls": {
            "is_https_initial": True,
            "is_https_final": True,
            "http_to_https_redirect": True,
            "certificate_assessed": True,
            "certificate_valid": True,
            "tls_protocol": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "hostname": "secure-demo.internal",
            "port": 443,
            "days_remaining": 142,
            "valid_from": "2026-01-01 00:00:00 UTC",
            "valid_until": "2027-01-01 00:00:00 UTC",
            "issuer": "CN=DigiCert Global Root G2, organizationName=DigiCert Inc",
            "subject": "CN=secure-demo.internal",
            "error_detail": "",
        },
    },
    "legacy": {
        "id": "legacy",
        "name": "Legacy Unhardened Website (Missing Security Headers)",
        "simulated_target": "https://legacy-portal.internal/",
        "description": "Simulates an older web application missing CSP, Clickjacking protection, and HSTS, exposing users to UI redress and script injection.",
        "status_code": 200,
        "is_https": True,
        "headers": {
            "Content-Type": "text/html; charset=ISO-8859-1",
            "Server": "Apache/2.4.29 (Unix)",
            "X-Powered-By": "PHP/7.2.34",
        },
        "raw_cookies": [
            "PHPSESSID=d9f48a176e01bc; path=/",
        ],
        "tls": {
            "is_https_initial": True,
            "is_https_final": True,
            "http_to_https_redirect": False,
            "certificate_assessed": True,
            "certificate_valid": True,
            "tls_protocol": "TLSv1.2",
            "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
            "hostname": "legacy-portal.internal",
            "port": 443,
            "days_remaining": 22,
            "valid_from": "2025-05-01 00:00:00 UTC",
            "valid_until": "2026-11-12 00:00:00 UTC",
            "issuer": "CN=Let's Encrypt Authority X3",
            "subject": "CN=legacy-portal.internal",
            "error_detail": "",
        },
    },
    "permissive_cors": {
        "id": "permissive_cors",
        "name": "Misconfigured API with Permissive CORS",
        "simulated_target": "https://api-service.internal/v1/userdata",
        "description": "Simulates an API endpoint returning a wildcard origin combined with Access-Control-Allow-Credentials and broad allowed HTTP verbs.",
        "status_code": 200,
        "is_https": True,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "X-Content-Type-Options": "nosniff",
        },
        "raw_cookies": [
            "jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9; Path=/; Secure; SameSite=Lax",
        ],
        "tls": {
            "is_https_initial": True,
            "is_https_final": True,
            "http_to_https_redirect": True,
            "certificate_assessed": True,
            "certificate_valid": True,
            "tls_protocol": "TLSv1.3",
            "cipher_suite": "TLS_AES_128_GCM_SHA256",
            "hostname": "api-service.internal",
            "port": 443,
            "days_remaining": 88,
            "valid_from": "2026-02-01 00:00:00 UTC",
            "valid_until": "2027-02-01 00:00:00 UTC",
            "issuer": "CN=Cloudflare Inc ECC CA-3",
            "subject": "CN=api-service.internal",
            "error_detail": "",
        },
    },
    "vulnerable_cookies": {
        "id": "vulnerable_cookies",
        "name": "Insecure Session Cookies & Cleartext Transport",
        "simulated_target": "http://insecure-store.internal/checkout",
        "description": "Simulates an unencrypted HTTP application issuing sensitive session tokens without the Secure, HttpOnly, and SameSite cookie attributes.",
        "status_code": 200,
        "is_https": False,
        "headers": {
            "Content-Type": "text/html",
            "Server": "nginx/1.18.0",
        },
        "raw_cookies": [
            "user_session=token987654321; Path=/",
            "remember_me=user_alice_secret; Path=/; Max-Age=2592000",
            "tracking_id=track_xyz999; Path=/; SameSite=None",
        ],
        "tls": {
            "is_https_initial": False,
            "is_https_final": False,
            "http_to_https_redirect": False,
            "certificate_assessed": False,
            "certificate_valid": "Not assessed",
            "tls_protocol": "Not assessed",
            "cipher_suite": "Not assessed",
            "hostname": "insecure-store.internal",
            "port": 80,
            "days_remaining": None,
            "valid_from": None,
            "valid_until": None,
            "issuer": "Not assessed",
            "subject": "Not assessed",
            "error_detail": "Target terminated on plain HTTP. Transport encryption is not configured.",
        },
    },
    "timeout_error": {
        "id": "timeout_error",
        "name": "Simulated Gateway Timeout & Network Drop",
        "simulated_target": "https://unresponsive-host.internal/gateway",
        "description": "Simulates server connection timeout and demonstrates how SecureScan cleanly handles network unreachability without false positives.",
        "status_code": None,
        "is_https": True,
        "error_type": "TIMEOUT",
        "error_message": "Request timed out after 6 seconds. The target server was unresponsive.",
    },
}


def run_demo_fixture_scan(scenario_id: str) -> dict[str, Any]:
    """
    Executes an offline simulated assessment against one of the preconfigured test fixtures.
    """
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        raise ValueError(f"Unknown demo scenario '{scenario_id}'. Available: {list(DEMO_SCENARIOS.keys())}")

    start_time_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scan_id = f"DEMO-{scenario_id.upper()[:8]}-{uuid.uuid4().hex[:6].upper()}"

    if scenario_id == "timeout_error":
        return {
            "scan_id": scan_id,
            "status": "SCAN_FAILED",
            "success": False,
            "is_demo_fixture": True,
            "demo_scenario_name": scenario["name"],
            "error_type": scenario["error_type"],
            "error_message": scenario["error_message"],
            "timestamp": start_time_iso,
            "duration_seconds": 6.02,
            "target_url": scenario["simulated_target"],
            "hostname": "unresponsive-host.internal",
            "connectivity": {
                "success": False,
                "error_type": scenario["error_type"],
                "error_message": scenario["error_message"],
                "status_code": None,
                "response_time_ms": 6000.0,
            },
            "tls": {"is_https_initial": True, "is_https_final": False, "certificate_valid": "Not assessed"},
            "headers": {},
            "cors": {"has_cors_headers": False},
            "cookies": {"has_cookies": False},
            "findings": [],
            "summary": {
                "total_findings": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "security_score": 0,
                "grade": "N/A",
                "grade_label": "Simulated Gateway Timeout",
            },
        }

    is_https = scenario["is_https"]
    headers = scenario["headers"]
    raw_cookies = scenario.get("raw_cookies", [])

    header_res = analyze_security_headers(headers=headers, is_https=is_https)
    cors_res = analyze_cors_configuration(headers=headers)
    cookie_res = analyze_cookies(raw_cookie_headers=raw_cookies, is_https=is_https)

    connectivity_data = {
        "success": True,
        "initial_url": scenario["simulated_target"],
        "final_url": scenario["simulated_target"],
        "status_code": scenario["status_code"],
        "headers": headers,
        "cookies": ["session"] if raw_cookies else [],
        "raw_cookie_headers": raw_cookies,
        "response_time_ms": 42.5,
        "content_type": headers.get("Content-Type", "text/html"),
        "redirect_history": [],
        "resolved_ips": ["192.0.2.1 (Simulated Test Fixture)"],
    }

    findings, summary = compile_scan_findings(
        connectivity_data=connectivity_data,
        tls_data=scenario["tls"],
        header_data=header_res,
        cors_data=cors_res,
        cookie_data=cookie_res,
    )

    return {
        "scan_id": scan_id,
        "status": "COMPLETED",
        "success": True,
        "is_demo_fixture": True,
        "demo_scenario_name": scenario["name"],
        "timestamp": start_time_iso,
        "duration_seconds": 0.12,
        "target_url": scenario["simulated_target"],
        "final_url": scenario["simulated_target"],
        "hostname": scenario["tls"].get("hostname", "demo.internal"),
        "scan_profile": f"demo_fixture_{scenario_id}",
        "connectivity": connectivity_data,
        "tls": scenario["tls"],
        "headers": header_res,
        "cors": cors_res,
        "cookies": cookie_res,
        "findings": findings,
        "summary": summary,
    }


# =============================================================================
# 11. PDF SECURITY REPORT GENERATOR MODULE (REPORTLAB)
# =============================================================================

def safe_text(text: Any) -> str:
    """Escapes special characters to prevent XML parsing issues in ReportLab Paragraphs."""
    if text is None:
        return "None"
    s = str(text)
    if len(s) > 1000:
        s = s[:1000] + " ... [truncated]"
    return saxutils.escape(s)


class NumberedCanvas(canvas.Canvas):
    """Custom canvas that tracks total pages to print 'Page X of Y' in footer."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        if self._pageNumber > 1:
            self.drawString(
                54,
                750,
                "SecureScan — Automated Web Security Assessment Report (Ronak Ram)",
            )
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)

        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)

        footer_text = "CONFIDENTIAL & AUTHORIZED DEFENSIVE SECURITY EVALUATION"
        self.drawString(54, 32, footer_text)
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_str)
        self.restoreState()


def generate_security_pdf(scan_data: dict[str, Any]) -> bytes:
    """
    Builds a complete, formatted PDF document in memory and returns raw bytes.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    brand_title = ParagraphStyle(
        "BrandTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0F172A"),
    )
    report_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0284C7"),
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_text = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#334155"),
    )
    meta_label = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#475569"),
    )
    meta_val = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#0F172A"),
    )
    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0F172A"),
    )
    code_evidence = ParagraphStyle(
        "CodeEvidence",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
    )

    story = []

    # 1. Header Banner & Title
    story.append(Paragraph("🛡️ SECURESCAN", brand_title))
    story.append(Paragraph("Automated Web Security Assessment & Configuration Audit", report_subtitle))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=14))

    # 2. Executive Scan Metadata Table
    summary = scan_data.get("summary", {})
    metadata_table_data = [
        [
            Paragraph("<b>Target Hostname:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("hostname", "N/A")), meta_val),
            Paragraph("<b>Scan Identifier:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("scan_id", "N/A")), meta_val),
        ],
        [
            Paragraph("<b>Target URL:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("target_url", "N/A")), meta_val),
            Paragraph("<b>Assessment Date:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("timestamp", "N/A")), meta_val),
        ],
        [
            Paragraph("<b>Status:</b>", meta_label),
            Paragraph(safe_text(scan_data.get("status", "N/A")), meta_val),
            Paragraph("<b>Scan Duration:</b>", meta_label),
            Paragraph(f"{scan_data.get('duration_seconds', 0.0)} seconds", meta_val),
        ],
        [
            Paragraph("<b>Overall Posture Score:</b>", meta_label),
            Paragraph(f"<b>{summary.get('security_score', 'N/A')}/100 (Grade {summary.get('grade', 'N/A')})</b>", meta_val),
            Paragraph("<b>Auditor / Student:</b>", meta_label),
            Paragraph("Ronak Ram (IBM SkillsBuild)", meta_val),
        ],
    ]

    meta_table = Table(metadata_table_data, colWidths=[110, 150, 100, 144])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 3. Findings Severity Summary Cards Table
    story.append(Paragraph("Executive Severity Summary", section_heading))
    high_cnt = summary.get("high_count", 0)
    med_cnt = summary.get("medium_count", 0)
    low_cnt = summary.get("low_count", 0)
    info_cnt = summary.get("info_count", 0)

    summary_cards_data = [
        [
            Paragraph(f"<b>CRITICAL / HIGH</b><br/><font size='16'><b>{high_cnt}</b></font>", ParagraphStyle("H", parent=body_text, alignment=1, textColor=colors.HexColor("#EF4444"))),
            Paragraph(f"<b>MEDIUM</b><br/><font size='16'><b>{med_cnt}</b></font>", ParagraphStyle("M", parent=body_text, alignment=1, textColor=colors.HexColor("#F59E0B"))),
            Paragraph(f"<b>LOW</b><br/><font size='16'><b>{low_cnt}</b></font>", ParagraphStyle("L", parent=body_text, alignment=1, textColor=colors.HexColor("#0284C7"))),
            Paragraph(f"<b>INFORMATIONAL</b><br/><font size='16'><b>{info_cnt}</b></font>", ParagraphStyle("I", parent=body_text, alignment=1, textColor=colors.HexColor("#64748B"))),
        ]
    ]
    summary_cards_table = Table(summary_cards_data, colWidths=[126, 126, 126, 126])
    summary_cards_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#FEF2F2")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#FFFBEB")),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#F0F9FF")),
        ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_cards_table)
    story.append(Spacer(1, 14))

    # 4. Scope & Defensive Methodology
    story.append(Paragraph("Scope & Defensive Methodology", section_heading))
    methodology_text = (
        "This security assessment was executed strictly under authorized defensive conditions using non-destructive, "
        "passive HTTP/HTTPS configuration analysis. Checks evaluate transport security enforcement (TLS/HTTPS), "
        "HTTP security response headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, "
        "Permissions-Policy), Cross-Origin Resource Sharing (CORS) boundaries, and cookie security flags (Secure, "
        "HttpOnly, SameSite). No destructive exploits, payload injection, or brute-force tests were performed."
    )
    story.append(Paragraph(methodology_text, body_text))
    story.append(Spacer(1, 14))

    # 5. Detailed Findings Section
    story.append(Paragraph("Detailed Security Findings", section_heading))
    findings = scan_data.get("findings", [])

    if not findings:
        story.append(Paragraph(
            "<b>No security weaknesses detected by the passive configuration checks.</b><br/>"
            "<i>Note: A clean passive scan does not guarantee that the application is immune to business logic, "
            "authentication, or server-side injection vulnerabilities. Comprehensive penetration testing is recommended.</i>",
            body_text,
        ))
    else:
        for idx, finding in enumerate(findings, start=1):
            sev = finding.get("severity", "Informational")
            sev_colors = {
                "High": ("#EF4444", "#FEF2F2"),
                "Medium": ("#F59E0B", "#FFFBEB"),
                "Low": ("#0284C7", "#F0F9FF"),
                "Informational": ("#64748B", "#F8FAFC"),
            }
            border_col, bg_col = sev_colors.get(sev, ("#64748B", "#F8FAFC"))

            finding_flowables = [
                Spacer(1, 6),
                Paragraph(
                    f"<b>Finding {idx} [{safe_text(finding.get('id'))}] — {safe_text(finding.get('title'))}</b>",
                    finding_title_style,
                ),
                Spacer(1, 4),
            ]

            table_content = [
                [Paragraph("<b>Severity:</b>", meta_label), Paragraph(f"<b>{safe_text(sev)}</b>", meta_val),
                 Paragraph("<b>Category:</b>", meta_label), Paragraph(safe_text(finding.get("category")), meta_val)],
                [Paragraph("<b>Affected:</b>", meta_label), Paragraph(safe_text(finding.get("affected_component")), meta_val),
                 Paragraph("<b>Confidence:</b>", meta_label), Paragraph(safe_text(finding.get("confidence", "High")), meta_val)],
                [Paragraph("<b>Evidence:</b>", meta_label), Paragraph(safe_text(finding.get("evidence")), code_evidence), "", ""],
                [Paragraph("<b>Explanation:</b>", meta_label), Paragraph(safe_text(finding.get("explanation")), body_text), "", ""],
                [Paragraph("<b>Impact:</b>", meta_label), Paragraph(safe_text(finding.get("impact")), body_text), "", ""],
                [Paragraph("<b>Remediation:</b>", meta_label), Paragraph(safe_text(finding.get("remediation")), body_text), "", ""],
            ]

            f_table = Table(table_content, colWidths=[90, 414])
            f_table.setStyle(TableStyle([
                ("SPAN", (1, 2), (-1, 2)),
                ("SPAN", (1, 3), (-1, 3)),
                ("SPAN", (1, 4), (-1, 4)),
                ("SPAN", (1, 5), (-1, 5)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_col)),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(border_col)),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))

            finding_flowables.append(f_table)
            finding_flowables.append(Spacer(1, 10))
            story.append(KeepTogether(finding_flowables))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Limitations & Legal Disclaimer", section_heading))
    disclaimer_text = (
        "SecureScan is an educational and defensive audit tool designed to evaluate HTTP header hygiene and network transport "
        "configuration. It does not exploit weaknesses, inject SQL, execute XSS vectors, or perform state-changing "
        "vulnerability assessments. The absence of findings does not certify an application as invulnerable. Testing must "
        "always be authorized by the application owner. The evaluators and authors assume no liability for misuse."
    )
    story.append(Paragraph(disclaimer_text, ParagraphStyle("Disc", parent=body_text, fontName="Helvetica-Oblique", textColor=colors.HexColor("#64748B"))))

    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


# =============================================================================
# 12. SCAN ORCHESTRATION SERVICE
# =============================================================================

class ScanService:
    """Singleton-style scan coordinator and history store."""

    def __init__(self, max_history: int = Config.MAX_HISTORY_ENTRIES):
        self.max_history = max_history
        self._history: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def run_scan(
        self,
        raw_url: str,
        is_authorized: bool,
        timeout: int = Config.DEFAULT_TIMEOUT_SECONDS,
        scan_profile: str = "standard_passive",
    ) -> dict[str, Any]:
        """
        Executes a defensive passive web security assessment.
        """
        start_time_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        t0 = time.perf_counter()
        scan_id = uuid.uuid4().hex[:12].upper()

        if not is_authorized:
            return {
                "scan_id": scan_id,
                "status": "ABORTED_UNAUTHORIZED",
                "success": False,
                "error_message": (
                    "Authorization confirmation required. You must check the authorization box "
                    "confirming you own or have explicit written permission to test this target."
                ),
                "timestamp": start_time_iso,
                "duration_seconds": 0.0,
                "target_url": raw_url,
                "hostname": "",
                "findings": [],
                "summary": {},
            }

        is_valid_url, url_err, meta = validate_target_url(raw_url)
        if not is_valid_url:
            return {
                "scan_id": scan_id,
                "status": "VALIDATION_FAILED",
                "success": False,
                "error_message": f"URL Validation Error: {url_err}",
                "timestamp": start_time_iso,
                "duration_seconds": 0.0,
                "target_url": raw_url,
                "hostname": "",
                "findings": [],
                "summary": {},
            }

        normalized_url = meta["normalized_url"]
        hostname = meta["hostname"]

        client = SafeHttpClient(timeout=timeout)
        conn_res = client.request_target(normalized_url)

        if not conn_res.get("success"):
            duration = round(time.perf_counter() - t0, 2)
            result = {
                "scan_id": scan_id,
                "status": "SCAN_FAILED",
                "success": False,
                "error_type": conn_res.get("error_type"),
                "error_message": conn_res.get("error_message"),
                "timestamp": start_time_iso,
                "duration_seconds": duration,
                "target_url": normalized_url,
                "hostname": hostname,
                "connectivity": conn_res,
                "tls": {
                    "is_https_initial": meta["scheme"] == "https",
                    "is_https_final": False,
                    "certificate_valid": "Not assessed",
                    "tls_protocol": "Not assessed",
                },
                "headers": {},
                "cors": {"has_cors_headers": False, "status": "Not Configured"},
                "cookies": {"has_cookies": False, "cookies": []},
                "findings": [],
                "summary": {
                    "total_findings": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "info_count": 0,
                    "security_score": 0,
                    "grade": "N/A",
                    "grade_label": "Scan Incomplete (Unreachable Host)",
                },
            }
            self._save_to_history(result)
            return result

        final_url = conn_res.get("final_url", normalized_url)
        tls_res = assess_tls_configuration(
            initial_url=normalized_url,
            final_url=final_url,
            redirect_history=conn_res.get("redirect_history", []),
            timeout=timeout,
        )

        headers = conn_res.get("headers", {})
        is_https_final = tls_res.get("is_https_final", False)
        header_res = analyze_security_headers(headers=headers, is_https=is_https_final)
        cors_res = analyze_cors_configuration(headers=headers)

        raw_cookie_headers = conn_res.get("raw_cookie_headers", [])
        cookie_res = analyze_cookies(raw_cookie_headers=raw_cookie_headers, is_https=is_https_final)

        findings, summary = compile_scan_findings(
            connectivity_data=conn_res,
            tls_data=tls_res,
            header_data=header_res,
            cors_data=cors_res,
            cookie_data=cookie_res,
        )

        duration = round(time.perf_counter() - t0, 2)

        result = {
            "scan_id": scan_id,
            "status": "COMPLETED",
            "success": True,
            "timestamp": start_time_iso,
            "duration_seconds": duration,
            "target_url": normalized_url,
            "final_url": final_url,
            "hostname": hostname,
            "scan_profile": scan_profile,
            "connectivity": conn_res,
            "tls": tls_res,
            "headers": header_res,
            "cors": cors_res,
            "cookies": cookie_res,
            "findings": findings,
            "summary": summary,
        }

        self._save_to_history(result)
        return result

    def _save_to_history(self, result: dict[str, Any]) -> None:
        """Stores scan result in thread-safe memory ring buffer."""
        with self._lock:
            entry = {
                "scan_id": result["scan_id"],
                "target_url": result["target_url"],
                "hostname": result.get("hostname", "Unknown"),
                "status": result["status"],
                "timestamp": result["timestamp"],
                "duration_seconds": result.get("duration_seconds", 0.0),
                "high_count": result.get("summary", {}).get("high_count", 0),
                "medium_count": result.get("summary", {}).get("medium_count", 0),
                "low_count": result.get("summary", {}).get("low_count", 0),
                "grade": result.get("summary", {}).get("grade", "N/A"),
                "full_result": result,
            }
            self._history.insert(0, entry)
            if len(self._history) > self.max_history:
                self._history.pop()

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieves full scan result by unique scan ID."""
        with self._lock:
            for entry in self._history:
                if entry["scan_id"] == scan_id:
                    return entry["full_result"]
            return None

    def get_history(self) -> list[dict[str, Any]]:
        """Returns list of recent scan summary items."""
        with self._lock:
            return list(self._history)

    def clear_history(self) -> None:
        """Clears stored scan history."""
        with self._lock:
            self._history.clear()


scan_service = ScanService()


# =============================================================================
# 13. FLASK WEB APPLICATION FACTORY
# =============================================================================

def create_app(config_class=Config) -> Flask:
    """Application factory for SecureScan Web Dashboard."""
    # Find template and static directories if available relative to current file or cwd
    current_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(current_dir, "templates")
    static_dir = os.path.join(current_dir, "static")

    if not os.path.exists(templates_dir):
        templates_dir = os.path.join(os.getcwd(), "templates")
    if not os.path.exists(static_dir):
        static_dir = os.path.join(os.getcwd(), "static")

    app = Flask(
        __name__,
        template_folder=templates_dir if os.path.exists(templates_dir) else None,
        static_folder=static_dir if os.path.exists(static_dir) else None,
    )
    app.config.from_object(config_class)

    def get_csrf_token() -> str:
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(24)
        return session["_csrf_token"]

    app.jinja_env.globals["csrf_token"] = get_csrf_token

    def validate_csrf():
        if request.method in ("POST", "PUT", "DELETE"):
            client_token = request.form.get("csrf_token")
            session_token = session.get("_csrf_token")
            if not client_token or not session_token or not secrets.compare_digest(client_token, session_token):
                abort(400, description="Invalid or missing CSRF security token.")

    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/results") or request.path.startswith("/reports"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

    @app.route("/", methods=["GET"])
    def index():
        history = scan_service.get_history()
        total_scans = len(history)
        high_cnt = sum(item.get("high_count", 0) for item in history)
        med_cnt = sum(item.get("medium_count", 0) for item in history)
        low_cnt = sum(item.get("low_count", 0) for item in history)

        session_metrics = {
            "total_scans": total_scans,
            "high": high_cnt,
            "medium": med_cnt,
            "low": low_cnt,
        }
        return render_template("index.html", session_metrics=session_metrics)

    @app.route("/scan", methods=["POST"])
    def initiate_scan():
        validate_csrf()
        target_url = request.form.get("target_url", "").strip()
        auth_confirm = bool(request.form.get("auth_confirm"))
        timeout_raw = request.form.get("timeout", str(Config.DEFAULT_TIMEOUT_SECONDS))
        scan_profile = request.form.get("scan_profile", "standard_passive")

        if not auth_confirm:
            flash(
                "Authorization confirmation is mandatory. You must confirm permission before scanning.",
                "error",
            )
            return redirect(url_for("index"))

        try:
            timeout = int(timeout_raw)
        except ValueError:
            timeout = Config.DEFAULT_TIMEOUT_SECONDS

        result = scan_service.run_scan(
            raw_url=target_url,
            is_authorized=auth_confirm,
            timeout=timeout,
            scan_profile=scan_profile,
        )

        if not result.get("success"):
            flash(result.get("error_message", "Failed to complete security assessment."), "error")
            if result.get("scan_id") and result.get("status") == "SCAN_FAILED":
                return redirect(url_for("view_results", scan_id=result["scan_id"]))
            return redirect(url_for("index"))

        return redirect(url_for("view_results", scan_id=result["scan_id"]))

    @app.route("/results/<scan_id>", methods=["GET"])
    def view_results(scan_id: str):
        scan = scan_service.get_scan(scan_id)
        if not scan:
            abort(404, description=f"Scan record '{scan_id}' not found in active session memory.")
        return render_template("scan_results.html", scan=scan)

    @app.route("/demo", methods=["GET"])
    def demo_page():
        return render_template("demo.html", scenarios=DEMO_SCENARIOS)

    @app.route("/demo/run/<scenario_id>", methods=["GET"])
    def run_demo_scenario(scenario_id: str):
        try:
            demo_result = run_demo_fixture_scan(scenario_id)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("demo_page"))

        scan_service._save_to_history(demo_result)
        return redirect(url_for("view_results", scan_id=demo_result["scan_id"]))

    @app.route("/reports/<scan_id>/pdf", methods=["GET"])
    def download_pdf_report(scan_id: str):
        scan = scan_service.get_scan(scan_id)
        if not scan:
            abort(404, description=f"Scan record '{scan_id}' not found.")

        try:
            pdf_bytes = generate_security_pdf(scan)
        except Exception as exc:
            flash(f"Failed to generate PDF report: {exc}", "error")
            return redirect(url_for("view_results", scan_id=scan_id))

        safe_hostname = scan.get("hostname", "Target").replace(".", "_")
        filename = f"SecureScan_Report_{safe_hostname}_{scan_id}.pdf"

        return send_file(
            BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )

    @app.route("/history", methods=["GET"])
    def history_page():
        history = scan_service.get_history()
        return render_template("history.html", history=history)

    @app.route("/history/clear", methods=["POST"])
    def clear_history_action():
        validate_csrf()
        scan_service.clear_history()
        flash("Scan history cleared successfully.", "success")
        return redirect(url_for("history_page"))

    @app.route("/about", methods=["GET"])
    def about_page():
        return render_template("about.html")

    @app.errorhandler(400)
    def bad_request_error(error):
        return (
            render_template(
                "error.html",
                error_code=400,
                error_title="Bad Request",
                error_message=str(error.description if hasattr(error, "description") else error),
            ),
            400,
        )

    @app.errorhandler(404)
    def not_found_error(error):
        return (
            render_template(
                "error.html",
                error_code=404,
                error_title="Resource Not Found",
                error_message=str(error.description if hasattr(error, "description") else "The requested page or scan record does not exist."),
            ),
            404,
        )

    @app.errorhandler(500)
    def internal_server_error(error):
        return (
            render_template(
                "error.html",
                error_code=500,
                error_title="Internal Processing Error",
                error_message="An internal error occurred while processing the request. Technical details have been logged securely.",
            ),
            500,
        )

    return app


# =============================================================================
# 14. COMMAND-LINE INTERFACE (CLI) & ENTRY POINT
# =============================================================================

def print_banner():
    banner = r"""
  ____                            ____                  
 / ___|  ___  ___ _   _ _ __ ___ / ___|  ___ __ _ _ __  
 \___ \ / _ \/ __| | | | '__/ _ \\___ \ / __/ _` | '_ \ 
  ___) |  __/ (__| |_| | | |  __/ ___) | (_| (_| | | | |
 |____/ \___|\___|\__,_|_|  \___||____/ \___\__,_|_| |_|
  Defensive Web Security Scanner & Configuration Auditor
  Author: Ronak Ram | IBM SkillsBuild Cyber Security BootCamp 2026
"""
    print(banner)


def format_cli_results(result: dict[str, Any]) -> str:
    """Formats scan results for terminal display."""
    lines = []
    lines.append("=" * 78)
    lines.append(f"  TARGET: {result.get('target_url')}")
    lines.append(f"  STATUS: {result.get('status')} | DURATION: {result.get('duration_seconds')}s")
    lines.append(f"  SCAN ID: {result.get('scan_id')} | DATE: {result.get('timestamp')}")

    summary = result.get("summary", {})
    score = summary.get("security_score", "N/A")
    grade = summary.get("grade", "N/A")
    lines.append(f"  OVERALL POSTURE SCORE: {score}/100 (Grade {grade})")
    lines.append(f"  SEVERITIES: High={summary.get('high_count', 0)} | Med={summary.get('medium_count', 0)} | Low={summary.get('low_count', 0)} | Info={summary.get('info_count', 0)}")
    lines.append("=" * 78)

    findings = result.get("findings", [])
    if not findings:
        lines.append("  [+] No security weaknesses detected in passive configuration check.")
    else:
        for idx, f in enumerate(findings, start=1):
            lines.append(f"\n  [{f.get('severity', 'INFO').upper()}] #{idx}: {f.get('title')} ({f.get('id')})")
            lines.append(f"      Category : {f.get('category')}")
            lines.append(f"      Evidence : {f.get('evidence')}")
            lines.append(f"      Impact   : {f.get('impact')}")
            lines.append(f"      Remedy   : {f.get('remediation')}")

    lines.append("\n" + "=" * 78)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="SecureScan — Automated Web Security Scanner & Configuration Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Launch Web Dashboard:
    python RonakRam_SecureScan.py --web
    python RonakRam_SecureScan.py

  Run Safe Offline Demonstration Fixture:
    python RonakRam_SecureScan.py --demo hardened
    python RonakRam_SecureScan.py --demo legacy --pdf legacy_report.pdf
    python RonakRam_SecureScan.py --list-demos

  Run Live Passive Scan on Authorized Target:
    python RonakRam_SecureScan.py --url https://example.com --auth --pdf example_report.pdf
        """,
    )

    parser.add_argument("--url", type=str, help="Target URL to scan (must start with http:// or https://)")
    parser.add_argument("--auth", action="store_true", help="Confirm you are authorized to scan the target URL")
    parser.add_argument("--timeout", type=int, default=6, help="Network timeout in seconds (2-10, default 6)")
    parser.add_argument("--demo", type=str, help="Run an offline demo scenario (e.g. hardened, legacy, permissive_cors, vulnerable_cookies, timeout_error)")
    parser.add_argument("--list-demos", action="store_true", help="List all available offline demonstration scenarios")
    parser.add_argument("--pdf", type=str, help="Generate and save a ReportLab PDF audit report to the specified file path")
    parser.add_argument("--json", action="store_true", help="Output raw JSON scan results to stdout")
    parser.add_argument("--web", action="store_true", help="Launch the Flask web dashboard")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface for web dashboard (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port for web dashboard (default: 5000)")

    args = parser.parse_args()

    # If no arguments provided, or --web requested, launch Web Server
    if len(sys.argv) == 1 or args.web:
        print_banner()
        print(f"[*] Starting SecureScan Web Dashboard on http://{args.host}:{args.port}")
        print("[*] Access the SOC Dashboard in your browser: http://127.0.0.1:5000")
        print("[*] Press CTRL+C to stop the web server.\n")
        app = create_app()
        app.run(host=args.host, port=args.port, debug=False)
        return

    print_banner()

    # List demo scenarios
    if args.list_demos:
        print("Available Offline Demonstration Scenarios (No Network Required):")
        print("-" * 75)
        for scen_id, info in DEMO_SCENARIOS.items():
            print(f"  • {scen_id:<20} : {info['name']}")
            print(f"    Target: {info.get('simulated_target')}")
            print(f"    Summary: {info['description']}\n")
        print("To run a scenario: python RonakRam_SecureScan.py --demo <scenario_id>")
        return

    # Run offline demo
    if args.demo:
        scen_id = args.demo.strip().lower()
        if scen_id not in DEMO_SCENARIOS:
            print(f"[-] Error: Unknown scenario '{scen_id}'. Use --list-demos to see available options.")
            sys.exit(1)

        print(f"[*] Running offline demonstration scenario: '{scen_id}'...")
        result = run_demo_fixture_scan(scen_id)

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(format_cli_results(result))

        if args.pdf:
            pdf_bytes = generate_security_pdf(result)
            with open(args.pdf, "wb") as f:
                f.write(pdf_bytes)
            print(f"\n[+] PDF Security Audit Report exported to: {os.path.abspath(args.pdf)}")
        return

    # Run live target scan
    if args.url:
        if not args.auth:
            print("[-] Error: Authorization confirmation is mandatory.")
            print("    Please provide --auth to confirm you have permission to assess this endpoint.")
            sys.exit(1)

        print(f"[*] Initiating defensive passive scan for: {args.url}")
        print(f"[*] Timeout: {args.timeout} seconds | SSRF protections: ACTIVE")
        result = scan_service.run_scan(
            raw_url=args.url,
            is_authorized=True,
            timeout=args.timeout,
        )

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(format_cli_results(result))

        if args.pdf:
            pdf_bytes = generate_security_pdf(result)
            with open(args.pdf, "wb") as f:
                f.write(pdf_bytes)
            print(f"\n[+] PDF Security Audit Report exported to: {os.path.abspath(args.pdf)}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
