"""
Safe Local Demonstration Fixtures Module for SecureScan.
Provides controlled, deterministic test scenarios representing different web security postures:
1. Hardened Enterprise Application (Grade A - All security headers, strict HSTS, secure cookies)
2. Typical Legacy Website (Grade D - Missing CSP, Clickjacking prone, Missing HSTS)
3. Permissive CORS API (Grade C/D - Wildcard origin with credentials, loose methods)
4. Vulnerable Session Cookies (Grade D - Plaintext cookies without Secure/HttpOnly)
5. Network Timeout / Unreachable Server Simulation (Failure handling)

Enables complete offline demonstration and evaluation without outbound internet traffic.
"""

from datetime import datetime, timezone
from typing import Any
import uuid

from scanner.cookie_checks import analyze_cookies
from scanner.cors_checks import analyze_cors_configuration
from scanner.findings import compile_scan_findings
from scanner.header_checks import analyze_security_headers


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
            # Missing CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
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
    Clearly marks the result with `is_demo_fixture = True`.
    """
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario:
        raise ValueError(f"Unknown demo scenario '{scenario_id}'. Available: {list(DEMO_SCENARIOS.keys())}")

    start_time_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scan_id = f"DEMO-{scenario_id.upper()[:8]}-{uuid.uuid4().hex[:6].upper()}"

    # Handle timeout scenario
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

    # Run analysis modules against the fixture headers & cookies
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
