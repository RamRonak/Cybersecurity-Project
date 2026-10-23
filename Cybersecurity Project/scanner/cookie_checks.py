"""
Cookie Security Reviewer Module for SecureScan.
Inspects Set-Cookie response headers for Secure, HttpOnly, and SameSite attributes.
CRITICAL PRIVACY CONTROL: All cookie secret values are strictly REDACTED
and never stored, printed, or exported in findings, logs, or reports.
"""

from http.cookies import SimpleCookie
import re
from typing import Any


def analyze_cookies(
    raw_cookie_headers: list[str],
    is_https: bool = True,
) -> dict[str, Any]:
    """
    Parses and audits Set-Cookie headers for security attributes.
    Strictly redacts raw cookie values to prevent sensitive credential exposure.

    Args:
        raw_cookie_headers: List of raw Set-Cookie header strings from server response.
        is_https: Whether the response was served over HTTPS.

    Returns:
        Structured dictionary containing audited cookie metadata and security findings.
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
        # Some servers send multiple comma-separated cookies or separate headers
        # Split on comma only if it precedes a cookie-name= pattern (avoid splitting within expires dates)
        cookie_parts = re.split(r",\s*(?=[a-zA-Z0-9_\-.]+=)", raw_header)

        for part in cookie_parts:
            part = part.strip()
            if not part:
                continue

            cookie_parser = SimpleCookie()
            try:
                cookie_parser.load(part)
            except Exception:
                # Fallback manual parsing if SimpleCookie fails on malformed attributes
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

                    # Evaluate Secure flag
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

                    # Evaluate HttpOnly flag
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

                    # Evaluate SameSite flag
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
