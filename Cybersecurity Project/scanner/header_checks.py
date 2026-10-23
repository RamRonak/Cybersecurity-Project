"""
HTTP Security Header Analyzer Module for SecureScan.
Inspects response headers for Content-Security-Policy, HSTS, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, and Permissions-Policy.
Evaluates observed values rather than merely verifying header presence.
"""

import re
from typing import Any


def analyze_security_headers(headers: dict[str, str], is_https: bool = True) -> dict[str, Any]:
    """
    Analyzes HTTP response headers against modern security configuration standards.

    Args:
        headers: Case-insensitive dictionary of HTTP response headers.
        is_https: Whether the response was delivered over HTTPS.

    Returns:
        Structured dictionary of header assessment results and findings details.
    """
    # Normalize headers to lowercase keys for case-insensitive lookup
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
            elif max_age < 15724800:  # 6 months
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
            details = "Correctly configured to 'nosniff'."
        else:
            status = "Review Recommended"
            severity = "Low"
            issues = [f"Observed value '{xcto_val}' is invalid; must be 'nosniff'."]
            details = f"Invalid directive '{xcto_val}'. Expected 'nosniff'."

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
        # If CSP has frame-ancestors, modern browsers use frame-ancestors instead of X-Frame-Options
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
