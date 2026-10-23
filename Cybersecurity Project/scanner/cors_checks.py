"""
CORS Configuration Analyzer Module for SecureScan.
Safely inspects Cross-Origin Resource Sharing (CORS) response headers,
identifies permissive wildcards, evaluates credential exposure risks,
and detects overly permissive methods or headers.
"""

from typing import Any


def analyze_cors_configuration(headers: dict[str, str]) -> dict[str, Any]:
    """
    Evaluates observed CORS response headers against defensive security practices.

    Args:
        headers: Case-insensitive dictionary of HTTP response headers.

    Returns:
        Structured evaluation of observed CORS policies, potential misconfigurations, and findings.
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

    # Evaluate Access-Control-Allow-Origin
    is_wildcard_origin = acao == "*"
    is_credentials_allowed = str(acac).lower() == "true" if acac else False

    if is_wildcard_origin and is_credentials_allowed:
        # Invalid per Fetch specification, but signals dangerous developer intent
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
                "The endpoint permits any external domain ('*') to read responses. While completely normal for public CDNs, "
                "fonts, and public APIs, it should not be applied to private or authenticated internal data."
            ),
            "impact": "Any web origin can access responses from this endpoint via client-side JavaScript requests.",
            "remediation": "If this endpoint serves authenticated or sensitive data, restrict origin to approved domains.",
        })
        if risk_level != "High":
            risk_level = "Low"

    # Evaluate Allowed Methods
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

    # Evaluate Allowed Headers
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
