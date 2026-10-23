"""
Findings and Risk Classification Engine for SecureScan.
Aggregates, standardizes, scores, and categorizes security findings
from TLS, headers, CORS, cookies, and connectivity assessments.
"""

from dataclasses import asdict, dataclass
from typing import Any


SEVERITY_LEVELS = ("High", "Medium", "Low", "Informational")


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
        """Convert finding to standard JSON/serializable dictionary."""
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

    Returns:
        tuple (findings_list, summary_metrics)
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
            # Build unique ID
            slug = hdr_name.replace("Content-Security-Policy", "CSP").replace("Strict-Transport-Security", "HSTS").replace("X-Content-Type-Options", "XCTO").replace("X-Frame-Options", "XFO").replace("Referrer-Policy", "RP").replace("Permissions-Policy", "PP")
            evidence_text = f"Observed header value: '{hdr_info.get('value')}'" if hdr_info.get("value") else "Header was not returned in HTTP response headers."

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

    # Summary metric calculations
    total = len(findings)
    high = sum(1 for f in findings if f.severity == "High")
    medium = sum(1 for f in findings if f.severity == "Medium")
    low = sum(1 for f in findings if f.severity == "Low")
    info = sum(1 for f in findings if f.severity == "Informational")

    # Security Posture Score Calculation (out of 100)
    # Deductions: High = -25, Medium = -10, Low = -4, Info = 0
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
