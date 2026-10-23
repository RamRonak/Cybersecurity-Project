"""
TLS and HTTPS Assessment Module for SecureScan.
Safely queries TLS certificate metadata, validates transport security,
checks HTTP to HTTPS upgrade redirection, and verifies certificate lifetime.
"""

from datetime import datetime, timezone
import socket
import ssl
from typing import Any
from urllib.parse import urlsplit


def assess_tls_configuration(
    initial_url: str,
    final_url: str,
    redirect_history: list[dict[str, Any]],
    timeout: int = 5,
) -> dict[str, Any]:
    """
    Evaluates TLS enforcement, HTTPS adoption, and retrieves certificate validity details.

    Args:
        initial_url: Original user-requested target URL.
        final_url: Destination URL after following verified redirects.
        redirect_history: Hop-by-hop list of redirects followed.
        timeout: Socket connection timeout in seconds.

    Returns:
        Structured dictionary detailing HTTPS status, redirection, and certificate metadata.
    """
    parsed_initial = urlsplit(initial_url)
    parsed_final = urlsplit(final_url)

    is_https_initial = parsed_initial.scheme.lower() == "https"
    is_https_final = parsed_final.scheme.lower() == "https"

    # Determine if HTTP redirected to HTTPS safely
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

    # If the endpoint does not support HTTPS or terminates on plain HTTP
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

    # Attempt standard TLS connection using default security context
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
                    # Parse subject and issuer
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

                    # Parse expiration and calculate days remaining
                    not_after = cert.get("notAfter")
                    not_before = cert.get("notBefore")

                    if not_after:
                        # Format example: 'May 15 12:00:00 2026 GMT'
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
