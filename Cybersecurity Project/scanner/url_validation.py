"""
URL Validation Module for SecureScan.
Enforces strict RFC-compliant parsing, disallows embedded credentials,
filters forbidden schemes, and normalizes URLs prior to network interaction.
"""

import re
from urllib.parse import urlsplit, urlunsplit


# Regex for valid RFC 1123 domain names / labels
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Allowed protocols for safe web security assessment
PERMITTED_SCHEMES = {"http", "https"}

# Safe standard web ports allowed for assessment
PERMITTED_PORTS = {80, 443, 8080, 8443}


class URLValidationError(ValueError):
    """Raised when a URL violates security or formatting policies."""
    pass


def validate_target_url(raw_url: str, allow_custom_ports: bool = True) -> tuple[bool, str, dict]:
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
    # Exclude default ports from netloc to normalize
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
        ""  # Fragments are not sent over HTTP
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
