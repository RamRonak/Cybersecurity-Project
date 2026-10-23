"""
Configuration module for SecureScan — Automated Web Security Scanner.
Defines security limits, network boundaries, timeouts, and application settings.
"""

import os
import secrets


class Config:
    """Base application configuration."""

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
        "SecureScan-Auditor/1.0 (+Defensive Web Security Scanner; Educational Assessment)"
    )

    # Allowed URL schemes
    ALLOWED_SCHEMES = {"http", "https"}

    # Disallowed destination ports (optional hardening)
    # Default allowed standard web ports
    ALLOWED_PORTS = {80, 443, 8080, 8443}


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True


class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Production environment configuration with enforced strict security."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
