"""
Safe HTTP Client Module for SecureScan.
Executes defensive HTTP/HTTPS requests with conservative timeouts, response size limits,
manual redirect verification against SSRF, and strict TLS enforcement.
"""

import time
from typing import Any
from urllib.parse import urlsplit
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import Config
from scanner.network_safety import (
    resolve_and_validate_hostname,
    validate_redirect_target,
)


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

        # Configure session without automated redirects (we handle redirects manually)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": Config.SCANNER_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.session.trust_env = False  # Ignore system proxies unless explicitly intended

    def request_target(self, target_url: str) -> dict[str, Any]:
        """
        Executes a safe GET request to the target URL, verifying DNS and SSRF
        at each step and re-validating any HTTP redirects.

        Returns:
            Dictionary containing response metadata, headers, timing, and error details.
        """
        current_url = target_url
        redirect_history: list[dict[str, Any]] = []
        hop_count = 0

        parsed = urlsplit(current_url)
        initial_hostname = parsed.hostname or ""

        # Pre-flight DNS & SSRF validation on the initial target
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
                # Perform single HTTP request with allow_redirects=False
                resp = self.session.get(
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True,  # Stream to enforce size limit before downloading large body
                    verify=True,  # Never disable TLS verification
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
            except requests.exceptions.Timeout as exc:
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

            # Check if response is a redirect (301, 302, 303, 307, 308)
            if resp.is_redirect or resp.status_code in {301, 302, 303, 307, 308}:
                location = resp.headers.get("Location")
                redirect_history.append({
                    "hop": hop_count + 1,
                    "from_url": current_url,
                    "status_code": resp.status_code,
                    "location_header": location,
                })

                if not location:
                    # Missing Location header on redirect status; treat as terminal
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

                # Validate the redirect target URL and its destination IP
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

            # Terminal response reached
            break

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Read only up to max_bytes to safeguard memory
        try:
            raw_content = b""
            for chunk in resp.iter_content(chunk_size=4096):
                raw_content += chunk
                if len(raw_content) >= self.max_bytes:
                    break
        except Exception:
            pass
        finally:
            resp.close()

        # Extract raw Set-Cookie headers for accurate cookie inspection
        # Requests collapses multiple Set-Cookie headers into single strings or cookies jar
        raw_cookie_headers = []
        if "Set-Cookie" in resp.headers:
            raw_cookie_headers.append(resp.headers["Set-Cookie"])
        # Also inspect raw response headers if available from urllib3
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
