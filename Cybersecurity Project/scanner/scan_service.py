"""
Scan Orchestrator Service for SecureScan.
Coordinates target validation, safe HTTP execution, TLS checks, header analysis,
CORS inspection, cookie reviews, and history persistence.
"""

from datetime import datetime, timezone
import threading
import time
from typing import Any
import uuid

from config import Config
from scanner.cookie_checks import analyze_cookies
from scanner.cors_checks import analyze_cors_configuration
from scanner.findings import compile_scan_findings
from scanner.header_checks import analyze_security_headers
from scanner.http_client import SafeHttpClient
from scanner.tls_checks import assess_tls_configuration
from scanner.url_validation import validate_target_url


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

        Args:
            raw_url: Website URL to scan.
            is_authorized: User confirmation that they have explicit permission to test the target.
            timeout: Network request timeout (seconds).
            scan_profile: Assessment profile identifier (passive only).

        Returns:
            Structured scan result dictionary containing all assessment data and findings.
        """
        start_time_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        t0 = time.perf_counter()
        scan_id = uuid.uuid4().hex[:12].upper()

        # Step 1: Enforce mandatory authorization confirmation
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

        # Step 2: Validate URL syntax, scheme, and credentials
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

        # Step 3: Perform safe HTTP communication (enforcing SSRF boundaries)
        client = SafeHttpClient(timeout=timeout)
        conn_res = client.request_target(normalized_url)

        # Check for connectivity or security boundary abort
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

        # Step 4: Perform TLS Assessment
        final_url = conn_res.get("final_url", normalized_url)
        tls_res = assess_tls_configuration(
            initial_url=normalized_url,
            final_url=final_url,
            redirect_history=conn_res.get("redirect_history", []),
            timeout=timeout,
        )

        # Step 5: Audit Security Headers
        headers = conn_res.get("headers", {})
        is_https_final = tls_res.get("is_https_final", False)
        header_res = analyze_security_headers(headers=headers, is_https=is_https_final)

        # Step 6: Audit CORS Configuration
        cors_res = analyze_cors_configuration(headers=headers)

        # Step 7: Audit Cookies (with strict redaction)
        raw_cookie_headers = conn_res.get("raw_cookie_headers", [])
        cookie_res = analyze_cookies(raw_cookie_headers=raw_cookie_headers, is_https=is_https_final)

        # Step 8: Compile and Score All Findings
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
            # Create a lightweight history summary entry
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


# Default global instance
scan_service = ScanService()
