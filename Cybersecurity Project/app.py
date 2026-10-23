"""
SecureScan — Automated Web Security Scanner
Main Flask Application Entry Point.
"""

from io import BytesIO
import os
import secrets
from typing import Any
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from config import Config
from reports.pdf_generator import generate_security_pdf
from scanner.demo_fixtures import DEMO_SCENARIOS, run_demo_fixture_scan
from scanner.scan_service import scan_service


def create_app(config_class=Config) -> Flask:
    """Application factory for SecureScan."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # -------------------------------------------------------------------------
    # CSRF Token Protection Mechanism
    # -------------------------------------------------------------------------
    def get_csrf_token() -> str:
        """Generates or retrieves the per-session CSRF token."""
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(24)
        return session["_csrf_token"]

    app.jinja_env.globals["csrf_token"] = get_csrf_token

    def validate_csrf():
        """Validates the CSRF token on mutating HTTP methods."""
        if request.method in ("POST", "PUT", "DELETE"):
            client_token = request.form.get("csrf_token")
            session_token = session.get("_csrf_token")
            if not client_token or not session_token or not secrets.compare_digest(client_token, session_token):
                abort(400, description="Invalid or missing CSRF security token.")

    # -------------------------------------------------------------------------
    # Defense-in-Depth Response Headers
    # -------------------------------------------------------------------------
    @app.after_request
    def apply_security_headers(response):
        """Applies essential security headers to all SecureScan responses."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Prevent caching of scan results containing target telemetry
        if request.path.startswith("/results") or request.path.startswith("/reports"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

    # -------------------------------------------------------------------------
    # Application Routes
    # -------------------------------------------------------------------------
    @app.route("/", methods=["GET"])
    def index():
        """Landing dashboard: scan launch form, session metrics, and methodology."""
        history = scan_service.get_history()

        # Compute current session aggregate findings
        total_scans = len(history)
        high_cnt = sum(item.get("high_count", 0) for item in history)
        med_cnt = sum(item.get("medium_count", 0) for item in history)
        low_cnt = sum(item.get("low_count", 0) for item in history)

        session_metrics = {
            "total_scans": total_scans,
            "high": high_cnt,
            "medium": med_cnt,
            "low": low_cnt,
        }

        return render_template("index.html", session_metrics=session_metrics)

    @app.route("/scan", methods=["POST"])
    def initiate_scan():
        """Validates target URL and executes a defensive security assessment."""
        validate_csrf()

        target_url = request.form.get("target_url", "").strip()
        auth_confirm = bool(request.form.get("auth_confirm"))
        timeout_raw = request.form.get("timeout", str(Config.DEFAULT_TIMEOUT_SECONDS))
        scan_profile = request.form.get("scan_profile", "standard_passive")

        if not auth_confirm:
            flash(
                "Authorization confirmation is mandatory. You must confirm permission before scanning.",
                "error",
            )
            return redirect(url_for("index"))

        try:
            timeout = int(timeout_raw)
        except ValueError:
            timeout = Config.DEFAULT_TIMEOUT_SECONDS

        # Execute scan via ScanService
        result = scan_service.run_scan(
            raw_url=target_url,
            is_authorized=auth_confirm,
            timeout=timeout,
            scan_profile=scan_profile,
        )

        if not result.get("success"):
            flash(result.get("error_message", "Failed to complete security assessment."), "error")
            # If scan was saved with scan_id in history, allow viewing the failure report
            if result.get("scan_id") and result.get("status") == "SCAN_FAILED":
                return redirect(url_for("view_results", scan_id=result["scan_id"]))
            return redirect(url_for("index"))

        return redirect(url_for("view_results", scan_id=result["scan_id"]))

    @app.route("/results/<scan_id>", methods=["GET"])
    def view_results(scan_id: str):
        """Displays detailed audit findings, headers, TLS assessment, and remediation."""
        scan = scan_service.get_scan(scan_id)
        if not scan:
            abort(404, description=f"Scan record '{scan_id}' not found in active session memory.")
        return render_template("scan_results.html", scan=scan)

    @app.route("/demo", methods=["GET"])
    def demo_page():
        """Displays the safe offline demonstration scenarios."""
        return render_template("demo.html", scenarios=DEMO_SCENARIOS)

    @app.route("/demo/run/<scenario_id>", methods=["GET"])
    def run_demo_scenario(scenario_id: str):
        """Triggers an offline simulated test fixture and displays the report."""
        try:
            demo_result = run_demo_fixture_scan(scenario_id)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("demo_page"))

        # Save to history so it can be viewed and downloaded as PDF
        scan_service._save_to_history(demo_result)
        return redirect(url_for("view_results", scan_id=demo_result["scan_id"]))

    @app.route("/reports/<scan_id>/pdf", methods=["GET"])
    def download_pdf_report(scan_id: str):
        """Generates and downloads a ReportLab PDF security audit report."""
        scan = scan_service.get_scan(scan_id)
        if not scan:
            abort(404, description=f"Scan record '{scan_id}' not found.")

        try:
            pdf_bytes = generate_security_pdf(scan)
        except Exception as exc:
            flash(f"Failed to generate PDF report: {exc}", "error")
            return redirect(url_for("view_results", scan_id=scan_id))

        safe_hostname = scan.get("hostname", "Target").replace(".", "_")
        filename = f"SecureScan_Report_{safe_hostname}_{scan_id}.pdf"

        return send_file(
            BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )

    @app.route("/history", methods=["GET"])
    def history_page():
        """Lists recent scans conducted in the current session."""
        history = scan_service.get_history()
        return render_template("history.html", history=history)

    @app.route("/history/clear", methods=["POST"])
    def clear_history_action():
        """Clears stored scan records from session memory."""
        validate_csrf()
        scan_service.clear_history()
        flash("Scan history cleared successfully.", "success")
        return redirect(url_for("history_page"))

    @app.route("/about", methods=["GET"])
    def about_page():
        """Technical documentation, OWASP references, and ethical guidelines."""
        return render_template("about.html")

    # -------------------------------------------------------------------------
    # Error Handlers
    # -------------------------------------------------------------------------
    @app.errorhandler(400)
    def bad_request_error(error):
        return (
            render_template(
                "error.html",
                error_code=400,
                error_title="Bad Request",
                error_message=str(error.description if hasattr(error, "description") else error),
            ),
            400,
        )

    @app.errorhandler(404)
    def not_found_error(error):
        return (
            render_template(
                "error.html",
                error_code=404,
                error_title="Resource Not Found",
                error_message=str(error.description if hasattr(error, "description") else "The requested page or scan record does not exist."),
            ),
            404,
        )

    @app.errorhandler(500)
    def internal_server_error(error):
        return (
            render_template(
                "error.html",
                error_code=500,
                error_title="Internal Processing Error",
                error_message="An internal error occurred while processing the request. Technical details have been logged securely.",
            ),
            500,
        )

    return app


# Application instance for development / WSGI
app = create_app()


if __name__ == "__main__":
    # Standard entry point for local execution
    app.run(host="127.0.0.1", port=5000, debug=True)
