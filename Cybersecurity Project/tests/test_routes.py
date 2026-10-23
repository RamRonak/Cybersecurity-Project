"""
Integration tests for Flask application routes and workflows in SecureScan.
"""

from unittest.mock import patch
import pytest
from app import create_app
from config import TestingConfig


@pytest.fixture
def client():
    """Configures a test client for the Flask app."""
    app = create_app(TestingConfig)
    with app.test_client() as client:
        with app.app_context():
            yield client


class TestFlaskRoutes:
    """Tests covering all web routes and HTTP workflows."""

    def test_dashboard_route(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Automated Web Security Scanner" in resp.data
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"

    def test_demo_page_route(self, client):
        resp = client.get("/demo")
        assert resp.status_code == 200
        assert b"Safe Local Demonstration Laboratory" in resp.data
        assert b"Hardened Enterprise" in resp.data

    def test_run_demo_scenario_and_view_results(self, client):
        # Trigger offline demo scenario
        resp = client.get("/demo/run/hardened", follow_redirects=True)
        assert resp.status_code == 200
        assert b"secure-demo.internal" in resp.data
        assert b"Simulated Offline Test Fixture" in resp.data
        assert b"grade-A" in resp.data
        assert b"Strong Security Posture" in resp.data

    def test_download_pdf_report(self, client):
        # Trigger offline demo scenario first
        resp = client.get("/demo/run/hardened")
        assert resp.status_code == 302
        scan_id = resp.headers["Location"].split("/")[-1]

        # Request PDF
        pdf_resp = client.get(f"/reports/{scan_id}/pdf")
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["Content-Type"] == "application/pdf"
        assert pdf_resp.data.startswith(b"%PDF-")

    def test_scan_unauthorized_rejected(self, client):
        # First GET / to initialize CSRF token in session
        client.get("/")
        with client.session_transaction() as sess:
            csrf_token = sess.get("_csrf_token")

        resp = client.post(
            "/scan",
            data={
                "csrf_token": csrf_token,
                "target_url": "https://example.com",
                # Omit auth_confirm
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Authorization confirmation is mandatory" in resp.data

    def test_scan_ssrf_destination_blocked(self, client):
        client.get("/")
        with client.session_transaction() as sess:
            csrf_token = sess.get("_csrf_token")

        # Scan attempt toward loopback address
        resp = client.post(
            "/scan",
            data={
                "csrf_token": csrf_token,
                "target_url": "http://127.0.0.1:8080/admin",
                "auth_confirm": "on",
                "timeout": "4",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert (
            b"disallowed" in resp.data.lower()
            or b"loopback" in resp.data.lower()
            or b"forbidden" in resp.data.lower()
            or b"error" in resp.data.lower()
        )

    def test_history_page_and_clear_action(self, client):
        # Run a demo scenario to populate history
        client.get("/demo/run/legacy")

        resp = client.get("/history")
        assert resp.status_code == 200
        assert b"legacy-portal.internal" in resp.data

        # Clear history
        with client.session_transaction() as sess:
            csrf_token = sess.get("_csrf_token")

        clear_resp = client.post(
            "/history/clear",
            data={"csrf_token": csrf_token},
            follow_redirects=True,
        )
        assert clear_resp.status_code == 200
        assert b"No Scan Records in Memory" in clear_resp.data

    def test_about_page_route(self, client):
        resp = client.get("/about")
        assert resp.status_code == 200
        assert b"SecureScan Technical Documentation" in resp.data
        assert b"Content-Security-Policy" in resp.data
        assert b"Strict-Transport-Security" in resp.data

    def test_nonexistent_scan_returns_404(self, client):
        resp = client.get("/results/UNKNOWN-ID-999")
        assert resp.status_code == 404
        assert b"Resource Not Found" in resp.data or b"404" in resp.data
