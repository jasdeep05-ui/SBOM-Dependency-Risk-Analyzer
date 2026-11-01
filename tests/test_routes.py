"""
Tests for app/routes.py — Phase 6.

Uses Flask test client + responses library to mock OSV API calls.
All tests run against an in-memory SQLite database.
"""

import io
import json
import os

import pytest
import responses as rsps_lib

from app import create_app, db as _db
from app.models import Scan, Vulnerability

OSV_URL = "https://api.osv.dev/v1/query"

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# ---------------------------------------------------------------------------
# App and client fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def app():
    """Create a test Flask app with an in-memory SQLite database."""
    test_app = create_app("tests.test_config")
    with test_app.app_context():
        _db.create_all()
    yield test_app
    with test_app.app_context():
        _db.drop_all()


@pytest.fixture
def client(app):
    """Return a Flask test client with a fresh database for each test."""
    with app.app_context():
        _db.drop_all()
        _db.create_all()
    return app.test_client()


# ---------------------------------------------------------------------------
# Test configuration module (tests/test_config.py is created inline below)
# ---------------------------------------------------------------------------

# We create a tiny config module at import time so create_app("tests.test_config") works
import sys, types
_test_config = types.ModuleType("tests.test_config")
_test_config.SECRET_KEY = "test-secret-key"
_test_config.SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
_test_config.SQLALCHEMY_TRACK_MODIFICATIONS = False
_test_config.UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "tmp_uploads")
_test_config.EXPORT_FOLDER = os.path.join(os.path.dirname(__file__), "tmp_exports")
_test_config.MAX_CONTENT_LENGTH = 2 * 1024 * 1024
_test_config.ALLOWED_EXTENSIONS = {".txt", ".json"}
_test_config.CORS_ALLOWED_ORIGINS = []
_test_config.DEBUG = False
sys.modules["tests.test_config"] = _test_config
os.makedirs(_test_config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(_test_config.EXPORT_FOLDER, exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _upload(client, filename, content, field="file"):
    """POST a file to /api/scan and return the response."""
    data = {field: (io.BytesIO(content.encode()), filename)}
    return client.post("/api/scan", data=data, content_type="multipart/form-data")


def _mock_osv_empty():
    """Register a mock OSV response returning zero vulnerabilities."""
    rsps_lib.add(rsps_lib.POST, OSV_URL, json={"vulns": []}, status=200)


def _mock_osv_vuln():
    """Register a mock OSV response with one critical vulnerability."""
    rsps_lib.add(
        rsps_lib.POST, OSV_URL,
        json={
            "vulns": [
                {
                    "id": "GHSA-route-test-0001",
                    "summary": "Critical route test vuln",
                    "details": "A critical vulnerability.",
                    "published": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-15T00:00:00Z",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "affected": [
                        {
                            "package": {"name": "flask", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "3.1.0"}],
                                }
                            ],
                        }
                    ],
                    "references": [{"type": "WEB", "url": "https://example.com/advisory/1"}],
                }
            ]
        },
        status=200,
    )


SIMPLE_REQUIREMENTS = "flask==3.0.3\nrequests>=2.28\n"
SIMPLE_PACKAGE_JSON = json.dumps({
    "dependencies": {"express": "4.18.2", "lodash": "^4.17.21"}
})


# ===========================================================================
# GET /
# ===========================================================================

class TestIndex:
    def test_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_returns_json(self, client):
        r = client.get("/")
        assert r.content_type.startswith("application/json")

    def test_contains_application_key(self, client):
        data = r = client.get("/")
        assert "application" in r.get_json()


# ===========================================================================
# GET /health
# ===========================================================================

class TestHealth:
    def test_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_status_ok(self, client):
        r = client.get("/health")
        assert r.get_json()["status"] == "ok"


# ===========================================================================
# POST /api/scan — validation
# ===========================================================================

class TestScanValidation:
    def test_no_file_returns_400(self, client):
        r = client.post("/api/scan")
        assert r.status_code == 400
        assert "error" in r.get_json()

    def test_wrong_field_name_returns_400(self, client):
        data = {"upload": (io.BytesIO(b"flask==1.0"), "requirements.txt")}
        r = client.post("/api/scan", data=data, content_type="multipart/form-data")
        assert r.status_code == 400

    def test_unsupported_extension_returns_400(self, client):
        r = _upload(client, "deps.csv", "flask,1.0")
        assert r.status_code == 400
        assert "Unsupported file type" in r.get_json()["error"]

    def test_empty_file_content(self, client):
        r = _upload(client, "requirements.txt", "")
        assert r.status_code == 400

    def test_only_comments_returns_400(self, client):
        r = _upload(client, "requirements.txt", "# just a comment\n")
        assert r.status_code == 400

    def test_invalid_json_returns_400(self, client):
        r = _upload(client, "package.json", "{ not valid json")
        assert r.status_code == 400

    def test_json_array_returns_400(self, client):
        r = _upload(client, "package.json", "[1, 2, 3]")
        assert r.status_code == 400


# ===========================================================================
# POST /api/scan — successful scan
# ===========================================================================

class TestScanSuccess:
    @rsps_lib.activate
    def test_returns_201(self, client):
        _mock_osv_empty()
        r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        assert r.status_code == 201

    @rsps_lib.activate
    def test_response_has_scan_id(self, client):
        _mock_osv_empty()
        r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        assert "scan_id" in r.get_json()

    @rsps_lib.activate
    def test_response_has_risk_score(self, client):
        _mock_osv_empty()
        r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        data = r.get_json()
        assert "risk_score" in data
        assert "risk_category" in data

    @rsps_lib.activate
    def test_response_has_vulnerability_counts(self, client):
        _mock_osv_empty()
        r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        data = r.get_json()
        assert "vulnerability_counts" in data
        vc = data["vulnerability_counts"]
        for key in ("critical", "high", "medium", "low", "unknown", "total"):
            assert key in vc

    @rsps_lib.activate
    def test_response_has_score_label(self, client):
        _mock_osv_empty()
        r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        assert "score_label" in r.get_json()
        assert "Custom Project Risk Score" in r.get_json()["score_label"]

    @rsps_lib.activate
    def test_response_has_sbom_url(self, client):
        _mock_osv_empty()
        r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        data = r.get_json()
        assert "sbom_available" in data

    @rsps_lib.activate
    def test_scan_persisted_in_db(self, client, app):
        _mock_osv_empty()
        r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        scan_id = r.get_json()["scan_id"]
        with app.app_context():
            scan = _db.session.get(Scan, scan_id)
            assert scan is not None
            assert scan.filename == "requirements.txt"

    @rsps_lib.activate
    def test_package_json_scan(self, client):
        _mock_osv_empty()
        r = _upload(client, "package.json", SIMPLE_PACKAGE_JSON)
        assert r.status_code == 201
        data = r.get_json()
        assert data["ecosystem"] == "npm"

    @rsps_lib.activate
    def test_vulnerability_found(self, client):
        _mock_osv_vuln()
        r = _upload(client, "requirements.txt", "flask==3.0.3\n")
        data = r.get_json()
        assert data["vulnerability_counts"]["critical"] >= 1
        assert data["has_vulnerabilities"] is True

    @rsps_lib.activate
    def test_skipped_deps_reported(self, client):
        _mock_osv_empty()
        r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        data = r.get_json()
        # requests>=2.28 is a range — should appear in skipped_deps
        assert "skipped_deps" in data
        assert data["skipped_deps"] >= 0


# ===========================================================================
# GET /api/scan/<scan_id>
# ===========================================================================

class TestGetScan:
    @rsps_lib.activate
    def test_returns_scan_detail(self, client):
        _mock_osv_empty()
        create_r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        scan_id = create_r.get_json()["scan_id"]
        r = client.get(f"/api/scan/{scan_id}")
        assert r.status_code == 200
        data = r.get_json()
        assert data["id"] == scan_id

    def test_unknown_id_returns_404(self, client):
        r = client.get("/api/scan/99999")
        assert r.status_code == 404
        assert "error" in r.get_json()

    @rsps_lib.activate
    def test_includes_vulnerabilities_key(self, client):
        _mock_osv_empty()
        create_r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        scan_id = create_r.get_json()["scan_id"]
        r = client.get(f"/api/scan/{scan_id}")
        assert "vulnerabilities" in r.get_json()


# ===========================================================================
# GET /api/scans
# ===========================================================================

class TestListScans:
    def test_empty_list(self, client):
        r = client.get("/api/scans")
        assert r.status_code == 200
        assert r.get_json() == []

    @rsps_lib.activate
    def test_returns_list_after_scan(self, client):
        _mock_osv_empty()
        _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        r = client.get("/api/scans")
        data = r.get_json()
        assert isinstance(data, list)
        assert len(data) >= 1

    @rsps_lib.activate
    def test_summary_fields_present(self, client):
        _mock_osv_empty()
        _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        r = client.get("/api/scans")
        scan = r.get_json()[0]
        for key in ("id", "filename", "ecosystem", "created_at", "risk_score"):
            assert key in scan


# ===========================================================================
# GET /api/scan/<scan_id>/sbom
# ===========================================================================

class TestGetSbom:
    @rsps_lib.activate
    def test_returns_sbom(self, client):
        _mock_osv_empty()
        create_r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        scan_id = create_r.get_json()["scan_id"]
        r = client.get(f"/api/scan/{scan_id}/sbom")
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("bomFormat") == "CycloneDX"

    def test_unknown_scan_sbom_404(self, client):
        r = client.get("/api/scan/99999/sbom")
        assert r.status_code == 404


# ===========================================================================
# DELETE /api/scan/<scan_id>
# ===========================================================================

class TestDeleteScan:
    @rsps_lib.activate
    def test_delete_existing_scan(self, client, app):
        _mock_osv_empty()
        create_r = _upload(client, "requirements.txt", SIMPLE_REQUIREMENTS)
        scan_id = create_r.get_json()["scan_id"]

        r = client.delete(f"/api/scan/{scan_id}")
        assert r.status_code == 200
        assert "deleted" in r.get_json()["message"].lower()

        with app.app_context():
            assert _db.session.get(Scan, scan_id) is None

    def test_delete_nonexistent_returns_404(self, client):
        r = client.delete("/api/scan/99999")
        assert r.status_code == 404

    @rsps_lib.activate
    def test_vulnerabilities_cascade_deleted(self, client, app):
        _mock_osv_vuln()
        create_r = _upload(client, "requirements.txt", "flask==3.0.3\n")
        scan_id = create_r.get_json()["scan_id"]

        client.delete(f"/api/scan/{scan_id}")

        with app.app_context():
            vuln_count = Vulnerability.query.filter_by(scan_id=scan_id).count()
            assert vuln_count == 0


# ===========================================================================
# Error handling
# ===========================================================================

class TestErrorHandling:
    @rsps_lib.activate
    def test_osv_failure_still_returns_scan(self, client):
        """A scan where OSV fails should still produce a result, not a 500."""
        import requests as req_lib
        rsps_lib.add(
            rsps_lib.POST, OSV_URL,
            body=req_lib.exceptions.ConnectionError("Network down"),
        )
        r = _upload(client, "requirements.txt", "flask==3.0.3\n")
        # Should succeed with a scan showing error_deps
        assert r.status_code == 201
        data = r.get_json()
        assert data["error_deps"] >= 1

    @rsps_lib.activate
    def test_insufficient_coverage_flagged(self, client):
        """All-skipped deps should set insufficient_coverage=True."""
        # Only range deps — OSV never called
        r = _upload(client, "requirements.txt", "flask>=3.0\nrequests>=2.0\n")
        assert r.status_code == 201
        data = r.get_json()
        assert data["insufficient_coverage"] is True
