"""
Tests for app/report_generator.py — Phase 9.

Uses lightweight mock Scan / Vulnerability objects so the report generator
can be exercised without touching the database.
"""

import csv
import io
import os
import tempfile
import types
from datetime import datetime, timezone

import pytest

from app.report_generator import generate_pdf, generate_csv


# ---------------------------------------------------------------------------
# Minimal mock objects (no DB required)
# ---------------------------------------------------------------------------

def _make_scan(
    scan_id=1,
    filename="requirements.txt",
    ecosystem="PyPI",
    risk_score=45,
    risk_grade="C",
    risk_grade_label="Medium",
    total_deps=5,
    scanned_deps=4,
    skipped_deps=1,
    error_deps=0,
    vulnerabilities=None,
):
    s = types.SimpleNamespace()
    s.id = scan_id
    s.filename = filename
    s.ecosystem = ecosystem
    s.created_at = datetime(2024, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
    s.risk_score = risk_score
    s.risk_grade = risk_grade
    s.risk_grade_label = risk_grade_label
    s.total_deps = total_deps
    s.scanned_deps = scanned_deps
    s.skipped_deps = skipped_deps
    s.error_deps = error_deps
    s.vulnerabilities = vulnerabilities or []
    return s


def _make_vuln(
    vuln_id="GHSA-test-0001",
    package_name="flask",
    version="2.0.0",
    severity="High",
    cvss_score=7.5,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    fixed_version="2.3.0",
    recommendation="Upgrade to flask>=2.3.0",
    scan_status="scanned",
    title="Test vulnerability",
    description="A test vulnerability description.",
    error_message=None,
):
    v = types.SimpleNamespace()
    v.vuln_id = vuln_id
    v.package_name = package_name
    v.version = version
    v.severity = severity
    v.cvss_score = cvss_score
    v.cvss_vector = cvss_vector
    v.fixed_version = fixed_version
    v.recommendation = recommendation
    v.scan_status = scan_status
    v.title = title
    v.description = description
    v.error_message = error_message
    return v


# ---------------------------------------------------------------------------
# Fixture: temporary export directory
# ---------------------------------------------------------------------------

@pytest.fixture
def export_dir(tmp_path):
    """A temporary directory that is cleaned up after each test."""
    d = tmp_path / "exports"
    d.mkdir()
    return str(d)


# ===========================================================================
# PDF — file creation
# ===========================================================================

class TestGeneratePDF:
    def test_returns_filepath(self, export_dir):
        scan = _make_scan()
        path = generate_pdf(scan, [], export_dir)
        assert isinstance(path, str)

    def test_file_exists(self, export_dir):
        scan = _make_scan()
        path = generate_pdf(scan, [], export_dir)
        assert os.path.isfile(path)

    def test_file_non_empty(self, export_dir):
        scan = _make_scan()
        path = generate_pdf(scan, [], export_dir)
        assert os.path.getsize(path) > 0

    def test_filename_includes_scan_id(self, export_dir):
        scan = _make_scan(scan_id=42)
        path = generate_pdf(scan, [], export_dir)
        assert "42" in os.path.basename(path)

    def test_pdf_magic_bytes(self, export_dir):
        """PDF files start with the %PDF magic bytes."""
        scan = _make_scan()
        path = generate_pdf(scan, [], export_dir)
        with open(path, "rb") as fh:
            header = fh.read(4)
        assert header == b"%PDF"

    def test_pdf_with_vulnerabilities(self, export_dir):
        vuln = _make_vuln()
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_pdf(scan, [vuln], export_dir)
        assert os.path.getsize(path) > 1000

    def test_pdf_all_severities(self, export_dir):
        """PDF generation succeeds for every severity level."""
        vulns = [
            _make_vuln("GHSA-crit", severity="Critical", cvss_score=9.8),
            _make_vuln("GHSA-high", severity="High", cvss_score=7.5),
            _make_vuln("GHSA-med",  severity="Medium", cvss_score=4.3),
            _make_vuln("GHSA-low",  severity="Low",    cvss_score=2.1),
            _make_vuln("GHSA-unk",  severity="Unknown", cvss_score=None),
        ]
        scan = _make_scan(vulnerabilities=vulns)
        path = generate_pdf(scan, vulns, export_dir)
        assert os.path.isfile(path)
        assert os.path.getsize(path) > 0

    def test_pdf_zero_vulns_produces_file(self, export_dir):
        scan = _make_scan(scanned_deps=3, vulnerabilities=[])
        path = generate_pdf(scan, [], export_dir)
        assert os.path.isfile(path)

    def test_pdf_none_fields_handled(self, export_dir):
        """Gracefully handles vuln rows with None optional fields."""
        vuln = _make_vuln(
            cvss_score=None,
            cvss_vector=None,
            fixed_version=None,
            recommendation=None,
        )
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_pdf(scan, [vuln], export_dir)
        assert os.path.isfile(path)

    def test_pdf_creates_export_dir_if_missing(self, tmp_path):
        """generate_pdf creates the export folder when it does not exist."""
        missing_dir = str(tmp_path / "does_not_exist" / "exports")
        scan = _make_scan()
        path = generate_pdf(scan, [], missing_dir)
        assert os.path.isfile(path)

    def test_pdf_grade_a_scan(self, export_dir):
        scan = _make_scan(risk_score=0, risk_grade="A", risk_grade_label="No known risk detected")
        path = generate_pdf(scan, [], export_dir)
        assert os.path.isfile(path)

    def test_pdf_grade_f_scan(self, export_dir):
        vulns = [_make_vuln(severity="Critical", cvss_score=9.8)] * 5
        scan = _make_scan(risk_score=100, risk_grade="F", risk_grade_label="Critical",
                          vulnerabilities=vulns)
        path = generate_pdf(scan, vulns, export_dir)
        assert os.path.isfile(path)


# ===========================================================================
# CSV — file creation and content
# ===========================================================================

class TestGenerateCSV:
    def test_returns_filepath(self, export_dir):
        scan = _make_scan()
        path = generate_csv(scan, [], export_dir)
        assert isinstance(path, str)

    def test_file_exists(self, export_dir):
        scan = _make_scan()
        path = generate_csv(scan, [], export_dir)
        assert os.path.isfile(path)

    def test_file_non_empty(self, export_dir):
        scan = _make_scan()
        path = generate_csv(scan, [], export_dir)
        assert os.path.getsize(path) > 0

    def test_filename_includes_scan_id(self, export_dir):
        scan = _make_scan(scan_id=7)
        path = generate_csv(scan, [], export_dir)
        assert "7" in os.path.basename(path)

    def test_csv_has_correct_headers(self, export_dir):
        scan = _make_scan()
        path = generate_csv(scan, [], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            headers = reader.fieldnames
        expected = [
            "Package", "Version", "Ecosystem", "Vuln ID",
            "Severity", "CVSS Score", "CVSS Vector",
            "Fixed Version", "Recommendation", "Scan Status",
        ]
        assert headers == expected

    def test_csv_zero_vulns_has_one_data_row(self, export_dir):
        """A clean scan produces exactly one data row (informational)."""
        scan = _make_scan()
        path = generate_csv(scan, [], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 1

    def test_csv_zero_vulns_informational_message(self, export_dir):
        scan = _make_scan()
        path = generate_csv(scan, [], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            row = list(csv.DictReader(fh))[0]
        assert "No vulnerable" in row["Recommendation"] or row["Vuln ID"] == "None found"

    def test_csv_one_vuln_correct_row_count(self, export_dir):
        vuln = _make_vuln()
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_csv(scan, [vuln], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 1

    def test_csv_multiple_vulns_correct_row_count(self, export_dir):
        vulns = [
            _make_vuln("GHSA-0001", package_name="pkg-a"),
            _make_vuln("GHSA-0002", package_name="pkg-b"),
            _make_vuln("GHSA-0003", package_name="pkg-c"),
        ]
        scan = _make_scan(vulnerabilities=vulns)
        path = generate_csv(scan, vulns, export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 3

    def test_csv_row_contains_vuln_id(self, export_dir):
        vuln = _make_vuln(vuln_id="GHSA-test-csv-id")
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_csv(scan, [vuln], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows[0]["Vuln ID"] == "GHSA-test-csv-id"

    def test_csv_row_contains_package_name(self, export_dir):
        vuln = _make_vuln(package_name="mypackage")
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_csv(scan, [vuln], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows[0]["Package"] == "mypackage"

    def test_csv_row_contains_severity(self, export_dir):
        vuln = _make_vuln(severity="Critical")
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_csv(scan, [vuln], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows[0]["Severity"] == "Critical"

    def test_csv_row_contains_fixed_version(self, export_dir):
        vuln = _make_vuln(fixed_version="3.0.0")
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_csv(scan, [vuln], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows[0]["Fixed Version"] == "3.0.0"

    def test_csv_row_none_fields_show_dash(self, export_dir):
        """None optional fields are rendered as '—' not 'None'."""
        vuln = _make_vuln(cvss_score=None, cvss_vector=None, fixed_version=None)
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_csv(scan, [vuln], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows[0]["CVSS Score"] == "—"
        assert rows[0]["CVSS Vector"] == "—"
        assert rows[0]["Fixed Version"] == "—"

    def test_csv_ecosystem_from_scan(self, export_dir):
        """Ecosystem column is taken from the Scan record."""
        vuln = _make_vuln()
        scan = _make_scan(ecosystem="npm", vulnerabilities=[vuln])
        path = generate_csv(scan, [vuln], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows[0]["Ecosystem"] == "npm"

    def test_csv_utf8_encoded(self, export_dir):
        """CSV file is valid UTF-8."""
        vuln = _make_vuln()
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_csv(scan, [vuln], export_dir)
        with open(path, "rb") as fh:
            raw = fh.read()
        raw.decode("utf-8")  # raises if not valid UTF-8

    def test_csv_creates_export_dir_if_missing(self, tmp_path):
        """generate_csv creates the export folder when it does not exist."""
        missing_dir = str(tmp_path / "does_not_exist" / "exports")
        scan = _make_scan()
        path = generate_csv(scan, [], missing_dir)
        assert os.path.isfile(path)

    def test_csv_recommendation_present(self, export_dir):
        vuln = _make_vuln(recommendation="Upgrade to flask>=2.3.0")
        scan = _make_scan(vulnerabilities=[vuln])
        path = generate_csv(scan, [vuln], export_dir)
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows[0]["Recommendation"] == "Upgrade to flask>=2.3.0"
