"""
Tests for app/scanner.py — Phase 4.

All OSV HTTP calls are mocked with the `responses` library.
No network access is required or made during these tests.
"""

import json

import pytest
import responses as rsps_lib
from responses import RequestsMock

from app.scanner import (
    STATUS_SCAN_ERROR,
    STATUS_SCANNED,
    STATUS_SKIPPED_OTHER,
    STATUS_SKIPPED_RANGE,
    STATUS_SKIPPED_UNPINNED,
    _build_recommendation,
    _cvss_score_to_label,
    _extract_fixed_version,
    _extract_references,
    _extract_severity,
    _parse_cvss2_score,
    _parse_cvss3_score,
    _query_osv,
    scan_dependencies,
)

OSV_URL = "https://api.osv.dev/v1/query"

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _exact_dep(name, version, ecosystem="PyPI"):
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": version,
        "version_specifier": f"=={version}",
        "is_exact_version": True,
        "dependency_type": "direct",
        "parsing_status": "parsed",
        "skip_reason": None,
    }

def _range_dep(name, spec=">=1.0", ecosystem="PyPI"):
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": None,
        "version_specifier": spec,
        "is_exact_version": False,
        "dependency_type": "direct",
        "parsing_status": "parsed",
        "skip_reason": None,
    }

def _unpinned_dep(name, ecosystem="PyPI"):
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": None,
        "version_specifier": "",
        "is_exact_version": False,
        "dependency_type": "direct",
        "parsing_status": "parsed",
        "skip_reason": None,
    }

def _skipped_dep(name, status="skipped_vcs"):
    return {
        "name": name,
        "ecosystem": "PyPI",
        "version": None,
        "version_specifier": "",
        "is_exact_version": False,
        "dependency_type": "direct",
        "parsing_status": status,
        "skip_reason": f"Parser skipped: {status}",
    }

OSV_VULN_WITH_CVSS3 = {
    "vulns": [
        {
            "id": "GHSA-test-1234-abcd",
            "summary": "Remote code execution in example-pkg",
            "details": "A critical vulnerability allowing RCE.",
            "published": "2024-01-15T00:00:00Z",
            "modified": "2024-02-01T00:00:00Z",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ],
            "affected": [
                {
                    "package": {"name": "example-pkg", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.0.1"},
                            ],
                        }
                    ],
                }
            ],
            "references": [
                {"type": "WEB", "url": "https://example.com/advisory/1"},
                {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
            ],
        }
    ]
}

OSV_VULN_WITH_DB_SEVERITY = {
    "vulns": [
        {
            "id": "GHSA-db-sev-test",
            "summary": "High severity via database_specific",
            "details": "Details here.",
            "published": "2024-03-01T00:00:00Z",
            "modified": "2024-03-15T00:00:00Z",
            "severity": [],
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"name": "pkg-b", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "3.1.0"}],
                        }
                    ],
                }
            ],
            "references": [],
        }
    ]
}

OSV_EMPTY = {"vulns": []}

OSV_NO_SEVERITY = {
    "vulns": [
        {
            "id": "GHSA-no-sev",
            "summary": "No severity info",
            "details": "Unknown severity.",
            "published": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "severity": [],
            "affected": [],
            "references": [],
        }
    ]
}


# ===========================================================================
# _parse_cvss3_score / _parse_cvss2_score
# ===========================================================================

class TestCvssScoreParsing:
    def test_cvss3_critical(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = _parse_cvss3_score(v)
        assert score == pytest.approx(9.8, abs=0.05)

    def test_cvss3_medium(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
        score = _parse_cvss3_score(v)
        assert score is not None
        assert 4.0 <= score < 7.0

    def test_cvss3_invalid_returns_none(self):
        assert _parse_cvss3_score("not-a-vector") is None

    def test_cvss3_empty_returns_none(self):
        assert _parse_cvss3_score("") is None

    def test_cvss3_returns_float(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = _parse_cvss3_score(v)
        assert isinstance(score, float)

    def test_cvss2_critical(self):
        v = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        score = _parse_cvss2_score(v)
        assert score == pytest.approx(10.0, abs=0.05)

    def test_cvss2_invalid_returns_none(self):
        assert _parse_cvss2_score("bad-vector") is None


# ===========================================================================
# _cvss_score_to_label
# ===========================================================================

class TestCvssScoreToLabel:
    def test_critical(self):   assert _cvss_score_to_label(9.8) == "Critical"
    def test_critical_lo(self): assert _cvss_score_to_label(9.0) == "Critical"
    def test_high(self):       assert _cvss_score_to_label(8.9) == "High"
    def test_high_lo(self):    assert _cvss_score_to_label(7.0) == "High"
    def test_medium(self):     assert _cvss_score_to_label(6.9) == "Medium"
    def test_medium_lo(self):  assert _cvss_score_to_label(4.0) == "Medium"
    def test_low(self):        assert _cvss_score_to_label(3.9) == "Low"
    def test_low_lo(self):     assert _cvss_score_to_label(0.1) == "Low"
    def test_zero(self):       assert _cvss_score_to_label(0.0) == "Unknown"


# ===========================================================================
# _extract_severity
# ===========================================================================

class TestExtractSeverity:
    def test_cvss3_extracted(self):
        record = {
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        }
        label, score, vector = _extract_severity(record)
        assert label == "Critical"
        assert isinstance(score, float)
        assert "CVSS:3.1" in vector

    def test_cvss3_preferred_over_cvss2(self):
        record = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
                {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
            ]
        }
        label, score, vector = _extract_severity(record)
        assert "CVSS:3.1" in vector

    def test_database_specific_severity_high(self):
        record = {
            "severity": [],
            "database_specific": {"severity": "HIGH"},
        }
        label, score, vector = _extract_severity(record)
        assert label == "High"
        assert score is None

    def test_database_specific_moderate_maps_to_medium(self):
        record = {
            "severity": [],
            "database_specific": {"severity": "MODERATE"},
        }
        label, score, vector = _extract_severity(record)
        assert label == "Medium"

    def test_no_severity_returns_unknown(self):
        record = {"severity": []}
        label, score, vector = _extract_severity(record)
        assert label == "Unknown"
        assert score is None
        assert vector is None

    def test_empty_record_returns_unknown(self):
        label, score, vector = _extract_severity({})
        assert label == "Unknown"

    def test_unknown_never_low(self):
        """Missing severity must never silently become Low."""
        record = {"severity": [], "database_specific": {}}
        label, _, _ = _extract_severity(record)
        assert label == "Unknown"
        assert label != "Low"


# ===========================================================================
# _extract_fixed_version
# ===========================================================================

class TestExtractFixedVersion:
    def test_finds_fixed_version(self):
        record = {
            "affected": [
                {
                    "package": {"name": "example-pkg", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.0.1"}],
                        }
                    ],
                }
            ]
        }
        assert _extract_fixed_version(record, "example-pkg") == "2.0.1"

    def test_no_fixed_returns_none(self):
        record = {
            "affected": [
                {
                    "package": {"name": "pkg", "ecosystem": "PyPI"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}
                    ],
                }
            ]
        }
        assert _extract_fixed_version(record, "pkg") is None

    def test_wrong_package_name_returns_none(self):
        record = {
            "affected": [
                {
                    "package": {"name": "other-pkg", "ecosystem": "PyPI"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}
                    ],
                }
            ]
        }
        assert _extract_fixed_version(record, "example-pkg") is None


# ===========================================================================
# scan_dependencies — skipping logic (no HTTP needed)
# ===========================================================================

class TestScanDependenciesSkipping:
    def test_range_dep_skipped(self):
        results = scan_dependencies([_range_dep("requests", ">=2.0")])
        assert len(results) == 1
        assert results[0]["scan_status"] == STATUS_SKIPPED_RANGE
        assert results[0]["vuln_id"] is None

    def test_unpinned_dep_skipped(self):
        results = scan_dependencies([_unpinned_dep("six")])
        assert len(results) == 1
        assert results[0]["scan_status"] == STATUS_SKIPPED_UNPINNED

    def test_vcs_dep_skipped(self):
        results = scan_dependencies([_skipped_dep("git-pkg", "skipped_vcs")])
        assert results[0]["scan_status"] == STATUS_SKIPPED_OTHER

    def test_skipped_dep_has_error_message(self):
        results = scan_dependencies([_range_dep("pkg", ">=1.0")])
        assert results[0]["error_message"] is not None

    def test_skipped_dep_version_is_none(self):
        results = scan_dependencies([_unpinned_dep("pkg")])
        assert results[0]["version"] is None

    def test_empty_list(self):
        assert scan_dependencies([]) == []

    def test_all_fields_present_in_skipped(self):
        results = scan_dependencies([_range_dep("pkg")])
        required = {"package_name", "version", "version_type", "scan_status",
                    "error_message", "vuln_id", "severity", "cvss_score",
                    "cvss_vector", "fixed_version", "references"}
        assert required.issubset(results[0].keys())


# ===========================================================================
# scan_dependencies — OSV HTTP mocking
# ===========================================================================

class TestScanDependenciesOSV:
    @rsps_lib.activate
    def test_successful_scan_with_vulnerability(self):
        rsps_lib.add(
            rsps_lib.POST, OSV_URL,
            json=OSV_VULN_WITH_CVSS3, status=200,
        )
        results = scan_dependencies([_exact_dep("example-pkg", "1.0.0")])
        vuln_rows = [r for r in results if r["vuln_id"]]
        assert len(vuln_rows) == 1
        row = vuln_rows[0]
        assert row["scan_status"] == STATUS_SCANNED
        assert row["vuln_id"] == "GHSA-test-1234-abcd"
        assert row["severity"] == "Critical"
        assert row["cvss_score"] == pytest.approx(9.8, abs=0.1)
        assert row["fixed_version"] == "2.0.1"
        assert row["recommendation"] is not None
        assert "2.0.1" in row["recommendation"]

    @rsps_lib.activate
    def test_clean_scan_zero_vulns(self):
        rsps_lib.add(rsps_lib.POST, OSV_URL, json=OSV_EMPTY, status=200)
        results = scan_dependencies([_exact_dep("clean-pkg", "5.0.0")])
        assert len(results) == 1
        assert results[0]["scan_status"] == STATUS_SCANNED
        assert results[0]["vuln_id"] is None
        # A clean scan must NOT look like an error
        assert results[0]["error_message"] is None

    @rsps_lib.activate
    def test_unknown_severity_preserved(self):
        rsps_lib.add(rsps_lib.POST, OSV_URL, json=OSV_NO_SEVERITY, status=200)
        results = scan_dependencies([_exact_dep("unsev-pkg", "1.0.0")])
        vuln_rows = [r for r in results if r["vuln_id"]]
        assert len(vuln_rows) == 1
        assert vuln_rows[0]["severity"] == "Unknown"
        assert vuln_rows[0]["cvss_score"] is None

    @rsps_lib.activate
    def test_database_specific_severity(self):
        rsps_lib.add(rsps_lib.POST, OSV_URL, json=OSV_VULN_WITH_DB_SEVERITY, status=200)
        results = scan_dependencies([_exact_dep("pkg-b", "2.0.0")])
        vuln_rows = [r for r in results if r["vuln_id"]]
        assert vuln_rows[0]["severity"] == "High"

    @rsps_lib.activate
    def test_http_500_becomes_scan_error(self):
        rsps_lib.add(rsps_lib.POST, OSV_URL, status=500)
        results = scan_dependencies([_exact_dep("bad-pkg", "1.0.0")])
        assert results[0]["scan_status"] == STATUS_SCAN_ERROR
        assert results[0]["vuln_id"] is None
        assert results[0]["error_message"] is not None

    @rsps_lib.activate
    def test_http_500_never_zero_vulns_claim(self):
        """An API error must NOT produce a STATUS_SCANNED row with no vulns."""
        rsps_lib.add(rsps_lib.POST, OSV_URL, status=500)
        results = scan_dependencies([_exact_dep("bad-pkg", "1.0.0")])
        assert results[0]["scan_status"] != STATUS_SCANNED

    @rsps_lib.activate
    def test_http_429_rate_limit_becomes_scan_error(self):
        rsps_lib.add(rsps_lib.POST, OSV_URL, status=429)
        results = scan_dependencies([_exact_dep("rate-limited", "1.0.0")])
        assert results[0]["scan_status"] == STATUS_SCAN_ERROR

    @rsps_lib.activate
    def test_malformed_json_response_becomes_scan_error(self):
        rsps_lib.add(
            rsps_lib.POST, OSV_URL,
            body=b"not json {{{",
            status=200,
            content_type="application/json",
        )
        results = scan_dependencies([_exact_dep("bad-json-pkg", "1.0.0")])
        assert results[0]["scan_status"] == STATUS_SCAN_ERROR

    @rsps_lib.activate
    def test_correct_pypi_ecosystem_sent(self):
        rsps_lib.add(rsps_lib.POST, OSV_URL, json=OSV_EMPTY, status=200)
        scan_dependencies([_exact_dep("flask", "3.0.3", ecosystem="PyPI")])
        sent = json.loads(rsps_lib.calls[0].request.body)
        assert sent["package"]["ecosystem"] == "PyPI"

    @rsps_lib.activate
    def test_correct_npm_ecosystem_sent(self):
        rsps_lib.add(rsps_lib.POST, OSV_URL, json=OSV_EMPTY, status=200)
        scan_dependencies([_exact_dep("express", "4.18.2", ecosystem="npm")])
        sent = json.loads(rsps_lib.calls[0].request.body)
        assert sent["package"]["ecosystem"] == "npm"

    @rsps_lib.activate
    def test_deduplication_of_same_vuln(self):
        """Same vuln_id for the same package/version must appear only once."""
        duplicate_response = {
            "vulns": [
                OSV_VULN_WITH_CVSS3["vulns"][0],
                OSV_VULN_WITH_CVSS3["vulns"][0],  # duplicate
            ]
        }
        rsps_lib.add(rsps_lib.POST, OSV_URL, json=duplicate_response, status=200)
        results = scan_dependencies([_exact_dep("example-pkg", "1.0.0")])
        vuln_ids = [r["vuln_id"] for r in results if r["vuln_id"]]
        assert len(vuln_ids) == len(set(vuln_ids))

    @rsps_lib.activate
    def test_multiple_packages_each_queried(self):
        rsps_lib.add(rsps_lib.POST, OSV_URL, json=OSV_EMPTY, status=200)
        rsps_lib.add(rsps_lib.POST, OSV_URL, json=OSV_EMPTY, status=200)
        deps = [
            _exact_dep("flask", "3.0.3"),
            _exact_dep("requests", "2.31.0"),
        ]
        results = scan_dependencies(deps)
        assert len(rsps_lib.calls) == 2
        scanned = [r for r in results if r["scan_status"] == STATUS_SCANNED]
        assert len(scanned) == 2

    @rsps_lib.activate
    def test_timeout_becomes_scan_error(self):
        import requests as req_lib
        rsps_lib.add(rsps_lib.POST, OSV_URL, body=req_lib.exceptions.Timeout())
        results = scan_dependencies([_exact_dep("slow-pkg", "1.0.0")])
        assert results[0]["scan_status"] == STATUS_SCAN_ERROR

    @rsps_lib.activate
    def test_connection_error_becomes_scan_error(self):
        import requests as req_lib
        rsps_lib.add(
            rsps_lib.POST, OSV_URL,
            body=req_lib.exceptions.ConnectionError("Connection refused"),
        )
        results = scan_dependencies([_exact_dep("offline-pkg", "1.0.0")])
        assert results[0]["scan_status"] == STATUS_SCAN_ERROR


# ===========================================================================
# _build_recommendation
# ===========================================================================

class TestBuildRecommendation:
    def test_with_fixed_version_critical(self):
        r = _build_recommendation("2.0.1", "Critical")
        assert "2.0.1" in r
        assert "Immediately" in r or "upgrade" in r.lower()

    def test_with_fixed_version_low(self):
        r = _build_recommendation("1.5.0", "Low")
        assert "1.5.0" in r

    def test_no_fixed_version(self):
        r = _build_recommendation(None, "High")
        assert "No fixed version" in r or "no fixed" in r.lower()


# ===========================================================================
# CVSS v4 support (targeted improvement)
# ===========================================================================

class TestCvss4Support:
    """Verify CVSS v4 parsing and severity extraction."""

    def test_cvss4_available(self):
        from app.scanner import _CVSS4_AVAILABLE
        assert _CVSS4_AVAILABLE is True, (
            "cvss library >= 3.2 is installed; CVSS4 should be importable"
        )

    def test_parse_cvss4_score_medium(self):
        from app.scanner import _parse_cvss4_score
        # GHSA-652x-xj99-gmcc vector — base score 6.9 (Medium)
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score = _parse_cvss4_score(vector)
        assert score is not None
        assert isinstance(score, float)
        assert score == pytest.approx(6.9, abs=0.05)

    def test_parse_cvss4_score_returns_float_not_decimal(self):
        from app.scanner import _parse_cvss4_score
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        score = _parse_cvss4_score(vector)
        from decimal import Decimal
        assert not isinstance(score, Decimal)
        assert isinstance(score, float)

    def test_parse_cvss4_invalid_returns_none(self):
        from app.scanner import _parse_cvss4_score
        assert _parse_cvss4_score("not-a-v4-vector") is None

    def test_parse_cvss4_empty_returns_none(self):
        from app.scanner import _parse_cvss4_score
        assert _parse_cvss4_score("") is None

    def test_extract_severity_cvss4_entry(self):
        """CVSS_V4 type in severity array is parsed correctly."""
        record = {
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                }
            ]
        }
        label, score, vector = _extract_severity(record)
        assert label == "Medium"
        assert score == pytest.approx(6.9, abs=0.05)
        assert "CVSS:4.0" in vector

    def test_extract_severity_cvss4_preferred_over_cvss3(self):
        """When both CVSS_V4 and CVSS_V3 are present, CVSS_V4 takes precedence."""
        record = {
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                },
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
            ]
        }
        label, score, vector = _extract_severity(record)
        assert "CVSS:4.0" in vector
        assert label == "Medium"   # v4 score 6.9, not v3 score 9.8

    def test_extract_severity_cvss4_not_passed_to_cvss3_parser(self):
        """A CVSS v4 vector must not be handed to the CVSS3 parser."""
        from app.scanner import _parse_cvss3_score
        v4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
        # CVSS3 parser must return None for a v4 vector, not a score
        result = _parse_cvss3_score(v4_vector)
        assert result is None

    @rsps_lib.activate
    def test_scan_with_cvss4_only_vulnerability(self):
        """Full scan pipeline handles a vuln with only a CVSS_V4 severity entry."""
        rsps_lib.add(
            rsps_lib.POST, OSV_URL,
            json={
                "vulns": [
                    {
                        "id": "GHSA-cvss4-test",
                        "summary": "Test CVSSv4 only vulnerability",
                        "details": "Details.",
                        "published": "2024-01-01T00:00:00Z",
                        "modified": "2024-01-01T00:00:00Z",
                        "severity": [
                            {
                                "type": "CVSS_V4",
                                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                            }
                        ],
                        "affected": [
                            {
                                "package": {"name": "test-pkg", "ecosystem": "PyPI"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                    }
                                ],
                            }
                        ],
                        "references": [],
                    }
                ]
            },
            status=200,
        )
        from app.scanner import scan_dependencies as _scan
        results = _scan([{
            "name": "test-pkg", "ecosystem": "PyPI",
            "version": "1.0.0", "version_specifier": "==1.0.0",
            "is_exact_version": True, "dependency_type": "direct",
            "parsing_status": "parsed", "skip_reason": None,
        }])
        vuln_rows = [r for r in results if r["vuln_id"]]
        assert len(vuln_rows) == 1
        assert vuln_rows[0]["severity"] == "Medium"
        assert vuln_rows[0]["cvss_score"] == pytest.approx(6.9, abs=0.05)
        assert "CVSS:4.0" in vuln_rows[0]["cvss_vector"]


# ===========================================================================
# Fixed version extraction audit (targeted improvement)
# ===========================================================================

class TestExtractFixedVersionAudit:
    """
    Audits _extract_fixed_version against the live OSV response structure
    for GHSA-652x-xj99-gmcc (requests 2.31.0) and edge cases.
    """

    # Exact replica of the GHSA-652x-xj99-gmcc affected structure
    REQUESTS_RECORD = {
        "id": "GHSA-652x-xj99-gmcc",
        "affected": [
            {
                "package": {
                    "name": "requests",
                    "ecosystem": "PyPI",
                    "purl": "pkg:pypi/requests",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.3.0"},
                        ],
                    }
                ],
                "versions": ["0.0.1", "0.10.0", "2.0.0", "2.2.0"],  # AFFECTED versions, not fixed
            }
        ],
    }

    def test_finds_fixed_version_from_ranges(self):
        fixed = _extract_fixed_version(self.REQUESTS_RECORD, "requests")
        assert fixed == "2.3.0"

    def test_finds_fixed_version_with_ecosystem_match(self):
        fixed = _extract_fixed_version(self.REQUESTS_RECORD, "requests", ecosystem="PyPI")
        assert fixed == "2.3.0"

    def test_ecosystem_mismatch_returns_none(self):
        """When ecosystem is specified and doesn't match, no fixed version returned."""
        fixed = _extract_fixed_version(self.REQUESTS_RECORD, "requests", ecosystem="npm")
        assert fixed is None

    def test_versions_array_never_treated_as_fixed(self):
        """affected[].versions lists AFFECTED versions — none of them are the fixed version."""
        fixed = _extract_fixed_version(self.REQUESTS_RECORD, "requests")
        # The versions array contains "0.0.1", "0.10.0", "2.0.0", "2.2.0"
        # The fixed version is "2.3.0" — from ranges, not from versions[]
        assert fixed not in ["0.0.1", "0.10.0", "2.0.0", "2.2.0"]
        assert fixed == "2.3.0"

    def test_git_range_type_skipped(self):
        """GIT range type contains commit hashes — should be skipped."""
        record = {
            "affected": [
                {
                    "package": {"name": "mypkg", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [
                                {"introduced": "abc123def456"},
                                {"fixed": "deadbeef1234"},
                            ],
                        },
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.5.0"},
                            ],
                        },
                    ],
                }
            ]
        }
        fixed = _extract_fixed_version(record, "mypkg")
        # GIT range skipped; ECOSYSTEM range used
        assert fixed == "1.5.0"
        assert len(fixed) < 20  # not a commit hash

    def test_multiple_affected_entries_first_matching_wins(self):
        record = {
            "affected": [
                {
                    "package": {"name": "other-pkg", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
                },
                {
                    "package": {"name": "mypkg", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}],
                },
            ]
        }
        fixed = _extract_fixed_version(record, "mypkg")
        assert fixed == "2.0.1"

    def test_no_fixed_event_returns_none(self):
        record = {
            "affected": [
                {
                    "package": {"name": "mypkg", "ecosystem": "PyPI"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}
                    ],
                }
            ]
        }
        assert _extract_fixed_version(record, "mypkg") is None

    def test_empty_affected_returns_none(self):
        assert _extract_fixed_version({"affected": []}, "mypkg") is None

    def test_missing_affected_key_returns_none(self):
        assert _extract_fixed_version({}, "mypkg") is None

    def test_case_insensitive_name_match(self):
        record = {
            "affected": [
                {
                    "package": {"name": "Requests", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.3.0"}]}],
                }
            ]
        }
        # Query with lowercase name, record has titlecase name
        assert _extract_fixed_version(record, "requests") == "2.3.0"
