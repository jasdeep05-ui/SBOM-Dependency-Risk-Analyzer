"""
Tests for app/risk_scorer.py — Phase 5.
"""

import pytest
from app.risk_scorer import calculate_risk_score
from app.scanner import (
    STATUS_SCANNED,
    STATUS_SKIPPED_RANGE,
    STATUS_SKIPPED_UNPINNED,
    STATUS_SKIPPED_OTHER,
    STATUS_SCAN_ERROR,
)


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------

def _vuln(severity, pkg="pkg", ver="1.0.0"):
    """A scanned row with a vulnerability."""
    return {
        "package_name": pkg,
        "version": ver,
        "version_type": "exact",
        "scan_status": STATUS_SCANNED,
        "vuln_id": f"GHSA-test-{severity[:3].lower()}",
        "severity": severity,
        "cvss_score": None,
        "cvss_vector": None,
        "fixed_version": None,
        "recommendation": None,
        "error_message": None,
    }


def _clean(pkg="clean-pkg", ver="2.0.0"):
    """A scanned row with zero vulnerabilities."""
    return {
        "package_name": pkg,
        "version": ver,
        "version_type": "exact",
        "scan_status": STATUS_SCANNED,
        "vuln_id": None,
        "severity": None,
        "cvss_score": None,
        "cvss_vector": None,
        "fixed_version": None,
        "recommendation": None,
        "error_message": None,
    }


def _skipped(status=STATUS_SKIPPED_RANGE, pkg="skipped-pkg"):
    return {
        "package_name": pkg,
        "version": None,
        "version_type": "range",
        "scan_status": status,
        "vuln_id": None,
        "severity": None,
        "cvss_score": None,
        "cvss_vector": None,
        "fixed_version": None,
        "recommendation": None,
        "error_message": "Skipped",
    }


def _error(pkg="err-pkg"):
    return {
        "package_name": pkg,
        "version": "1.0.0",
        "version_type": "exact",
        "scan_status": STATUS_SCAN_ERROR,
        "vuln_id": None,
        "severity": None,
        "cvss_score": None,
        "cvss_vector": None,
        "fixed_version": None,
        "recommendation": None,
        "error_message": "API failure",
    }


# ===========================================================================
# Score formula
# ===========================================================================

class TestScoreFormula:
    def test_all_zero(self):
        result = calculate_risk_score([_clean()])
        assert result["score"] == 0

    def test_one_critical(self):
        result = calculate_risk_score([_vuln("Critical")])
        assert result["score"] == 10

    def test_one_high(self):
        result = calculate_risk_score([_vuln("High")])
        assert result["score"] == 5

    def test_one_medium(self):
        result = calculate_risk_score([_vuln("Medium")])
        assert result["score"] == 2

    def test_one_low(self):
        result = calculate_risk_score([_vuln("Low")])
        assert result["score"] == 1

    def test_mixed_formula(self):
        rows = [
            _vuln("Critical"),
            _vuln("Critical"),
            _vuln("High"),
            _vuln("Medium"),
            _vuln("Low"),
        ]
        # 2×10 + 1×5 + 1×2 + 1×1 = 28
        result = calculate_risk_score(rows)
        assert result["score"] == 28

    def test_score_capped_at_100(self):
        rows = [_vuln("Critical")] * 15  # 15×10 = 150 → capped
        result = calculate_risk_score(rows)
        assert result["score"] == 100

    def test_score_never_exceeds_100(self):
        rows = [_vuln("Critical")] * 100
        result = calculate_risk_score(rows)
        assert result["score"] <= 100


# ===========================================================================
# Unknown severity
# ===========================================================================

class TestUnknownSeverity:
    def test_unknown_excluded_from_score(self):
        rows = [_vuln("Unknown")]
        result = calculate_risk_score(rows)
        assert result["score"] == 0
        assert result["unknown_count"] == 1

    def test_unknown_counted_separately(self):
        rows = [_vuln("Unknown"), _vuln("Unknown"), _vuln("High")]
        result = calculate_risk_score(rows)
        assert result["unknown_count"] == 2
        assert result["high_count"] == 1
        assert result["score"] == 5  # only the High counts

    def test_unknown_never_treated_as_low(self):
        """Unknown vulns must not inflate the Low count."""
        rows = [_vuln("Unknown")]
        result = calculate_risk_score(rows)
        assert result["low_count"] == 0


# ===========================================================================
# Risk categories
# ===========================================================================

class TestRiskCategories:
    def test_zero_is_no_known_risk(self):
        result = calculate_risk_score([_clean()])
        assert result["risk_category"] == "No known risk detected"

    def test_score_1_is_low(self):
        result = calculate_risk_score([_vuln("Low")])  # score = 1
        assert result["risk_category"] == "Low"

    def test_score_29_is_low(self):
        rows = [_vuln("Low")] * 29  # 29×1 = 29
        result = calculate_risk_score(rows)
        assert result["risk_category"] == "Low"

    def test_score_30_is_medium(self):
        rows = [_vuln("Medium")] * 15  # 15×2 = 30
        result = calculate_risk_score(rows)
        assert result["risk_category"] == "Medium"

    def test_score_59_is_medium(self):
        rows = [_vuln("Medium")] * 29 + [_vuln("Low")]  # 29×2 + 1 = 59
        result = calculate_risk_score(rows)
        assert result["risk_category"] == "Medium"

    def test_score_60_is_high(self):
        rows = [_vuln("High")] * 12  # 12×5 = 60
        result = calculate_risk_score(rows)
        assert result["risk_category"] == "High"

    def test_score_79_is_high(self):
        rows = [_vuln("High")] * 15 + [_vuln("Medium")] * 2  # 75 + 4 = 79
        result = calculate_risk_score(rows)
        assert result["risk_category"] == "High"

    def test_score_80_is_critical(self):
        rows = [_vuln("Critical")] * 8  # 8×10 = 80
        result = calculate_risk_score(rows)
        assert result["risk_category"] == "Critical"

    def test_score_100_is_critical(self):
        rows = [_vuln("Critical")] * 15
        result = calculate_risk_score(rows)
        assert result["risk_category"] == "Critical"
        assert result["score"] == 100


# ===========================================================================
# Coverage counters
# ===========================================================================

class TestCoverageCounters:
    def test_scanned_count(self):
        rows = [_clean("pkg-a"), _clean("pkg-b")]
        result = calculate_risk_score(rows)
        assert result["scanned_count"] == 2

    def test_skipped_range_counted(self):
        rows = [_skipped(STATUS_SKIPPED_RANGE)]
        result = calculate_risk_score(rows)
        assert result["skipped_count"] == 1

    def test_skipped_unpinned_counted(self):
        rows = [_skipped(STATUS_SKIPPED_UNPINNED)]
        result = calculate_risk_score(rows)
        assert result["skipped_count"] == 1

    def test_error_counted(self):
        rows = [_error()]
        result = calculate_risk_score(rows)
        assert result["error_count"] == 1

    def test_mixed_coverage(self):
        rows = [
            _clean("a"),
            _vuln("High", "b"),
            _skipped(STATUS_SKIPPED_RANGE, "c"),
            _skipped(STATUS_SKIPPED_UNPINNED, "d"),
            _error("e"),
        ]
        result = calculate_risk_score(rows)
        # a and b are both scanned (same package_name check differs)
        assert result["scanned_count"] == 2
        assert result["skipped_count"] == 2
        assert result["error_count"] == 1


# ===========================================================================
# Insufficient coverage
# ===========================================================================

class TestInsufficientCoverage:
    def test_all_skipped_is_insufficient(self):
        rows = [
            _skipped(STATUS_SKIPPED_RANGE),
            _skipped(STATUS_SKIPPED_UNPINNED),
        ]
        result = calculate_risk_score(rows)
        assert result["insufficient_coverage"] is True
        assert result["risk_category"] == "Insufficient Coverage"

    def test_all_errors_is_insufficient(self):
        rows = [_error(), _error("e2")]
        result = calculate_risk_score(rows)
        assert result["insufficient_coverage"] is True

    def test_mix_skip_and_error_is_insufficient(self):
        rows = [_skipped(), _error()]
        result = calculate_risk_score(rows)
        assert result["insufficient_coverage"] is True

    def test_one_scanned_not_insufficient(self):
        rows = [_clean(), _skipped()]
        result = calculate_risk_score(rows)
        assert result["insufficient_coverage"] is False

    def test_empty_results_not_insufficient(self):
        """Edge case: nothing submitted — no deps at all."""
        result = calculate_risk_score([])
        # scanned=0 and skipped+error=0 → not flagged as insufficient
        assert result["insufficient_coverage"] is False

    def test_insufficient_score_is_zero(self):
        """Score is still 0 when insufficient; category overrides the label."""
        rows = [_skipped()]
        result = calculate_risk_score(rows)
        assert result["score"] == 0
        assert result["risk_category"] == "Insufficient Coverage"


# ===========================================================================
# Return dict structure
# ===========================================================================

class TestReturnStructure:
    def test_all_expected_keys_present(self):
        result = calculate_risk_score([_clean()])
        expected = {
            "score", "risk_category", "score_label", "insufficient_coverage",
            "critical_count", "high_count", "medium_count", "low_count",
            "unknown_count", "scanned_count", "skipped_count", "error_count",
            "total_vuln_count", "has_vulnerabilities",
        }
        assert expected.issubset(result.keys())

    def test_score_label_always_present(self):
        result = calculate_risk_score([_vuln("Critical")])
        assert "Custom Project Risk Score" in result["score_label"]
        assert "not CVSS" in result["score_label"]

    def test_has_vulnerabilities_true(self):
        result = calculate_risk_score([_vuln("High")])
        assert result["has_vulnerabilities"] is True

    def test_has_vulnerabilities_false_on_clean(self):
        result = calculate_risk_score([_clean()])
        assert result["has_vulnerabilities"] is False

    def test_total_vuln_count_excludes_clean_rows(self):
        rows = [_clean(), _vuln("High"), _vuln("Low")]
        result = calculate_risk_score(rows)
        assert result["total_vuln_count"] == 2
