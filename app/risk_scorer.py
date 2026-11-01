"""
Risk Scorer — Phase 5.

Public API
----------
calculate_risk_score(scan_results) -> dict

Computes a custom project risk score from the output of scan_dependencies().

Score formula (capped at 100):
  score = min(critical×10 + high×5 + medium×2 + low×1, 100)

Risk categories:
  0          → "No known risk detected"  (only if coverage is sufficient)
  1 – 29     → "Low"
  30 – 59    → "Medium"
  60 – 79    → "High"
  80 – 100   → "Critical"

IMPORTANT — insufficient coverage:
  If scanned_count == 0 and (skipped_count + error_count) > 0, the score is
  marked insufficient_coverage=True and the category becomes
  "Insufficient Coverage" instead of "No known risk detected".
  This prevents a zero score from being misread as "safe" when no deps
  were actually checked.

Unknown-severity vulnerabilities are counted but EXCLUDED from the numeric
score formula. They are surfaced separately so they are never silently dropped.

The label "Custom Project Risk Score (not CVSS)" is included in every return
dict so callers consistently display the correct description.
"""

import logging
from app.scanner import (
    STATUS_SCANNED,
    STATUS_SKIPPED_RANGE,
    STATUS_SKIPPED_UNPINNED,
    STATUS_SKIPPED_OTHER,
    STATUS_SCAN_ERROR,
)

logger = logging.getLogger(__name__)

# Severity weights
_WEIGHTS = {
    "Critical": 10,
    "High":     5,
    "Medium":   2,
    "Low":      1,
}

# Score → category mapping (checked in descending order)
_CATEGORIES = [
    (80, "Critical"),
    (60, "High"),
    (30, "Medium"),
    (1,  "Low"),
    (0,  "No known risk detected"),
]


def calculate_risk_score(scan_results: list[dict]) -> dict:
    """
    Calculate the custom project risk score from scan results.

    Args:
        scan_results: List of dicts from scan_dependencies().

    Returns:
        Dict with keys:
          score                int      — 0–100
          risk_category        str      — human-readable category
          score_label          str      — always "Custom Project Risk Score (not CVSS)"
          insufficient_coverage bool    — True when no deps were actually scanned
          critical_count       int
          high_count           int
          medium_count         int
          low_count            int
          unknown_count        int      — vulns with severity "Unknown"
          scanned_count        int      — deps successfully queried (zero or more vulns)
          skipped_count        int      — deps skipped (range/unpinned/other)
          error_count          int      — deps that failed with scan_error
          total_vuln_count     int      — sum of critical+high+medium+low+unknown
          has_vulnerabilities  bool
    """
    counts = _count_results(scan_results)

    critical = counts["critical"]
    high     = counts["high"]
    medium   = counts["medium"]
    low      = counts["low"]
    unknown  = counts["unknown"]
    scanned  = counts["scanned"]
    skipped  = counts["skipped"]
    errors   = counts["errors"]

    # Numeric score — Unknown excluded
    raw_score = critical * 10 + high * 5 + medium * 2 + low * 1
    score = min(raw_score, 100)

    # Insufficient coverage guard
    insufficient = (scanned == 0) and (skipped + errors > 0)

    if insufficient:
        category = "Insufficient Coverage"
    else:
        category = _score_to_category(score)

    total_vulns = critical + high + medium + low + unknown

    return {
        "score":               score,
        "risk_category":       category,
        "score_label":         "Custom Project Risk Score (not CVSS)",
        "insufficient_coverage": insufficient,
        "critical_count":      critical,
        "high_count":          high,
        "medium_count":        medium,
        "low_count":           low,
        "unknown_count":       unknown,
        "scanned_count":       scanned,
        "skipped_count":       skipped,
        "error_count":         errors,
        "total_vuln_count":    total_vulns,
        "has_vulnerabilities": total_vulns > 0,
    }


def _count_results(scan_results: list[dict]) -> dict:
    """
    Tally vulnerability severities and dependency statuses.

    A dep with scan_status == STATUS_SCANNED counts once toward scanned_count
    regardless of how many vulnerabilities it has.  Vulnerability rows share
    the same package_name+version, so we track unique scanned packages
    separately from vulnerability counts.
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    scanned_packages: set[str] = set()
    skipped = 0
    errors = 0

    for row in scan_results:
        status = row.get("scan_status", "")
        name = row.get("package_name", "")
        version = row.get("version") or ""
        pkg_key = f"{name}:{version}"

        if status == STATUS_SCAN_ERROR:
            errors += 1
        elif status in (STATUS_SKIPPED_RANGE,
                        STATUS_SKIPPED_UNPINNED,
                        STATUS_SKIPPED_OTHER):
            skipped += 1
        elif status == STATUS_SCANNED:
            # Track unique scanned package@version combos
            scanned_packages.add(pkg_key)
            # Count vulnerability severity
            severity = (row.get("severity") or "").strip()
            vuln_id = row.get("vuln_id")
            if vuln_id:  # only count rows that represent an actual vulnerability
                label = severity.lower() if severity else ""
                if label == "critical":
                    severity_counts["critical"] += 1
                elif label == "high":
                    severity_counts["high"] += 1
                elif label == "medium":
                    severity_counts["medium"] += 1
                elif label == "low":
                    severity_counts["low"] += 1
                else:
                    severity_counts["unknown"] += 1

    return {
        **severity_counts,
        "scanned": len(scanned_packages),
        "skipped": skipped,
        "errors":  errors,
    }


def _score_to_category(score: int) -> str:
    """Map a numeric score to a risk category string."""
    for threshold, label in _CATEGORIES:
        if score >= threshold:
            return label
    return "No known risk detected"
