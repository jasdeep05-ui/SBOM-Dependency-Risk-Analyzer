"""
OSV Vulnerability Scanner — Phase 4.

Public API
----------
scan_dependencies(dependencies) -> list[dict]

Queries the OSV API (https://api.osv.dev/v1/query) for each dependency
that has an exact, known version. Returns one result dict per
(dependency × vulnerability) pair, plus one status-only dict for every
dependency that was skipped or failed.

Result dict schema
------------------
Each dict always contains:
  package_name    str          — normalised package name
  version         str|None     — exact version queried, or None
  version_type    str          — "exact" | "range" | "unpinned" | "skipped_*"
  scan_status     str          — see STATUS_* constants below
  error_message   str|None     — set for scan_error rows

Vulnerability-specific fields (None for non-vuln rows):
  vuln_id         str|None     — OSV/CVE/GHSA identifier
  title           str|None     — short summary
  description     str|None     — full details
  severity        str|None     — "Critical"|"High"|"Medium"|"Low"|"Unknown"
  cvss_score      float|None   — numeric CVSS base score (from parsed vector)
  cvss_vector     str|None     — raw CVSS vector string
  fixed_version   str|None     — earliest fixed version from OSV ranges
  references      list[str]    — reference URLs
  published       str|None     — ISO 8601 published date
  modified        str|None     — ISO 8601 last-modified date
  recommendation  str|None     — human-readable remediation string

scan_status values
------------------
  STATUS_SCANNED          — OSV queried successfully (may have 0 vulns)
  STATUS_SKIPPED_RANGE    — version is a range; not queried
  STATUS_SKIPPED_UNPINNED — no version; not queried
  STATUS_SKIPPED_OTHER    — other parser-skipped status (VCS, URL, editable, etc.)
  STATUS_SCAN_ERROR       — API call failed after retries
"""

import logging
import time
from decimal import Decimal, InvalidOperation

import requests
from cvss import CVSS2, CVSS3, CVSS2Error, CVSS3Error
try:
    from cvss import CVSS4, CVSS4Error
    _CVSS4_AVAILABLE = True
except ImportError:
    _CVSS4_AVAILABLE = False
    CVSS4 = None       # type: ignore[assignment,misc]
    CVSS4Error = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Status constants
# ---------------------------------------------------------------------------
STATUS_SCANNED = "scanned"
STATUS_SKIPPED_RANGE = "skipped_range"
STATUS_SKIPPED_UNPINNED = "skipped_unpinned"
STATUS_SKIPPED_OTHER = "skipped_other"
STATUS_SCAN_ERROR = "scan_error"

# ---------------------------------------------------------------------------
# OSV API configuration
# ---------------------------------------------------------------------------
OSV_API_URL = "https://api.osv.dev/v1/query"
_REQUEST_TIMEOUT = 10        # seconds per attempt
_MAX_RETRIES = 3
_RETRY_BACKOFF = [1, 2, 4]  # seconds between retries

# ---------------------------------------------------------------------------
# Ecosystem mapping: parser values → OSV ecosystem identifiers
# ---------------------------------------------------------------------------
_ECOSYSTEM_MAP = {
    "PyPI": "PyPI",
    "npm":  "npm",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_dependencies(dependencies: list[dict]) -> list[dict]:
    """
    Scan a list of parsed dependencies for known vulnerabilities.

    Args:
        dependencies: List of dicts as returned by app.parser.parse_file().

    Returns:
        Flat list of result dicts — one per vulnerability found, plus one
        status-only dict per dep with no vulnerabilities or that was skipped.
    """
    results = []

    for dep in dependencies:
        name = dep.get("name", "")
        version = dep.get("version")         # None unless is_exact_version
        is_exact = dep.get("is_exact_version", False)
        ecosystem = dep.get("ecosystem", "")
        parsing_status = dep.get("parsing_status", "parsed")
        version_specifier = dep.get("version_specifier", "")
        dep_type = dep.get("dependency_type", "direct")

        # Determine version_type for the result row
        if version_specifier and not is_exact:
            version_type = "range"
        elif not version_specifier and not is_exact:
            version_type = "unpinned"
        else:
            version_type = "exact"

        # --- Skip non-exact dependencies ---
        if not is_exact or not version:
            if parsing_status in ("skipped_vcs", "skipped_url",
                                  "skipped_editable", "skipped_unsupported",
                                  "skipped_invalid"):
                status = STATUS_SKIPPED_OTHER
                skip_reason = dep.get("skip_reason") or f"Parser status: {parsing_status}"
            elif not version_specifier:
                status = STATUS_SKIPPED_UNPINNED
                skip_reason = "No version specified — cannot query OSV"
            else:
                status = STATUS_SKIPPED_RANGE
                skip_reason = (
                    f"Non-exact version specifier '{version_specifier}' — "
                    "cannot reliably query OSV"
                )
            results.append(_make_status_row(
                name=name, version=version, version_type=version_type,
                scan_status=status, error_message=skip_reason,
            ))
            continue

        # --- OSV lookup for exact-version deps ---
        osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem)
        if not osv_ecosystem:
            results.append(_make_status_row(
                name=name, version=version, version_type=version_type,
                scan_status=STATUS_SKIPPED_OTHER,
                error_message=f"Unsupported ecosystem: {ecosystem!r}",
            ))
            continue

        try:
            osv_response = _query_osv(name, version, osv_ecosystem)
        except Exception as exc:  # noqa: BLE001
            logger.warning("OSV query failed for %s==%s: %s", name, version, exc)
            results.append(_make_status_row(
                name=name, version=version, version_type=version_type,
                scan_status=STATUS_SCAN_ERROR,
                error_message=str(exc)[:500],
            ))
            continue

        vulns_raw = osv_response.get("vulns", [])

        if not vulns_raw:
            # Successful scan, zero vulnerabilities found
            results.append(_make_status_row(
                name=name, version=version, version_type=version_type,
                scan_status=STATUS_SCANNED,
            ))
            continue

        # Parse each vulnerability record
        seen_ids: set[str] = set()
        dep_had_results = False
        for vuln_record in vulns_raw:
            vuln_id = vuln_record.get("id", "")
            dedup_key = f"{name}:{version}:{vuln_id}"
            if dedup_key in seen_ids:
                continue
            seen_ids.add(dedup_key)
            dep_had_results = True

            vuln_dict = _parse_vuln_record(
                vuln_record=vuln_record,
                package_name=name,
                version=version,
                version_type=version_type,
                ecosystem=osv_ecosystem,
            )
            results.append(vuln_dict)

        if not dep_had_results:
            results.append(_make_status_row(
                name=name, version=version, version_type=version_type,
                scan_status=STATUS_SCANNED,
            ))

    return results


# ---------------------------------------------------------------------------
# OSV HTTP layer
# ---------------------------------------------------------------------------

def _query_osv(package_name: str, version: str, ecosystem: str) -> dict:
    """
    POST a single query to the OSV API.

    Retries up to _MAX_RETRIES times on connection errors and timeouts.
    Raises requests.exceptions.HTTPError on non-2xx responses.
    Raises RuntimeError if all retries are exhausted.

    Returns the parsed JSON response dict.
    """
    payload = {
        "package": {
            "name": package_name,
            "version": version,
            "ecosystem": ecosystem,
        }
    }

    last_exc: Exception | None = None
    for attempt, backoff in enumerate(
        [0] + _RETRY_BACKOFF[: _MAX_RETRIES - 1], start=1
    ):
        if backoff:
            logger.debug(
                "OSV retry %d for %s==%s (waiting %ds)",
                attempt, package_name, version, backoff,
            )
            time.sleep(backoff)
        try:
            resp = requests.post(
                OSV_API_URL,
                json=payload,
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as exc:
            last_exc = exc
            logger.warning(
                "OSV connection/timeout error (attempt %d/%d) for %s==%s: %s",
                attempt, _MAX_RETRIES, package_name, version, exc,
            )
            continue
        except requests.exceptions.HTTPError as exc:
            # Non-retryable — raise immediately (e.g. 400, 429, 500)
            raise RuntimeError(
                f"OSV HTTP {exc.response.status_code} for {package_name}=={version}: {exc}"
            ) from exc
        except (ValueError, KeyError) as exc:
            raise RuntimeError(
                f"OSV returned malformed JSON for {package_name}=={version}: {exc}"
            ) from exc

    raise RuntimeError(
        f"OSV query failed after {_MAX_RETRIES} attempts for "
        f"{package_name}=={version}: {last_exc}"
    )


# ---------------------------------------------------------------------------
# Vulnerability record parser
# ---------------------------------------------------------------------------

def _parse_vuln_record(
    vuln_record: dict,
    package_name: str,
    version: str,
    version_type: str,
    ecosystem: str | None = None,
) -> dict:
    """Parse a single OSV vulnerability record into a result dict."""
    vuln_id = vuln_record.get("id", "")
    title = vuln_record.get("summary") or vuln_record.get("id") or ""
    description = vuln_record.get("details") or ""
    published = vuln_record.get("published")
    modified = vuln_record.get("modified")

    severity_label, cvss_score, cvss_vector = _extract_severity(vuln_record)
    fixed_version = _extract_fixed_version(vuln_record, package_name, ecosystem)
    references = _extract_references(vuln_record)

    recommendation = _build_recommendation(fixed_version, severity_label)

    return {
        "package_name": package_name,
        "version": version,
        "version_type": version_type,
        "scan_status": STATUS_SCANNED,
        "error_message": None,
        "vuln_id": vuln_id,
        "title": title[:500] if title else None,
        "description": description[:2000] if description else None,
        "severity": severity_label,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "fixed_version": fixed_version,
        "references": references,
        "published": published,
        "modified": modified,
        "recommendation": recommendation,
    }


# ---------------------------------------------------------------------------
# Severity extraction
# ---------------------------------------------------------------------------

def _extract_severity(
    vuln_record: dict,
) -> tuple[str, float | None, str | None]:
    """
    Extract severity label, numeric CVSS base score, and raw vector.

    Priority order:
      1. CVSS_V4 entry in severity[] array  (supported: cvss >= 3.2)
      2. CVSS_V3 entry in severity[] array
      3. CVSS_V2 entry in severity[] array
      4. database_specific.severity string
      5. → "Unknown"

    Returns (severity_label, cvss_score_float_or_None, cvss_vector_or_None).
    CVSS base score is parsed from the vector string using the `cvss` library —
    never by casting the vector to float.

    Note: CVSS v4 vectors are identified by the "CVSS_V4" type field.
    They are NOT passed to CVSS3 or CVSS2 parsers — doing so would produce
    incorrect results. If the `cvss` library does not support v4 at runtime
    (ImportError), CVSS_V4 entries fall through to the database_specific
    or Unknown fallback.
    """
    severity_list = vuln_record.get("severity") or []

    # --- CVSS_V4 (highest precedence when library supports it) ---
    if _CVSS4_AVAILABLE:
        for entry in severity_list:
            if entry.get("type") == "CVSS_V4":
                vector = entry.get("score", "")
                score = _parse_cvss4_score(vector)
                if score is not None:
                    label = _cvss_score_to_label(score)
                    return label, score, vector

    # --- CVSS_V3 ---
    for entry in severity_list:
        if entry.get("type") == "CVSS_V3":
            vector = entry.get("score", "")
            score = _parse_cvss3_score(vector)
            if score is not None:
                label = _cvss_score_to_label(score)
                return label, score, vector

    # --- CVSS_V2 fallback ---
    for entry in severity_list:
        if entry.get("type") == "CVSS_V2":
            vector = entry.get("score", "")
            score = _parse_cvss2_score(vector)
            if score is not None:
                label = _cvss_score_to_label(score)
                return label, score, vector

    # --- database_specific.severity string ---
    db_specific = vuln_record.get("database_specific") or {}
    db_severity = (db_specific.get("severity") or "").strip().upper()
    if db_severity:
        label = _string_severity_to_label(db_severity)
        if label != "Unknown":
            return label, None, None

    # Nothing found — explicitly Unknown
    return "Unknown", None, None


def _parse_cvss4_score(vector: str) -> float | None:
    """
    Parse a CVSS v4 vector string and return the base score as float.

    Uses cvss.CVSS4 from the installed `cvss` library (>= 3.2).
    Returns None if parsing fails or if CVSS4 is unavailable.
    Never passes a CVSS v4 vector to CVSS3 or CVSS2 parsers.
    """
    if not vector or not _CVSS4_AVAILABLE:
        return None
    try:
        score = CVSS4(vector).base_score
        return float(score)
    except Exception:  # noqa: BLE001  (CVSS4Error or any parse failure)
        return None


def _parse_cvss3_score(vector: str) -> float | None:
    """Parse a CVSS v3 vector string and return the base score as float."""
    if not vector:
        return None
    try:
        score = CVSS3(vector).base_score
        return float(score)
    except (CVSS3Error, InvalidOperation, TypeError, ValueError):
        return None


def _parse_cvss2_score(vector: str) -> float | None:
    """Parse a CVSS v2 vector string and return the base score as float."""
    if not vector:
        return None
    try:
        score = CVSS2(vector).base_score
        return float(score)
    except (CVSS2Error, InvalidOperation, TypeError, ValueError):
        return None


def _cvss_score_to_label(score: float) -> str:
    """Map a numeric CVSS base score to a severity label."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Unknown"


def _string_severity_to_label(s: str) -> str:
    """Map a database_specific severity string to a normalised label."""
    mapping = {
        "CRITICAL": "Critical",
        "HIGH":     "High",
        "MODERATE": "Medium",   # GitHub Advisory uses MODERATE
        "MEDIUM":   "Medium",
        "LOW":      "Low",
        "NONE":     "Low",
    }
    return mapping.get(s.upper(), "Unknown")


# ---------------------------------------------------------------------------
# Fixed version extraction
# ---------------------------------------------------------------------------

def _extract_fixed_version(
    vuln_record: dict,
    package_name: str,
    ecosystem: str | None = None,
) -> str | None:
    """
    Extract the earliest fixed version for the given package from OSV ranges.

    Searches affected[].ranges[].events for event dicts that contain the
    key "fixed". Returns the first match, or None.

    Matching rules:
    - Package name is compared case-insensitively.
    - If `ecosystem` is supplied, the affected entry's ecosystem is also
      matched case-insensitively. This avoids extracting a fix version
      intended for a different ecosystem that happens to share a package name.
    - Only `ranges[].events[].fixed` is used — `affected[].versions` lists
      affected (vulnerable) versions, not fixed versions, and is never read.
    - All ECOSYSTEM and SEMVER range types are searched; GIT ranges are skipped
      (their "fixed" value is a commit hash, not a version string).
    """
    affected_list = vuln_record.get("affected") or []
    for affected_entry in affected_list:
        pkg = affected_entry.get("package") or {}

        # Name must match (case-insensitive)
        if pkg.get("name", "").lower() != package_name.lower():
            continue

        # Ecosystem must match when provided
        if ecosystem:
            entry_ecosystem = pkg.get("ecosystem", "")
            if entry_ecosystem.lower() != ecosystem.lower():
                continue

        for range_entry in (affected_entry.get("ranges") or []):
            range_type = range_entry.get("type", "")
            # GIT ranges use commit hashes as "fixed" — not useful as version strings
            if range_type == "GIT":
                continue
            for event in (range_entry.get("events") or []):
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)
    return None


# ---------------------------------------------------------------------------
# References extraction
# ---------------------------------------------------------------------------

def _extract_references(vuln_record: dict) -> list[str]:
    """Return a list of reference URLs from the OSV record."""
    refs = []
    for ref in (vuln_record.get("references") or []):
        url = ref.get("url") or ref.get("link")
        if url:
            refs.append(url)
    return refs[:10]  # cap at 10 to keep DB rows manageable


# ---------------------------------------------------------------------------
# Recommendation builder
# ---------------------------------------------------------------------------

def _build_recommendation(fixed_version: str | None, severity: str) -> str:
    """Build a human-readable remediation recommendation string."""
    if fixed_version:
        urgency = ""
        if severity == "Critical":
            urgency = "Immediately upgrade"
        elif severity == "High":
            urgency = "Upgrade as soon as possible"
        else:
            urgency = "Upgrade"
        return f"{urgency} to version {fixed_version} or later."
    return (
        "No fixed version available. "
        "Monitor for updates and consider an alternative package."
    )


# ---------------------------------------------------------------------------
# Status-only row builder
# ---------------------------------------------------------------------------

def _make_status_row(
    name: str,
    version: str | None,
    version_type: str,
    scan_status: str,
    error_message: str | None = None,
) -> dict:
    """Build a result dict for a dependency with no vulnerability data."""
    return {
        "package_name": name,
        "version": version,
        "version_type": version_type,
        "scan_status": scan_status,
        "error_message": error_message,
        "vuln_id": None,
        "title": None,
        "description": None,
        "severity": None,
        "cvss_score": None,
        "cvss_vector": None,
        "fixed_version": None,
        "references": [],
        "published": None,
        "modified": None,
        "recommendation": None,
    }
