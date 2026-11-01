"""
Flask routes — main Blueprint (Phase 6 full implementation).

Endpoints
---------
GET  /                         Landing page (returns JSON info for now; UI in Phase 7)
GET  /health                   Liveness check
POST /api/scan                 Upload + scan a requirements.txt or package.json
GET  /api/scan/<scan_id>       Full scan result with vulnerabilities
GET  /api/scans                List all scan summaries
GET  /api/scan/<scan_id>/sbom  Raw CycloneDX SBOM JSON for a scan
DELETE /api/scan/<scan_id>     Delete a scan and all its vulnerability records

Security
--------
* Filenames sanitised with werkzeug.utils.secure_filename.
* Only .txt and .json extensions accepted.
* MAX_CONTENT_LENGTH enforced by Flask (returns 413 before handler).
* Uploaded files deleted immediately after parsing (parser's finally block).
* No stack traces exposed in API responses.
* No internal paths exposed.
"""

import logging
import os
import traceback
from datetime import datetime, timezone
from werkzeug.utils import secure_filename

from flask import Blueprint, current_app, jsonify, request

from app import db
from app.models import Scan, Vulnerability
from app.parser import parse_file
from app.sbom_generator import generate_sbom
from app.scanner import scan_dependencies, STATUS_SCANNED, STATUS_SCAN_ERROR
from app.risk_scorer import calculate_risk_score

logger = logging.getLogger(__name__)

main = Blueprint("main", __name__)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _allowed_file(filename: str) -> bool:
    """Return True if the filename has an allowed extension."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in current_app.config.get("ALLOWED_EXTENSIONS", {".txt", ".json"})


def _json_error(message: str, status: int = 400) -> tuple:
    """Return a JSON error response."""
    return jsonify({"error": message}), status


def _detect_ecosystem(deps: list[dict]) -> str:
    """Infer the primary ecosystem from parsed dependencies."""
    ecosystems = [d.get("ecosystem", "") for d in deps]
    if "PyPI" in ecosystems:
        return "PyPI"
    if "npm" in ecosystems:
        return "npm"
    return "unknown"


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@main.app_errorhandler(413)
def request_entity_too_large(e):
    max_mb = current_app.config.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024) // (1024 * 1024)
    return _json_error(f"File too large. Maximum upload size is {max_mb} MB.", 413)


@main.app_errorhandler(404)
def not_found(e):
    return _json_error("Resource not found.", 404)


@main.app_errorhandler(405)
def method_not_allowed(e):
    return _json_error("Method not allowed.", 405)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@main.route("/")
def index():
    """Landing route — returns application info as JSON (UI delivered in Phase 7)."""
    return jsonify({
        "application": "SBOM & Dependency Risk Analyzer",
        "version": "1.0.0",
        "description": (
            "Upload a requirements.txt or package.json to scan "
            "dependencies for known vulnerabilities."
        ),
        "endpoints": {
            "POST /api/scan":                    "Upload and scan a dependency file",
            "GET  /api/scan/<id>":               "Retrieve scan results",
            "GET  /api/scans":                   "List all scans",
            "GET  /api/scan/<id>/sbom":          "Retrieve CycloneDX SBOM",
            "DELETE /api/scan/<id>":             "Delete a scan",
            "GET  /health":                      "Health check",
        },
    })


@main.route("/health")
def health():
    """Liveness check — returns 200 OK."""
    return jsonify({"status": "ok", "message": "SBOM Dependency Risk Analyzer is running."})


@main.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Upload and scan a requirements.txt or package.json file.

    Multipart form-data field name: 'file'

    Returns a full scan result JSON on success (201).
    Returns 400 for validation errors, 500 for unexpected failures.
    """
    # --- Validate file presence ---
    if "file" not in request.files:
        return _json_error("No file part in the request. Use field name 'file'.", 400)

    uploaded = request.files["file"]
    if not uploaded or not uploaded.filename:
        return _json_error("No file selected.", 400)

    filename = secure_filename(uploaded.filename)
    if not filename:
        return _json_error("Invalid filename.", 400)

    if not _allowed_file(filename):
        return _json_error(
            f"Unsupported file type. Only requirements.txt and package.json are accepted. "
            f"Got: {os.path.splitext(filename)[1] or '(no extension)'}",
            400,
        )

    # --- Save to uploads folder ---
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, filename)

    # Prevent path traversal
    if not os.path.abspath(filepath).startswith(os.path.abspath(upload_folder)):
        return _json_error("Invalid file path.", 400)

    try:
        uploaded.save(filepath)
    except OSError as exc:
        logger.error("Could not save uploaded file: %s", exc)
        return _json_error("Could not save uploaded file.", 500)

    # --- Parse dependencies (file is deleted inside parse_file's finally block) ---
    try:
        dependencies = parse_file(filepath, filename)
    except ValueError as exc:
        return _json_error(f"File validation failed: {exc}", 400)
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected parse error: %s", traceback.format_exc())
        return _json_error("Failed to parse the uploaded file.", 500)

    if not dependencies:
        return _json_error("No dependencies found in the uploaded file.", 400)

    # --- Generate SBOM ---
    try:
        sbom_json = generate_sbom(dependencies, filename)
    except Exception as exc:  # noqa: BLE001
        logger.error("SBOM generation failed: %s", exc)
        sbom_json = None  # non-fatal; continue with scan

    # --- Scan vulnerabilities ---
    try:
        scan_results = scan_dependencies(dependencies)
    except Exception as exc:  # noqa: BLE001
        logger.error("Vulnerability scan failed: %s", traceback.format_exc())
        return _json_error("Vulnerability scanning failed unexpectedly.", 500)

    # --- Calculate risk score ---
    risk = calculate_risk_score(scan_results)
    ecosystem = _detect_ecosystem(dependencies)

    # --- Persist to database ---
    try:
        scan_record, vuln_records = _persist_scan(
            filename=filename,
            ecosystem=ecosystem,
            dependencies=dependencies,
            scan_results=scan_results,
            sbom_json=sbom_json,
            risk=risk,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Database persistence failed: %s", traceback.format_exc())
        db.session.rollback()
        return _json_error("Failed to save scan results.", 500)

    # --- Build response ---
    response = _build_scan_response(scan_record, vuln_records, risk, dependencies)
    return jsonify(response), 201


@main.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id: int):
    """Return full scan details including all vulnerability records."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return _json_error(f"Scan {scan_id} not found.", 404)
    return jsonify(scan.to_dict())


@main.route("/api/scans", methods=["GET"])
def api_list_scans():
    """Return a list of all scan summaries, newest first."""
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return jsonify([s.to_summary_dict() for s in scans])


@main.route("/api/scan/<int:scan_id>/sbom", methods=["GET"])
def api_get_sbom(scan_id: int):
    """Return the raw CycloneDX SBOM JSON for a scan."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return _json_error(f"Scan {scan_id} not found.", 404)
    if not scan.sbom_json:
        return _json_error("No SBOM available for this scan.", 404)
    # Return the SBOM as a JSON object (it was stored as a JSON string)
    import json
    try:
        sbom_data = json.loads(scan.sbom_json)
    except (ValueError, TypeError):
        return _json_error("Stored SBOM is malformed.", 500)
    return jsonify(sbom_data)


@main.route("/api/scan/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id: int):
    """Delete a scan and all its associated vulnerability records."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return _json_error(f"Scan {scan_id} not found.", 404)
    try:
        db.session.delete(scan)
        db.session.commit()
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        logger.error("Failed to delete scan %d: %s", scan_id, exc)
        return _json_error("Failed to delete scan.", 500)
    return jsonify({"message": f"Scan {scan_id} deleted successfully."}), 200


# ---------------------------------------------------------------------------
# Database persistence
# ---------------------------------------------------------------------------

def _persist_scan(
    filename: str,
    ecosystem: str,
    dependencies: list[dict],
    scan_results: list[dict],
    sbom_json: str | None,
    risk: dict,
) -> tuple[Scan, list[Vulnerability]]:
    """
    Persist Scan and Vulnerability records in a single transaction.
    Returns (scan_record, list_of_vulnerability_records).
    """
    scan_record = Scan(
        filename=filename,
        ecosystem=ecosystem,
        created_at=datetime.now(timezone.utc),
        risk_score=risk["score"],
        risk_grade=_score_to_grade(risk["score"]),
        risk_grade_label=risk["risk_category"],
        total_deps=len(dependencies),
        scanned_deps=risk["scanned_count"],
        skipped_deps=risk["skipped_count"],
        error_deps=risk["error_count"],
        sbom_json=sbom_json,
    )
    db.session.add(scan_record)
    db.session.flush()  # get scan_record.id before adding children

    vuln_records: list[Vulnerability] = []

    for row in scan_results:
        v = Vulnerability(
            scan_id=scan_record.id,
            package_name=row.get("package_name", ""),
            version=row.get("version"),
            version_type=row.get("version_type", ""),
            scan_status=row.get("scan_status", ""),
            vuln_id=row.get("vuln_id"),
            severity=row.get("severity"),
            cvss_score=row.get("cvss_score"),
            cvss_vector=row.get("cvss_vector"),
            title=row.get("title"),
            description=row.get("description"),
            fixed_version=row.get("fixed_version"),
            recommendation=row.get("recommendation"),
            error_message=row.get("error_message"),
        )
        db.session.add(v)
        vuln_records.append(v)

    db.session.commit()
    return scan_record, vuln_records


# ---------------------------------------------------------------------------
# Response builder
# ---------------------------------------------------------------------------

def _build_scan_response(
    scan: Scan,
    vuln_records: list[Vulnerability],
    risk: dict,
    dependencies: list[dict],
) -> dict:
    """Build the structured JSON response returned from POST /api/scan."""
    # Collect only vuln rows (rows with a vuln_id)
    vulns = [v.to_dict() for v in vuln_records if v.vuln_id]

    # Coverage summary
    skipped_deps = [
        {"name": d["name"], "reason": d.get("skip_reason"), "specifier": d.get("version_specifier")}
        for d in dependencies
        if not d.get("is_exact_version")
        and d.get("parsing_status", "parsed") == "parsed"
    ]

    return {
        "scan_id":             scan.id,
        "filename":            scan.filename,
        "ecosystem":           scan.ecosystem,
        "scanned_at":          scan.created_at.isoformat(),
        "score_label":         risk["score_label"],
        "risk_score":          risk["score"],
        "risk_category":       risk["risk_category"],
        "insufficient_coverage": risk["insufficient_coverage"],
        "total_deps":          scan.total_deps,
        "scanned_deps":        risk["scanned_count"],
        "skipped_deps":        risk["skipped_count"],
        "error_deps":          risk["error_count"],
        "vulnerability_counts": {
            "critical": risk["critical_count"],
            "high":     risk["high_count"],
            "medium":   risk["medium_count"],
            "low":      risk["low_count"],
            "unknown":  risk["unknown_count"],
            "total":    risk["total_vuln_count"],
        },
        "has_vulnerabilities": risk["has_vulnerabilities"],
        "vulnerabilities":     vulns,
        "skipped_dependencies": skipped_deps,
        "sbom_available":      scan.sbom_json is not None,
        "sbom_url":            f"/api/scan/{scan.id}/sbom",
    }


# ---------------------------------------------------------------------------
# Grade helper (for Scan model)
# ---------------------------------------------------------------------------

def _score_to_grade(score: int) -> str:
    """Map a numeric risk score to a letter grade (A–F)."""
    if score == 0:
        return "A"
    if score <= 29:
        return "B"
    if score <= 59:
        return "C"
    if score <= 79:
        return "D"
    return "F"
