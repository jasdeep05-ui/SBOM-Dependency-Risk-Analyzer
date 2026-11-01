"""
Flask routes — main Blueprint.

Phase 1 stub: provides a minimal health-check endpoint so the application
can start and the database can be initialised. Full routes are implemented
in Phase 6.
"""

from flask import Blueprint, jsonify

main = Blueprint("main", __name__)


@main.route("/health")
def health():
    """Simple liveness check — returns 200 OK."""
    return jsonify({"status": "ok", "message": "SBOM Dependency Risk Analyzer is running."})
