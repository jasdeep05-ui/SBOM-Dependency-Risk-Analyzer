"""
SQLAlchemy database models.

Two models:
  Scan           — one record per uploaded file scan
  Vulnerability  — one record per vulnerability finding (or skip/error record) per scan
"""

from datetime import datetime, timezone

from . import db


class Scan(db.Model):
    """Represents a single dependency scan run."""

    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    ecosystem = db.Column(db.String(50), nullable=False)  # "pypi" or "npm"
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Risk summary
    risk_score = db.Column(db.Integer, nullable=True)   # 0–100
    risk_grade = db.Column(db.String(1), nullable=True)  # A–F
    risk_grade_label = db.Column(db.String(50), nullable=True)

    # Coverage counters
    total_deps = db.Column(db.Integer, nullable=False, default=0)
    scanned_deps = db.Column(db.Integer, nullable=False, default=0)
    skipped_deps = db.Column(db.Integer, nullable=False, default=0)
    error_deps = db.Column(db.Integer, nullable=False, default=0)

    # CycloneDX SBOM stored as a JSON string
    sbom_json = db.Column(db.Text, nullable=True)

    # Relationship
    vulnerabilities = db.relationship(
        "Vulnerability", backref="scan", lazy=True, cascade="all, delete-orphan"
    )

    def to_summary_dict(self):
        """Return a lightweight dict suitable for the scan-list API response."""
        return {
            "id": self.id,
            "filename": self.filename,
            "ecosystem": self.ecosystem,
            "created_at": self.created_at.isoformat(),
            "risk_score": self.risk_score,
            "risk_grade": self.risk_grade,
            "risk_grade_label": self.risk_grade_label,
            "total_deps": self.total_deps,
            "scanned_deps": self.scanned_deps,
            "skipped_deps": self.skipped_deps,
            "error_deps": self.error_deps,
        }

    def to_dict(self):
        """Return the full scan dict including all vulnerability records."""
        d = self.to_summary_dict()
        d["sbom_json"] = self.sbom_json
        d["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        return d


class Vulnerability(db.Model):
    """
    Represents one row per dependency-per-vulnerability (or one row per
    skipped/errored dependency when no vulnerabilities exist).

    scan_status values:
      "scanned"           — OSV was queried successfully (may have 0 vulns)
      "skipped_range"     — version is a range; OSV not queried
      "skipped_unpinned"  — no version specified; OSV not queried
      "scan_error"        — OSV query failed (timeout, HTTP error, etc.)
    """

    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)

    # Dependency identity
    package_name = db.Column(db.String(255), nullable=False)
    version = db.Column(db.String(100), nullable=True)       # exact version, if known
    version_type = db.Column(db.String(20), nullable=False)  # "exact" | "range" | "unpinned"
    scan_status = db.Column(db.String(30), nullable=False)   # see docstring above

    # Vulnerability details (null for skipped/error rows)
    vuln_id = db.Column(db.String(100), nullable=True)       # e.g. "GHSA-xxxx" or "CVE-xxxx"
    severity = db.Column(db.String(20), nullable=True)       # Critical/High/Medium/Low/Unknown
    cvss_score = db.Column(db.Float, nullable=True)          # numeric base score
    cvss_vector = db.Column(db.String(200), nullable=True)   # raw CVSS vector string
    title = db.Column(db.String(500), nullable=True)
    description = db.Column(db.Text, nullable=True)
    fixed_version = db.Column(db.String(100), nullable=True)
    recommendation = db.Column(db.String(500), nullable=True)

    # Set when scan_status == "scan_error"
    error_message = db.Column(db.String(500), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "package_name": self.package_name,
            "version": self.version,
            "version_type": self.version_type,
            "scan_status": self.scan_status,
            "vuln_id": self.vuln_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "title": self.title,
            "description": self.description,
            "fixed_version": self.fixed_version,
            "recommendation": self.recommendation,
            "error_message": self.error_message,
        }
