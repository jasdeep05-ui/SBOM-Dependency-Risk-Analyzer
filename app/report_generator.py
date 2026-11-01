"""
Report generator — Phase 8.

Produces PDF and CSV export files for a completed scan.

Functions
---------
generate_pdf(scan, vulnerabilities, export_folder) -> str
    Build a ReportLab PDF and return its absolute file path.

generate_csv(scan, vulnerabilities, export_folder) -> str
    Build a stdlib CSV and return its absolute file path.
"""

import csv
import os
from datetime import timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ---------------------------------------------------------------------------
# Severity colour map (RGB tuples, 0-1 scale)
# ---------------------------------------------------------------------------

_SEVERITY_COLOURS = {
    "Critical": colors.HexColor("#dc2626"),   # red
    "High":     colors.HexColor("#ea580c"),   # orange
    "Medium":   colors.HexColor("#d97706"),   # amber
    "Low":      colors.HexColor("#16a34a"),   # green
    "Unknown":  colors.HexColor("#6b7280"),   # grey
}

_GRADE_COLOURS = {
    "A": colors.HexColor("#16a34a"),
    "B": colors.HexColor("#65a30d"),
    "C": colors.HexColor("#d97706"),
    "D": colors.HexColor("#ea580c"),
    "F": colors.HexColor("#dc2626"),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _created_at_str(scan) -> str:
    """Return a human-readable UTC timestamp for a Scan record."""
    dt = scan.created_at
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _severity_colour(severity: str):
    return _SEVERITY_COLOURS.get(severity or "Unknown", _SEVERITY_COLOURS["Unknown"])


def _grade_colour(grade: str):
    return _GRADE_COLOURS.get(grade or "F", _GRADE_COLOURS["F"])


# ---------------------------------------------------------------------------
# PDF generator
# ---------------------------------------------------------------------------

def generate_pdf(scan, vulnerabilities: list, export_folder: str) -> str:
    """
    Generate a PDF report for *scan* and write it to *export_folder*.

    Parameters
    ----------
    scan          : app.models.Scan instance
    vulnerabilities : list of app.models.Vulnerability instances
    export_folder : directory path where the file will be written

    Returns
    -------
    str — absolute path to the generated PDF file
    """
    os.makedirs(export_folder, exist_ok=True)
    filename = f"scan_{scan.id}_report.pdf"
    filepath = os.path.join(export_folder, filename)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title2", parent=styles["Title"], fontSize=18, spaceAfter=6
    )
    heading_style = ParagraphStyle(
        "Heading2b", parent=styles["Heading2"], fontSize=13, spaceAfter=4
    )
    normal_style = styles["Normal"]
    small_style = ParagraphStyle(
        "Small", parent=styles["Normal"], fontSize=8, leading=10
    )

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"SBOM Risk Report — Scan {scan.id}",
    )

    story = []

    # --- Cover / Header ---
    story.append(Paragraph("SBOM &amp; Dependency Risk Analyzer", title_style))
    story.append(Paragraph("Vulnerability Report", styles["Heading1"]))
    story.append(Spacer(1, 0.4 * cm))

    # Metadata table
    grade_colour = _grade_colour(scan.risk_grade)
    meta_data = [
        ["File", scan.filename or "—"],
        ["Ecosystem", scan.ecosystem or "—"],
        ["Scanned at", _created_at_str(scan)],
        ["Risk Score (Custom Project Risk Score — not CVSS)",
         f"{scan.risk_score} / 100"],
        ["Risk Grade", scan.risk_grade or "—"],
        ["Risk Category", scan.risk_grade_label or "—"],
        ["Total Dependencies", str(scan.total_deps)],
        ["Scanned", str(scan.scanned_deps)],
        ["Skipped", str(scan.skipped_deps)],
        ["Errors", str(scan.error_deps)],
    ]
    meta_table = Table(meta_data, colWidths=[9 * cm, 8 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",    (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.white, colors.HexColor("#f8fafc")]),
        ("TEXTCOLOR", (1, 4), (1, 4), grade_colour),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.6 * cm))

    # --- Severity summary ---
    story.append(Paragraph("Severity Summary", heading_style))
    vuln_rows = [v for v in vulnerabilities if v.vuln_id]
    sev_counts: dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0
    }
    for v in vuln_rows:
        sev = v.severity or "Unknown"
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    sev_table_data = [["Severity", "Count"]]
    for sev, count in sev_counts.items():
        sev_table_data.append([sev, str(count)])

    sev_table = Table(sev_table_data, colWidths=[5 * cm, 3 * cm])
    sev_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ALIGN",      (1, 0), (1, -1), "CENTER"),
    ]
    for i, sev in enumerate(["Critical", "High", "Medium", "Low", "Unknown"], start=1):
        if sev_counts.get(sev, 0) > 0:
            sev_style.append(
                ("TEXTCOLOR", (0, i), (0, i), _severity_colour(sev))
            )
    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)
    story.append(Spacer(1, 0.6 * cm))

    # --- Vulnerability detail table ---
    story.append(Paragraph("Vulnerability Details", heading_style))

    if not vuln_rows:
        story.append(Paragraph("No vulnerabilities found.", normal_style))
    else:
        headers = ["Package", "Version", "ID", "Severity", "CVSS", "Fixed", "Recommendation"]
        rows = [headers]
        for v in vuln_rows:
            rows.append([
                Paragraph(v.package_name or "—", small_style),
                Paragraph(v.version or "—", small_style),
                Paragraph(v.vuln_id or "—", small_style),
                Paragraph(v.severity or "Unknown", small_style),
                str(v.cvss_score) if v.cvss_score is not None else "—",
                Paragraph(v.fixed_version or "—", small_style),
                Paragraph(v.recommendation or "—", small_style),
            ])

        col_widths = [3.5 * cm, 2.0 * cm, 3.5 * cm, 2.0 * cm, 1.5 * cm, 2.0 * cm, 3.0 * cm]
        detail_table = Table(rows, colWidths=col_widths, repeatRows=1)
        detail_style = [
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
            ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f8fafc")]),
        ]
        detail_table.setStyle(TableStyle(detail_style))
        story.append(detail_table)

    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph(
        '<font size="8" color="#6b7280">'
        "Generated by SBOM &amp; Dependency Risk Analyzer — IBM Cybersecurity Training"
        "</font>",
        normal_style,
    ))

    doc.build(story)
    return filepath


# ---------------------------------------------------------------------------
# CSV generator
# ---------------------------------------------------------------------------

def generate_csv(scan, vulnerabilities: list, export_folder: str) -> str:
    """
    Generate a CSV report for *scan* and write it to *export_folder*.

    Parameters
    ----------
    scan          : app.models.Scan instance
    vulnerabilities : list of app.models.Vulnerability instances
    export_folder : directory path where the file will be written

    Returns
    -------
    str — absolute path to the generated CSV file
    """
    os.makedirs(export_folder, exist_ok=True)
    filename = f"scan_{scan.id}_report.csv"
    filepath = os.path.join(export_folder, filename)

    fieldnames = [
        "Package",
        "Version",
        "Ecosystem",
        "Vuln ID",
        "Severity",
        "CVSS Score",
        "CVSS Vector",
        "Fixed Version",
        "Recommendation",
        "Scan Status",
    ]

    vuln_rows = [v for v in vulnerabilities if v.vuln_id]

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        if not vuln_rows:
            # Write a single informational row so the CSV is never empty
            writer.writerow({
                "Package": scan.filename or "—",
                "Version": "—",
                "Ecosystem": scan.ecosystem or "—",
                "Vuln ID": "None found",
                "Severity": "—",
                "CVSS Score": "—",
                "CVSS Vector": "—",
                "Fixed Version": "—",
                "Recommendation": "No vulnerable dependencies detected.",
                "Scan Status": "clean",
            })
        else:
            for v in vuln_rows:
                writer.writerow({
                    "Package": v.package_name or "—",
                    "Version": v.version or "—",
                    "Ecosystem": scan.ecosystem or "—",
                    "Vuln ID": v.vuln_id or "—",
                    "Severity": v.severity or "Unknown",
                    "CVSS Score": v.cvss_score if v.cvss_score is not None else "—",
                    "CVSS Vector": v.cvss_vector or "—",
                    "Fixed Version": v.fixed_version or "—",
                    "Recommendation": v.recommendation or "—",
                    "Scan Status": v.scan_status or "—",
                })

    return filepath
