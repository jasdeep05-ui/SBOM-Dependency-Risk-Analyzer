# SBOM & Dependency Risk Analyzer

A cybersecurity web application that helps developers identify vulnerable third-party software dependencies. Developed as part of **IBM Cybersecurity Training**.

---

## Features

| # | Feature |
|---|---------|
| 1 | Upload `requirements.txt` (Python) or `package.json` (Node.js) files |
| 2 | Extract dependency names and versions |
| 3 | Generate an SBOM using the **CycloneDX 1.5** standard |
| 4 | Scan dependencies using the **OSV vulnerability database API** |
| 5 | Classify vulnerabilities by severity: Critical, High, Medium, Low |
| 6 | Calculate a custom **Dependency Risk Score** (0–100) |
| 7 | Display results in a professional dark-theme dashboard |
| 8 | Provide per-vulnerability remediation recommendations |
| 9 | Export reports as **PDF** (ReportLab) and **CSV** |

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.13, Flask 3.x |
| Database | SQLite via Flask-SQLAlchemy |
| SBOM | `cyclonedx-python-lib` (CycloneDX 1.5 JSON) |
| Vulnerability API | [OSV.dev](https://osv.dev/) — `https://api.osv.dev/v1/query` |
| CVSS parsing | `cvss` 3.2 (v2, v3, v4 all supported) |
| PDF export | ReportLab |
| Frontend | Vanilla HTML5 / CSS3 / JavaScript (no framework) |
| Testing | pytest + responses (HTTP mocking) |

---

## Project Structure

```
SBOM-Dependency-Risk-Analyzer/
│
├── app/
│   ├── __init__.py            Flask app factory (create_app)
│   ├── models.py              SQLAlchemy models: Scan, Vulnerability
│   ├── parser.py              requirements.txt + package.json parser
│   ├── sbom_generator.py      CycloneDX 1.5 SBOM generator
│   ├── scanner.py             OSV API scanner (CVSS v2/v3/v4 aware)
│   ├── risk_scorer.py         Custom risk scoring engine (0–100)
│   ├── routes.py              All Flask routes + export endpoints
│   └── report_generator.py   PDF (ReportLab) + CSV report generation
│
├── templates/
│   └── index.html             Single-page dashboard
│
├── static/
│   ├── css/dashboard.css      Dark navy cybersecurity theme
│   └── js/dashboard.js        Upload, scan, results, history, delete, export
│
├── tests/
│   ├── fixtures/              sample_requirements.txt, sample_package.json, …
│   ├── test_parser.py         94 tests
│   ├── test_sbom_generator.py 53 tests
│   ├── test_scanner.py        69 tests
│   ├── test_risk_scorer.py    36 tests
│   ├── test_routes.py         47 tests (incl. export endpoints)
│   └── test_report_generator.py  33 tests
│
├── config.py                  Application configuration
├── run.py                     Development entry point
├── requirements.txt           Python dependencies
└── .gitignore
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the development server

```bash
set FLASK_ENV=development   # Windows
flask run --app run
```

Or:

```bash
python run.py
```

The app will be available at **http://localhost:5000**.

### 3. Run the test suite

```bash
pytest
```

All tests should pass (332 total).

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard HTML |
| `GET` | `/health` | Liveness check |
| `POST` | `/api/scan` | Upload + scan a file (`multipart/form-data`, field `file`) |
| `GET` | `/api/scan/<id>` | Full scan result with vulnerabilities |
| `GET` | `/api/scans` | List all scan summaries |
| `GET` | `/api/scan/<id>/sbom` | Raw CycloneDX SBOM JSON |
| `DELETE` | `/api/scan/<id>` | Delete a scan and all its vulnerability records |
| `GET` | `/api/scan/<id>/export/pdf` | Download PDF report |
| `GET` | `/api/scan/<id>/export/csv` | Download CSV report |

---

## Risk Score

The **Custom Project Risk Score** (0–100) is **not a CVSS score**. It is a weighted count of vulnerabilities found in the scanned dependencies:

| Severity | Points |
|----------|--------|
| Critical | 10 |
| High     | 5  |
| Medium   | 2  |
| Low      | 1  |
| Unknown  | 0 (counted separately) |

Score is capped at 100.

| Score Range | Category |
|-------------|----------|
| 0 | No known risk detected |
| 1–29 | Low |
| 30–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

---

## Security Notes

- Uploaded files are sanitised with `werkzeug.utils.secure_filename` and **deleted immediately** after parsing.
- Only `.txt` and `.json` extensions are accepted.
- Maximum upload size: **2 MB** (HTTP 413 returned otherwise).
- No stack traces or internal paths are exposed in API responses.
- Path traversal attacks are blocked by `os.path.abspath` comparison.

---

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *(insecure fallback)* | Flask secret key — **set this in production** |
| `FLASK_ENV` | `production` | Set to `development` to enable debug mode |
| `CORS_ALLOWED_ORIGINS` | *(empty — CORS disabled)* | Comma-separated allowed origins |

---

## License

Developed for IBM Cybersecurity Training — educational use only.
