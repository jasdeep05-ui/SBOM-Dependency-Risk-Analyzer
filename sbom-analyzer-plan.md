# SBOM & Dependency Risk Analyzer — Implementation Plan

## Top-Level Overview

**Goal:** Build a full-stack web application that allows developers to upload `requirements.txt` or
`package.json` files, extract their dependencies, generate a CycloneDX-compliant SBOM, scan for known
vulnerabilities via the OSV API, classify findings by severity, calculate a custom project risk score,
display results in a professional dashboard, and export reports as PDF or CSV.

**Stack:** Python Flask · SQLite (via SQLAlchemy) · CycloneDX · OSV API · Bootstrap 5 · Chart.js · ReportLab

**Scope:** 9 development phases from project scaffolding through documentation. No authentication layer
is required for this training project.

**Non-Goals:** No user authentication, no multi-tenancy, no Docker packaging (unless later requested).

---

## Folder Structure

```
SBOM-Dependency-Risk-Analyzer/
│
├── app/
│   ├── __init__.py               # Flask app factory
│   ├── routes.py                 # All API + page routes
│   ├── parser.py                 # requirements.txt & package.json parser
│   ├── sbom_generator.py         # CycloneDX SBOM builder
│   ├── vulnerability_scanner.py  # OSV API integration
│   ├── risk_scorer.py            # Severity classification & risk scoring
│   ├── report_generator.py       # PDF & CSV export
│   └── models.py                 # SQLite DB models via Flask-SQLAlchemy
│
├── static/
│   ├── css/
│   │   └── dashboard.css
│   ├── js/
│   │   └── dashboard.js
│   └── assets/
│       └── logo.png
│
├── templates/
│   ├── index.html                # Upload page
│   ├── dashboard.html            # Results dashboard
│   └── report.html               # Printable report view
│
├── tests/
│   ├── __init__.py
│   ├── test_parser.py            # Parser unit tests
│   ├── test_sbom_generator.py    # SBOM generation tests
│   ├── test_vulnerability_scanner.py  # Scanner + OSV mock tests
│   ├── test_risk_scorer.py       # Scoring logic tests
│   └── fixtures/
│       ├── sample_requirements.txt    # Valid sample with pinned + unpinned deps
│       ├── sample_requirements_malformed.txt  # Malformed lines
│       ├── sample_package.json        # Valid sample with exact + range versions
│       └── sample_package_malformed.json     # Malformed JSON
│
├── uploads/                      # Temp uploaded files — deleted after scan (gitignored)
├── exports/                      # Generated PDF/CSV outputs (gitignored)
├── instance/
│   └── scans.db                  # SQLite database
│
├── requirements.txt              # Python dependencies
├── config.py                     # App configuration
├── run.py                        # Entry point (development only)
├── README.md                     # Setup, architecture, usage, API reference
└── .gitignore
```

---

## Python Dependencies (requirements.txt)

```
Flask==3.0.3
Flask-SQLAlchemy==3.1.1
flask-cors==4.0.1
requests==2.32.3
cyclonedx-python-lib==7.3.0
packageurl-python==0.15.3
cvss==3.2
reportlab==4.2.2
Werkzeug==3.0.3
pytest==8.2.2
pytest-mock==3.14.0
responses==0.25.3
```

> `packageurl-python` — PURL construction and validation for SBOM components.
> `cvss` — Parse CVSS v2/v3 vector strings and extract numeric base scores reliably.
> `responses` — HTTP mocking library for unit tests (mocks `requests` without monkeypatching).

---

## Key Technical Decisions

### Version Handling
- The parser preserves the **original version specifier string** (e.g. `>=1.2.0`, `^3.4.1`, `*`).
- Each dependency is classified as one of three version states:
  - `exact` — a single pinned version (e.g. `==1.2.0` in pip, `1.2.0` without prefix in npm)
  - `range` — a version range or constraint (e.g. `>=1.0`, `^2.0`, `~1.5`)
  - `unpinned` — no version specified at all
- OSV is **only queried for `exact` versions**. Range and unpinned dependencies are flagged with a
  `scan_status` of `"skipped_range"` or `"skipped_unpinned"` respectively, and are displayed in the
  dashboard with a clear notice rather than misleading scan results.

### Severity Handling
- Severity is extracted from the OSV response in this priority order:
  1. CVSS v3 base score from `severity[].score` (type `CVSS_V3`)
  2. CVSS v2 base score from `severity[].score` (type `CVSS_V2`)
  3. Database-specific string (e.g. `database_specific.severity`)
- CVSS numeric scores are mapped: 9.0–10.0 → Critical, 7.0–8.9 → High, 4.0–6.9 → Medium, 0.1–3.9 → Low
- When no severity information is present in the OSV record, severity is stored as **`"Unknown"`** —
  never silently mapped to Low. The raw CVSS score (if available) is also stored for transparency.
- The dashboard displays Unknown findings in a separate category with a visual indicator.

### Risk Scoring
- The risk score is a **custom project score (0–100)**, clearly labelled as such — not an official
  CVSS score.
- Formula: `min(Critical×10 + High×5 + Medium×2 + Low×1, 100)`
- Unknown-severity vulnerabilities are **excluded from the numeric score** but counted and displayed
  separately in the dashboard.
- Grade mapping: A (0–19 · Safe) · B (20–39 · Low Risk) · C (40–59 · Moderate) ·
  D (60–79 · High Risk) · F (80–100 · Critical)

### SBOM Compliance
- The CycloneDX component `version` field is **only populated when `version_type == "exact"`**.
  For range or unpinned dependencies, the `version` field is omitted (left empty/None) — never
  set to a range specifier like `">=1.0.0"`, which would be invalid per the CycloneDX spec.
- The original version specifier for non-exact entries is stored in a CycloneDX component
  **property** (`originalVersionSpecifier`) so it is preserved in the SBOM without polluting
  the structured `version` field.
- All PURLs are constructed and validated using the `packageurl-python` library. Invalid PURLs
  are logged and the component is written without a purl rather than failing.
- SBOM metadata includes: timestamp (UTC ISO 8601), tool name, tool version, and component count.
- Output is validated as parseable CycloneDX 1.5 JSON (checked by test suite).

### Upload Security
- Maximum upload size: **2 MB**, enforced via Flask's `MAX_CONTENT_LENGTH` setting.
- Allowed file extensions: `.txt` (requirements) and `.json` (package.json) only.
- File contents are validated before parsing: `.txt` files must be text-decodable as UTF-8;
  `.json` files must parse as valid JSON with a top-level object.
- Filenames are sanitised with `werkzeug.utils.secure_filename` before writing to disk.
- Uploaded files are **deleted from the `uploads/` directory** immediately after parsing completes,
  whether parsing succeeds or fails. Uploaded files are never executed.

### Configuration & Environment
- `SECRET_KEY` is loaded from the `SECRET_KEY` environment variable; a hard-coded fallback is only
  used in development and triggers a visible warning.
- `DEBUG` mode defaults to `False` and is only enabled when `FLASK_ENV=development`.
- CORS is **disabled by default**. It can be enabled for specific origins via the
  `CORS_ALLOWED_ORIGINS` environment variable (comma-separated). Blanket `*` CORS is not permitted.

---

## Sub-Tasks

---

### Phase 1 — Project Setup & Configuration

**Intent:** Scaffold the full directory structure, Flask app factory, configuration, database
initialization, and entry point. This establishes the skeleton that all other phases build on.

**Expected Outcomes:**
- `run.py` starts a Flask development server without errors
- SQLite database file is created on first run via `db.create_all()`
- All directories exist and are correctly structured
- `.gitignore` excludes `uploads/`, `exports/`, `instance/`, `__pycache__/`, `.env`
- Secret key is loaded from environment variable; a fallback dev key triggers a logged warning
- Debug mode defaults to off and is only enabled via `FLASK_ENV=development`
- `MAX_CONTENT_LENGTH` is set to 2 MB in config

**Todo List:**
1. Create `.gitignore` with standard Python + Flask exclusions (`__pycache__`, `*.pyc`, `.env`,
   `uploads/`, `exports/`, `instance/`, `.pytest_cache/`)
2. Create `config.py`:
   - `SECRET_KEY` from `os.environ.get("SECRET_KEY")` with dev fallback + warning log
   - `SQLALCHEMY_DATABASE_URI` pointing to `instance/scans.db`
   - `UPLOAD_FOLDER`, `EXPORT_FOLDER`, `MAX_CONTENT_LENGTH = 2 * 1024 * 1024`
   - `ALLOWED_EXTENSIONS = {".txt", ".json"}`
   - `CORS_ALLOWED_ORIGINS` from `os.environ.get("CORS_ALLOWED_ORIGINS", "")` — empty means disabled
   - `DEBUG` set only when `FLASK_ENV == "development"`
3. Create `app/__init__.py` as Flask app factory:
   - Init SQLAlchemy
   - Apply CORS only if `CORS_ALLOWED_ORIGINS` is non-empty, targeting specific origins
   - Register Blueprint from `routes.py`
   - Call `db.create_all()` inside app context on startup
4. Create `app/models.py` with two SQLAlchemy models:
   - `Scan` — id, filename, ecosystem, created_at, risk_score, risk_grade, sbom_json,
     total_deps, scanned_deps, skipped_deps, error_deps
   - `Vulnerability` — id, scan_id (FK), package_name, version, version_type, scan_status,
     vuln_id, severity, cvss_score, cvss_vector, title, description, fixed_version,
     recommendation, error_message
   (Note: `scan_status` values: `"scanned"`, `"skipped_range"`, `"skipped_unpinned"`, `"scan_error"`)
5. Create `run.py` — imports app factory, sets `FLASK_ENV=development` guard, runs with
   `debug=True` only in development
6. Create `requirements.txt` with all Python dependencies (including `packageurl-python`, `cvss`,
   `responses`, `pytest`, `pytest-mock`)
7. Create placeholder `uploads/.gitkeep` and `exports/.gitkeep`
8. Create `tests/__init__.py`

**Relevant Context:** No existing code. Standard Flask app factory pattern.

**Status:** [ ] pending

---

### Phase 2 — Dependency Parser

**Intent:** Parse uploaded `requirements.txt` (Python) and `package.json` (Node.js) files to extract
a structured list of dependencies with their version state clearly classified. Only exact versions are
marked suitable for OSV scanning. Malformed individual entries never crash the whole parse.

**Expected Outcomes:**
- `app/parser.py` exposes `parse_file(filepath, filename)` function
- Returns a list of dicts: `[{name, version_raw, version_exact, version_type, ecosystem}]`
  - `version_raw` — original specifier string as-is (e.g. `">=1.2.0"`, `"^3.0.1"`, `""`)
  - `version_exact` — resolved exact version string when `version_type == "exact"`, else `None`
  - `version_type` — one of `"exact"`, `"range"`, `"unpinned"`
- `version_type == "exact"` only when the version is a plain, fully-resolved version number —
  never for wildcard (`*`), ranges (`>=`, `^`, `~`, `>`), Git URLs, workspace: refs, or URL deps
- Scoped npm package names (`@scope/package`) are parsed correctly
- File contents are validated before parsing (UTF-8 for `.txt`, valid JSON object for `.json`)
- Malformed individual lines/entries are skipped with `logging.warning` — not a hard failure
- Uploaded file is deleted from disk after parsing completes (success or failure)

**Todo List:**
1. Implement file content validation helpers:
   - `validate_txt_file(filepath)` — attempt UTF-8 decode, raise `ValueError` on failure
   - `validate_json_file(filepath)` — attempt `json.load`, raise `ValueError` if not a dict
2. Implement `parse_requirements_txt(filepath)`:
   - Line-by-line, skip blanks, `#` comments, `-r`/`-c`/`-e` option lines, and URL-based deps
   - Strip extras (`package[extra]`) using regex; preserve package name only
   - `==x.y.z` (single exact pin) → `exact`; any other operator or multiple specifiers → `range`;
     no version at all → `unpinned`
3. Implement `parse_package_json(filepath)`:
   - Load JSON, merge `dependencies` and `devDependencies` (skip missing keys)
   - Support scoped package names (`@scope/pkg`) — preserve `@scope/` prefix in `name`
   - Classify version string: bare semver digits only → `exact`; `^`/`~`/`>`/`<`/`>=`/`<=`/`*`
     prefix, `||`, `-`, `x` wildcard, `workspace:`, `file:`, `git+`, `http` → `range`; empty → `unpinned`
   - Wrap each entry parse in try/except; log warning and skip on error
4. Implement `parse_file(filepath, filename)` dispatcher:
   - Validate file content first; raise `ValueError` on invalid content
   - Call correct parser, then delete the uploaded file in a `finally` block
5. Write `tests/fixtures/sample_requirements.txt` — mix of pinned (`==`), range (`>=`, `~=`),
   unpinned, comments, extras, and one URL dep (to be classified as range/skipped)
6. Write `tests/fixtures/sample_requirements_malformed.txt` — malformed lines mixed with valid ones
7. Write `tests/fixtures/sample_package.json` — exact semver, `^`/`~` ranges, `*`, scoped package,
   `workspace:` ref, unpinned entries
8. Write `tests/fixtures/sample_package_malformed.json` — invalid JSON (not a dict)

**Relevant Context:** `app/parser.py` (new). No external libraries beyond stdlib.

**Status:** [ ] pending

---

### Phase 3 — SBOM Generator

**Intent:** Take the parsed dependency list and produce a valid CycloneDX 1.5 SBOM document (JSON).
Exact versions go into the component `version` field; non-exact original specifiers are preserved in
a component property rather than polluting the structured `version` field.

**Expected Outcomes:**
- `app/sbom_generator.py` exposes `generate_sbom(dependencies, source_filename)` function
- Returns a CycloneDX-compliant JSON string (spec version 1.5)
- Component `version` field is set to `version_exact` if available, **left empty otherwise** —
  never set to a range specifier (e.g. `">=1.0.0"`)
- For non-exact deps, the original `version_raw` specifier is stored as a component property with
  name `originalVersionSpecifier`
- PURLs are constructed from `(name, version_exact, ecosystem)` using `packageurl-python`; built
  only when `version_exact` is not None. Invalid PURLs are logged and omitted; component is still
  included without a purl field
- SBOM metadata includes: UTC timestamp, tool name `"SBOM-Dependency-Risk-Analyzer"`, tool version,
  total component count
- Returned JSON can be parsed by `json.loads` and contains `bomFormat` = `"CycloneDX"`

**Todo List:**
1. Implement `build_purl(name, version_exact, ecosystem)` helper:
   - Only called when `version_exact` is not None
   - Construct `pkg:pypi/name@version` or `pkg:npm/%40scope%2Fname@version` (URL-encode scope)
   - Validate with `PackageURL.from_string()` from `packageurl-python`
   - Return validated purl string, or `None` on `ValueError` (log warning)
2. Implement `generate_sbom(dependencies, source_filename)`:
   - Create `Bom` instance and populate metadata (timestamp, tool)
   - For each dependency:
     - Set `version` = `version_exact` if available, else omit the field (pass `None`)
     - If `version_raw` and `version_type != "exact"`, add a property `originalVersionSpecifier`
     - Build purl only when `version_exact` is not None
     - Create `Component` of type `ComponentType.LIBRARY`
   - Serialize to JSON using the library's JSON serializer
3. Return the JSON string

**Relevant Context:** `app/sbom_generator.py` (new). Uses `cyclonedx-python-lib` and `packageurl-python`.

**Status:** [ ] pending

---

### Phase 4 — Vulnerability Scanner

**Intent:** Query the OSV API for each `exact`-version dependency to retrieve CVEs and advisories.
Range and unpinned dependencies are skipped. API failures produce a `scan_error` record — never a
clean/zero-vulnerability result. CVSS scores are parsed from vector strings using the `cvss` library.

**Expected Outcomes:**
- `app/vulnerability_scanner.py` exposes `scan_dependencies(dependencies)` function
- Ecosystem identifiers: `"PyPI"` for Python packages, `"npm"` for Node.js packages
- Only queries OSV for `version_type == "exact"` dependencies
- Non-exact deps get `scan_status` of `"skipped_range"` or `"skipped_unpinned"`
- If `query_osv` raises (timeout, connection error, HTTP error, malformed JSON), the dependency
  gets `scan_status = "scan_error"` and `error_message` — **never reported as zero vulnerabilities**
- Severity stored as `"Critical"` / `"High"` / `"Medium"` / `"Low"` / `"Unknown"` — never defaulted
- CVSS base score is extracted by parsing the CVSS vector string using the `cvss` library —
  **never by converting the raw vector string to a float directly**
- Raw CVSS vector string and numeric base score both stored when available
- Returns a flat list of result dicts covering all input dependencies

**Todo List:**
1. Implement `query_osv(package_name, version, ecosystem)`:
   - Use `"PyPI"` for pypi ecosystem (capital P), `"npm"` for npm
   - POST to `https://api.osv.dev/v1/query` with body `{package: {name, version, ecosystem}}`
   - 10-second timeout; retry up to 3 times with exponential back-off on `requests.exceptions.ConnectionError` and `requests.exceptions.Timeout`
   - Raise `requests.exceptions.HTTPError` on non-2xx responses (call `response.raise_for_status()`)
   - Return parsed JSON dict, or raise the exception on final failure
2. Implement `extract_severity(vuln_record)` → returns `(severity_label: str, cvss_score: float|None, cvss_vector: str|None)`:
   - Iterate `severity` array; check `type` field for `"CVSS_V3"` first, then `"CVSS_V2"`
   - Parse base score from the vector string using `cvss.CVSS3(vector).base_score` or
     `cvss.CVSS2(vector).base_score` — never cast the vector string to float
   - Map numeric score: ≥9.0 → Critical, ≥7.0 → High, ≥4.0 → Medium, >0 → Low
   - Fall back to `database_specific.severity` string: map `"CRITICAL"/"HIGH"/"MODERATE"/"MEDIUM"/"LOW"` strings
   - If nothing found: return `("Unknown", None, None)` — never `"Low"` as a default
3. Implement `extract_fixed_version(vuln_record, package_name)`:
   - Search `affected[].ranges[].events` where the event has key `"fixed"`; return first found or `None`
4. Implement `scan_dependencies(dependencies)`:
   - For `version_type != "exact"`: append a skipped record (no vuln fields) with appropriate `scan_status`
   - For `exact`: call `query_osv` inside a try/except; on any exception set `scan_status = "scan_error"`,
     record `error_message`, and do **not** produce a zero-vulnerability result for that package
   - On success: parse each vuln record, build full result dicts, deduplicate by `(package_name, version, vuln_id)`
   - Return flat list covering all input dependencies

**Relevant Context:** `app/vulnerability_scanner.py` (new). Uses `cvss` library. OSV API: https://google.github.io/osv.dev/api/

**Status:** [ ] pending

---

### Phase 5 — Risk Scorer

**Intent:** Aggregate vulnerability findings into a custom project risk score (0–100) with a letter
grade. Unknown-severity findings and scan errors are tracked separately and excluded from the numeric
formula. If coverage is insufficient (no packages were successfully scanned), a warning flag is
returned so the dashboard never implies a clean result.

**Expected Outcomes:**
- `app/risk_scorer.py` exposes `calculate_risk_score(vulnerabilities)` function
- Returns a dict with keys:
  `{score, grade, grade_label, critical_count, high_count, medium_count, low_count,
    unknown_count, skipped_count, error_count, scanned_count, insufficient_coverage}`
- `score` and `grade` are computed only from Critical / High / Medium / Low findings; capped at 100
- `unknown_count` — vulnerabilities with severity `"Unknown"`
- `skipped_count` — records with `scan_status` in `["skipped_range", "skipped_unpinned"]`
- `error_count` — records with `scan_status == "scan_error"`
- `scanned_count` — records with `scan_status == "scanned"` (successfully queried)
- `insufficient_coverage = True` when `scanned_count == 0` and `(skipped_count + error_count) > 0`
- All consumers label the score as **"Custom Project Risk Score (not CVSS)"**

**Todo List:**
1. Implement `count_by_severity(vulnerabilities)` — returns counts for each severity label,
   plus `unknown`, `skipped`, `error`, `scanned`
2. Implement `calculate_risk_score(vulnerabilities)`:
   - Formula: `min(critical×10 + high×5 + medium×2 + low×1, 100)`
   - Exclude Unknown, skipped, and error records from formula
   - Compute `insufficient_coverage` flag
3. Implement `assign_grade(score)` — returns `(letter, label)` tuple:
   - A (0–19 · Safe) · B (20–39 · Low Risk) · C (40–59 · Moderate) · D (60–79 · High Risk) · F (80–100 · Critical)
4. Return full summary dict with all fields listed above

**Relevant Context:** `app/risk_scorer.py` (new). Pure Python, no external dependencies.

**Status:** [ ] pending

---

### Phase 6 — Flask Routes & API

**Intent:** Wire all backend modules together through Flask routes — handling secure file uploads,
running the full scan pipeline, persisting results to SQLite, and serving dashboard pages.

**Expected Outcomes:**
- `GET /` serves the upload page (`index.html`)
- `POST /api/scan` validates file (size, extension, content), runs full pipeline, deletes temp file,
  persists to DB, returns JSON
- `GET /api/scans` returns all past scan summaries
- `GET /api/scan/<scan_id>` returns full scan detail including vulnerabilities
- `GET /dashboard/<scan_id>` renders `dashboard.html`
- `MAX_CONTENT_LENGTH` violation returns a clear 413 JSON error response
- All API errors return `{error: message}` with appropriate HTTP status codes

**Todo List:**
1. Create `app/routes.py` and register a Flask Blueprint
2. Implement `GET /` — render `index.html`
3. Implement `POST /api/scan`:
   - Reject missing file, wrong extension, oversized upload (413) before writing to disk
   - Save with `secure_filename`; validate file content (UTF-8 / valid JSON)
   - Run `parse_file` → `generate_sbom` → `scan_dependencies` → `calculate_risk_score`
   - Persist `Scan` and `Vulnerability` records; temp file is deleted by `parse_file`'s `finally` block
   - Return full JSON result
4. Add `@app.errorhandler(413)` to return JSON error for oversized uploads
5. Implement `GET /api/scans` — return scan summaries
6. Implement `GET /api/scan/<scan_id>` — return scan + vulnerabilities; 404 if not found
7. Implement `GET /dashboard/<scan_id>` — render `dashboard.html`
8. Register Blueprint in `app/__init__.py`

**Relevant Context:** `app/routes.py` (new), `app/__init__.py` (update). All pipeline modules from Phases 2–5.

**Status:** [ ] pending

---

### Phase 7 — Frontend Dashboard

**Intent:** Build a professional, responsive web UI with three views: an upload landing page, a scan
results dashboard with severity charts (including Unknown category), and a printable report view.

**Expected Outcomes:**
- Upload page: drag-and-drop + click-to-upload, client-side extension validation, loading spinner,
  2 MB size check with user-friendly error message before submission
- Dashboard: custom risk score badge (labelled "Custom Project Risk Score — not CVSS"), severity
  donut chart including Unknown slice, vulnerability table (package, version type flag, severity,
  CVE ID, description, fix version, recommendation), skipped-dependency notice section
- Scan history sidebar linking to past scans
- Export buttons (PDF, CSV) on dashboard
- Severity row colour coding: Critical=red, High=orange, Medium=yellow, Low=blue, Unknown=grey
- Bootstrap 5 responsive layout

**Todo List:**
1. Create `templates/index.html` — upload form, Bootstrap 5, drag-and-drop area, JS fetch POST to
   `/api/scan`, client-side validation (extension + 2 MB limit), spinner on submit, redirect on success
2. Create `templates/dashboard.html` — fetches `/api/scan/<id>`, renders:
   - Risk score card labelled "Custom Project Risk Score (not CVSS)"
   - Severity donut chart (Critical / High / Medium / Low / Unknown slices)
   - Skipped-dependency alert box (if `skipped_count > 0`)
   - Vulnerability table with all columns including Recommendation
   - Remediation summary card (count of packages with available fix vs. no fix)
3. Create `templates/report.html` — printer-friendly SBOM summary + full vulnerability list
4. Create `static/css/dashboard.css` — severity colour palette, risk score card styling, table row colours
5. Create `static/js/dashboard.js` — Chart.js donut init, fetch and populate table, export button handlers

**Relevant Context:** `templates/` and `static/` directories (new). Bootstrap 5 and Chart.js via CDN.

**Status:** [ ] pending

---

### Phase 8 — Report Export (PDF & CSV)

**Intent:** Allow users to download scan results as a PDF report or CSV file, both of which include
the Unknown severity category and the "Custom Project Risk Score" label.

**Expected Outcomes:**
- `GET /api/export/<scan_id>/csv` — downloadable `.csv` with columns: Package, Version, Version Type,
  Scan Status, Vulnerability ID, Severity, CVSS Score, Title, Fixed Version, Recommendation
- `GET /api/export/<scan_id>/pdf` — downloadable `.pdf` with cover page (scan metadata, risk score
  labelled as custom score), severity summary table (including Unknown), full vulnerability table
- Temp export files are generated in `exports/` and streamed to the client

**Todo List:**
1. Create `app/report_generator.py`
2. Implement `generate_csv(scan, vulnerabilities)` using Python `csv` stdlib — all columns including
   Unknown findings; return file path
3. Implement `generate_pdf(scan, vulnerabilities)` using `reportlab`:
   - Cover: filename, date, risk score with "Custom Project Risk Score (not CVSS)" label, grade
   - Severity summary table including Unknown count
   - Full vulnerability table (all columns)
   - Return file path
4. Add `GET /api/export/<scan_id>/csv` route — generate, stream with `send_file`, MIME `text/csv`
5. Add `GET /api/export/<scan_id>/pdf` route — generate, stream with `send_file`, MIME `application/pdf`

**Relevant Context:** `app/report_generator.py` (new), `app/routes.py` (update). `reportlab` + stdlib `csv`.

**Status:** [ ] pending

---

### Phase 9 — Tests & Documentation

**Intent:** Validate all core modules with unit tests covering happy paths, edge cases, malformed
inputs, and API failure modes. Add route and report generator tests. Provide a complete README.
All external API calls are mocked during tests.

**Expected Outcomes:**
- All tests pass with `pytest` from the project root
- Parser: pinned, range, unpinned, scoped npm, extras, Git URL deps, malformed lines, invalid content
- SBOM: valid CycloneDX JSON output, correct version/property handling for exact vs. non-exact,
  invalid PURL produces component without purl field, `bomFormat` key present
- Scanner: correct `"PyPI"`/`"npm"` ecosystem identifiers, exact deps queried, range/unpinned
  skipped, CVSS vector parsed via `cvss` library (not cast to float), `scan_error` on API failure,
  retry behaviour, empty `vulns` array → zero vulnerability records (not scan_error)
- Scorer: formula, grade boundaries, `unknown_count` excluded from score, `insufficient_coverage`
  flag set when `scanned_count == 0`
- Routes: file upload validation (wrong extension, oversized, invalid content), successful scan
  pipeline, 404 on unknown scan id
- Report generator: CSV columns correct, PDF file produced, Unknown and scan_error rows included

**Todo List:**
1. Create `tests/test_parser.py`:
   - Test pinned `==`, range `>=`/`~=`, unpinned, extras, URL deps classified as range
   - Test scoped npm package names (`@scope/pkg`) parsed correctly
   - Test `*`, `workspace:`, `git+` versions classified as range/unpinned (not exact)
   - Test malformed lines skipped, valid lines returned
   - Test `validate_txt_file` rejects non-UTF-8 bytes
   - Test `validate_json_file` rejects non-dict JSON (e.g. list)
2. Create `tests/test_sbom_generator.py`:
   - Test output parses as valid JSON with `bomFormat == "CycloneDX"`
   - Test exact dep: `version` field set, purl present
   - Test non-exact dep: `version` field empty/None, `originalVersionSpecifier` property present
   - Test invalid PURL still produces a component without purl field
3. Create `tests/test_vulnerability_scanner.py` (mock all `requests.post` calls using `responses` library):
   - Test correct ecosystem string: `"PyPI"` for pypi, `"npm"` for npm
   - Test successful scan: fields mapped correctly from mock OSV response
   - Test `extract_severity`: CVSS V3 vector parsed via `cvss.CVSS3`, numeric score correct
   - Test `extract_severity`: returns `("Unknown", None, None)` when no severity data present
   - Test range dep → `scan_status == "skipped_range"`, no vuln fields
   - Test unpinned dep → `scan_status == "skipped_unpinned"`
   - Test HTTP 500 → `scan_status == "scan_error"`, not zero vulnerabilities
   - Test connection timeout → `scan_status == "scan_error"` after retries
   - Test empty `vulns` array → zero vuln records with `scan_status == "scanned"`
4. Create `tests/test_risk_scorer.py`:
   - Test formula for known inputs
   - Test Unknown vulns excluded from score, in `unknown_count`
   - Test scan_error records in `error_count`, not in score
   - Test `insufficient_coverage = True` when `scanned_count == 0`
   - Test score capped at 100
   - Test all grade boundaries
5. Create `tests/test_routes.py` (use Flask test client):
   - Test `POST /api/scan` with wrong extension → 400
   - Test `POST /api/scan` with valid fixture file → 200, scan_id in response
   - Test `GET /api/scan/<id>` with unknown id → 404
   - Test `GET /api/scans` returns list
6. Create `tests/test_report_generator.py`:
   - Test CSV output has correct header columns and one row per vulnerability
   - Test PDF file is created and non-empty
   - Test Unknown and scan_error rows are included in CSV
7. Create `README.md` with: description, prerequisites, installation, environment variables,
   how to run, feature list, API endpoint table, architecture overview, sample usage

**Relevant Context:** `tests/` directory. Uses `pytest`, `pytest-mock`, `responses`. Fixtures in `tests/fixtures/`.

**Status:** [ ] pending

---

## Dependency Risk — Custom Project Scoring Formula

> ⚠️ This is a **custom project-defined risk score**, not an official CVSS score.
> It is used solely to give developers an at-a-glance signal about dependency health.

| Severity | Weight |
|---|---|
| Critical | ×10 |
| High | ×5 |
| Medium | ×2 |
| Low | ×1 |
| **Unknown** | **excluded from formula — counted separately** |

**Formula:** `score = min(critical×10 + high×5 + medium×2 + low×1, 100)`

| Score Range | Grade | Label |
|---|---|---|
| 0 – 19 | A | Safe |
| 20 – 39 | B | Low Risk |
| 40 – 59 | C | Moderate |
| 60 – 79 | D | High Risk |
| 80 – 100 | F | Critical |

**Example:** 2 Critical + 3 High + 1 Unknown → score = min(20 + 15, 100) = **35 → Grade B**
(Unknown finding is shown separately in the dashboard but does not affect the numeric score.)
