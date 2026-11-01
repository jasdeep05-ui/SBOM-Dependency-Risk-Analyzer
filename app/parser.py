"""
Dependency parser for requirements.txt (PyPI) and package.json (npm).

Public API
----------
parse_file(filepath, filename) -> list[dict]

Each returned dict has:
  name             str   — package name (normalised, lowercase)
  ecosystem        str   — "PyPI" or "npm"
  version          str|None — exact version string when is_exact_version is True, else None
  version_specifier str  — original specifier as written (e.g. ">=1.2,<2", "^3.0.1", "")
  is_exact_version bool  — True only for a single, fully-resolved version number
  dependency_type  str   — "direct" or "dev"
  parsing_status   str   — "parsed" | "skipped_vcs" | "skipped_url" | "skipped_editable"
                           | "skipped_unsupported" | "skipped_invalid"
  skip_reason      str|None — human-readable explanation when parsing_status != "parsed"

Rules
-----
* is_exact_version is ONLY True when the specifier is a single `==x.y.z` (pip)
  or a bare semver/integer string with no operators (npm).
* Wildcards, ranges, VCS URLs, workspace refs, and `latest` are NEVER exact.
* Malformed individual lines/entries are skipped with a warning — they never crash the parse.
* The uploaded file is deleted from disk in a finally block after parsing.
"""

import json
import logging
import os
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Matches a bare version number: one or more digit-separated segments
# e.g. "1", "1.2", "1.2.3", "1.2.3.4", "1.0.0a1", "2.0.0.post1"
_BARE_VERSION_RE = re.compile(
    r"^\d+(\.\d+)*([._-]?(alpha|beta|rc|a|b|c|post|dev)\d*)?$",
    re.IGNORECASE,
)

# Matches a single exact pip specifier: ==<version> with nothing else
_PIP_EXACT_RE = re.compile(r"^==\s*(\S+)$")

# Matches any pip version constraint operator
_PIP_OPERATOR_RE = re.compile(r"[><=!~^]")

# npm version prefixes that indicate a range, not an exact version
_NPM_RANGE_PREFIXES = ("^", "~", ">", "<", ">=", "<=", "!=", "*", "x", "X")

# npm non-registry dependency indicators
_NPM_VCS_PREFIXES = (
    "git+", "git://", "github:", "gitlab:", "bitbucket:",
    "file:", "workspace:", "link:",
    "npm:",  # npm alias protocol: npm:lodash@4 — not a registry version
)
_NPM_URL_RE = re.compile(r"^https?://")


# ---------------------------------------------------------------------------
# File content validators
# ---------------------------------------------------------------------------

def validate_txt_file(filepath: str) -> None:
    """Raise ValueError if the file cannot be decoded as UTF-8 text."""
    with open(filepath, "rb") as fh:
        raw = fh.read()
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"File is not valid UTF-8 text: {exc}") from exc


def validate_json_file(filepath: str) -> dict:
    """
    Load and return the parsed JSON object.
    Raise ValueError if the file is not valid JSON or not a JSON object (dict).
    """
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"File is not valid JSON: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"File is not valid UTF-8 text: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"package.json must be a JSON object (dict), got {type(data).__name__}"
        )
    return data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_dep(
    name: str,
    ecosystem: str,
    version_specifier: str,
    is_exact: bool,
    dep_type: str,
    status: str = "parsed",
    skip_reason: str | None = None,
    _exact_version: str | None = None,
) -> dict:
    """
    Build the canonical dependency dict.

    `_exact_version` is the bare version number (e.g. "1.2.3") when is_exact
    is True. The `version` field in the output is ALWAYS the bare version only
    (no operator prefix like '==').
    """
    if is_exact:
        bare = _exact_version if _exact_version is not None else version_specifier
    else:
        bare = None
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": bare,
        "version_specifier": version_specifier,
        "is_exact_version": is_exact,
        "dependency_type": dep_type,
        "parsing_status": status,
        "skip_reason": skip_reason,
    }


def _normalise_pip_name(name: str) -> str:
    """
    PEP 503 normalisation: lowercase, replace runs of [-_.] with a single hyphen.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# requirements.txt parser
# ---------------------------------------------------------------------------

def parse_requirements_txt(filepath: str) -> list[dict]:
    """
    Parse a requirements.txt file and return a list of dependency dicts.

    Handles:
      - Blank lines and # comments
      - -r / -c / -e / --requirement / --constraint / --editable options
      - Extras:  package[extra1,extra2]==1.0
      - Environment markers:  package==1.0; python_version >= "3.8"
      - URL/VCS dependencies:  https://..., git+https://..., package @ git+...
      - Exact pins:  package==1.2.3
      - Ranges / constraints:  package>=1.0,<2.0  / package~=1.4
      - Unpinned:  package  (no version at all)
    """
    validate_txt_file(filepath)
    results = []

    with open(filepath, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()

        # Skip blanks and pure comments
        if not line or line.startswith("#"):
            continue

        # Option lines: -r, -c, --requirement, --constraint, --index-url, etc.
        # Must be checked BEFORE inline comment stripping.
        if re.match(r"^-[rc]\b", line) or re.match(r"^--\S+", line):
            continue

        # Editable installs: -e <path or VCS>
        # Must be checked BEFORE inline comment stripping (e.g. "-e .  # comment").
        if line.startswith("-e") and (len(line) == 2 or line[2] in (" ", "\t")):
            ref = line[2:].strip() or "."
            results.append(
                _make_dep(
                    name=ref,
                    ecosystem="PyPI",
                    version_specifier="",
                    is_exact=False,
                    dep_type="direct",
                    status="skipped_editable",
                    skip_reason="Editable install — cannot resolve version",
                )
            )
            continue

        if line.startswith("--editable"):
            ref = line.split(None, 1)[1].strip() if " " in line else "."
            results.append(
                _make_dep(
                    name=ref,
                    ecosystem="PyPI",
                    version_specifier="",
                    is_exact=False,
                    dep_type="direct",
                    status="skipped_editable",
                    skip_reason="Editable install — cannot resolve version",
                )
            )
            continue

        # Inline comment removal (keep only part before #, after special lines handled)
        if " #" in line:
            line = line[: line.index(" #")].strip()

        try:
            dep = _parse_pip_line(line, lineno)
            if dep is not None:
                results.append(dep)
        except Exception as exc:  # noqa: BLE001
            logger.warning("requirements.txt line %d skipped due to error: %s", lineno, exc)
            results.append(
                _make_dep(
                    name=line[:80],
                    ecosystem="PyPI",
                    version_specifier="",
                    is_exact=False,
                    dep_type="direct",
                    status="skipped_invalid",
                    skip_reason=f"Parse error on line {lineno}: {exc}",
                )
            )

    return results


def _parse_pip_line(line: str, lineno: int) -> dict | None:
    """
    Parse a single non-blank, non-comment requirements.txt line.
    Returns a dep dict or None if the line should be silently skipped.
    """
    # URL-only lines (no package name prefix) — e.g. https://example.com/pkg.whl
    if _NPM_URL_RE.match(line):
        return _make_dep(
            name=line[:80],
            ecosystem="PyPI",
            version_specifier="",
            is_exact=False,
            dep_type="direct",
            status="skipped_url",
            skip_reason="Direct URL dependency — cannot resolve exact version",
        )

    # VCS prefix lines — e.g. git+https://github.com/...
    if any(line.startswith(p) for p in ("git+", "git://", "svn+", "hg+", "bzr+")):
        return _make_dep(
            name=line[:80],
            ecosystem="PyPI",
            version_specifier="",
            is_exact=False,
            dep_type="direct",
            status="skipped_vcs",
            skip_reason="VCS dependency — cannot resolve exact version",
        )

    # PEP 440 "package @ url" syntax
    if " @ " in line:
        name_part = line.split(" @ ")[0].strip()
        name = _extract_pip_name(name_part)
        return _make_dep(
            name=name,
            ecosystem="PyPI",
            version_specifier="",
            is_exact=False,
            dep_type="direct",
            status="skipped_url",
            skip_reason="Direct URL/VCS reference via PEP 440 @ syntax",
        )

    # Strip environment markers (semicolon and everything after)
    if ";" in line:
        line = line[: line.index(";")].strip()

    # Now parse: name[extras]<specifier>
    # Regex: capture name (with optional extras), then optional specifier
    m = re.match(
        r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"   # package name
        r"(\[[^\]]*\])?"                                     # optional extras [...]
        r"\s*(.*)?$",                                        # optional version specifier
        line,
    )
    if not m:
        raise ValueError(f"Cannot parse line: {line!r}")

    raw_name = m.group(1)
    specifier = (m.group(4) or "").strip()
    name = _normalise_pip_name(raw_name)

    if not name:
        return None

    # Classify version
    is_exact, bare_version, specifier_clean = _classify_pip_specifier(specifier)

    return _make_dep(
        name=name,
        ecosystem="PyPI",
        version_specifier=specifier_clean,
        is_exact=is_exact,
        dep_type="direct",
        status="parsed",
        skip_reason=None,
        _exact_version=bare_version,
    )


def _extract_pip_name(text: str) -> str:
    """Extract just the package name portion (strip extras)."""
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", text.strip())
    return _normalise_pip_name(m.group(1)) if m else text.strip()[:80]


def _classify_pip_specifier(specifier: str) -> tuple[bool, str | None, str]:
    """
    Returns (is_exact, exact_version_or_None, cleaned_specifier).

    is_exact is True ONLY for a single == pin with no other constraints.
    """
    s = specifier.strip()

    if not s:
        # Unpinned
        return False, None, ""

    # Single exact pin: ==1.2.3 (no comma, no other operators)
    if "," not in s:
        m = _PIP_EXACT_RE.match(s)
        if m:
            ver = m.group(1).strip()
            return True, ver, s

    # Anything else (>=, <=, ~=, !=, multiple constraints, wildcards)
    return False, None, s


# ---------------------------------------------------------------------------
# package.json parser
# ---------------------------------------------------------------------------

def parse_package_json(filepath: str) -> list[dict]:
    """
    Parse a package.json file and return a list of dependency dicts.

    Reads both `dependencies` (direct) and `devDependencies` (dev).
    Supports scoped package names (@scope/package).
    """
    data = validate_json_file(filepath)
    results = []

    dep_sections = [
        ("dependencies", "direct"),
        ("devDependencies", "dev"),
    ]

    for section_key, dep_type in dep_sections:
        section = data.get(section_key)
        if not section or not isinstance(section, dict):
            continue

        for pkg_name, version_value in section.items():
            try:
                dep = _parse_npm_entry(pkg_name, version_value, dep_type)
                results.append(dep)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "package.json entry %r skipped due to error: %s", pkg_name, exc
                )
                results.append(
                    _make_dep(
                        name=pkg_name,
                        ecosystem="npm",
                        version_specifier=str(version_value)[:100],
                        is_exact=False,
                        dep_type=dep_type,
                        status="skipped_invalid",
                        skip_reason=f"Parse error: {exc}",
                    )
                )

    return results


def _parse_npm_entry(pkg_name: str, version_value, dep_type: str) -> dict:
    """Parse a single package.json dependency entry."""
    # Normalise name to lowercase
    name = pkg_name.strip().lower()

    # version_value must be a string
    if not isinstance(version_value, str):
        version_value = str(version_value)

    spec = version_value.strip()

    # VCS / URL / non-registry dependencies
    if any(spec.startswith(p) for p in _NPM_VCS_PREFIXES):
        return _make_dep(
            name=name,
            ecosystem="npm",
            version_specifier=spec,
            is_exact=False,
            dep_type=dep_type,
            status="skipped_vcs",
            skip_reason="VCS/workspace/file dependency — cannot resolve exact version",
        )

    if _NPM_URL_RE.match(spec):
        return _make_dep(
            name=name,
            ecosystem="npm",
            version_specifier=spec,
            is_exact=False,
            dep_type=dep_type,
            status="skipped_url",
            skip_reason="URL dependency — cannot resolve exact version",
        )

    # "latest", "next", and similar dist-tags
    if re.match(r"^[a-zA-Z][a-zA-Z0-9._-]*$", spec) and not _BARE_VERSION_RE.match(spec):
        return _make_dep(
            name=name,
            ecosystem="npm",
            version_specifier=spec,
            is_exact=False,
            dep_type=dep_type,
            status="parsed",
            skip_reason=None,
        )

    is_exact, cleaned = _classify_npm_version(spec)

    return _make_dep(
        name=name,
        ecosystem="npm",
        version_specifier=cleaned,
        is_exact=is_exact,
        dep_type=dep_type,
        status="parsed",
        skip_reason=None,
        _exact_version=cleaned if is_exact else None,
    )


def _classify_npm_version(spec: str) -> tuple[bool, str]:
    """
    Returns (is_exact, cleaned_specifier).

    is_exact is True ONLY when spec is a bare semver string with no operators:
    e.g. "1.2.3", "2.0.0", "1" — but NOT "^1.2", "~1.2", ">=1", "*", "x.x".
    """
    s = spec.strip()

    # Empty → unpinned
    if not s or s in ("*", ""):
        return False, s

    # Any leading range operator → not exact
    if any(s.startswith(p) for p in _NPM_RANGE_PREFIXES):
        return False, s

    # Range operators embedded (|| or - range)
    if "||" in s or re.search(r"\s+-\s+", s):
        return False, s

    # Contains a space (compound range like ">=1.0.0 <2.0.0")
    if " " in s:
        return False, s

    # "x" wildcard segments: 1.x, 1.2.x, 1.X
    if re.search(r"\.[xX]$", s) or re.search(r"^[xX]$", s):
        return False, s

    # Bare version: digits and dots only (with optional pre-release suffix)
    if _BARE_VERSION_RE.match(s):
        return True, s

    # Anything else we can't classify → not exact
    return False, s


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

def parse_file(filepath: str, filename: str) -> list[dict]:
    """
    Parse an uploaded dependency file.

    Args:
        filepath: Absolute path to the file on disk.
        filename: Original filename (used to select the correct parser).

    Returns:
        List of dependency dicts (see module docstring for schema).

    Raises:
        ValueError: If the file type is unsupported or file content is invalid.

    The uploaded file is deleted from disk after parsing (success or failure).
    """
    fname_lower = filename.lower()

    if fname_lower == "requirements.txt" or fname_lower.endswith(".txt"):
        parser_fn = parse_requirements_txt
    elif fname_lower == "package.json" or fname_lower.endswith(".json"):
        parser_fn = parse_package_json
    else:
        raise ValueError(
            f"Unsupported file type: {filename!r}. "
            "Only requirements.txt and package.json are accepted."
        )

    try:
        return parser_fn(filepath)
    finally:
        try:
            os.remove(filepath)
            logger.debug("Deleted uploaded file: %s", filepath)
        except OSError as exc:
            logger.warning("Could not delete uploaded file %s: %s", filepath, exc)
