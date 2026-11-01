"""
Unit tests for app/parser.py — Phase 2.

Tests cover:
  - requirements.txt: exact pins, ranges, unpinned, extras, markers,
    VCS, URL, editable, option lines, malformed lines
  - package.json: exact versions, ranges (^/~/*), scoped names,
    VCS/file/workspace/URL deps, devDependencies, invalid JSON,
    non-dict JSON, missing sections, unpinned
  - validate_txt_file / validate_json_file helpers
  - parse_file dispatcher
  - File deletion in finally block
"""

import json
import os
import shutil
import tempfile

import pytest

from app.parser import (
    parse_file,
    parse_package_json,
    parse_requirements_txt,
    validate_json_file,
    validate_txt_file,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name: str) -> str:
    """Return absolute path to a fixture file."""
    return os.path.join(FIXTURES, name)


def _write_tmp(content: str | bytes, suffix: str = ".txt") -> str:
    """Write content to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    if isinstance(content, str):
        content = content.encode("utf-8")
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
    return path


def _copy_fixture(name: str) -> str:
    """Copy a fixture to a temp file (so parse_file can delete it)."""
    src = _fixture(name)
    fd, dst = tempfile.mkstemp(suffix=os.path.splitext(name)[1])
    os.close(fd)
    shutil.copy2(src, dst)
    return dst


def _by_name(deps: list[dict], name: str) -> dict | None:
    return next((d for d in deps if d["name"] == name), None)


# ===========================================================================
# validate_txt_file
# ===========================================================================

class TestValidateTxtFile:
    def test_valid_utf8_passes(self):
        path = _write_tmp("flask==1.0\n")
        try:
            validate_txt_file(path)  # should not raise
        finally:
            os.remove(path)

    def test_binary_raises(self):
        path = _write_tmp(b"\xff\xfe binary garbage \x00\x01")
        try:
            with pytest.raises(ValueError, match="UTF-8"):
                validate_txt_file(path)
        finally:
            os.remove(path)


# ===========================================================================
# validate_json_file
# ===========================================================================

class TestValidateJsonFile:
    def test_valid_object_returns_dict(self):
        path = _write_tmp('{"name": "pkg", "version": "1.0.0"}', suffix=".json")
        try:
            data = validate_json_file(path)
            assert isinstance(data, dict)
            assert data["name"] == "pkg"
        finally:
            os.remove(path)

    def test_invalid_json_raises(self):
        path = _write_tmp("{ not valid json", suffix=".json")
        try:
            with pytest.raises(ValueError, match="not valid JSON"):
                validate_json_file(path)
        finally:
            os.remove(path)

    def test_json_array_raises(self):
        path = _write_tmp("[1, 2, 3]", suffix=".json")
        try:
            with pytest.raises(ValueError, match="dict"):
                validate_json_file(path)
        finally:
            os.remove(path)

    def test_malformed_fixture(self):
        with pytest.raises(ValueError):
            validate_json_file(_fixture("sample_package_malformed.json"))


# ===========================================================================
# parse_requirements_txt — using fixture
# ===========================================================================

class TestParseRequirementsTxt:
    @pytest.fixture(autouse=True)
    def deps(self):
        # Parse from fixture directly (no deletion, file persists)
        self._deps = parse_requirements_txt(_fixture("sample_requirements.txt"))
        return self._deps

    # --- Exact pins ---

    def test_flask_exact(self, deps):
        d = _by_name(deps, "flask")
        assert d is not None
        assert d["is_exact_version"] is True
        assert d["version"] == "3.0.3"
        assert d["version_specifier"] == "==3.0.3"
        assert d["ecosystem"] == "PyPI"
        assert d["parsing_status"] == "parsed"

    def test_sqlalchemy_exact(self, deps):
        d = _by_name(deps, "sqlalchemy")
        assert d["is_exact_version"] is True
        assert d["version"] == "2.0.28"

    def test_werkzeug_exact(self, deps):
        d = _by_name(deps, "werkzeug")
        assert d["is_exact_version"] is True

    # --- Ranges / constraints ---

    def test_requests_range(self, deps):
        # requests>=2.28.0,<3.0.0 — the extras version is also present; find range one
        range_entries = [
            d for d in deps
            if d["name"] == "requests" and not d["is_exact_version"]
            and d["parsing_status"] == "parsed"
        ]
        assert len(range_entries) >= 1
        d = range_entries[0]
        assert d["is_exact_version"] is False
        assert d["version"] is None

    def test_urllib3_range(self, deps):
        d = _by_name(deps, "urllib3")
        assert d["is_exact_version"] is False
        assert d["version"] is None

    def test_numpy_compatible_release(self, deps):
        d = _by_name(deps, "numpy")
        assert d["is_exact_version"] is False
        assert "~=" in d["version_specifier"]

    def test_pytest_range(self, deps):
        d = _by_name(deps, "pytest")
        assert d["is_exact_version"] is False

    # --- Unpinned ---

    def test_six_unpinned(self, deps):
        d = _by_name(deps, "six")
        assert d is not None
        assert d["is_exact_version"] is False
        assert d["version"] is None
        assert d["version_specifier"] == ""
        assert d["parsing_status"] == "parsed"

    # --- Extras ---

    def test_requests_security_extras(self, deps):
        # requests[security]==2.31.0 — exact pin, extras stripped
        exact_requests = [
            d for d in deps
            if d["name"] == "requests" and d["is_exact_version"] is True
        ]
        assert len(exact_requests) >= 1
        assert exact_requests[0]["version"] == "2.31.0"

    # --- Environment markers stripped ---

    def test_pywin32_marker_stripped(self, deps):
        d = _by_name(deps, "pywin32")
        assert d is not None
        assert d["is_exact_version"] is True
        assert d["version"] == "306"

    # --- Skipped entries ---

    def test_vcs_dep_skipped(self, deps):
        vcs = [d for d in deps if d["parsing_status"] == "skipped_vcs"]
        assert len(vcs) >= 1
        assert vcs[0]["is_exact_version"] is False

    def test_url_dep_skipped(self, deps):
        url = [d for d in deps if d["parsing_status"] == "skipped_url"]
        assert len(url) >= 1

    def test_editable_dep_skipped(self, deps):
        editable = [d for d in deps if d["parsing_status"] == "skipped_editable"]
        assert len(editable) >= 1

    # --- No stray None names ---

    def test_no_none_names(self, deps):
        for d in deps:
            assert d["name"] is not None
            assert isinstance(d["name"], str)
            assert len(d["name"]) > 0

    # --- Required fields present ---

    def test_all_required_fields(self, deps):
        required = {
            "name", "ecosystem", "version", "version_specifier",
            "is_exact_version", "dependency_type", "parsing_status", "skip_reason",
        }
        for d in deps:
            assert required.issubset(d.keys()), f"Missing fields in: {d}"


# ===========================================================================
# parse_requirements_txt — malformed fixture
# ===========================================================================

class TestParseRequirementsTxtMalformed:
    @pytest.fixture(autouse=True)
    def deps(self):
        self._deps = parse_requirements_txt(
            _fixture("sample_requirements_malformed.txt")
        )
        return self._deps

    def test_valid_lines_are_parsed(self, deps):
        names = [d["name"] for d in deps]
        assert "flask" in names
        assert "requests" in names
        assert "six" in names
        assert "werkzeug" in names

    def test_malformed_line_is_skipped(self, deps):
        invalid = [d for d in deps if d["parsing_status"] == "skipped_invalid"]
        assert len(invalid) >= 1

    def test_total_count_reasonable(self, deps):
        # Should not crash; should return some deps
        assert len(deps) >= 4


# ===========================================================================
# parse_requirements_txt — inline unit cases
# ===========================================================================

class TestParseRequirementsTxtInline:
    def _parse(self, content: str) -> list[dict]:
        path = _write_tmp(content)
        try:
            return parse_requirements_txt(path)
        finally:
            # file may or may not exist after parse (parse_requirements_txt
            # does NOT delete; only parse_file does)
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    def test_exact_pin(self):
        deps = self._parse("Django==4.2.1\n")
        assert deps[0]["is_exact_version"] is True
        assert deps[0]["version"] == "4.2.1"
        assert deps[0]["name"] == "django"

    def test_gte_range_not_exact(self):
        deps = self._parse("requests>=2.0\n")
        assert deps[0]["is_exact_version"] is False
        assert deps[0]["version"] is None

    def test_tilde_compatible_not_exact(self):
        deps = self._parse("numpy~=1.24\n")
        assert deps[0]["is_exact_version"] is False

    def test_multi_constraint_not_exact(self):
        deps = self._parse("pkg>=1.0,<2.0\n")
        assert deps[0]["is_exact_version"] is False

    def test_unpinned(self):
        deps = self._parse("six\n")
        assert deps[0]["is_exact_version"] is False
        assert deps[0]["version_specifier"] == ""

    def test_comment_line_skipped(self):
        deps = self._parse("# this is a comment\n")
        assert len(deps) == 0

    def test_blank_line_skipped(self):
        deps = self._parse("\n   \n")
        assert len(deps) == 0

    def test_extras_stripped(self):
        deps = self._parse("requests[security]==2.31.0\n")
        assert deps[0]["name"] == "requests"
        assert deps[0]["is_exact_version"] is True
        assert deps[0]["version"] == "2.31.0"

    def test_env_marker_stripped(self):
        deps = self._parse('pywin32==306; sys_platform == "win32"\n')
        assert deps[0]["is_exact_version"] is True
        assert deps[0]["version"] == "306"

    def test_vcs_dep(self):
        deps = self._parse("git+https://github.com/user/repo.git\n")
        assert deps[0]["parsing_status"] == "skipped_vcs"

    def test_url_dep(self):
        deps = self._parse("https://example.com/pkg-1.0.tar.gz\n")
        assert deps[0]["parsing_status"] == "skipped_url"

    def test_editable_dep(self):
        deps = self._parse("-e .\n")
        assert deps[0]["parsing_status"] == "skipped_editable"

    def test_option_line_skipped(self):
        deps = self._parse("-r other.txt\nflask==1.0\n")
        assert len(deps) == 1
        assert deps[0]["name"] == "flask"

    def test_pep440_at_syntax(self):
        deps = self._parse("mylib @ git+https://github.com/user/mylib.git\n")
        assert deps[0]["parsing_status"] == "skipped_url"

    def test_inline_comment_stripped(self):
        deps = self._parse("flask==1.0  # main framework\n")
        assert deps[0]["is_exact_version"] is True
        assert deps[0]["version"] == "1.0"

    def test_name_normalised_lowercase(self):
        deps = self._parse("Django==4.2\n")
        assert deps[0]["name"] == "django"

    def test_name_normalised_underscores(self):
        deps = self._parse("Pillow_Utils==1.0\n")
        assert deps[0]["name"] == "pillow-utils"

    def test_dependency_type_is_direct(self):
        deps = self._parse("flask==1.0\n")
        assert deps[0]["dependency_type"] == "direct"


# ===========================================================================
# parse_package_json — using fixture
# ===========================================================================

class TestParsePackageJson:
    @pytest.fixture(autouse=True)
    def deps(self):
        self._deps = parse_package_json(_fixture("sample_package.json"))
        return self._deps

    # --- Exact versions ---

    def test_express_exact(self, deps):
        d = _by_name(deps, "express")
        assert d is not None
        assert d["is_exact_version"] is True
        assert d["version"] == "4.18.2"
        assert d["ecosystem"] == "npm"
        assert d["dependency_type"] == "direct"

    def test_babel_core_scoped_exact(self, deps):
        d = _by_name(deps, "@babel/core")
        assert d is not None
        assert d["is_exact_version"] is True
        assert d["version"] == "7.23.9"

    def test_jest_dev_exact(self, deps):
        d = _by_name(deps, "jest")
        assert d is not None
        assert d["is_exact_version"] is True
        assert d["version"] == "29.7.0"
        assert d["dependency_type"] == "dev"

    def test_typescript_dev_exact(self, deps):
        d = _by_name(deps, "typescript")
        assert d["is_exact_version"] is True
        assert d["version"] == "5.3.3"

    # --- Ranges ---

    def test_lodash_caret_range(self, deps):
        d = _by_name(deps, "lodash")
        assert d["is_exact_version"] is False
        assert d["version"] is None
        assert "^" in d["version_specifier"]

    def test_axios_tilde_range(self, deps):
        d = _by_name(deps, "axios")
        assert d["is_exact_version"] is False
        assert "~" in d["version_specifier"]

    def test_react_gte_range(self, deps):
        d = _by_name(deps, "react")
        assert d["is_exact_version"] is False

    def test_uuid_wildcard(self, deps):
        d = _by_name(deps, "uuid")
        assert d["is_exact_version"] is False
        assert d["version_specifier"] == "*"

    def test_eslint_dev_range(self, deps):
        d = _by_name(deps, "eslint")
        assert d["is_exact_version"] is False
        assert d["dependency_type"] == "dev"

    # --- Scoped packages ---

    def test_scoped_scope_utils_range(self, deps):
        d = _by_name(deps, "@scope/utils")
        assert d is not None
        assert d["is_exact_version"] is False

    # --- VCS / file / workspace / URL ---

    def test_vcs_dep_skipped(self, deps):
        d = _by_name(deps, "vcs-dep")
        assert d["parsing_status"] == "skipped_vcs"
        assert d["is_exact_version"] is False

    def test_file_dep_skipped(self, deps):
        d = _by_name(deps, "file-dep")
        assert d["parsing_status"] == "skipped_vcs"

    def test_workspace_dep_skipped(self, deps):
        d = _by_name(deps, "workspace-dep")
        assert d["parsing_status"] == "skipped_vcs"

    def test_url_dep_skipped(self, deps):
        d = _by_name(deps, "url-dep")
        assert d["parsing_status"] == "skipped_url"

    # --- dist-tag (latest) ---

    def test_latest_not_exact(self, deps):
        d = _by_name(deps, "legacy-pkg")
        assert d["is_exact_version"] is False
        assert d["version"] is None

    # --- Unpinned ---

    def test_unpinned_dev(self, deps):
        d = _by_name(deps, "unpinned-dev")
        assert d["is_exact_version"] is False
        assert d["version"] is None
        assert d["dependency_type"] == "dev"

    # --- Required fields ---

    def test_all_required_fields(self, deps):
        required = {
            "name", "ecosystem", "version", "version_specifier",
            "is_exact_version", "dependency_type", "parsing_status", "skip_reason",
        }
        for d in deps:
            assert required.issubset(d.keys()), f"Missing fields in: {d}"

    def test_ecosystem_is_npm(self, deps):
        for d in deps:
            assert d["ecosystem"] == "npm"


# ===========================================================================
# parse_package_json — inline unit cases
# ===========================================================================

class TestParsePackageJsonInline:
    def _parse(self, deps_dict: dict, dev_dict: dict | None = None) -> list[dict]:
        data = {"dependencies": deps_dict}
        if dev_dict is not None:
            data["devDependencies"] = dev_dict
        path = _write_tmp(json.dumps(data), suffix=".json")
        try:
            return parse_package_json(path)
        finally:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    def test_exact_bare_version(self):
        deps = self._parse({"express": "4.18.2"})
        assert deps[0]["is_exact_version"] is True
        assert deps[0]["version"] == "4.18.2"

    def test_caret_not_exact(self):
        deps = self._parse({"lodash": "^4.17.21"})
        assert deps[0]["is_exact_version"] is False
        assert deps[0]["version"] is None

    def test_tilde_not_exact(self):
        deps = self._parse({"axios": "~1.6.0"})
        assert deps[0]["is_exact_version"] is False

    def test_wildcard_not_exact(self):
        deps = self._parse({"pkg": "*"})
        assert deps[0]["is_exact_version"] is False

    def test_x_wildcard_not_exact(self):
        deps = self._parse({"pkg": "1.x"})
        assert deps[0]["is_exact_version"] is False

    def test_latest_not_exact(self):
        deps = self._parse({"pkg": "latest"})
        assert deps[0]["is_exact_version"] is False

    def test_gt_range_not_exact(self):
        deps = self._parse({"pkg": ">=1.0.0"})
        assert deps[0]["is_exact_version"] is False

    def test_compound_range_not_exact(self):
        deps = self._parse({"pkg": ">=1.0.0 <2.0.0"})
        assert deps[0]["is_exact_version"] is False

    def test_or_range_not_exact(self):
        deps = self._parse({"pkg": "1.0.0 || 2.0.0"})
        assert deps[0]["is_exact_version"] is False

    def test_git_not_exact(self):
        deps = self._parse({"pkg": "git+https://github.com/user/repo.git"})
        assert deps[0]["parsing_status"] == "skipped_vcs"
        assert deps[0]["is_exact_version"] is False

    def test_workspace_not_exact(self):
        deps = self._parse({"pkg": "workspace:*"})
        assert deps[0]["parsing_status"] == "skipped_vcs"

    def test_file_not_exact(self):
        deps = self._parse({"pkg": "file:../local"})
        assert deps[0]["parsing_status"] == "skipped_vcs"

    def test_url_not_exact(self):
        deps = self._parse({"pkg": "https://example.com/pkg.tgz"})
        assert deps[0]["parsing_status"] == "skipped_url"

    def test_scoped_name_preserved(self):
        deps = self._parse({"@babel/core": "7.23.9"})
        assert deps[0]["name"] == "@babel/core"
        assert deps[0]["is_exact_version"] is True

    def test_dev_dependency_type(self):
        deps = self._parse({}, dev_dict={"jest": "29.7.0"})
        assert deps[0]["dependency_type"] == "dev"

    def test_direct_dependency_type(self):
        deps = self._parse({"express": "4.18.2"})
        assert deps[0]["dependency_type"] == "direct"

    def test_missing_dependencies_section(self):
        path = _write_tmp('{"name": "no-deps"}', suffix=".json")
        try:
            result = parse_package_json(path)
            assert result == []
        finally:
            os.remove(path)

    def test_empty_string_version_unpinned(self):
        deps = self._parse({"pkg": ""})
        assert deps[0]["is_exact_version"] is False
        assert deps[0]["version"] is None

    def test_name_lowercased(self):
        deps = self._parse({"Express": "4.18.2"})
        assert deps[0]["name"] == "express"


# ===========================================================================
# parse_file dispatcher
# ===========================================================================

class TestParseFileDispatcher:
    def test_txt_dispatches_to_requirements_parser(self):
        dst = _copy_fixture("sample_requirements.txt")
        result = parse_file(dst, "requirements.txt")
        assert len(result) > 0
        assert all(d["ecosystem"] == "PyPI" for d in result)
        assert not os.path.exists(dst), "File should be deleted after parse_file"

    def test_json_dispatches_to_package_json_parser(self):
        dst = _copy_fixture("sample_package.json")
        result = parse_file(dst, "package.json")
        assert len(result) > 0
        assert all(d["ecosystem"] == "npm" for d in result)
        assert not os.path.exists(dst), "File should be deleted after parse_file"

    def test_file_deleted_on_success(self):
        dst = _copy_fixture("sample_requirements.txt")
        parse_file(dst, "requirements.txt")
        assert not os.path.exists(dst)

    def test_file_deleted_on_parse_error(self):
        """Even when parse raises, the temp file must be deleted."""
        dst = _copy_fixture("sample_package_malformed.json")
        with pytest.raises(ValueError):
            parse_file(dst, "package.json")
        assert not os.path.exists(dst)

    def test_unsupported_extension_raises(self):
        path = _write_tmp("data", suffix=".csv")
        try:
            with pytest.raises(ValueError, match="Unsupported"):
                parse_file(path, "data.csv")
        finally:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass


# ===========================================================================
# Targeted review additions — Phase 2 gap coverage
# ===========================================================================

class TestParserTargetedReview:
    """
    Targeted tests added during Phase 2 review to cover:
      1. Extras stripped from name but dep still present
      2. Every skipped category present in output
      3. npm: alias, unusual specifiers never classified as exact
      4. direct vs dev distinction preserved
    """

    def _parse_req(self, content: str) -> list[dict]:
        import tempfile, os
        path = _write_tmp(content)
        result = parse_requirements_txt(path)
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        return result

    def _parse_pkg(self, deps_dict, dev_dict=None):
        import tempfile, json, os
        data = {"dependencies": deps_dict}
        if dev_dict:
            data["devDependencies"] = dev_dict
        path = _write_tmp(json.dumps(data), suffix=".json")
        result = parse_package_json(path)
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        return result

    # 1. Extras stripped — name is canonical, dep still present
    def test_extras_stripped_name_is_base(self):
        deps = self._parse_req("requests[security,socks]==2.31.0\n")
        assert len(deps) == 1
        assert deps[0]["name"] == "requests"          # extras gone from name
        assert deps[0]["is_exact_version"] is True
        assert deps[0]["version"] == "2.31.0"
        assert deps[0]["parsing_status"] == "parsed"  # dep IS in output

    def test_extras_multiple_stripped(self):
        deps = self._parse_req("boto3[crt,s3transfer]>=1.26\n")
        assert deps[0]["name"] == "boto3"
        assert deps[0]["is_exact_version"] is False

    # 2. Every skipped category represented
    def test_all_skipped_categories_present(self):
        content = (
            "git+https://github.com/user/repo.git\n"          # skipped_vcs
            "https://example.com/pkg-1.0.tar.gz\n"            # skipped_url
            "-e .\n"                                           # skipped_editable
            "mylib @ git+https://github.com/user/mylib\n"     # skipped_url (@ syntax)
            "===\n"                                            # skipped_invalid
            "flask==1.0\n"                                     # parsed (control)
        )
        deps = self._parse_req(content)
        statuses = {d["parsing_status"] for d in deps}
        assert "skipped_vcs" in statuses
        assert "skipped_url" in statuses
        assert "skipped_editable" in statuses
        assert "skipped_invalid" in statuses
        assert "parsed" in statuses
        # All skipped deps have skip_reason set
        for d in deps:
            if d["parsing_status"] != "parsed":
                assert d["skip_reason"] is not None
                assert len(d["skip_reason"]) > 0

    # 3. npm: alias, unusual specifiers — never exact
    def test_npm_alias_not_exact(self):
        deps = self._parse_pkg({"my-alias": "npm:lodash@^4.17.21"})
        assert deps[0]["is_exact_version"] is False
        assert deps[0]["parsing_status"] == "skipped_vcs"

    def test_npm_alias_bare_version_not_exact(self):
        """npm:lodash@4.17.21 — still an alias, not a direct registry pin."""
        deps = self._parse_pkg({"my-lodash": "npm:lodash@4.17.21"})
        assert deps[0]["is_exact_version"] is False

    def test_unusual_specifier_version_range_expression(self):
        """1.0.0 - 2.0.0 (hyphen range) must not be exact."""
        deps = self._parse_pkg({"pkg": "1.0.0 - 2.0.0"})
        assert deps[0]["is_exact_version"] is False

    def test_dist_tag_next_not_exact(self):
        deps = self._parse_pkg({"pkg": "next"})
        assert deps[0]["is_exact_version"] is False

    def test_dist_tag_beta_not_exact(self):
        deps = self._parse_pkg({"pkg": "beta"})
        assert deps[0]["is_exact_version"] is False

    # 4. direct vs dev preserved
    def test_direct_and_dev_both_preserved(self):
        deps = self._parse_pkg(
            {"express": "4.18.2"},
            dev_dict={"jest": "29.7.0"},
        )
        by_name = {d["name"]: d for d in deps}
        assert by_name["express"]["dependency_type"] == "direct"
        assert by_name["jest"]["dependency_type"] == "dev"

    def test_same_package_direct_and_dev_both_appear(self):
        """If a package appears in both sections, both entries are preserved."""
        deps = self._parse_pkg(
            {"lodash": "^4.17.21"},
            dev_dict={"lodash": "^4.17.21"},
        )
        names = [d["name"] for d in deps]
        assert names.count("lodash") == 2
        types = {d["dependency_type"] for d in deps if d["name"] == "lodash"}
        assert types == {"direct", "dev"}
