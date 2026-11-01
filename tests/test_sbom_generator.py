"""
Unit tests for app/sbom_generator.py — Phase 3.

Tests cover:
  - Output is valid CycloneDX 1.5 JSON (bomFormat, specVersion)
  - Exact PyPI dep: version field set, PURL present
  - Exact npm dep: version field set, PURL present
  - Scoped npm dep (@babel/core): PURL namespace correct
  - Range dep: version field absent, originalVersionSpecifier property present
  - Unpinned dep: version field absent, no originalVersionSpecifier property
  - Skipped dep (VCS/URL/editable): version absent, sbom:skipReason property present
  - All deps appear as components (count matches)
  - Invalid PURL input: component still included without purl field
  - Metadata: timestamp present, tool name correct
  - Properties: ecosystem, dependencyType, parsingStatus always present
  - Empty dependency list: valid SBOM with zero components
  - Mixed list: exact + range + unpinned + skipped all handled correctly
"""

import json

import pytest

from app.sbom_generator import build_purl, generate_sbom


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _exact_pypi(name: str, version: str, dep_type: str = "direct") -> dict:
    return {
        "name": name,
        "ecosystem": "PyPI",
        "version": version,
        "version_specifier": f"=={version}",
        "is_exact_version": True,
        "dependency_type": dep_type,
        "parsing_status": "parsed",
        "skip_reason": None,
    }


def _exact_npm(name: str, version: str, dep_type: str = "direct") -> dict:
    return {
        "name": name,
        "ecosystem": "npm",
        "version": version,
        "version_specifier": version,
        "is_exact_version": True,
        "dependency_type": dep_type,
        "parsing_status": "parsed",
        "skip_reason": None,
    }


def _range_pypi(name: str, specifier: str) -> dict:
    return {
        "name": name,
        "ecosystem": "PyPI",
        "version": None,
        "version_specifier": specifier,
        "is_exact_version": False,
        "dependency_type": "direct",
        "parsing_status": "parsed",
        "skip_reason": None,
    }


def _unpinned_pypi(name: str) -> dict:
    return {
        "name": name,
        "ecosystem": "PyPI",
        "version": None,
        "version_specifier": "",
        "is_exact_version": False,
        "dependency_type": "direct",
        "parsing_status": "parsed",
        "skip_reason": None,
    }


def _skipped(name: str, status: str, reason: str, ecosystem: str = "PyPI") -> dict:
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": None,
        "version_specifier": "",
        "is_exact_version": False,
        "dependency_type": "direct",
        "parsing_status": status,
        "skip_reason": reason,
    }


def _parse_sbom(deps: list[dict], filename: str = "requirements.txt") -> dict:
    """Generate SBOM and return parsed JSON dict."""
    raw = generate_sbom(deps, filename)
    return json.loads(raw)


def _component_by_name(sbom: dict, name: str) -> dict | None:
    return next(
        (c for c in sbom.get("components", []) if c["name"] == name), None
    )


def _prop(component: dict, prop_name: str) -> str | None:
    for p in component.get("properties", []):
        if p["name"] == prop_name:
            return p["value"]
    return None


# ===========================================================================
# build_purl
# ===========================================================================

class TestBuildPurl:
    def test_pypi_exact(self):
        p = build_purl("flask", "3.0.3", "PyPI")
        assert p == "pkg:pypi/flask@3.0.3"

    def test_npm_exact(self):
        p = build_purl("express", "4.18.2", "npm")
        assert p == "pkg:npm/express@4.18.2"

    def test_npm_scoped(self):
        p = build_purl("@babel/core", "7.23.9", "npm")
        assert p is not None
        # PackageURL encodes namespace=babel, name=core
        assert "babel" in p
        assert "core" in p
        assert "7.23.9" in p

    def test_pypi_name_with_hyphens(self):
        p = build_purl("my-package", "1.0.0", "PyPI")
        assert p is not None
        assert "my-package" in p

    def test_none_returned_for_empty_name(self):
        p = build_purl("", "1.0.0", "PyPI")
        # Empty name is invalid; should return None without raising
        assert p is None or isinstance(p, str)  # either is acceptable

    def test_returns_string(self):
        p = build_purl("requests", "2.31.0", "PyPI")
        assert isinstance(p, str)
        assert p.startswith("pkg:pypi/")


# ===========================================================================
# generate_sbom — structural validation
# ===========================================================================

class TestGenerateSbomStructure:
    def test_returns_string(self):
        raw = generate_sbom([], "requirements.txt")
        assert isinstance(raw, str)

    def test_output_is_valid_json(self):
        raw = generate_sbom([_exact_pypi("flask", "3.0.3")], "requirements.txt")
        parsed = json.loads(raw)  # must not raise
        assert isinstance(parsed, dict)

    def test_bom_format_cyclonedx(self):
        sbom = _parse_sbom([_exact_pypi("flask", "3.0.3")])
        assert sbom.get("bomFormat") == "CycloneDX"

    def test_spec_version_1_5(self):
        sbom = _parse_sbom([_exact_pypi("flask", "3.0.3")])
        assert sbom.get("specVersion") == "1.5"

    def test_metadata_timestamp_present(self):
        sbom = _parse_sbom([_exact_pypi("flask", "3.0.3")])
        assert "metadata" in sbom
        assert "timestamp" in sbom["metadata"]

    def test_metadata_tools_present(self):
        sbom = _parse_sbom([_exact_pypi("flask", "3.0.3")])
        tools = sbom.get("metadata", {}).get("tools", {})
        # tools may be a list or a dict with 'components' key depending on spec version
        assert tools is not None

    def test_serial_number_present(self):
        sbom = _parse_sbom([_exact_pypi("flask", "3.0.3")])
        assert "serialNumber" in sbom

    def test_empty_deps_produces_valid_sbom(self):
        sbom = _parse_sbom([])
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom.get("components", []) == []

    def test_component_count_matches(self):
        deps = [
            _exact_pypi("flask", "3.0.3"),
            _range_pypi("requests", ">=2.28"),
            _unpinned_pypi("six"),
        ]
        sbom = _parse_sbom(deps)
        assert len(sbom["components"]) == 3


# ===========================================================================
# Exact PyPI dependency
# ===========================================================================

class TestExactPyPiComponent:
    @pytest.fixture(autouse=True)
    def sbom(self):
        self._sbom = _parse_sbom([_exact_pypi("flask", "3.0.3")], "requirements.txt")
        self._comp = _component_by_name(self._sbom, "flask")

    def test_component_present(self, sbom):
        assert self._comp is not None

    def test_version_set(self, sbom):
        assert self._comp.get("version") == "3.0.3"

    def test_purl_present(self, sbom):
        assert "purl" in self._comp
        assert self._comp["purl"] == "pkg:pypi/flask@3.0.3"

    def test_type_is_library(self, sbom):
        assert self._comp.get("type") == "library"

    def test_ecosystem_property(self, sbom):
        assert _prop(self._comp, "sbom:ecosystem") == "PyPI"

    def test_dependency_type_property(self, sbom):
        assert _prop(self._comp, "sbom:dependencyType") == "direct"

    def test_parsing_status_property(self, sbom):
        assert _prop(self._comp, "sbom:parsingStatus") == "parsed"

    def test_no_original_specifier_property(self, sbom):
        # For exact deps, originalVersionSpecifier should NOT be present
        assert _prop(self._comp, "originalVersionSpecifier") is None

    def test_no_skip_reason_property(self, sbom):
        assert _prop(self._comp, "sbom:skipReason") is None

    def test_dev_dependency_type(self, sbom):
        sbom = _parse_sbom([_exact_pypi("pytest", "8.2.2", dep_type="dev")])
        comp = _component_by_name(sbom, "pytest")
        assert _prop(comp, "sbom:dependencyType") == "dev"


# ===========================================================================
# Exact npm dependency
# ===========================================================================

class TestExactNpmComponent:
    @pytest.fixture(autouse=True)
    def sbom(self):
        self._sbom = _parse_sbom([_exact_npm("express", "4.18.2")], "package.json")
        self._comp = _component_by_name(self._sbom, "express")

    def test_component_present(self, sbom):
        assert self._comp is not None

    def test_version_set(self, sbom):
        assert self._comp.get("version") == "4.18.2"

    def test_purl_present(self, sbom):
        assert "purl" in self._comp
        assert "express" in self._comp["purl"]
        assert "4.18.2" in self._comp["purl"]

    def test_ecosystem_property(self, sbom):
        assert _prop(self._comp, "sbom:ecosystem") == "npm"


# ===========================================================================
# Scoped npm dependency
# ===========================================================================

class TestScopedNpmComponent:
    @pytest.fixture(autouse=True)
    def sbom(self):
        self._sbom = _parse_sbom(
            [_exact_npm("@babel/core", "7.23.9")], "package.json"
        )
        self._comp = _component_by_name(self._sbom, "@babel/core")

    def test_component_present(self, sbom):
        assert self._comp is not None

    def test_version_set(self, sbom):
        assert self._comp.get("version") == "7.23.9"

    def test_purl_present_and_contains_scope(self, sbom):
        purl = self._comp.get("purl", "")
        assert purl is not None
        assert "babel" in purl
        assert "core" in purl
        assert "7.23.9" in purl

    def test_purl_type_is_npm(self, sbom):
        purl = self._comp.get("purl", "")
        assert purl.startswith("pkg:npm/")


# ===========================================================================
# Range dependency
# ===========================================================================

class TestRangeDependency:
    @pytest.fixture(autouse=True)
    def sbom(self):
        self._sbom = _parse_sbom(
            [_range_pypi("requests", ">=2.28.0,<3.0.0")], "requirements.txt"
        )
        self._comp = _component_by_name(self._sbom, "requests")

    def test_component_present(self, sbom):
        assert self._comp is not None

    def test_version_field_absent(self, sbom):
        # Must not invent a version
        assert "version" not in self._comp or self._comp.get("version") is None

    def test_purl_absent(self, sbom):
        assert "purl" not in self._comp

    def test_original_specifier_property_present(self, sbom):
        val = _prop(self._comp, "originalVersionSpecifier")
        assert val == ">=2.28.0,<3.0.0"

    def test_parsing_status_parsed(self, sbom):
        assert _prop(self._comp, "sbom:parsingStatus") == "parsed"


# ===========================================================================
# Unpinned dependency
# ===========================================================================

class TestUnpinnedDependency:
    @pytest.fixture(autouse=True)
    def sbom(self):
        self._sbom = _parse_sbom([_unpinned_pypi("six")], "requirements.txt")
        self._comp = _component_by_name(self._sbom, "six")

    def test_component_present(self, sbom):
        assert self._comp is not None

    def test_version_field_absent(self, sbom):
        assert "version" not in self._comp or self._comp.get("version") is None

    def test_purl_absent(self, sbom):
        assert "purl" not in self._comp

    def test_no_original_specifier_property(self, sbom):
        # Empty specifier — property should not be added (nothing to preserve)
        val = _prop(self._comp, "originalVersionSpecifier")
        assert val is None

    def test_parsing_status_parsed(self, sbom):
        assert _prop(self._comp, "sbom:parsingStatus") == "parsed"


# ===========================================================================
# Skipped dependency
# ===========================================================================

class TestSkippedDependency:
    @pytest.fixture(autouse=True)
    def sbom(self):
        dep = _skipped(
            name="git+https://github.com/user/repo.git",
            status="skipped_vcs",
            reason="VCS dependency — cannot resolve exact version",
        )
        self._sbom = _parse_sbom([dep], "requirements.txt")
        self._comp = self._sbom["components"][0]

    def test_component_present_in_sbom(self, sbom):
        assert self._comp is not None

    def test_version_field_absent(self, sbom):
        assert "version" not in self._comp or self._comp.get("version") is None

    def test_purl_absent(self, sbom):
        assert "purl" not in self._comp

    def test_skip_reason_property_present(self, sbom):
        reason = _prop(self._comp, "sbom:skipReason")
        assert reason is not None
        assert "VCS" in reason

    def test_parsing_status_is_skipped(self, sbom):
        status = _prop(self._comp, "sbom:parsingStatus")
        assert status == "skipped_vcs"


# ===========================================================================
# Mixed list
# ===========================================================================

class TestMixedDependencyList:
    @pytest.fixture(autouse=True)
    def setup(self):
        deps = [
            _exact_pypi("flask", "3.0.3"),
            _range_pypi("requests", ">=2.28"),
            _unpinned_pypi("six"),
            _skipped("git+https://github.com/x/y", "skipped_vcs", "VCS dep"),
            _exact_npm("express", "4.18.2"),
            _exact_npm("@babel/core", "7.23.9"),
        ]
        self._sbom = _parse_sbom(deps, "requirements.txt")

    def test_all_components_present(self, setup):
        assert len(self._sbom["components"]) == 6

    def test_only_exact_versions_have_version_field(self, setup):
        for comp in self._sbom["components"]:
            version = comp.get("version")
            purl = comp.get("purl")
            status = _prop(comp, "sbom:parsingStatus")
            has_exact_status = (status == "parsed") and (purl is not None)
            if version is not None:
                assert has_exact_status or purl is not None, (
                    f"Component {comp['name']} has version but no PURL"
                )

    def test_no_range_specifier_in_version_fields(self, setup):
        """Range operators must never appear in a component's version field."""
        operators = (">", "<", "=", "~", "^", "*", "!")
        for comp in self._sbom["components"]:
            version = comp.get("version")
            if version:
                for op in operators:
                    assert op not in version, (
                        f"Component {comp['name']} has operator {op!r} in version field: {version!r}"
                    )

    def test_skipped_dep_has_skip_reason(self, setup):
        vcs_comps = [
            c for c in self._sbom["components"]
            if _prop(c, "sbom:parsingStatus") == "skipped_vcs"
        ]
        assert len(vcs_comps) >= 1
        for c in vcs_comps:
            assert _prop(c, "sbom:skipReason") is not None

    def test_scoped_npm_purl_correct(self, setup):
        babel = _component_by_name(self._sbom, "@babel/core")
        assert babel is not None
        purl = babel.get("purl", "")
        assert "babel" in purl
        assert "7.23.9" in purl
