"""
CycloneDX 1.5 SBOM Generator.

Public API
----------
generate_sbom(dependencies, source_filename) -> str

Produces a CycloneDX 1.5 JSON string from a list of dependency dicts as
returned by app.parser.parse_file().

CycloneDX field mapping
-----------------------
* Component.version  — set to the bare exact version ONLY when
  dep["is_exact_version"] is True. Left unset (None) otherwise.
  A range specifier (e.g. ">=1.0") is NEVER placed in the version field.
* Component.properties["originalVersionSpecifier"] — set to
  dep["version_specifier"] for non-exact entries so the original
  constraint is preserved without polluting the structured version field.
* Component.purl — constructed and validated with packageurl-python.
  Built only for exact-version deps; omitted (not None-set) otherwise.
  Invalid PURLs are logged and the component is still included.
* Component.properties["sbom:dependencyType"] — "direct" or "dev".
* Component.properties["sbom:parsingStatus"] — parsing_status from parser.
* Component.properties["sbom:skipReason"] — present only for skipped deps.

npm scoped packages
-------------------
@scope/package maps to PURL:  pkg:npm/%40scope%2Fpackage@version
The PackageURL library handles URL-encoding of the namespace when we pass
namespace and name separately.
"""

import logging
from datetime import datetime, timezone
from io import StringIO

from cyclonedx.model import Property, Tool
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot5
from packageurl import PackageURL

logger = logging.getLogger(__name__)

# Displayed in SBOM metadata
_TOOL_NAME = "SBOM-Dependency-Risk-Analyzer"
_TOOL_VERSION = "1.0.0"
_TOOL_VENDOR = "IBM Cybersecurity Training"


# ---------------------------------------------------------------------------
# PURL builder
# ---------------------------------------------------------------------------

def build_purl(name: str, version: str, ecosystem: str) -> str | None:
    """
    Build and validate a Package URL for the given dependency.

    Args:
        name:       Package name (may include @scope/ prefix for npm).
        version:    Bare exact version string (e.g. "3.0.3").
        ecosystem:  "PyPI" or "npm".

    Returns:
        Validated PURL string, or None if construction/validation fails.
    """
    try:
        pkg_type = "pypi" if ecosystem == "PyPI" else "npm"

        if pkg_type == "npm" and name.startswith("@"):
            # Split @scope/package into namespace + name for correct PURL encoding
            # e.g. @babel/core → namespace="babel", name="core"
            parts = name[1:].split("/", 1)
            if len(parts) == 2:
                namespace, pkg_name = parts
            else:
                namespace = None
                pkg_name = name
            purl = PackageURL(
                type=pkg_type,
                namespace=namespace,
                name=pkg_name,
                version=version,
            )
        else:
            purl = PackageURL(
                type=pkg_type,
                name=name,
                version=version,
            )

        # Round-trip validation: ensure the PURL is parseable
        PackageURL.from_string(str(purl))
        return str(purl)

    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Could not build PURL for %r version %r (ecosystem=%s): %s",
            name, version, ecosystem, exc,
        )
        return None


# ---------------------------------------------------------------------------
# SBOM generator
# ---------------------------------------------------------------------------

def generate_sbom(dependencies: list[dict], source_filename: str) -> str:
    """
    Generate a CycloneDX 1.5 JSON SBOM from parsed dependency dicts.

    Args:
        dependencies:    List of dicts from app.parser.parse_file().
        source_filename: Original uploaded filename (stored in SBOM metadata).

    Returns:
        CycloneDX 1.5 JSON string.

    The returned string is guaranteed to be parseable by json.loads() and
    to contain "bomFormat": "CycloneDX" and "specVersion": "1.5".
    """
    bom = Bom()

    # Metadata
    bom.metadata = BomMetaData(
        timestamp=datetime.now(timezone.utc),
        tools=[
            Tool(
                vendor=_TOOL_VENDOR,
                name=_TOOL_NAME,
                version=_TOOL_VERSION,
            )
        ],
    )

    for dep in dependencies:
        component = _build_component(dep)
        bom.components.add(component)

    serializer = JsonV1Dot5(bom)
    return serializer.output_as_string(indent=2)


# ---------------------------------------------------------------------------
# Component builder
# ---------------------------------------------------------------------------

def _build_component(dep: dict) -> Component:
    """
    Build a CycloneDX Component from a single parser dependency dict.

    Version field rules:
    - Exact version → set Component.version to the bare version string.
    - Non-exact / skipped → Component.version is NOT set (omitted from JSON).
    - Original specifier for non-exact entries is stored in a property.
    """
    name: str = dep["name"]
    ecosystem: str = dep["ecosystem"]
    is_exact: bool = dep.get("is_exact_version", False)
    version_exact: str | None = dep.get("version")        # bare version or None
    version_specifier: str = dep.get("version_specifier", "")
    dep_type: str = dep.get("dependency_type", "direct")
    parsing_status: str = dep.get("parsing_status", "parsed")
    skip_reason: str | None = dep.get("skip_reason")

    # Build component — version set ONLY for exact pins
    component = Component(
        name=name,
        type=ComponentType.LIBRARY,
        version=version_exact,   # None → omitted from JSON output
    )

    # Add PURL for exact-version deps only
    if is_exact and version_exact:
        purl_str = build_purl(name, version_exact, ecosystem)
        if purl_str:
            try:
                component.purl = PackageURL.from_string(purl_str)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to attach purl %r to component %r: %s", purl_str, name, exc)

    # Properties
    # 1. Preserve original version specifier for non-exact deps
    if version_specifier and not is_exact:
        component.properties.add(
            Property(name="originalVersionSpecifier", value=version_specifier)
        )

    # 2. Ecosystem
    component.properties.add(
        Property(name="sbom:ecosystem", value=ecosystem)
    )

    # 3. Dependency type (direct / dev)
    component.properties.add(
        Property(name="sbom:dependencyType", value=dep_type)
    )

    # 4. Parsing status
    component.properties.add(
        Property(name="sbom:parsingStatus", value=parsing_status)
    )

    # 5. Skip reason (only for skipped/unsupported deps)
    if skip_reason:
        component.properties.add(
            Property(name="sbom:skipReason", value=skip_reason)
        )

    return component
