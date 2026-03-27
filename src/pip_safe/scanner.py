"""Scanner orchestrator — runs all analyzers and computes a risk score."""

from __future__ import annotations

from pip_safe.analyzers import database, metadata, typosquatting
from pip_safe.analyzers import behavioral
from pip_safe.models import Finding, ScanResult, Severity
from pip_safe.utils import fetch_pypi_metadata

# Score deductions per severity level
SEVERITY_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 15,
    Severity.LOW: 5,
    Severity.INFO: 0,
}


def compute_score(findings: list[Finding]) -> int:
    """Calculate a safety score (0-100) from a list of findings."""
    score = 100
    for finding in findings:
        score -= SEVERITY_DEDUCTIONS.get(finding.severity, 0)
    return max(0, min(100, score))


def scan_package(
    package_name: str,
    version: str | None = None,
    skip_behavioral: bool = False,
) -> ScanResult:
    """Run all analyzers against a package and return an aggregated ScanResult."""
    all_findings: list[Finding] = []

    # 1. Database check — fast, no network needed
    db_findings = database.analyze(package_name)
    all_findings.extend(db_findings)

    # 2. Typosquatting check — purely local computation
    typo_findings = typosquatting.analyze(package_name)
    all_findings.extend(typo_findings)

    # 3. Metadata check — requires one PyPI API call
    meta_findings = metadata.analyze(package_name, version)
    all_findings.extend(meta_findings)

    # 4. Behavioral analysis — downloads the package; can be skipped
    if not skip_behavioral:
        behavioral_findings = behavioral.analyze(package_name, version)
        all_findings.extend(behavioral_findings)

    # Resolve version from PyPI if not provided
    resolved_version = version or _resolve_version(package_name)

    score = compute_score(all_findings)
    safe = score > 60

    # Collect some metadata for display
    pkg_metadata = _collect_metadata(package_name, version)

    return ScanResult(
        package_name=package_name,
        version=resolved_version,
        safe=safe,
        score=score,
        findings=all_findings,
        metadata=pkg_metadata,
    )


def _resolve_version(package_name: str) -> str:
    """Attempt to resolve the latest version of a package from PyPI."""
    meta = fetch_pypi_metadata(package_name)
    if meta:
        return meta.get("info", {}).get("version", "unknown")
    return "unknown"


def _collect_metadata(package_name: str, version: str | None) -> dict:
    """Collect display metadata from PyPI."""
    meta = fetch_pypi_metadata(package_name, version)
    if not meta:
        return {}

    info = meta.get("info", {})
    return {
        "summary": info.get("summary", ""),
        "author": info.get("author") or info.get("maintainer", ""),
        "home_page": info.get("home_page", ""),
        "license": info.get("license", ""),
        "requires_python": info.get("requires_python", ""),
        "project_urls": info.get("project_urls") or {},
    }
