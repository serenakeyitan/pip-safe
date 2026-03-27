"""PyPI metadata analyzer — check package metadata for risk signals."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from pip_safe.models import Finding, Severity
from pip_safe.utils import fetch_pypi_metadata, normalize_package_name

# Thresholds
NEW_PACKAGE_DAYS = 7          # Packages newer than this many days are suspicious
LOW_DOWNLOAD_THRESHOLD = 100  # Fewer than this many downloads is suspicious
HIGH_DEPENDENCY_COUNT = 50    # More than this many dependencies is suspicious
SUSPICIOUS_VERSION_DOWNLOADS = 10_000  # High downloads with v0.0.1 is suspicious


def analyze(package_name: str, version: str | None = None) -> list[Finding]:
    """Fetch and analyze PyPI metadata for a package."""
    findings: list[Finding] = []

    meta = fetch_pypi_metadata(package_name, version)
    if meta is None:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Package Not Found on PyPI",
                description=(
                    f"Package '{package_name}' was not found on PyPI. "
                    "This could mean the package name is wrong, the package has been "
                    "removed (possibly after being flagged as malicious), or it is "
                    "a private/internal package name that should not be installed from PyPI."
                ),
                evidence=f"GET https://pypi.org/pypi/{package_name}/json -> 404",
            )
        )
        return findings

    info = meta.get("info", {})
    releases = meta.get("releases", {})
    urls = meta.get("urls", [])

    findings.extend(_check_package_age(info, releases))
    findings.extend(_check_download_count(info, urls))
    findings.extend(_check_homepage_and_source(info))
    findings.extend(_check_version_anomaly(info, urls))
    findings.extend(_check_dependency_explosion(info))
    findings.extend(_check_maintainer_count(info))

    return findings


def _check_package_age(info: dict, releases: dict) -> list[Finding]:
    """Flag packages that are very new (< 7 days old)."""
    findings: list[Finding] = []

    # Find the earliest release date across all versions
    earliest_upload: datetime | None = None

    for version_files in releases.values():
        for file_info in version_files:
            upload_str = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
            if not upload_str:
                continue
            try:
                # Handle both ISO 8601 with Z and without timezone
                upload_str = upload_str.replace("Z", "+00:00")
                if "+" not in upload_str and upload_str.count("-") < 3:
                    upload_str += "+00:00"
                dt = datetime.fromisoformat(upload_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if earliest_upload is None or dt < earliest_upload:
                    earliest_upload = dt
            except (ValueError, AttributeError):
                continue

    if earliest_upload is None:
        return findings

    now = datetime.now(tz=timezone.utc)
    age_days = (now - earliest_upload).days

    if age_days < NEW_PACKAGE_DAYS:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Very New Package",
                description=(
                    f"Package '{info.get('name', '?')}' was first published only "
                    f"{age_days} day(s) ago (on {earliest_upload.date()}). "
                    "Newly created packages are a common vector for supply chain attacks, "
                    "as they haven't had time to be reviewed by the community."
                ),
                evidence=f"First upload: {earliest_upload.isoformat()}, Age: {age_days} days",
            )
        )

    return findings


def _check_download_count(info: dict, urls: list[dict]) -> list[Finding]:
    """Flag packages with very few downloads."""
    findings: list[Finding] = []

    # PyPI's JSON API doesn't include download counts directly.
    # We can infer from the number of releases and their file counts as a proxy,
    # but the real download stats come from pypistats.org. We check the releases count.
    total_versions = len(info.get("releases", {})) if "releases" in info else 0

    # Use the downloads field if present (sometimes available in the info dict)
    downloads = info.get("downloads", {})
    monthly = downloads.get("last_month", -1) if isinstance(downloads, dict) else -1

    if monthly != -1 and monthly < LOW_DOWNLOAD_THRESHOLD:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Very Low Download Count",
                description=(
                    f"Package '{info.get('name', '?')}' has only {monthly} downloads "
                    f"in the past month. Low download counts can indicate a newly created "
                    "malicious package that has not been widely adopted."
                ),
                evidence=f"Monthly downloads (last month): {monthly}",
            )
        )

    return findings


def _check_homepage_and_source(info: dict) -> list[Finding]:
    """Flag packages with no homepage or source URL."""
    findings: list[Finding] = []

    homepage = info.get("home_page") or ""
    project_urls = info.get("project_urls") or {}
    source_url = (
        project_urls.get("Source")
        or project_urls.get("Repository")
        or project_urls.get("Source Code")
        or project_urls.get("Homepage")
        or ""
    )

    has_url = bool(homepage.strip() or source_url.strip())

    if not has_url:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="No Homepage or Source URL",
                description=(
                    f"Package '{info.get('name', '?')}' has no homepage or source code URL. "
                    "Legitimate packages typically link to a GitHub/GitLab repository or "
                    "documentation site. Missing URLs make it harder to audit the source code."
                ),
                evidence="home_page and project_urls are empty",
            )
        )

    return findings


def _check_version_anomaly(info: dict, urls: list[dict]) -> list[Finding]:
    """Flag suspicious version patterns (e.g., v0.0.1 that suddenly has high downloads)."""
    findings: list[Finding] = []

    version = info.get("version", "")

    # Version 0.0.1 with large download count is suspicious
    if re.match(r"^0\.0\.[01]$", version):
        downloads = info.get("downloads", {})
        monthly = downloads.get("last_month", -1) if isinstance(downloads, dict) else -1
        if monthly > SUSPICIOUS_VERSION_DOWNLOADS:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="Suspicious Version-Download Mismatch",
                    description=(
                        f"Package '{info.get('name', '?')}' is at version {version} "
                        f"but has {monthly:,} monthly downloads. A 0.0.x version with "
                        "extremely high downloads may indicate this package is impersonating "
                        "a popular package to attract accidental installs."
                    ),
                    evidence=f"Version: {version}, Monthly downloads: {monthly}",
                )
            )

    return findings


def _check_dependency_explosion(info: dict) -> list[Finding]:
    """Flag packages with an unusually large number of dependencies."""
    findings: list[Finding] = []

    requires_dist = info.get("requires_dist") or []
    dep_count = len(requires_dist)

    if dep_count > HIGH_DEPENDENCY_COUNT:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Dependency Count Explosion",
                description=(
                    f"Package '{info.get('name', '?')}' declares {dep_count} dependencies. "
                    f"Packages with more than {HIGH_DEPENDENCY_COUNT} dependencies significantly "
                    "expand the attack surface and may pull in malicious transitive dependencies."
                ),
                evidence=f"requires_dist count: {dep_count}",
            )
        )

    return findings


def _check_maintainer_count(info: dict) -> list[Finding]:
    """Info-level finding about maintainer count."""
    findings: list[Finding] = []

    maintainer = info.get("maintainer") or ""
    author = info.get("author") or ""

    # Single-character or clearly fake author names
    author_name = maintainer or author
    if author_name and len(author_name.strip()) <= 1:
        findings.append(
            Finding(
                severity=Severity.LOW,
                title="Suspicious Author Name",
                description=(
                    f"Package '{info.get('name', '?')}' has a suspiciously short author/maintainer "
                    f"name: '{author_name}'. This may indicate a quickly-created throwaway account."
                ),
                evidence=f"author='{author}', maintainer='{maintainer}'",
            )
        )

    return findings
