"""OSV (Open Source Vulnerabilities) database checker.

Queries the OSV API at https://api.osv.dev/v1/query to find known CVEs
and security advisories for a given package+version.
"""
from __future__ import annotations

import requests

from pip_safe.models import Finding, Severity

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 10


def analyze(package_name: str, version: str | None = None) -> list[Finding]:
    """Query OSV for known vulnerabilities affecting package_name@version."""
    findings: list[Finding] = []

    payload: dict = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI",
        }
    }
    if version:
        payload["version"] = version

    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=OSV_TIMEOUT)
        if resp.status_code != 200:
            return findings
        data = resp.json()
    except requests.RequestException:
        return findings

    vulns = data.get("vulns", [])
    if not vulns:
        return findings

    for vuln in vulns:
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", "No summary available.")
        details = vuln.get("details", "")
        aliases = vuln.get("aliases", [])
        alias_str = ", ".join(aliases) if aliases else ""

        # Determine severity from CVSS score if available
        severity = _determine_severity(vuln)

        description = (
            f"Package '{package_name}' has a known vulnerability: {summary}"
        )
        if alias_str:
            description += f" (also known as: {alias_str})"

        findings.append(
            Finding(
                severity=severity,
                title=f"Known Vulnerability: {vuln_id}",
                description=description,
                evidence=(
                    f"OSV ID: {vuln_id} | "
                    f"Details: {(details or summary)[:200]}"
                ),
            )
        )

    return findings


def _determine_severity(vuln: dict) -> Severity:
    """Infer severity from CVSS scores in the OSV vulnerability record."""
    for severity_entry in vuln.get("severity", []):
        score_str = severity_entry.get("score", "")
        sev_type = severity_entry.get("type", "")

        # CVSS_V3 scores look like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        if sev_type == "CVSS_V3" and score_str:
            base = _parse_cvss_base_score(score_str)
            if base is not None:
                if base >= 9.0:
                    return Severity.CRITICAL
                if base >= 7.0:
                    return Severity.HIGH
                if base >= 4.0:
                    return Severity.MEDIUM
                return Severity.LOW

    # Fall back to database_specific scores
    for entry in vuln.get("database_specific", {}).get("severity", []):
        level = str(entry).upper()
        if level == "CRITICAL":
            return Severity.CRITICAL
        if level == "HIGH":
            return Severity.HIGH
        if level == "MODERATE" or level == "MEDIUM":
            return Severity.MEDIUM
        if level == "LOW":
            return Severity.LOW

    return Severity.MEDIUM  # default if unknown


def _parse_cvss_base_score(vector: str) -> float | None:
    """Extract numeric base score from CVSS vector string if embedded, else return None."""
    # Sometimes the score is appended: "CVSS:3.1/... 7.5"
    parts = vector.strip().split()
    for part in reversed(parts):
        try:
            score = float(part)
            if 0.0 <= score <= 10.0:
                return score
        except ValueError:
            continue
    return None
