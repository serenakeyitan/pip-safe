"""Known malicious package database checker."""

from __future__ import annotations

from pip_safe.models import Finding, Severity
from pip_safe.utils import normalize_package_name

# Known malicious packages with descriptions of their threat
KNOWN_MALICIOUS: dict[str, str] = {
    "colourama": "Typosquat of 'colorama' - steals credentials",
    "djanga": "Typosquat of 'django' - backdoor",
    "urlib3": "Typosquat of 'urllib3' - credential stealer",
    "urllib4": "Typosquat of 'urllib3' - info stealer",
    "loguru-dev": "Malicious variant of loguru",
    "noblesse": "Known credential stealer",
    "noblesse2": "Known credential stealer variant",
    "noblesseplus": "Known credential stealer variant",
    "getpip": "Fake pip package - malware",
    "get-pip": "Fake pip package - malware",
    "crypt": "Malicious package stealing crypto wallets",
    "py-util": "Known malware",
    "pyutil": "Known malware variant",
    "openssl-python": "Fake OpenSSL package",
    "python-ssl": "Fake SSL package - data stealer",
    "lxml2": "Typosquat of lxml",
    "requestts": "Typosquat of requests",
    "requersts": "Typosquat of requests",
    "req-ests": "Typosquat of requests",
    "python-dateutils": "Typosquat of python-dateutil",
    "panda": "Typosquat of pandas",
    "pandass": "Typosquat of pandas",
    "numipy": "Typosquat of numpy",
    "numpyy": "Typosquat of numpy",
    "set-utils": "Known data exfiltration package",
    "aws-login-tool": "Fake AWS tool - credential harvester",
    "cloud-utils": "Known malware",
    "discord-selfbot-v14": "Known malware",
    "discordpy-buttons": "Backdoored discord library",
    "aioboto": "Credential stealer targeting AWS",
}

# Build a normalized lookup for fast matching
_NORMALIZED_DB: dict[str, str] = {
    normalize_package_name(k): v for k, v in KNOWN_MALICIOUS.items()
}


def analyze(package_name: str) -> list[Finding]:
    """Check a package name against the known malicious package database."""
    findings: list[Finding] = []
    normalized = normalize_package_name(package_name)

    if normalized in _NORMALIZED_DB:
        description = _NORMALIZED_DB[normalized]
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                title="Known Malicious Package",
                description=(
                    f"Package '{package_name}' is in the known malicious package database. "
                    f"Threat: {description}. "
                    "Do NOT install this package."
                ),
                evidence=f"Matched database entry: '{package_name}' -> {description}",
            )
        )

    return findings


def is_known_malicious(package_name: str) -> bool:
    """Return True if the package is in the known malicious database."""
    return normalize_package_name(package_name) in _NORMALIZED_DB


def get_threat_description(package_name: str) -> str | None:
    """Return the threat description for a known malicious package, or None."""
    normalized = normalize_package_name(package_name)
    return _NORMALIZED_DB.get(normalized)
