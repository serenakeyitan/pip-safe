"""Data models for pip-safe scan results."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security finding from an analyzer."""

    severity: Severity
    title: str
    description: str
    evidence: str = ""

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}: {self.description}"


@dataclass
class ScanResult:
    """Aggregated result of scanning a package across all analyzers."""

    package_name: str
    version: str
    safe: bool
    score: int  # 0-100, higher = safer
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    def medium_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    def low_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.LOW]

    def info_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.INFO]

    def severity_counts(self) -> dict[str, int]:
        return {
            "CRITICAL": len(self.critical_findings()),
            "HIGH": len(self.high_findings()),
            "MEDIUM": len(self.medium_findings()),
            "LOW": len(self.low_findings()),
            "INFO": len(self.info_findings()),
        }
