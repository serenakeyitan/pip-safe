"""Tests for the scanner orchestrator."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from pip_safe.models import Finding, ScanResult, Severity
from pip_safe.scanner import compute_score, scan_package


class TestComputeScore:
    def test_empty_findings(self):
        assert compute_score([]) == 100

    def test_score_floor(self):
        findings = [Finding(Severity.CRITICAL, "T", "d")] * 10
        assert compute_score(findings) == 0

    def test_score_ceiling(self):
        assert compute_score([]) == 100


class TestScanPackage:
    @patch("pip_safe.scanner.behavioral.analyze")
    @patch("pip_safe.scanner.metadata.analyze")
    @patch("pip_safe.scanner.typosquatting.analyze")
    @patch("pip_safe.scanner.database.analyze")
    @patch("pip_safe.scanner._resolve_version")
    @patch("pip_safe.scanner._collect_metadata")
    def test_known_malicious_is_unsafe(
        self,
        mock_meta,
        mock_version,
        mock_db,
        mock_typo,
        mock_meta_analyze,
        mock_behavioral,
    ):
        mock_db.return_value = [Finding(Severity.CRITICAL, "Known Malicious", "desc")]
        mock_typo.return_value = []
        mock_meta_analyze.return_value = []
        mock_behavioral.return_value = []
        mock_version.return_value = "0.1.0"
        mock_meta.return_value = {}

        result = scan_package("colourama", skip_behavioral=True)
        assert result.safe is False
        assert result.score == 60  # 100 - 40 = 60 — at boundary, unsafe (requires >60)

    @patch("pip_safe.scanner.behavioral.analyze")
    @patch("pip_safe.scanner.metadata.analyze")
    @patch("pip_safe.scanner.typosquatting.analyze")
    @patch("pip_safe.scanner.database.analyze")
    @patch("pip_safe.scanner._resolve_version")
    @patch("pip_safe.scanner._collect_metadata")
    def test_clean_package_is_safe(
        self,
        mock_meta,
        mock_version,
        mock_db,
        mock_typo,
        mock_meta_analyze,
        mock_behavioral,
    ):
        mock_db.return_value = []
        mock_typo.return_value = []
        mock_meta_analyze.return_value = []
        mock_behavioral.return_value = []
        mock_version.return_value = "2.28.0"
        mock_meta.return_value = {}

        result = scan_package("requests", skip_behavioral=True)
        assert result.safe is True
        assert result.score == 100

    @patch("pip_safe.scanner.behavioral.analyze")
    @patch("pip_safe.scanner.metadata.analyze")
    @patch("pip_safe.scanner.typosquatting.analyze")
    @patch("pip_safe.scanner.database.analyze")
    @patch("pip_safe.scanner._resolve_version")
    @patch("pip_safe.scanner._collect_metadata")
    def test_skip_behavioral_flag(
        self,
        mock_meta,
        mock_version,
        mock_db,
        mock_typo,
        mock_meta_analyze,
        mock_behavioral,
    ):
        mock_db.return_value = []
        mock_typo.return_value = []
        mock_meta_analyze.return_value = []
        mock_behavioral.return_value = []
        mock_version.return_value = "1.0.0"
        mock_meta.return_value = {}

        scan_package("some-package", skip_behavioral=True)
        mock_behavioral.assert_not_called()

    @patch("pip_safe.scanner.behavioral.analyze")
    @patch("pip_safe.scanner.metadata.analyze")
    @patch("pip_safe.scanner.typosquatting.analyze")
    @patch("pip_safe.scanner.database.analyze")
    @patch("pip_safe.scanner._resolve_version")
    @patch("pip_safe.scanner._collect_metadata")
    def test_result_fields(
        self,
        mock_meta,
        mock_version,
        mock_db,
        mock_typo,
        mock_meta_analyze,
        mock_behavioral,
    ):
        mock_db.return_value = []
        mock_typo.return_value = [Finding(Severity.HIGH, "Typo", "desc")]
        mock_meta_analyze.return_value = []
        mock_behavioral.return_value = []
        mock_version.return_value = "1.0.0"
        mock_meta.return_value = {"summary": "A test package"}

        result = scan_package("numpyy", skip_behavioral=True)
        assert isinstance(result, ScanResult)
        assert result.package_name == "numpyy"
        assert result.version == "1.0.0"
        assert result.score == 75  # 100 - 25
        assert result.safe is True  # 75 >= 60
        assert len(result.findings) == 1
