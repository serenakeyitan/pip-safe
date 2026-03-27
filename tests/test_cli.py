"""Tests for the CLI commands."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pip_safe.cli import cli
from pip_safe.models import Finding, ScanResult, Severity


def make_safe_result(package: str = "requests") -> ScanResult:
    return ScanResult(
        package_name=package,
        version="2.28.0",
        safe=True,
        score=100,
        findings=[],
        metadata={"summary": "HTTP library"},
    )


def make_unsafe_result(package: str = "colourama") -> ScanResult:
    return ScanResult(
        package_name=package,
        version="0.1.0",
        safe=False,
        score=20,
        findings=[
            Finding(
                severity=Severity.CRITICAL,
                title="Known Malicious Package",
                description="This package is in the known malicious database",
                evidence="Matched: colourama",
            )
        ],
        metadata={},
    )


class TestScanCommand:
    def setup_method(self):
        self.runner = CliRunner()

    @patch("pip_safe.cli.scan_package")
    def test_scan_safe_package_exits_0(self, mock_scan):
        mock_scan.return_value = make_safe_result()
        result = self.runner.invoke(cli, ["scan", "requests"])
        assert result.exit_code == 0

    @patch("pip_safe.cli.scan_package")
    def test_scan_unsafe_package_exits_1(self, mock_scan):
        mock_scan.return_value = make_unsafe_result()
        result = self.runner.invoke(cli, ["scan", "colourama"])
        assert result.exit_code == 1

    @patch("pip_safe.cli.scan_package")
    def test_scan_json_output(self, mock_scan):
        mock_scan.return_value = make_safe_result()
        result = self.runner.invoke(cli, ["scan", "requests", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["package_name"] == "requests"
        assert data["safe"] is True
        assert "score" in data
        assert "findings" in data

    @patch("pip_safe.cli.scan_package")
    def test_scan_with_version(self, mock_scan):
        mock_scan.return_value = make_safe_result()
        result = self.runner.invoke(cli, ["scan", "requests", "--version", "2.28.0"])
        assert result.exit_code == 0
        mock_scan.assert_called_once_with(
            package_name="requests", version="2.28.0", skip_behavioral=False
        )

    @patch("pip_safe.cli.scan_package")
    def test_scan_no_behavioral_flag(self, mock_scan):
        mock_scan.return_value = make_safe_result()
        self.runner.invoke(cli, ["scan", "requests", "--no-behavioral"])
        mock_scan.assert_called_once_with(
            package_name="requests", version=None, skip_behavioral=True
        )

    @patch("pip_safe.cli.scan_package")
    def test_scan_shows_score(self, mock_scan):
        mock_scan.return_value = make_safe_result()
        result = self.runner.invoke(cli, ["scan", "requests"])
        assert "100" in result.output or "SAFE" in result.output


class TestAuditCommand:
    def setup_method(self):
        self.runner = CliRunner()

    @patch("pip_safe.cli.scan_package")
    def test_audit_missing_file(self, mock_scan):
        result = self.runner.invoke(cli, ["audit", "--requirements", "/nonexistent/requirements.txt"])
        assert result.exit_code == 1

    @patch("pip_safe.cli.scan_package")
    def test_audit_valid_requirements(self, mock_scan, tmp_path):
        mock_scan.return_value = make_safe_result("requests")
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\n")

        result = self.runner.invoke(cli, ["audit", "--requirements", str(req_file)])
        assert result.exit_code == 0
        mock_scan.assert_called()

    @patch("pip_safe.cli.scan_package")
    def test_audit_json_output(self, mock_scan, tmp_path):
        mock_scan.return_value = make_safe_result("requests")
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\n")

        result = self.runner.invoke(
            cli, ["audit", "--requirements", str(req_file), "--json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["package_name"] == "requests"

    @patch("pip_safe.cli.scan_package")
    def test_audit_unsafe_exits_1(self, mock_scan, tmp_path):
        mock_scan.return_value = make_unsafe_result("colourama")
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("colourama==0.1.0\n")

        result = self.runner.invoke(cli, ["audit", "--requirements", str(req_file)])
        assert result.exit_code == 1

    @patch("pip_safe.cli.scan_package")
    def test_audit_skips_comments_and_empty_lines(self, mock_scan, tmp_path):
        mock_scan.return_value = make_safe_result("requests")
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "# This is a comment\n\nrequests>=2.0\n-r other.txt\n"
        )

        result = self.runner.invoke(cli, ["audit", "--requirements", str(req_file)])
        # Should only scan 'requests', not comment or -r line
        assert mock_scan.call_count == 1


class TestVersionFlag:
    def setup_method(self):
        self.runner = CliRunner()

    def test_version_flag(self):
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
