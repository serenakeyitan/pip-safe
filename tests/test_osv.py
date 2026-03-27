"""Tests for OSV vulnerability analyzer."""
from __future__ import annotations

from unittest.mock import patch

import pytest
import responses as responses_lib

from pip_safe.analyzers.osv import _determine_severity, _parse_cvss_base_score, analyze
from pip_safe.models import Severity


class TestParseCvssBaseScore:
    def test_score_at_end(self):
        assert _parse_cvss_base_score("CVSS:3.1/AV:N/AC:L 9.8") == 9.8

    def test_no_score(self):
        assert _parse_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N") is None

    def test_invalid_string(self):
        assert _parse_cvss_base_score("") is None


class TestDetermineSeverity:
    def test_critical_cvss(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N 9.8"}]}
        assert _determine_severity(vuln) == Severity.CRITICAL

    def test_high_cvss(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N 7.5"}]}
        assert _determine_severity(vuln) == Severity.HIGH

    def test_medium_cvss(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N 5.0"}]}
        assert _determine_severity(vuln) == Severity.MEDIUM

    def test_low_cvss(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N 2.0"}]}
        assert _determine_severity(vuln) == Severity.LOW

    def test_no_severity_defaults_medium(self):
        vuln = {}
        assert _determine_severity(vuln) == Severity.MEDIUM


class TestAnalyzeOSV:
    @patch("pip_safe.analyzers.osv.requests.post")
    def test_no_vulns(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"vulns": []}
        findings = analyze("requests", "2.28.0")
        assert findings == []

    @patch("pip_safe.analyzers.osv.requests.post")
    def test_vuln_found(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-1234-abcd-xxxx",
                    "summary": "Remote code execution in example-pkg",
                    "details": "An attacker can execute arbitrary code.",
                    "aliases": ["CVE-2024-12345"],
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N 9.8"}],
                }
            ]
        }
        findings = analyze("example-pkg", "1.0.0")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "GHSA-1234-abcd-xxxx" in findings[0].title
        assert "CVE-2024-12345" in findings[0].description

    @patch("pip_safe.analyzers.osv.requests.post")
    def test_api_error_returns_empty(self, mock_post):
        mock_post.return_value.status_code = 500
        findings = analyze("some-pkg")
        assert findings == []

    @patch("pip_safe.analyzers.osv.requests.post")
    def test_network_error_returns_empty(self, mock_post):
        import requests
        mock_post.side_effect = requests.RequestException("timeout")
        findings = analyze("some-pkg")
        assert findings == []
