# pip-safe

**PyPI Package Security Scanner — detect supply chain attacks before they happen.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/pip-safe.svg)](https://pypi.org/project/pip-safe/)
[![CI](https://github.com/serenakeyitan/pip-safe/actions/workflows/ci.yml/badge.svg)](https://github.com/serenakeyitan/pip-safe/actions/workflows/ci.yml)

---

## The Problem: The litellm Supply Chain Attack

In early 2024, the popular LLM library **litellm** was targeted in a supply chain attack. Attackers uploaded a malicious package to PyPI designed to trick developers into accidentally `pip install`-ing it. Andrej Karpathy [tweeted about it](https://twitter.com/karpathy), bringing the issue to the attention of the broader machine learning community.

This is not an isolated incident. Supply chain attacks via PyPI have become increasingly common:

- **Typosquatting** — packages with names one keystroke away from popular libraries
- **Dependency confusion** — malicious packages that shadow internal package names
- **Install-time execution** — `setup.py` scripts that run malicious code during `pip install`
- **Credential theft** — packages that silently exfiltrate your AWS keys, SSH keys, and GitHub tokens

**pip-safe** is a drop-in wrapper for pip that scans every package before installation, catching these attacks before they can harm you.

---

## Features

- **Typosquatting detection** — Levenshtein distance analysis against 100+ popular packages
- **Known malicious package database** — instantly blocks packages with confirmed attack history
- **Behavioral AST analysis** — static analysis of every `.py` file in the package, looking for:
  - `eval()`/`exec()` with obfuscated arguments
  - Base64-encoded URLs or shell commands
  - Network calls (`requests`, `urllib`, `socket`) at import time
  - Subprocess spawning `curl`, `wget`, `nc`, or shell commands
  - Reading `~/.ssh/`, `~/.aws/`, `~/.kube/` credential files
  - Exfiltrating environment variables with `SECRET`, `KEY`, `TOKEN`, `PASSWORD`
  - DNS-based data exfiltration patterns
- **PyPI metadata analysis** — flags packages that are brand-new, have no source URL, or have dependency count explosions
- **Beautiful terminal output** — colored risk indicators, progress bars, and audit tables via `rich`
- **4 commands** — `scan`, `install`, `audit`, `check-env`
- **JSON output** — machine-readable results for CI integration
- **Zero false-negative on known malicious packages** — database check always runs first

---

## Installation

```bash
pip install pip-safe
```

Or install from source:

```bash
git clone https://github.com/serenakeyitan/pip-safe.git
cd pip-safe
pip install -e .
```

---

## Quick Start

### Scan a package before installing

```
$ pip-safe scan litellm

  litellm v1.20.0  —  SAFE
  Safety Score: ████████████████████ 95/100
  LLM provider abstraction library

  LOW (1)
    LOW  No Homepage or Source URL
      Package 'litellm' has no homepage or source code URL.
```

### Block a malicious package

```
$ pip-safe scan colourama

  colourama v0.1.0  —  UNSAFE
  Safety Score: ░░░░░░░░░░░░░░░░░░░░ 0/100

  CRITICAL (1)
     CRITICAL  Known Malicious Package
      Package 'colourama' is in the known malicious package database.
      Threat: Typosquat of 'colorama' - steals credentials.
      Do NOT install this package.
      Evidence: Matched database entry: 'colourama' -> Typosquat of 'colorama' - steals credentials

$ echo $?
1
```

### Safe install (scans first)

```
$ pip-safe install requests pandas

Scanning requests...
  requests v2.31.0  —  SAFE
  Safety Score: ████████████████████ 100/100

Scanning pandas...
  pandas v2.1.0  —  SAFE
  Safety Score: ████████████████████ 100/100

Installing: requests pandas
Running: python -m pip install requests pandas
...
Successfully installed requests-2.31.0 pandas-2.1.0
```

### Audit your requirements.txt

```
$ pip-safe audit --requirements requirements.txt

Auditing 12 package(s) from requirements.txt

╭─────────────────────────────────────────────────────────╮
│                      Audit Results                       │
├──────────────────┬─────────┬───────┬────────┬───────────┤
│ Package          │ Version │ Score │ Status │ Issues    │
├──────────────────┼─────────┼───────┼────────┼───────────┤
│ requests         │ 2.31.0  │   100 │  SAFE  │           │
│ pandas           │ 2.1.0   │   100 │  SAFE  │           │
│ numpy            │ 1.24.0  │   100 │  SAFE  │           │
│ colourama        │ 0.1.0   │     0 │ UNSAFE │ Known Ma… │
╰──────────────────┴─────────┴───────┴────────┴───────────╯

✗ 1 unsafe package(s) found.
```

### Check your current environment

```
$ pip-safe check-env

Checking 142 installed package(s)...

✓ All 142 installed packages passed checks.
```

---

## Command Reference

### `pip-safe scan`

Scan a single package for security issues.

```bash
pip-safe scan <package> [OPTIONS]

Options:
  -v, --version TEXT    Specific version to scan
  --json                Output results as JSON
  --no-behavioral       Skip behavioral analysis (faster, less thorough)
```

**Examples:**
```bash
pip-safe scan requests
pip-safe scan numpy --version 1.24.0
pip-safe scan suspicious-pkg --json | jq '.safe'
pip-safe scan large-pkg --no-behavioral   # skip download + AST analysis
```

**Exit codes:** `0` = safe, `1` = unsafe or error

---

### `pip-safe install`

Scan packages, then install safe ones via pip. Blocks unsafe packages.

```bash
pip-safe install <packages...> [OPTIONS]

Options:
  -y, --yes             Auto-skip unsafe packages without prompting
  --force               Install even if unsafe (not recommended)
  --no-behavioral       Skip behavioral analysis
  --pip-args TEXT       Extra args to pass to pip install
```

**Examples:**
```bash
pip-safe install requests pandas numpy
pip-safe install some-package --yes
pip-safe install risky-pkg --force               # override block
pip-safe install pkg --pip-args "--no-deps"      # pass args to pip
```

---

### `pip-safe audit`

Audit all packages in a requirements file. Great for CI pipelines.

```bash
pip-safe audit [OPTIONS]

Options:
  -r, --requirements FILE   Requirements file to audit (default: requirements.txt)
  --json                    Output results as JSON
  --no-behavioral           Skip behavioral analysis
```

**Examples:**
```bash
pip-safe audit
pip-safe audit --requirements requirements-dev.txt
pip-safe audit --json > audit-report.json         # save for CI artifact
pip-safe audit --no-behavioral                    # fast mode for CI
```

**CI integration (GitHub Actions):**
```yaml
- name: Security audit
  run: pip-safe audit --requirements requirements.txt
```

---

### `pip-safe check-env`

Scan all currently installed packages using the database and typosquatting analyzers.

```bash
pip-safe check-env [OPTIONS]

Options:
  --json    Output results as JSON
```

**Examples:**
```bash
pip-safe check-env
pip-safe check-env --json | jq '.[] | select(.findings | length > 0)'
```

---

## How It Works

pip-safe runs four independent analyzers in sequence:

### 1. Database Checker (`analyzers/database.py`)

Instantly checks the package name against a curated list of ~30+ known malicious packages with confirmed attack histories (typosquats, credential stealers, backdoors). This check is purely local — no network requests.

**Severity: CRITICAL** — blocks installation immediately.

### 2. Typosquatting Detector (`analyzers/typosquatting.py`)

Computes Levenshtein edit distance between the requested package name and 100+ popular packages (numpy, requests, boto3, openai, litellm, etc.). Flags packages with distance ≤ 2.

Also detects:
- **Numeric substitution**: `requ3sts` → `requests`
- **Separator confusion**: `python_dateutil` vs `python-dateutil`

**Severity: HIGH** — dangerous but not automatically conclusive.

### 3. PyPI Metadata Analyzer (`analyzers/metadata.py`)

Fetches the PyPI JSON API for the package and checks:
- **Package age** — packages < 7 days old are suspicious
- **Missing URLs** — no homepage or source code link
- **Version/download mismatch** — v0.0.1 with suspiciously high downloads
- **Dependency explosion** — > 50 dependencies expands attack surface
- **Short author names** — throwaway accounts

**Severity: LOW to HIGH** depending on the signal.

### 4. Behavioral AST Scanner (`analyzers/behavioral.py`)

The most powerful analyzer. Downloads the actual package tarball/wheel from PyPI and performs static analysis on every `.py` file:

1. **Obfuscation detection** — `eval()`/`exec()` with non-literal args, base64-encoded payloads
2. **Subprocess scanning** — `subprocess.run/call/Popen` with `curl`, `wget`, `nc`, `bash -c`
3. **Network-at-import** — `requests.get()`, `socket.connect()`, `urllib.urlopen()` at module level
4. **Credential access** — reading `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.kube/config`
5. **Env var exfiltration** — `os.getenv("AWS_SECRET_ACCESS_KEY")`, etc.
6. **Filesystem crawling** — `os.walk()` or `glob.glob()` with home directory paths
7. **DNS exfiltration** — DNS queries combined with encoding, used to hide stolen data

**Severity: CRITICAL to HIGH** — the most actionable findings.

### Scoring

Each finding deducts from a starting score of 100:
- CRITICAL: −40 points
- HIGH: −25 points
- MEDIUM: −15 points
- LOW: −5 points
- INFO: no deduction

**Score ≥ 60 → SAFE** | **Score < 60 → UNSAFE**

---

## Comparison

| Feature | pip-safe | pip-audit | safety |
|---|---|---|---|
| Known malicious DB | ✅ | ❌ | ✅ (paid) |
| Typosquatting detection | ✅ | ❌ | ❌ |
| Behavioral AST analysis | ✅ | ❌ | ❌ |
| PyPI metadata checks | ✅ | ❌ | ❌ |
| CVE/vulnerability DB | ❌ | ✅ | ✅ |
| Drop-in pip wrapper | ✅ | ❌ | ❌ |
| Beautiful rich output | ✅ | ✅ | ❌ |
| JSON output | ✅ | ✅ | ✅ |
| CI integration | ✅ | ✅ | ✅ |
| Free & open source | ✅ | ✅ | ⚠️ |

**Recommendation:** Use pip-safe *alongside* pip-audit for best coverage — pip-safe catches supply chain attacks, pip-audit catches known CVEs in existing packages.

---

## Development

```bash
# Clone and install in development mode
git clone https://github.com/serenakeyitan/pip-safe.git
cd pip-safe
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=pip_safe --cov-report=term-missing

# Run linter
ruff check src/

# Run type checker
mypy src/
```

### Project Structure

```
pip-safe/
├── src/pip_safe/
│   ├── cli.py              # Click CLI entry point
│   ├── scanner.py          # Orchestrates analyzers, computes score
│   ├── models.py           # Finding, ScanResult dataclasses
│   ├── utils.py            # Levenshtein, PyPI download helpers
│   └── analyzers/
│       ├── database.py     # Known malicious package DB
│       ├── typosquatting.py # Edit distance analysis
│       ├── metadata.py     # PyPI API metadata checks
│       └── behavioral.py   # AST static analysis engine
└── tests/
    ├── test_analyzers.py   # Unit tests for all analyzers
    ├── test_scanner.py     # Score calculation tests
    ├── test_cli.py         # CLI command tests
    └── fixtures/
        └── malicious_pkg/setup.py  # Example malicious package for testing
```

### Contributing

Contributions welcome! Especially:
- **Expanding the known malicious package database** — submit PRs with verified malicious packages
- **New behavioral checks** — new AST patterns for supply chain attack techniques
- **Integration with OSV/OSSF databases** — cross-reference with the Open Source Vulnerabilities DB

Please open an issue first to discuss major changes.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built in response to the litellm PyPI supply chain attack. Stay safe out there.*
