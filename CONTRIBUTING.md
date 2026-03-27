# Contributing to pip-safe

Thank you for helping make the Python ecosystem safer! 🛡️

## Ways to Contribute

### 1. Add Known Malicious Packages

The most impactful contribution: add newly discovered malicious packages to the database.

**File:** `src/pip_safe/analyzers/database.py`

```python
KNOWN_MALICIOUS: dict[str, str] = {
    ...
    "your-package-name": "Description of the threat and what it does",
}
```

**Requirements:**
- Must be a confirmed malicious package (link to a public advisory, blog post, or security report)
- Include a clear, factual description of the threat
- Open a PR with a link to the source report

**Good sources for malicious package reports:**
- [PyPI Malware Reports (GitHub)](https://github.com/pypi/advisory-database)
- [CISA Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [Socket.dev Blog](https://socket.dev/blog)
- [Phylum Research](https://blog.phylum.io/)
- [Checkmarx Research](https://checkmarx.com/blog/)

---

### 2. Add Behavioral Detection Patterns

Supply chain attackers evolve their techniques. Help us stay ahead by adding new AST patterns.

**File:** `src/pip_safe/analyzers/behavioral.py`

Example: adding detection for a new exfiltration technique:

```python
def _check_new_technique(ctx: ASTContext) -> list[Finding]:
    """Detect [description of technique]."""
    findings: list[Finding] = []
    for node in ast.walk(ctx.tree):
        # Your detection logic here
        if isinstance(node, ast.Call) and ...:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Descriptive title",
                description="What this does and why it's dangerous",
                evidence=_get_node_source(ctx, node),
            ))
    return findings
```

Then add your function to `analyze_directory()`.

**Guidelines:**
- Minimize false positives — legitimate code should not be flagged
- Include unit tests in `tests/test_analyzers.py`
- Provide a real-world example of the attack technique in a comment

---

### 3. Improve Typosquatting Detection

**File:** `src/pip_safe/analyzers/typosquatting.py`

- Add new popular packages to `POPULAR_PACKAGES` list
- Improve the detection algorithm (e.g., better handling of separator confusion)
- Add new homoglyph mappings (visually similar characters)

---

### 4. Improve PyPI Metadata Analysis

**File:** `src/pip_safe/analyzers/metadata.py`

Ideas:
- Flag packages with no source repository link
- Detect packages with an unusual number of dependencies added in a new version
- Flag packages that changed maintainer/author recently

---

## Development Setup

```bash
# Clone the repo
git clone https://github.com/serenakeyitan/pip-safe.git
cd pip-safe

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=pip_safe --cov-report=term-missing

# Run linter
ruff check src/

# Run formatter (check only)
black --check src/ tests/

# Run type checker
mypy src/
```

## Pull Request Process

1. **Fork** the repository and create a feature branch: `git checkout -b feat/my-feature`
2. **Make changes** with atomic commits using [Conventional Commits](https://www.conventionalcommits.org/) format:
   - `feat: add detection for X`
   - `fix: correct false positive in Y`
   - `docs: update README with Z`
   - `test: add tests for W`
3. **Run the test suite** and ensure all tests pass: `pytest tests/ -v`
4. **Run the linter**: `ruff check src/`
5. **Open a PR** against `main` with a clear description of:
   - What the change does
   - Why it's needed (link to source if adding a malicious package)
   - Test coverage

## Code Style

- Python 3.10+ with type hints
- Line length: 100 characters (enforced by ruff)
- Docstrings for all public functions
- No bare `except:` — catch specific exceptions

## Reporting False Positives

If pip-safe is flagging a legitimate package incorrectly, please [open an issue](https://github.com/serenakeyitan/pip-safe/issues) with:
- The package name and version
- The finding(s) that were triggered
- Why you believe it's a false positive

## Security Policy

If you discover a vulnerability in pip-safe itself, please open a GitHub issue — this project is a security tool and we take correctness seriously.

---

*Every contribution makes the Python ecosystem a little safer. Thank you!* 🙏
