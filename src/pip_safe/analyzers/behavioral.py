"""Behavioral static AST analysis for supply chain attack patterns."""

from __future__ import annotations

import ast
import base64
import re
import shutil
import tempfile
from pathlib import Path
from typing import NamedTuple

from pip_safe.models import Finding, Severity
from pip_safe.utils import download_package, extract_package

# ---------------------------------------------------------------------------
# Patterns to detect in source code
# ---------------------------------------------------------------------------

# Subprocess shell commands that suggest network activity or shell spawning
DANGEROUS_SUBPROCESS_ARGS = re.compile(
    r"\b(curl|wget|nc|netcat|bash\s+-c|sh\s+-c|powershell|ncat|socat)\b",
    re.IGNORECASE,
)

# Credential-related environment variable names
CREDENTIAL_ENV_PATTERN = re.compile(
    r"\b(SECRET|KEY|TOKEN|PASSWORD|PASSWD|API_KEY|AWS_|GCP_|AZURE_|GITHUB_|PRIVATE)\b",
    re.IGNORECASE,
)

# Sensitive filesystem paths
SENSITIVE_PATH_PATTERN = re.compile(
    r"(~/\.ssh|~/\.aws|~/\.kube|~/\.gnupg|/etc/passwd|/etc/shadow"
    r"|\.ssh/id_rsa|\.ssh/id_ed25519|\.ssh/authorized_keys"
    r"|\.aws/credentials|\.aws/config"
    r"|\.kube/config)",
    re.IGNORECASE,
)

# Base64-encoded strings that look like URLs or shell commands
BASE64_URL_PATTERN = re.compile(r"^(https?://|curl |wget |bash |sh )", re.IGNORECASE)

# DNS exfiltration: encoding data in DNS subdomains
DNS_EXFIL_PATTERN = re.compile(
    r"(socket\.getaddrinfo|socket\.gethostbyname|dns\.(resolver|query))",
    re.IGNORECASE,
)


class ASTContext(NamedTuple):
    filepath: Path
    source: str
    tree: ast.AST


def _load_ast(filepath: Path) -> ASTContext | None:
    """Parse a Python file into an AST context."""
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
        return ASTContext(filepath=filepath, source=source, tree=tree)
    except (SyntaxError, OSError):
        return None


def _get_node_source(ctx: ASTContext, node: ast.AST) -> str:
    """Extract source lines around an AST node for evidence."""
    try:
        lines = ctx.source.splitlines()
        lineno = getattr(node, "lineno", 1)
        start = max(0, lineno - 2)
        end = min(len(lines), lineno + 1)
        snippet = "\n".join(lines[start:end])
        return f"line {lineno}: {snippet.strip()}"
    except Exception:
        return ""


def _node_is_at_module_level(node: ast.AST, tree: ast.AST) -> bool:
    """Check if a node is directly in the module body (not inside a function/class)."""
    for child in ast.walk(tree):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for descendant in ast.walk(child):
                if descendant is node:
                    return False
    return True


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def _check_obfuscation(ctx: ASTContext) -> list[Finding]:
    """Detect eval/exec with non-literal arguments, and base64-encoded payloads."""
    findings: list[Finding] = []

    for node in ast.walk(ctx.tree):
        # eval() or exec() with a non-constant argument
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in ("eval", "exec") and node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant):
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            title="Dynamic Code Execution (eval/exec)",
                            description=(
                                f"Found `{func_name}()` called with a non-literal argument in "
                                f"{ctx.filepath.name}. This is a common technique to execute "
                                "obfuscated or remotely-fetched malicious code."
                            ),
                            evidence=_get_node_source(ctx, node),
                        )
                    )

        # Base64-encoded strings that decode to URLs or commands
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value.strip()
            # Must look like a base64 string (length divisible by 4 after padding, only b64 chars)
            if len(val) >= 20 and re.match(r"^[A-Za-z0-9+/=]+$", val):
                try:
                    # Pad if needed
                    padding = 4 - len(val) % 4
                    padded = val + ("=" * (padding % 4))
                    decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                    if BASE64_URL_PATTERN.search(decoded):
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                title="Base64-Encoded Command or URL",
                                description=(
                                    f"Found a base64-encoded string in {ctx.filepath.name} "
                                    "that decodes to a URL or shell command. This is often "
                                    "used to hide malicious network calls or code execution."
                                ),
                                evidence=(
                                    f"Encoded: '{val[:60]}...' "
                                    f"Decoded: '{decoded[:80]}'"
                                ),
                            )
                        )
                except Exception:
                    pass

    return findings


def _check_subprocess_calls(ctx: ASTContext) -> list[Finding]:
    """Detect subprocess calls with network-related commands."""
    findings: list[Finding] = []

    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue

        # Match subprocess.run, subprocess.call, subprocess.Popen, os.system, os.popen
        is_subprocess = False
        call_repr = ""

        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in ("subprocess", "os")
                and node.func.attr in ("run", "call", "Popen", "check_output", "system", "popen")
            ):
                is_subprocess = True
                call_repr = f"{node.func.value.id}.{node.func.attr}"
        elif isinstance(node.func, ast.Name) and node.func.id in ("system", "popen"):
            is_subprocess = True
            call_repr = node.func.id

        if not is_subprocess:
            continue

        # Check arguments for dangerous patterns
        evidence = _get_node_source(ctx, node)
        source_fragment = ctx.source[
            max(0, getattr(node, "col_offset", 0) - 5) : getattr(node, "col_offset", 0) + 200
        ]

        if DANGEROUS_SUBPROCESS_ARGS.search(evidence) or DANGEROUS_SUBPROCESS_ARGS.search(
            source_fragment
        ):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title="Suspicious Subprocess with Network Command",
                    description=(
                        f"Found `{call_repr}()` call with a network-related command "
                        f"(curl, wget, nc, etc.) in {ctx.filepath.name}. "
                        "This pattern is used to download and execute malicious payloads."
                    ),
                    evidence=evidence,
                )
            )
        elif _node_is_at_module_level(node, ctx.tree):
            # Any subprocess at module level (runs on import) is suspicious
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Subprocess Call at Module Level",
                    description=(
                        f"Found `{call_repr}()` executing at module import level in "
                        f"{ctx.filepath.name}. Code that runs shell commands on import "
                        "can execute arbitrary commands when the package is installed."
                    ),
                    evidence=evidence,
                )
            )

    return findings


def _check_network_at_import(ctx: ASTContext) -> list[Finding]:
    """Detect network calls (urllib, requests, httpx, socket) at module level."""
    findings: list[Finding] = []

    network_modules = {"urllib", "requests", "httpx", "socket", "http", "ftplib", "smtplib"}
    network_attrs = {"get", "post", "put", "delete", "request", "urlopen", "connect", "send"}

    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        if not _node_is_at_module_level(node, ctx.tree):
            continue

        func = node.func
        is_network = False
        call_desc = ""

        if isinstance(func, ast.Attribute):
            # requests.get(), socket.connect(), etc.
            if isinstance(func.value, ast.Name) and func.value.id in network_modules:
                if func.attr in network_attrs:
                    is_network = True
                    call_desc = f"{func.value.id}.{func.attr}"
            # urllib.request.urlopen()
            elif isinstance(func.value, ast.Attribute):
                if (
                    isinstance(func.value.value, ast.Name)
                    and func.value.value.id in network_modules
                ):
                    is_network = True
                    call_desc = f"{func.value.value.id}.{func.value.attr}.{func.attr}"
        elif isinstance(func, ast.Name) and func.id in ("urlopen", "urlretrieve"):
            is_network = True
            call_desc = func.id

        if is_network:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Network Call at Module Import Level",
                    description=(
                        f"Found network call `{call_desc}()` at module import level in "
                        f"{ctx.filepath.name}. Making network requests during import can "
                        "be used to exfiltrate data or download malicious code."
                    ),
                    evidence=_get_node_source(ctx, node),
                )
            )

    return findings


def _check_credential_access(ctx: ASTContext) -> list[Finding]:
    """Detect reading of sensitive files or credential-related environment variables."""
    findings: list[Finding] = []

    source = ctx.source

    # Check for sensitive path strings in the source
    for match in SENSITIVE_PATH_PATTERN.finditer(source):
        lineno = source[: match.start()].count("\n") + 1
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                title="Access to Sensitive Credential Files",
                description=(
                    f"Found reference to sensitive credential path '{match.group()}' in "
                    f"{ctx.filepath.name}. Reading SSH keys, AWS credentials, or kubeconfig "
                    "files is a hallmark of credential-stealing malware."
                ),
                evidence=f"line {lineno}: ...{source[max(0,match.start()-30):match.end()+30]}...",
            )
        )

    # Check for os.environ access combined with credential-related key names
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue

        # os.environ.get("SECRET_KEY") or os.getenv("TOKEN")
        func = node.func
        is_env_access = False
        if isinstance(func, ast.Attribute):
            if func.attr in ("get", "getenv") and isinstance(func.value, ast.Attribute):
                if (
                    isinstance(func.value.value, ast.Name)
                    and func.value.value.id == "os"
                    and func.value.attr == "environ"
                ):
                    is_env_access = True
            elif func.attr == "getenv" and isinstance(func.value, ast.Name):
                if func.value.id == "os":
                    is_env_access = True

        if is_env_access and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                if CREDENTIAL_ENV_PATTERN.search(first_arg.value):
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="Credential Environment Variable Access",
                            description=(
                                f"Found access to credential-related environment variable "
                                f"'{first_arg.value}' in {ctx.filepath.name}. "
                                "Packages that read credential env vars during install "
                                "may be attempting to exfiltrate secrets."
                            ),
                            evidence=_get_node_source(ctx, node),
                        )
                    )

    return findings


def _check_filesystem_crawling(ctx: ASTContext) -> list[Finding]:
    """Detect os.walk or glob with home directory paths."""
    findings: list[Finding] = []

    home_dir_patterns = re.compile(
        r"(os\.path\.expanduser\s*\(\s*['\"]~|Path\s*\(\s*['\"]~|os\.environ\s*\[\s*['\"]HOME)"
    )

    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        is_walk_or_glob = False
        call_name = ""

        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                if func.value.id == "os" and func.attr == "walk":
                    is_walk_or_glob = True
                    call_name = "os.walk"
                elif func.value.id == "glob" and func.attr in ("glob", "iglob"):
                    is_walk_or_glob = True
                    call_name = f"glob.{func.attr}"
        elif isinstance(func, ast.Name) and func.id in ("glob", "walk"):
            is_walk_or_glob = True
            call_name = func.id

        if not is_walk_or_glob:
            continue

        evidence = _get_node_source(ctx, node)
        if home_dir_patterns.search(evidence) or home_dir_patterns.search(ctx.source):
            # More targeted: check if the argument mentions home-like paths
            source_around = ctx.source[
                max(0, getattr(node, "lineno", 1) * 80 - 200) : getattr(node, "lineno", 1) * 80
                + 200
            ]
            if re.search(r"~|home|HOME|expanduser", evidence + source_around, re.IGNORECASE):
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title="Filesystem Crawling of Home Directory",
                        description=(
                            f"Found `{call_name}()` with apparent home directory traversal in "
                            f"{ctx.filepath.name}. Crawling user home directories is a common "
                            "technique to locate and exfiltrate credential files."
                        ),
                        evidence=evidence,
                    )
                )

    return findings


def _check_dns_exfiltration(ctx: ASTContext) -> list[Finding]:
    """Detect DNS-based data exfiltration patterns."""
    findings: list[Finding] = []

    if DNS_EXFIL_PATTERN.search(ctx.source):
        # Look more carefully: DNS + base64/encode suggests exfil
        if re.search(r"(encode|b64|base64|hex)", ctx.source, re.IGNORECASE):
            for node in ast.walk(ctx.tree):
                if not isinstance(node, ast.Call):
                    continue
                call_str = ast.unparse(node) if hasattr(ast, "unparse") else ""
                if DNS_EXFIL_PATTERN.search(call_str) and re.search(
                    r"(encode|b64|hex)", call_str
                ):
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            title="DNS-Based Data Exfiltration Pattern",
                            description=(
                                f"Found DNS lookup combined with encoding in {ctx.filepath.name}. "
                                "This pattern encodes stolen data (credentials, env vars) into "
                                "DNS queries to bypass network monitoring."
                            ),
                            evidence=_get_node_source(ctx, node),
                        )
                    )
                    break

    return findings


def _check_setup_py(setup_path: Path) -> list[Finding]:
    """Check setup.py for install-time execution of malicious code."""
    findings: list[Finding] = []
    ctx = _load_ast(setup_path)
    if not ctx:
        return findings

    source = ctx.source

    # Check for custom install commands that execute code
    if re.search(r"class\s+\w*(Install|Build|Develop)\w*\s*\(", source):
        if re.search(
            r"(subprocess|os\.system|urllib|requests|httpx|socket|eval|exec)", source
        ):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title="Malicious Custom Install Command in setup.py",
                    description=(
                        "setup.py defines a custom install/build command class that "
                        "calls subprocess, network, or eval functions. This executes "
                        "arbitrary code when the package is installed via pip."
                    ),
                    evidence=f"setup.py contains custom cmdclass with dangerous function calls",
                )
            )

    # Check for direct calls outside of if __name__ == '__main__' guard
    dangerous_calls = re.findall(
        r"(subprocess\.\w+|os\.system|urllib\.\w+|requests\.\w+|eval\s*\(|exec\s*\()",
        source,
    )
    if dangerous_calls:
        # Check if they're at module level (not guarded)
        for node in ast.walk(ctx.tree):
            if isinstance(node, ast.Call):
                lineno = getattr(node, "lineno", 0)
                call_str = ast.unparse(node) if hasattr(ast, "unparse") else ""
                if re.search(
                    r"subprocess\.|os\.system|eval|exec", call_str
                ) and _node_is_at_module_level(node, ctx.tree):
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            title="Code Execution in setup.py at Install Time",
                            description=(
                                "setup.py runs code at the module level (outside of functions "
                                "or __main__ guard) that executes system commands or evaluates "
                                "code. This runs automatically when pip processes the package."
                            ),
                            evidence=_get_node_source(ctx, node),
                        )
                    )
                    break

    # Check for post_install hooks
    if re.search(r"post_install|post-install|after_install", source, re.IGNORECASE):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Post-Install Hook Detected in setup.py",
                description=(
                    "setup.py references a post-install hook. While sometimes legitimate, "
                    "post-install scripts have been abused in supply chain attacks to run "
                    "malicious code after pip completes the installation."
                ),
                evidence="setup.py contains 'post_install' / 'after_install' reference",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def analyze(package_name: str, version: str | None = None) -> list[Finding]:
    """Download and statically analyze a package for behavioral indicators."""
    findings: list[Finding] = []
    tmpdir = None

    try:
        archive = download_package(package_name, version)
        if archive is None:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Behavioral Analysis Skipped",
                    description=(
                        f"Could not download package '{package_name}' for behavioral analysis. "
                        "The package may not exist on PyPI or may have no downloadable files."
                    ),
                    evidence="",
                )
            )
            return findings

        tmpdir = archive.parent
        extract_dir = extract_package(archive)
        if extract_dir is None:
            return findings

        # Collect all Python files
        py_files = list(extract_dir.rglob("*.py"))

        # Separately handle setup.py
        setup_files = [f for f in py_files if f.name in ("setup.py", "setup.cfg")]
        other_py_files = [f for f in py_files if f not in setup_files]

        for setup_file in setup_files:
            if setup_file.suffix == ".py":
                findings.extend(_check_setup_py(setup_file))

        # Run all checks on every Python file
        for py_file in py_files:
            ctx = _load_ast(py_file)
            if not ctx:
                continue

            findings.extend(_check_obfuscation(ctx))
            findings.extend(_check_subprocess_calls(ctx))
            findings.extend(_check_network_at_import(ctx))
            findings.extend(_check_credential_access(ctx))
            findings.extend(_check_filesystem_crawling(ctx))
            findings.extend(_check_dns_exfiltration(ctx))

    finally:
        if tmpdir and tmpdir.exists():
            try:
                shutil.rmtree(tmpdir)
            except OSError:
                pass

    return findings


def analyze_directory(directory: Path) -> list[Finding]:
    """Run behavioral analysis on an already-extracted package directory."""
    findings: list[Finding] = []

    py_files = list(directory.rglob("*.py"))

    for py_file in py_files:
        if py_file.name == "setup.py":
            findings.extend(_check_setup_py(py_file))

    for py_file in py_files:
        ctx = _load_ast(py_file)
        if not ctx:
            continue
        findings.extend(_check_obfuscation(ctx))
        findings.extend(_check_subprocess_calls(ctx))
        findings.extend(_check_network_at_import(ctx))
        findings.extend(_check_credential_access(ctx))
        findings.extend(_check_filesystem_crawling(ctx))
        findings.extend(_check_dns_exfiltration(ctx))

    return findings
