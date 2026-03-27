"""Click CLI entry point for pip-safe."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from pip_safe import __version__
from pip_safe.models import ScanResult, Severity
from pip_safe.scanner import scan_package
from pip_safe.utils import severity_color

console = Console()

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _severity_badge(severity: Severity) -> Text:
    """Return a colored severity badge as a Rich Text object."""
    color_map = {
        Severity.CRITICAL: "bold white on red",
        Severity.HIGH: "bold red",
        Severity.MEDIUM: "bold yellow",
        Severity.LOW: "bold blue",
        Severity.INFO: "dim",
    }
    return Text(f" {severity.value} ", style=color_map.get(severity, "white"))


def _score_color(score: int) -> str:
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    return "red"


def _print_scan_result(result: ScanResult, show_header: bool = True) -> None:
    """Pretty-print a ScanResult using Rich."""
    safe_str = "[green]SAFE[/green]" if result.safe else "[bold red]UNSAFE[/bold red]"
    score_color = _score_color(result.score)

    if show_header:
        title_text = (
            f"[bold]{result.package_name}[/bold] "
            f"[dim]v{result.version}[/dim]  —  {safe_str}"
        )
        console.print(Panel(title_text, expand=False))

    # Score bar
    bar_filled = int(result.score / 5)  # 20 segments for 100 points
    bar = f"[{score_color}]{'█' * bar_filled}[/{score_color}]{'░' * (20 - bar_filled)}"
    console.print(f"  Safety Score: {bar} [{score_color}]{result.score}/100[/{score_color}]")

    # Metadata
    if result.metadata.get("summary"):
        console.print(f"  [dim]{result.metadata['summary']}[/dim]")

    if not result.findings:
        console.print("\n  [green]✓ No security issues found.[/green]\n")
        return

    console.print()

    # Group findings by severity
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        sev_findings = [f for f in result.findings if f.severity == severity]
        if not sev_findings:
            continue

        color = severity_color(severity.value)
        console.print(f"  [{color}]{severity.value} ({len(sev_findings)})[/{color}]")

        for finding in sev_findings:
            badge = _severity_badge(finding.severity)
            console.print("    ", end="")
            console.print(badge, end="")
            console.print(f" [bold]{finding.title}[/bold]")
            console.print(f"      {finding.description}")
            if finding.evidence:
                console.print(f"      [dim]Evidence: {finding.evidence[:120]}[/dim]")
            console.print()


def _result_to_dict(result: ScanResult) -> dict:
    """Convert a ScanResult to a JSON-serializable dict."""
    return {
        "package_name": result.package_name,
        "version": result.version,
        "safe": result.safe,
        "score": result.score,
        "findings": [
            {
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
        "metadata": result.metadata,
    }


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(__version__, prog_name="pip-safe")
def cli() -> None:
    """pip-safe — PyPI package security scanner.

    Scan packages for supply chain attacks before installing them.
    """


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@cli.command("scan")
@click.argument("package")
@click.option("--version", "-v", default=None, help="Specific package version to scan.")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON.")
@click.option(
    "--no-behavioral",
    is_flag=True,
    help="Skip behavioral analysis (faster, but less thorough).",
)
def scan_cmd(package: str, version: str | None, output_json: bool, no_behavioral: bool) -> None:
    """Scan a PyPI package for security issues.

    Examples:\n
        pip-safe scan requests\n
        pip-safe scan numpy --version 1.24.0\n
        pip-safe scan suspicious-pkg --json\n
        pip-safe scan large-pkg --no-behavioral
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Scanning [bold]{package}[/bold]...", total=None)

        result = scan_package(
            package_name=package,
            version=version,
            skip_behavioral=no_behavioral,
        )
        progress.remove_task(task)

    if output_json:
        click.echo(json.dumps(_result_to_dict(result), indent=2))
    else:
        _print_scan_result(result)

    sys.exit(0 if result.safe else 1)


# ---------------------------------------------------------------------------
# install command
# ---------------------------------------------------------------------------


@cli.command("install")
@click.argument("packages", nargs=-1, required=True)
@click.option("--yes", "-y", is_flag=True, help="Auto-confirm installation of risky packages.")
@click.option("--force", is_flag=True, help="Force installation even if package is unsafe.")
@click.option(
    "--no-behavioral",
    is_flag=True,
    help="Skip behavioral analysis (faster, but less thorough).",
)
@click.option(
    "--pip-args",
    default="",
    help="Additional arguments to pass through to pip install.",
)
@click.option("--uv", is_flag=True, help="Use uv instead of pip for installation.")
def install_cmd(
    packages: tuple[str, ...],
    yes: bool,
    force: bool,
    no_behavioral: bool,
    pip_args: str,
    uv: bool,
) -> None:
    """Scan packages, then install safe ones via pip.

    Blocks unsafe packages unless --force is used.

    Examples:\n
        pip-safe install requests pandas\n
        pip-safe install some-pkg --yes\n
        pip-safe install risky-pkg --force
    """
    safe_packages: list[str] = []
    unsafe_packages: list[str] = []

    for package in packages:
        console.print(f"\n[bold]Scanning[/bold] [cyan]{package}[/cyan]...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"Analyzing {package}...", total=None)
            result = scan_package(package_name=package, skip_behavioral=no_behavioral)
            progress.remove_task(task)

        _print_scan_result(result, show_header=True)

        if result.safe:
            safe_packages.append(package)
        else:
            if force:
                console.print(
                    f"[yellow]⚠ {package} is UNSAFE but --force is set. Installing anyway.[/yellow]"
                )
                safe_packages.append(package)
            elif yes:
                console.print(
                    f"[yellow]⚠ {package} is UNSAFE. Skipping (use --force to override).[/yellow]"
                )
                unsafe_packages.append(package)
            else:
                if click.confirm(
                    f"\n[bold red]{package}[/bold red] is UNSAFE (score {result.score}/100). Install anyway?",
                    default=False,
                ):
                    safe_packages.append(package)
                else:
                    unsafe_packages.append(package)

    if unsafe_packages:
        console.print(
            f"\n[bold red]Blocked {len(unsafe_packages)} unsafe package(s):[/bold red] "
            + ", ".join(unsafe_packages)
        )

    if safe_packages:
        if uv:
            pip_cmd = ["uv", "pip", "install"] + list(safe_packages)
        else:
            pip_cmd = [sys.executable, "-m", "pip", "install"] + list(safe_packages)
        if pip_args:
            pip_cmd.extend(pip_args.split())

        console.print(f"\n[green]Installing:[/green] {' '.join(safe_packages)}")
        console.print(f"[dim]Running: {' '.join(pip_cmd)}[/dim]\n")

        result_proc = subprocess.run(pip_cmd)
        sys.exit(result_proc.returncode)

    if unsafe_packages:
        sys.exit(1)


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------


@cli.command("audit")
@click.option(
    "--requirements",
    "-r",
    default="requirements.txt",
    show_default=True,
    help="Path to requirements file to audit.",
)
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON.")
@click.option(
    "--no-behavioral",
    is_flag=True,
    help="Skip behavioral analysis (faster, but less thorough).",
)
def audit_cmd(requirements: str, output_json: bool, no_behavioral: bool) -> None:
    """Audit all packages in a requirements file.

    Examples:\n
        pip-safe audit\n
        pip-safe audit --requirements requirements-dev.txt\n
        pip-safe audit --json > audit-report.json
    """
    req_path = Path(requirements)
    if not req_path.exists():
        console.print(f"[red]Error:[/red] Requirements file not found: {requirements}")
        sys.exit(1)

    packages = _parse_requirements(req_path)
    if not packages:
        if not output_json:
            console.print(f"[yellow]No packages found in {requirements}[/yellow]")
        return

    if not output_json:
        console.print(f"\n[bold]Auditing {len(packages)} package(s) from[/bold] {requirements}\n")

    results: list[ScanResult] = []
    failed = 0

    if output_json:
        # In JSON mode: scan without progress display
        for pkg_name, pkg_version in packages:
            result = scan_package(
                package_name=pkg_name,
                version=pkg_version,
                skip_behavioral=no_behavioral,
            )
            results.append(result)
            if not result.safe:
                failed += 1
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning packages...", total=len(packages))

            for pkg_name, pkg_version in packages:
                progress.update(task, description=f"Scanning [cyan]{pkg_name}[/cyan]...")
                result = scan_package(
                    package_name=pkg_name,
                    version=pkg_version,
                    skip_behavioral=no_behavioral,
                )
                results.append(result)
                if not result.safe:
                    failed += 1
                progress.advance(task)

    if output_json:
        click.echo(json.dumps([_result_to_dict(r) for r in results], indent=2))
        sys.exit(1 if failed > 0 else 0)

    # Print summary table
    _print_audit_table(results)

    if failed > 0:
        console.print(f"\n[bold red]✗ {failed} unsafe package(s) found.[/bold red]")
        sys.exit(1)
    else:
        console.print(f"\n[bold green]✓ All {len(results)} packages passed security checks.[/bold green]")


def _parse_requirements(path: Path) -> list[tuple[str, str | None]]:
    """Parse a requirements.txt file into (name, version) tuples."""
    packages = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle ==, >=, <=, ~=, !=
        for op in ("==", ">=", "<=", "~=", "!=", ">", "<"):
            if op in line:
                name, ver_part = line.split(op, 1)
                name = name.strip()
                ver_part = ver_part.strip().split(",")[0].strip()  # take first version spec
                if op == "==":
                    packages.append((name, ver_part))
                else:
                    packages.append((name, None))
                break
        else:
            packages.append((line.strip(), None))
    return packages


def _print_audit_table(results: list[ScanResult]) -> None:
    """Print a summary table of audit results."""
    table = Table(
        title="Audit Results",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="dim")
    table.add_column("Score", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Critical", justify="center")
    table.add_column("High", justify="center")
    table.add_column("Medium", justify="center")
    table.add_column("Issues", style="dim")

    for result in sorted(results, key=lambda r: r.score):
        counts = result.severity_counts()
        status = "[green]SAFE[/green]" if result.safe else "[bold red]UNSAFE[/bold red]"
        score_color = _score_color(result.score)

        top_issue = ""
        for finding in result.findings:
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                top_issue = finding.title[:40]
                break

        table.add_row(
            result.package_name,
            result.version,
            f"[{score_color}]{result.score}[/{score_color}]",
            status,
            f"[red]{counts['CRITICAL']}[/red]" if counts["CRITICAL"] else "0",
            f"[yellow]{counts['HIGH']}[/yellow]" if counts["HIGH"] else "0",
            str(counts["MEDIUM"]) if counts["MEDIUM"] else "0",
            top_issue,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# check-env command
# ---------------------------------------------------------------------------


@cli.command("check-env")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON.")
def check_env_cmd(output_json: bool) -> None:
    """Scan all installed packages for known malicious ones.

    Uses importlib.metadata to enumerate the current environment.

    Examples:\n
        pip-safe check-env\n
        pip-safe check-env --json
    """
    try:
        import importlib.metadata as importlib_metadata
    except ImportError:
        import importlib_metadata  # type: ignore[no-reuse-source]

    from pip_safe.analyzers import database as db_analyzer
    from pip_safe.analyzers import typosquatting as typo_analyzer

    installed = {
        dist.metadata["Name"]: dist.metadata["Version"]
        for dist in importlib_metadata.distributions()
        if dist.metadata.get("Name")
    }

    console.print(f"\n[bold]Checking {len(installed)} installed package(s)...[/bold]\n")

    flagged: list[dict] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Checking packages...", total=len(installed))

        for pkg_name, pkg_version in installed.items():
            db_findings = db_analyzer.analyze(pkg_name)
            typo_findings = typo_analyzer.analyze(pkg_name)
            all_findings = db_findings + typo_findings

            if all_findings:
                flagged.append(
                    {
                        "name": pkg_name,
                        "version": pkg_version,
                        "findings": all_findings,
                    }
                )

            progress.advance(task)

    if output_json:
        output = [
            {
                "package_name": item["name"],
                "version": item["version"],
                "findings": [
                    {
                        "severity": f.severity.value,
                        "title": f.title,
                        "description": f.description,
                    }
                    for f in item["findings"]
                ],
            }
            for item in flagged
        ]
        click.echo(json.dumps(output, indent=2))
        sys.exit(1 if flagged else 0)

    if not flagged:
        console.print(
            f"[bold green]✓ All {len(installed)} installed packages passed checks.[/bold green]"
        )
        return

    console.print(f"[bold red]✗ {len(flagged)} suspicious package(s) found:[/bold red]\n")

    for item in flagged:
        console.print(
            f"  [bold cyan]{item['name']}[/bold cyan] [dim]v{item['version']}[/dim]"
        )
        for finding in item["findings"]:
            badge = _severity_badge(finding.severity)
            console.print("    ", end="")
            console.print(badge, end="")
            console.print(f" {finding.title}")
            console.print(f"      [dim]{finding.description[:100]}[/dim]")
        console.print()

    sys.exit(1)


if __name__ == "__main__":
    cli()
