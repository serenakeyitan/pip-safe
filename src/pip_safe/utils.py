"""Utility functions for pip-safe."""

from __future__ import annotations

import re
import tarfile
import tempfile
import zipfile
from pathlib import Path

import requests


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # j+1 instead of j since previous_row and current_row are one char longer than s2
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_package_name(name: str) -> str:
    """Normalize a PyPI package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def fetch_pypi_metadata(package: str, version: str | None = None) -> dict | None:
    """Fetch package metadata from PyPI JSON API."""
    if version:
        url = f"https://pypi.org/pypi/{package}/{version}/json"
    else:
        url = f"https://pypi.org/pypi/{package}/json"

    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        return None
    except requests.RequestException:
        return None


def download_package(package: str, version: str | None = None) -> Path | None:
    """Download the source distribution of a package to a temp directory."""
    meta = fetch_pypi_metadata(package, version)
    if not meta:
        return None

    urls = meta.get("urls", [])
    # prefer sdist, then wheel
    sdist_url = None
    wheel_url = None
    for u in urls:
        if u.get("packagetype") == "sdist":
            sdist_url = u["url"]
        elif u.get("packagetype") == "bdist_wheel" and wheel_url is None:
            wheel_url = u["url"]

    download_url = sdist_url or wheel_url
    if not download_url:
        return None

    tmpdir = Path(tempfile.mkdtemp(prefix="pip_safe_"))
    filename = download_url.split("/")[-1]
    dest = tmpdir / filename

    try:
        with requests.get(download_url, stream=True, timeout=30) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
    except requests.RequestException:
        return None

    return dest


def extract_package(archive_path: Path) -> Path | None:
    """Extract a .tar.gz or .whl archive and return the extraction directory."""
    extract_dir = archive_path.parent / "extracted"
    extract_dir.mkdir(exist_ok=True)

    name = archive_path.name
    try:
        if name.endswith(".tar.gz") or name.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(extract_dir)
        elif name.endswith(".whl") or name.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as z:
                z.extractall(extract_dir)
        else:
            return None
    except (tarfile.TarError, zipfile.BadZipFile, OSError):
        return None

    return extract_dir


def severity_color(severity: str) -> str:
    """Map severity to a rich color string."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }
    return colors.get(severity, "white")
