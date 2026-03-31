"""Typosquatting detection analyzer."""

from __future__ import annotations

from pip_safe.models import Finding, Severity
from pip_safe.utils import levenshtein_distance, normalize_package_name

# Top 100 popular packages that are frequent targets for typosquatting
POPULAR_PACKAGES = [
    "numpy",
    "pandas",
    "requests",
    "pip",
    "setuptools",
    "boto3",
    "urllib3",
    "botocore",
    "s3transfer",
    "six",
    "python-dateutil",
    "certifi",
    "charset-normalizer",
    "idna",
    "packaging",
    "cryptography",
    "pydantic",
    "fastapi",
    "django",
    "flask",
    "tensorflow",
    "torch",
    "scikit-learn",
    "scipy",
    "matplotlib",
    "pillow",
    "sqlalchemy",
    "click",
    "rich",
    "pytest",
    "black",
    "mypy",
    "ruff",
    "uvicorn",
    "httpx",
    "aiohttp",
    "celery",
    "redis",
    "psycopg2",
    "pymongo",
    "openai",
    "anthropic",
    "langchain",
    "litellm",
    "transformers",
    "huggingface-hub",
    "datasets",
    "accelerate",
    "diffusers",
    "tokenizers",
    "tqdm",
    "pyyaml",
    "toml",
    "dotenv",
    "python-dotenv",
    "paramiko",
    "fabric",
    "ansible",
    "kubernetes",
    "docker",
    "boto",
    "google-cloud-storage",
    "azure-storage-blob",
    "stripe",
    "twilio",
    "sendgrid",
    "jwt",
    "bcrypt",
    "passlib",
    "itsdangerous",
    "werkzeug",
    "jinja2",
    "marshmallow",
    "attrs",
    "cattrs",
    "trio",
    "anyio",
    "websockets",
    "grpcio",
    "protobuf",
    "avro",
    "kafka-python",
    "pika",
    "nats-py",
    "arrow",
    "pendulum",
    "pytz",
    "dateparser",
    "lxml",
    "beautifulsoup4",
    "selenium",
    "playwright",
    "scrapy",
    "httplib2",
    "pygments",
    "colorama",
    "termcolor",
    "loguru",
    "structlog",
    "sentry-sdk",
    "datadog",
    "prometheus-client",
    "opentelemetry-api",
]

# Normalized lookup set for fast membership testing
_POPULAR_NORMALIZED = {normalize_package_name(p): p for p in POPULAR_PACKAGES}

# Maximum Levenshtein distance to flag as suspicious
TYPOSQUAT_DISTANCE_THRESHOLD = 2


def analyze(package_name: str) -> list[Finding]:
    """Check if a package name is suspiciously similar to a popular package."""
    findings: list[Finding] = []
    normalized = normalize_package_name(package_name)

    # Exact match against popular packages — this is legitimate, not a typosquat
    if normalized in _POPULAR_NORMALIZED:
        return findings

    # Compare against each popular package using Levenshtein distance
    for popular_normalized, popular_original in _POPULAR_NORMALIZED.items():
        # Skip if the names are very different in length (optimization)
        len_diff = abs(len(normalized) - len(popular_normalized))
        if len_diff > TYPOSQUAT_DISTANCE_THRESHOLD + 1:
            continue

        dist = levenshtein_distance(normalized, popular_normalized)
        if 0 < dist <= TYPOSQUAT_DISTANCE_THRESHOLD:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Potential Typosquatting Detected",
                    description=(
                        f"Package '{package_name}' is suspiciously similar to the popular "
                        f"package '{popular_original}' (edit distance: {dist}). "
                        "This may be a typosquatting attack designed to trick developers "
                        "who mistype package names."
                    ),
                    evidence=(
                        f"'{normalized}' vs '{popular_normalized}' — "
                        f"Levenshtein distance: {dist}"
                    ),
                )
            )

    # Also check for common obfuscation patterns
    findings.extend(_check_common_patterns(package_name, normalized))

    return findings


def _check_common_patterns(package_name: str, normalized: str) -> list[Finding]:
    """Check for known obfuscation patterns beyond simple edit distance."""
    findings: list[Finding] = []

    # Check for numeric substitutions (e.g., "req uests" -> "requ3sts")
    digitless = normalized.replace("0", "o").replace("1", "l").replace("3", "e").replace("4", "a")
    if digitless != normalized and digitless in _POPULAR_NORMALIZED:
        original = _POPULAR_NORMALIZED[digitless]
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="Numeric Substitution Typosquat",
                description=(
                    f"Package '{package_name}' appears to use numeric character substitution "
                    f"to impersonate '{original}'. This is a common obfuscation technique "
                    "used in supply chain attacks."
                ),
                evidence=f"'{normalized}' with digits replaced -> '{digitless}' matches '{original}'",
            )
        )

    # Check for hyphen/underscore confusion with popular packages
    dehyphenated = normalized.replace("-", "").replace("_", "")
    for popular_normalized, popular_original in _POPULAR_NORMALIZED.items():
        popular_dehyphenated = popular_normalized.replace("-", "").replace("_", "")
        if (
            dehyphenated == popular_dehyphenated
            and normalized != popular_normalized
            and dehyphenated != normalized  # only if separators were actually removed
        ):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="Separator Confusion Typosquat",
                    description=(
                        f"Package '{package_name}' differs from '{popular_original}' only "
                        "in hyphen/underscore usage. Some tools normalize these, but this "
                        "could indicate a deliberate attempt at confusion."
                    ),
                    evidence=(
                        f"'{normalized}' and '{popular_normalized}' both reduce to "
                        f"'{dehyphenated}' when separators are removed"
                    ),
                )
            )
            break

    return findings


def get_closest_popular_package(package_name: str) -> tuple[str, int] | None:
    """Return the closest popular package and its distance, or None if package is popular."""
    normalized = normalize_package_name(package_name)
    if normalized in _POPULAR_NORMALIZED:
        return None

    best_match = None
    best_dist = float("inf")
    for popular_normalized, popular_original in _POPULAR_NORMALIZED.items():
        dist = levenshtein_distance(normalized, popular_normalized)
        if dist < best_dist:
            best_dist = dist
            best_match = popular_original

    if best_match and best_dist <= 5:
        return best_match, int(best_dist)
    return None
