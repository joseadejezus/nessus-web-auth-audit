"""Static guards on packaging and the pure/impure module split.

These catch the two things that break a pipx install without any test
noticing: a console-script target that no longer resolves, and a
module-scope playwright import that makes the offline code paths
require a browser.
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "nwaa"

OFFLINE_MODULES = [
    "nwaa.models",
    "nwaa.nessus_parser",
    "nwaa.classifier",
    "nwaa.scope",
    "nwaa.report",
    "nwaa.html_report",
    "nwaa.redaction",
    "nwaa.logging_utils",
    "nwaa.credential_tester",
    "nwaa.fingerprint",
    "nwaa.default_creds",
    "nwaa.probe",
    "nwaa.browser",
    "nwaa.cli",
]


def test_console_script_target_resolves():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^nwaa\s*=\s*"([\w.]+):(\w+)"', text, re.MULTILINE)
    assert match, "pyproject.toml must declare the nwaa console script"

    module_name, func_name = match.groups()
    module = importlib.import_module(module_name)
    assert callable(getattr(module, func_name))


def test_runtime_dependencies_are_declared():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "defusedxml" in text
    assert "playwright" in text


def test_package_is_importable_without_a_browser():
    for name in OFFLINE_MODULES:
        importlib.import_module(name)


def test_no_module_scope_playwright_imports():
    """Playwright must only ever be imported inside a function body."""
    offenders = []
    for path in sorted(PACKAGE.glob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.match(r"^(import|from)\s+playwright", line):
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, f"module-scope playwright imports: {offenders}"


def test_default_credential_data_is_packaged():
    """The profiles live in a data file that must survive a wheel build."""
    assert (PACKAGE / "data" / "default_credentials.json").is_file()
    assert (PACKAGE / "data" / "__init__.py").is_file()
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"nwaa.data" = ["*.json"]' in text


def test_no_credentials_are_hardcoded_in_python_source():
    """Default credentials belong in the reviewable data file, nowhere else.

    A ``"password":`` key in Python source may only be followed by a
    ``<placeholder>`` (docstrings showing the credentials-file format).
    """
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r'"password"\s*:\s*"(?!<)', line):
                offenders.append(f"{path.name}:{lineno}")
    assert not offenders, f"credential literals in Python source: {offenders}"


def test_stdlib_xml_is_never_used():
    """.nessus parsing must go through defusedxml only."""
    offenders = []
    for path in sorted(PACKAGE.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if re.search(r"^\s*(import|from)\s+xml\.", text, re.MULTILINE):
            offenders.append(path.name)
    assert not offenders, f"stdlib xml imports found: {offenders}"
