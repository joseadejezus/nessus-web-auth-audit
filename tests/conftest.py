from __future__ import annotations

from pathlib import Path

import pytest

from nwaa.classifier import identify_login_pages
from nwaa.nessus_parser import parse_nessus_file
from nwaa.redaction import clear_registered_secrets

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _reset_secret_registry():
    clear_registered_secrets()
    yield
    clear_registered_secrets()


@pytest.fixture
def sample_nessus_path() -> Path:
    return FIXTURES / "sample.nessus"


@pytest.fixture
def malicious_nessus_path() -> Path:
    return FIXTURES / "malicious_xxe.nessus"


@pytest.fixture
def devices_nessus_path() -> Path:
    return FIXTURES / "devices.nessus"


@pytest.fixture
def sample_scan(sample_nessus_path: Path):
    return parse_nessus_file(sample_nessus_path)


@pytest.fixture
def devices_scan(devices_nessus_path: Path):
    return parse_nessus_file(devices_nessus_path)


@pytest.fixture
def sample_login_pages(sample_scan):
    return identify_login_pages(sample_scan)
