from __future__ import annotations

import json
from datetime import datetime, timezone

from nwaa.models import AttemptVerdict, CredentialAttempt, ScanResult, ScreenshotResult
from nwaa.redaction import register_secret
from nwaa.report import build_json_report, render_text_report, write_json_report, write_text_report


def _result(sample_scan, sample_login_pages, attempts=None, screenshots=None):
    return ScanResult(
        nessus_file=sample_scan.source_path,
        generated_at=datetime.now(timezone.utc).isoformat(),
        services=list(sample_scan.services),
        login_pages=list(sample_login_pages),
        attempts=attempts or [],
        screenshots=screenshots or [],
    )


def test_summary_counts(sample_scan, sample_login_pages):
    data = build_json_report(_result(sample_scan, sample_login_pages))
    assert data["summary"]["web_services"] == 3
    assert data["summary"]["plaintext_http_services"] == 2
    assert data["summary"]["tls_web_services"] == 1
    assert data["summary"]["login_pages"] == 2


def test_login_pages_record_transport_and_plaintext_flag(sample_scan, sample_login_pages):
    data = build_json_report(_result(sample_scan, sample_login_pages))
    by_url = {p["url"]: p for p in data["login_pages"]}
    assert by_url["http://10.10.10.5/login.php"]["plaintext_transmission"] is True
    assert by_url["http://10.10.10.5/login.php"]["transport"] == "http"
    assert by_url["https://10.10.10.9/admin/login"]["plaintext_transmission"] is False
    assert by_url["https://10.10.10.9/admin/login"]["transport"] == "https"


def test_attempt_verdicts_are_counted(sample_scan, sample_login_pages):
    attempts = [
        CredentialAttempt(
            login_page=sample_login_pages[0],
            username="admin",
            credential_label="vendor-default",
            verdict=AttemptVerdict.SUCCESS,
            detail="ok",
        ),
        CredentialAttempt(
            login_page=sample_login_pages[1],
            username="admin",
            credential_label="vendor-default",
            verdict=AttemptVerdict.FAILED,
            detail="nope",
        ),
    ]
    data = build_json_report(_result(sample_scan, sample_login_pages, attempts=attempts))
    assert data["summary"]["attempts_by_verdict"] == {
        "default_credentials_successful": 1,
        "authentication_failed": 1,
    }


def test_reports_never_contain_a_password(sample_scan, sample_login_pages, tmp_path):
    register_secret("leaky-password")
    attempts = [
        CredentialAttempt(
            login_page=sample_login_pages[0],
            username="admin",
            credential_label="vendor-default",
            verdict=AttemptVerdict.FAILED,
            detail="submitted leaky-password to the form",
        )
    ]
    result = _result(sample_scan, sample_login_pages, attempts=attempts)

    json_path = write_json_report(result, tmp_path / "report.json")
    text_path = write_text_report(result, tmp_path / "report.txt")

    assert "leaky-password" not in json_path.read_text(encoding="utf-8")
    assert "leaky-password" not in text_path.read_text(encoding="utf-8")
    assert "***REDACTED***" in json_path.read_text(encoding="utf-8")


def test_json_report_is_serializable(sample_scan, sample_login_pages):
    data = build_json_report(_result(sample_scan, sample_login_pages))
    assert json.loads(json.dumps(data))["tool"] == "nwaa"


def test_text_report_contains_key_sections(sample_scan, sample_login_pages):
    screenshots = [
        ScreenshotResult(login_page=sample_login_pages[0], path="/tmp/a.png", success=True),
        ScreenshotResult(login_page=sample_login_pages[1], path=None, success=False, error="timeout"),
    ]
    text = render_text_report(_result(sample_scan, sample_login_pages, screenshots=screenshots))
    assert "PLAINTEXT HTTP SERVICES" in text
    assert "LOGIN PAGES" in text
    assert "SCREENSHOTS" in text
    assert "CREDENTIAL ATTEMPTS" in text
    assert "http://10.10.10.5/login.php" in text
    assert "FAIL" in text
