from __future__ import annotations

import base64
import re
from datetime import datetime, timezone

from nwaa.classifier import identify_login_pages
from nwaa.fingerprint import fingerprint_services
from nwaa.html_report import build_html_report, write_html_report
from nwaa.models import AttemptVerdict, CredentialAttempt, ScanResult, ScreenshotResult
from nwaa.redaction import register_secret
from nwaa.report import build_json_report

# 1x1 transparent PNG
TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def _report(sample_scan, sample_login_pages, **kwargs):
    result = ScanResult(
        nessus_file=sample_scan.source_path,
        generated_at=datetime.now(timezone.utc).isoformat(),
        services=list(sample_scan.services),
        login_pages=list(sample_login_pages),
        **kwargs,
    )
    return build_json_report(result)


def test_html_is_a_complete_standalone_document(sample_scan, sample_login_pages):
    html = build_html_report(_report(sample_scan, sample_login_pages))
    assert html.startswith("<!doctype html>")
    assert "</html>" in html
    assert "<style>" in html and "<script>" in html


def test_html_has_no_external_resources(sample_scan, sample_login_pages):
    """The viewer must open from file:// with no network access."""
    html = build_html_report(_report(sample_scan, sample_login_pages))
    for pattern in ('src="http', "src='http", 'href="http', "@import", "cdn."):
        assert pattern not in html


def test_report_data_is_embedded_for_the_viewer(sample_scan, sample_login_pages):
    html = build_html_report(_report(sample_scan, sample_login_pages))
    assert '<script type="application/json" id="nwaa-data">' in html
    assert "10.10.10.5" in html


def test_untrusted_values_cannot_break_out_of_the_data_script(sample_scan, sample_login_pages):
    report = _report(sample_scan, sample_login_pages)
    report["login_pages"][0]["url"] = "http://10.10.10.5/</script><script>alert(1)</script>"
    html = build_html_report(report)

    payload = html.split('id="nwaa-data">', 1)[1].split("</script>", 1)[0]
    assert "<" not in payload and ">" not in payload
    assert "\\u003c/script\\u003e" in payload
    # Exactly the tags we wrote ourselves, none injected by scan data.
    assert html.count("<script") == 2


def test_screenshots_are_embedded_as_data_uris(sample_scan, sample_login_pages, tmp_path):
    shot_path = tmp_path / "shot.png"
    shot_path.write_bytes(TINY_PNG)
    report = _report(
        sample_scan,
        sample_login_pages,
        screenshots=[
            ScreenshotResult(login_page=sample_login_pages[0], path=str(shot_path), success=True)
        ],
    )
    html = build_html_report(report)
    assert "data:image/png;base64," in html


def test_screenshots_can_be_linked_relatively_instead(sample_scan, sample_login_pages, tmp_path):
    shots_dir = tmp_path / "screenshots"
    shots_dir.mkdir()
    shot_path = shots_dir / "shot.png"
    shot_path.write_bytes(TINY_PNG)
    report = _report(
        sample_scan,
        sample_login_pages,
        screenshots=[
            ScreenshotResult(login_page=sample_login_pages[0], path=str(shot_path), success=True)
        ],
    )
    html_path = write_html_report(report, tmp_path / "report.html", embed_screenshots=False)
    html = html_path.read_text(encoding="utf-8")
    assert "screenshots/shot.png" in html
    assert "data:image/png;base64," not in html


def test_missing_screenshot_file_does_not_break_rendering(sample_scan, sample_login_pages, tmp_path):
    report = _report(
        sample_scan,
        sample_login_pages,
        screenshots=[
            ScreenshotResult(
                login_page=sample_login_pages[0], path=str(tmp_path / "gone.png"), success=True
            )
        ],
    )
    html = build_html_report(report)
    assert "</html>" in html


def test_html_report_never_contains_a_password(sample_scan, sample_login_pages):
    register_secret("leaky-password")
    report = _report(
        sample_scan,
        sample_login_pages,
        attempts=[
            CredentialAttempt(
                login_page=sample_login_pages[0],
                username="admin",
                credential_label="vendor-default",
                verdict=AttemptVerdict.FAILED,
                detail="submitted leaky-password to the form",
            )
        ],
    )
    html = build_html_report(report)
    assert "leaky-password" not in html
    assert "REDACTED" in html


def test_device_fingerprints_reach_the_viewer(devices_scan):
    login_pages = identify_login_pages(devices_scan)
    result = ScanResult(
        nessus_file=devices_scan.source_path,
        generated_at=datetime.now(timezone.utc).isoformat(),
        services=list(devices_scan.services),
        login_pages=login_pages,
        fingerprints=fingerprint_services(devices_scan),
    )
    html = build_html_report(build_json_report(result))
    assert "hp-printer" in html
    assert "Devices" in html


def test_written_file_is_utf8_and_titled(sample_scan, sample_login_pages, tmp_path):
    path = write_html_report(_report(sample_scan, sample_login_pages), tmp_path / "r.html")
    text = path.read_text(encoding="utf-8")
    assert re.search(r"<title>nwaa report — sample\.nessus</title>", text)
