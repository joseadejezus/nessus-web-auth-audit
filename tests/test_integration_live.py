"""End-to-end tests against a real browser and a real HTTP target.

Everything else in this suite is offline by design. These tests are the
opposite: they drive an actual Chromium against ``tests/lab_server.py``
so the code paths that only exist when a browser is present get executed
-- screenshotting, live banner probing, form submission, verdict
classification, and the route guard that keeps the browser inside the
scope the .nessus file authorized.

They skip themselves when Chromium is not installed (``nwaa setup``), so
a machine without a browser still gets a green offline suite. In CI the
browser is installed, so these run on every push.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

# tests/ is on sys.path under pytest's default import mode.
import lab_server as lab
from nwaa.browser import browser_available
from nwaa.cli import EXIT_OK, main

# Covers both "playwright is not installed" and "installed, but the Chromium
# build was never downloaded" — neither is a failure of the tool.
_ready, _detail = browser_available()
if not _ready:
    if os.environ.get("NWAA_REQUIRE_INTEGRATION") == "1":
        # Set in CI, where a missing browser is a broken job, not a machine
        # that simply has no Chromium. Without this, a failed browser install
        # would show up as a green run containing zero tests.
        raise RuntimeError(f"NWAA_REQUIRE_INTEGRATION=1 but no browser: {_detail}")
    pytest.skip(f"needs a real Chromium: {_detail}", allow_module_level=True)

pytestmark = pytest.mark.integration


@pytest.fixture
def lab_target():
    target = lab.start_lab_server()
    yield target
    target.stop()


def _scan(nessus: Path, out: Path, *extra: str) -> int:
    return main(
        [
            "scan",
            "--nessus", str(nessus),
            "--out", str(out),
            "--timeout-ms", "10000",
            "--log-level", "WARNING",
            *extra,
        ]
    )


def _report(out: Path) -> dict:
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def test_default_credential_chain_end_to_end(lab_target, tmp_path):
    """The whole active half of the tool, in one run.

    Scan file -> login page -> screenshot -> live banner -> HP profile ->
    the profile's first credential succeeding and its second failing.
    """
    nessus = lab.write_lab_nessus(
        tmp_path / "lab.nessus",
        lab_target.host,
        lab_target.port,
        [lab_target.login_url],
        operating_system="HP LaserJet 4250 Printer",
        system_type="printer",
    )
    out = tmp_path / "out"

    code = _scan(nessus, out, "--authorized", "--default-creds", "--max-attempts-per-page", "2")
    assert code == EXIT_OK
    report = _report(out)

    # The device: matched offline from the scan file's tags *and* live from
    # the Server header and page title, which is what "nessus+http" means.
    assert report["summary"]["login_pages"] == 1
    device = report["login_pages"][0]["device"]
    assert device["profile_id"] == "hp-printer"
    assert device["source"] == "nessus+http"
    assert device["confidence"] == "high"

    # The screenshot, and the banner the live half of that match came from.
    shot = report["screenshots"][0]
    assert shot["success"] is True
    assert shot["server"] == lab.DEFAULT_BANNER
    assert "LaserJet" in shot["page_title"]
    assert Path(shot["path"]).stat().st_size > 1_000

    # Two vendor defaults tried, in profile order: blank-password admin
    # (HP's factory state) succeeds, admin/admin does not.
    attempts = report["credential_attempts"]
    assert [a["verdict"] for a in attempts] == [
        "default_credentials_successful",
        "authentication_failed",
    ]
    assert all(a["credential_source"] == "vendor_default" for a in attempts)
    assert all(a["username"] == "admin" for a in attempts)
    assert report["summary"]["vendor_default_attempts"] == 2

    # ...and the device saw exactly those two submissions, no more.
    assert len(lab_target.requests_for(lab.LOGIN_PATH, "POST")) == 2
    assert len(lab_target.requests_for(lab.HOME_PATH, "GET")) == 1

    # A report with screenshots and attempts in it, for manual viewer checks.
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "data:image/png;base64," in html
    assert "default_credentials_successful" in html


def test_live_banner_alone_fingerprints_the_device(lab_target, tmp_path):
    """No vendor hint in the scan file: the match must come from the wire.

    The login URL is the bare root rather than the HP-shaped path, so
    nothing in the .nessus file names a vendor and only the live
    ``Server`` header and page title can produce the match.
    """
    nessus = lab.write_lab_nessus(
        tmp_path / "lab.nessus",
        lab_target.host,
        lab_target.port,
        [f"{lab_target.origin}/"],
        operating_system="Linux Kernel 5.15",
    )
    out = tmp_path / "out"

    code = _scan(nessus, out, "--authorized", "--default-creds", "--max-attempts-per-page", "1")
    assert code == EXIT_OK
    report = _report(out)

    device = report["login_pages"][0]["device"]
    assert device["profile_id"] == "hp-printer"
    assert device["source"] == "http"
    assert any("HP" in line for line in device["evidence"])


def test_page_without_a_password_field_is_not_tested(lab_target, tmp_path):
    """A form this tool cannot drive is reported as such, not guessed at."""
    nessus = lab.write_lab_nessus(
        tmp_path / "lab.nessus",
        lab_target.host,
        lab_target.port,
        [lab_target.no_password_url],
        operating_system="HP LaserJet 4250 Printer",
    )
    out = tmp_path / "out"

    code = _scan(
        nessus, out, "--authorized", "--profile", "hp-printer", "--max-attempts-per-page", "1"
    )
    assert code == EXIT_OK
    report = _report(out)

    attempt = report["credential_attempts"][0]
    assert attempt["verdict"] == "not_tested"
    assert "No password field" in attempt["detail"]
    assert lab_target.requests_for(lab.LOGIN_PATH, "POST") == []


def test_scope_guard_blocks_offscope_subresources(tmp_path):
    """The route guard, exercised by a real browser on a real page.

    The login page carries two 1x1 images: one on the host the .nessus
    authorized, one on a host it did not. The in-scope image proves the
    browser was loading images at all; the off-scope one must never be
    requested.
    """
    try:
        offscope = lab.start_lab_server(host="127.0.0.2")
    except OSError as exc:  # no loopback alias on this platform
        pytest.skip(f"cannot bind 127.0.0.2: {exc}")

    target = lab.start_lab_server(
        image_urls=(lab.TRACKER_PATH, f"{offscope.origin}{lab.TRACKER_PATH}")
    )
    try:
        nessus = lab.write_lab_nessus(
            tmp_path / "lab.nessus",
            target.host,
            target.port,
            [target.login_url],
            operating_system="HP LaserJet 4250 Printer",
        )
        out = tmp_path / "out"
        # --profile forces a credential pass, which waits for networkidle and
        # so guarantees the page's subresource requests have been decided.
        code = _scan(
            nessus, out, "--authorized", "--profile", "hp-printer", "--max-attempts-per-page", "1"
        )
        assert code == EXIT_OK

        assert target.requests_for(lab.TRACKER_PATH), "in-scope image was never requested"
        assert offscope.requests_for(lab.TRACKER_PATH) == [], "scope guard let an off-scope request through"
    finally:
        target.stop()
        offscope.stop()


def test_out_of_scope_login_page_is_never_contacted(lab_target, tmp_path):
    """A login page on a port the scan never saw is refused before navigation."""
    unscanned_port = lab_target.port + 1 if lab_target.port % 2 else lab_target.port - 1
    nessus = lab.write_lab_nessus(
        tmp_path / "lab.nessus",
        lab_target.host,
        lab_target.port,
        [f"http://{lab_target.host}:{unscanned_port}{lab.LOGIN_PATH}"],
    )
    out = tmp_path / "out"

    code = _scan(
        nessus, out, "--authorized", "--profile", "hp-printer", "--max-attempts-per-page", "1"
    )
    assert code == EXIT_OK
    report = _report(out)

    assert report["screenshots"][0]["success"] is False
    assert "scope" in (report["screenshots"][0]["error"] or "")
    attempt = report["credential_attempts"][0]
    assert attempt["verdict"] == "not_tested"
    assert lab_target.requests == []
