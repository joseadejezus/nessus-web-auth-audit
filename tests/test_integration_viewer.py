"""The HTML viewer, driven in a real browser.

`test_html_report.py` asserts the *document*: standalone, no external
resources, no innerHTML, passwords redacted. It cannot assert that the
thing works, because the viewer is a page of JavaScript and a static
string test never runs it. That gap is why the report shipped with a
`display: flex` rule quietly beating `[hidden]`, so the verdict chips
appeared on every tab until someone opened it by hand.

These tests open a report produced by a real lab scan — screenshots and
credential attempts included, which a parse-only report cannot give you
— and exercise the three things that had no coverage at all: the
screenshot lightbox (`<dialog>.showModal()`), the verdict chips actually
filtering, and lazy-loaded data-URI images decoding. Every tab is
rendered with a page-error listener attached, so a JS exception in any
renderer fails the suite instead of waiting to be noticed in front of a
client.

Skips itself when Chromium is not installed, like the other live tests.
"""
from __future__ import annotations

import os

import pytest

import lab_server as lab
from nwaa.browser import browser_available, chromium_launch_kwargs
from nwaa.cli import EXIT_OK, main

_ready, _detail = browser_available()
if not _ready:
    if os.environ.get("NWAA_REQUIRE_INTEGRATION") == "1":
        raise RuntimeError(f"NWAA_REQUIRE_INTEGRATION=1 but no browser: {_detail}")
    pytest.skip(f"needs a real Chromium: {_detail}", allow_module_level=True)

pytestmark = pytest.mark.integration

TAB_LABELS = (
    "Overview",
    "Login pages",
    "Devices",
    "Plaintext HTTP",
    "Credential attempts",
    "Screenshots",
    "Web services",
)


@pytest.fixture(scope="module")
def lab_report(tmp_path_factory):
    """One real lab scan, reused by every test in this module.

    A report with screenshots *and* attempts in it is the whole point:
    the lightbox and the chips have nothing to act on otherwise.
    """
    target = lab.start_lab_server()
    try:
        tmp = tmp_path_factory.mktemp("viewer")
        nessus = lab.write_lab_nessus(
            tmp / "lab.nessus",
            target.host,
            target.port,
            [target.login_url],
            operating_system="HP LaserJet 4250 Printer",
            system_type="printer",
        )
        out = tmp / "out"
        code = main(
            [
                "scan",
                "--nessus", str(nessus),
                "--out", str(out),
                "--authorized",
                "--default-creds",
                "--max-attempts-per-page", "2",
                "--timeout-ms", "10000",
                "--log-level", "WARNING",
            ]
        )
        assert code == EXIT_OK
        report = out / "report.html"
        assert report.is_file()
        return report
    finally:
        target.stop()


@pytest.fixture
def viewer(lab_report):
    """Yield (page, errors) for the opened report; errors must stay empty."""
    from playwright.sync_api import sync_playwright

    errors: list[str] = []

    def on_console(message) -> None:
        # Chromium logs a failed favicon fetch for any file:// page. That is
        # the browser, not the report — everything else is ours.
        if message.type == "error" and "favicon" not in message.text:
            errors.append(f"console: {message.text}")

    with sync_playwright() as p:
        browser = p.chromium.launch(**chromium_launch_kwargs())
        try:
            page = browser.new_page(viewport={"width": 1366, "height": 900})
            page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
            page.on("console", on_console)
            page.goto(lab_report.as_uri(), wait_until="load")
            yield page, errors
        finally:
            browser.close()


def _open_tab(page, label: str) -> None:
    page.get_by_role("tab", name=label, exact=True).click()


def test_every_tab_renders_without_a_javascript_error(viewer):
    page, errors = viewer

    for label in TAB_LABELS:
        _open_tab(page, label)
        assert page.locator("#view > *").count() > 0, f"{label} tab rendered nothing"

    assert errors == []


def test_controls_and_chips_appear_only_where_they_mean_something(viewer):
    """The regression that shipped once already, now checked in a browser.

    An author `display: flex` rule beat the UA stylesheet's `[hidden]`,
    so `el.hidden = true` was a no-op and the chips showed everywhere.
    """
    page, errors = viewer

    _open_tab(page, "Overview")
    assert page.locator("#controls").is_hidden()
    assert page.locator("#chips").is_hidden()

    _open_tab(page, "Login pages")
    assert page.locator("#controls").is_visible()
    assert page.locator("#chips").is_hidden(), "verdict chips leaked onto a non-attempts tab"

    _open_tab(page, "Credential attempts")
    assert page.locator("#controls").is_visible()
    assert page.locator("#chips").is_visible()

    assert errors == []


def test_verdict_chips_filter_the_attempts(viewer):
    page, errors = viewer
    _open_tab(page, "Credential attempts")

    # The lab device accepts exactly one of the two credentials tried.
    assert page.locator("#view .item").count() == 2

    chip = page.locator("#chips button", has_text="default credentials successful")
    chip.click()
    assert chip.get_attribute("aria-pressed") == "true"
    assert page.locator("#view .item").count() == 1
    assert "default credentials successful" in page.locator("#view .item").first.inner_text()

    chip.click()  # chips toggle off
    assert chip.get_attribute("aria-pressed") == "false"
    assert page.locator("#view .item").count() == 2

    assert errors == []


def test_embedded_screenshots_actually_decode(viewer):
    """`loading="lazy"` plus a data: URI is the combination nobody had run."""
    page, errors = viewer
    _open_tab(page, "Screenshots")

    img = page.locator("#view .shots img").first
    img.scroll_into_view_if_needed()
    # The tab renders after the load event, so the image is fetched (and
    # decoded, being a data: URI) only once this renderer has run.
    page.wait_for_function(
        "() => { const i = document.querySelector('#view .shots img');"
        " return !!i && i.complete && i.naturalWidth > 0; }"
    )
    assert img.evaluate("node => node.src.slice(0, 22)") == "data:image/png;base64,"
    assert img.evaluate("node => node.naturalWidth") > 0

    assert errors == []


def test_screenshot_lightbox_opens_and_closes(viewer):
    page, errors = viewer
    _open_tab(page, "Screenshots")

    dialog = page.locator("#lightbox")
    assert dialog.evaluate("node => node.open") is False

    page.locator("#view .shots img").first.click()
    assert dialog.evaluate("node => node.open") is True, "<dialog>.showModal() did not open"
    lightbox_img = page.locator("#lightbox-img")
    assert lightbox_img.evaluate("node => node.src.slice(0, 22)") == "data:image/png;base64,"
    assert page.locator("#lightbox-cap").inner_text().startswith("http://127.0.0.1:")

    dialog.click(position={"x": 5, "y": 5})
    assert dialog.evaluate("node => node.open") is False

    assert errors == []
