"""Platform handling — the Kali/Linux paths that decide whether Chromium
starts at all. Pure logic only: nothing here launches a browser."""
from __future__ import annotations

import pytest

from nwaa import browser


@pytest.fixture
def linux_root(monkeypatch):
    monkeypatch.setattr(browser, "is_linux", lambda: True)
    monkeypatch.setattr(browser, "running_as_root", lambda: True)


@pytest.fixture
def linux_user(monkeypatch):
    monkeypatch.setattr(browser, "is_linux", lambda: True)
    monkeypatch.setattr(browser, "running_as_root", lambda: False)


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(browser, "is_linux", lambda: False)
    monkeypatch.setattr(browser, "running_as_root", lambda: False)


def test_root_on_linux_disables_the_chromium_sandbox(linux_root):
    """Chromium refuses to start as root with the sandbox enabled, and a lot
    of Kali work happens in a root shell."""
    args = browser.chromium_launch_args()
    assert "--no-sandbox" in args
    assert "--disable-dev-shm-usage" in args


def test_unprivileged_linux_keeps_the_sandbox(linux_user):
    args = browser.chromium_launch_args()
    assert "--no-sandbox" not in args
    assert "--disable-dev-shm-usage" in args


def test_windows_needs_no_extra_flags(windows):
    assert browser.chromium_launch_args() == []


def test_launch_kwargs_are_headless_and_carry_args(linux_root):
    kwargs = browser.chromium_launch_kwargs()
    assert kwargs["headless"] is True
    assert "--no-sandbox" in kwargs["args"]


def test_launch_kwargs_omit_args_when_there_are_none(windows):
    assert browser.chromium_launch_kwargs() == {"headless": True}


def test_headless_linux_has_no_display(linux_user, monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert browser.has_display() is False


def test_linux_with_display_is_detected(linux_user, monkeypatch):
    monkeypatch.setenv("DISPLAY", ":0")
    assert browser.has_display() is True


def test_non_linux_is_always_treated_as_having_a_display(windows):
    assert browser.has_display() is True


def test_with_deps_is_rejected_off_linux(windows):
    ok, detail = browser.install_browser(with_deps=True)
    assert ok is False
    assert "Linux" in detail


def test_with_deps_requires_root(linux_user):
    ok, detail = browser.install_browser(with_deps=True)
    assert ok is False
    assert "root" in detail


def test_browsers_path_follows_the_environment_override(monkeypatch):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw")
    assert browser.browsers_path() == "/opt/pw"


def test_platform_report_mentions_the_browsers_path(monkeypatch):
    # Stubbed so the report never has to start a real Playwright driver.
    monkeypatch.setattr(browser, "browser_available", lambda: (False, "not installed"))
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw")
    report = browser.platform_report()
    assert "/opt/pw" in report
    assert "running as root" in report
    assert "not installed" in report
