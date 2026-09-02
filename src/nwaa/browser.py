"""Playwright browser bootstrap and platform quirks.

A pipx install gets the Playwright *library* but not the Chromium
*binary*, which is a separate ~150 MB download. Rather than making the
user find the right incantation, the tool installs it into its own
environment on request (``nwaa setup``, or ``--install-browser`` during
a scan).

Kali/Linux specifics handled here, because they are the difference
between "works" and "silently fails to launch" on the platform this tool
is meant to run on:

  * **Running as root.** Chromium's sandbox refuses to start as root, and
    a lot of Kali work happens in a root shell. ``--no-sandbox`` is added
    only in that case, with a warning, rather than always.
  * **Small /dev/shm.** Docker and some live images give /dev/shm 64 MB,
    which crashes Chromium mid-render; ``--disable-dev-shm-usage`` avoids
    it on Linux.
  * **Missing shared libraries.** ``playwright install`` downloads the
    browser but not the system libraries it links against. On Linux the
    fix is ``playwright install-deps`` as root, so ``nwaa setup
    --with-deps`` exists and the error message names it.
  * **The root cache trap.** Browsers land in ``~/.cache/ms-playwright``.
    Downloading under ``sudo`` puts them in ``/root`` where the normal
    user's nwaa cannot see them; ``platform_report`` prints the path in
    use so that mismatch is visible.
"""
from __future__ import annotations

import logging
import os
import platform
import shutil
# Justification kept above the pragma, not after it: bandit reads everything
# following "# nosec" as a list of test ids and warns about each prose word.
# Only used for the fixed 'playwright install' argv in install_browser().
import subprocess  # nosec B404
import sys
from pathlib import Path

logger = logging.getLogger("nwaa.browser")

PLAYWRIGHT_MISSING_MSG = (
    "The playwright package is not installed in this environment. "
    "Reinstall nwaa (pipx install nwaa) or run: pip install playwright"
)
BROWSER_MISSING_MSG = (
    "Chromium is not installed for Playwright. Run 'nwaa setup' once, "
    "or re-run this scan with --install-browser."
)
LINUX_DEPS_HINT = (
    "On Debian/Kali this usually means missing system libraries. Run "
    "'sudo $(which nwaa) setup --with-deps', or "
    "'sudo playwright install-deps chromium', then retry."
)


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def running_as_root() -> bool:
    """True on POSIX when the effective uid is 0 (common on Kali)."""
    getuid = getattr(os, "geteuid", None)
    return bool(getuid and getuid() == 0)


def chromium_launch_args() -> list[str]:
    """Chromium flags needed for this platform, and no others."""
    args: list[str] = []
    if is_linux():
        # 64 MB /dev/shm (containers, some live images) crashes the renderer.
        args.append("--disable-dev-shm-usage")
        if running_as_root():
            # Chromium's setuid sandbox refuses to run as root. Dropping it
            # is the documented workaround; the alternative is not scanning.
            args.append("--no-sandbox")
    return args


def chromium_launch_kwargs(headless: bool = True) -> dict:
    """Keyword arguments for ``p.chromium.launch()`` on this platform."""
    kwargs: dict = {"headless": headless}
    args = chromium_launch_args()
    if args:
        kwargs["args"] = args
        if "--no-sandbox" in args:
            logger.warning(
                "Running as root: launching Chromium with --no-sandbox. "
                "Prefer running nwaa as an unprivileged user."
            )
    return kwargs


def browser_available() -> tuple[bool, str]:
    """Report whether a Chromium binary is ready to drive."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False, PLAYWRIGHT_MISSING_MSG

    try:
        with sync_playwright() as p:
            executable = Path(p.chromium.executable_path)
    except Exception as exc:  # playwright raises its own Error subclass here
        logger.debug("Chromium lookup failed: %s", exc)
        return False, BROWSER_MISSING_MSG

    if not executable.exists():
        return False, BROWSER_MISSING_MSG
    return True, str(executable)


def browsers_path() -> str:
    """Where Playwright will look for browser builds on this machine."""
    override = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if override:
        return override
    if is_linux():
        return str(Path.home() / ".cache" / "ms-playwright")
    if sys.platform == "darwin":
        return str(Path.home() / "Library" / "Caches" / "ms-playwright")
    local_appdata = os.environ.get("LOCALAPPDATA", str(Path.home()))
    return str(Path(local_appdata) / "ms-playwright")


def install_browser(timeout_s: int = 900, with_deps: bool = False) -> tuple[bool, str]:
    """Download Chromium into this environment via the Playwright CLI.

    Runs the interpreter that is currently executing nwaa, so under pipx
    the browser lands in that isolated venv rather than somewhere the
    tool cannot see. ``with_deps`` additionally installs the OS packages
    Chromium links against, which needs root and only exists on Linux.
    """
    cmd = [sys.executable, "-m", "playwright", "install"]
    if with_deps:
        if not is_linux():
            return False, "--with-deps installs Linux system packages and only applies on Linux"
        if not running_as_root():
            return False, (
                "--with-deps installs system packages and must be run as root, e.g. "
                "'sudo $(which nwaa) setup --with-deps'"
            )
        cmd.append("--with-deps")
    cmd.append("chromium")

    logger.info("Installing Chromium for Playwright (this downloads ~150 MB)")
    try:
        # argv is built above from constants and sys.executable; shell=False,
        # and no value from a scan file or CLI flag ever reaches it.
        completed = subprocess.run(  # noqa: S603  # nosec B603
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except FileNotFoundError:
        return False, PLAYWRIGHT_MISSING_MSG
    except subprocess.TimeoutExpired:
        return False, f"Chromium download timed out after {timeout_s}s"

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        message = f"playwright install failed: {detail[-1] if detail else 'unknown error'}"
        if is_linux():
            message = f"{message} {LINUX_DEPS_HINT}"
        return False, message
    return True, f"Chromium installed into {browsers_path()}"


def has_display() -> bool:
    """Whether a desktop session exists to open an HTML report in.

    Headless Kali (SSH, a bare console, a container) has neither, and
    ``webbrowser.open`` there either fails or launches a text browser
    over the terminal the scan is printing to.
    """
    if not is_linux():
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def platform_report() -> str:
    """Diagnostics for ``nwaa setup`` — what nwaa sees about this machine."""
    ready, detail = browser_available()
    lines = [
        f"platform        : {platform.platform()}",
        f"python          : {platform.python_version()} ({sys.executable})",
        f"running as root : {running_as_root()}",
        f"browsers path   : {browsers_path()}",
        f"chromium args   : {' '.join(chromium_launch_args()) or '(none)'}",
        f"chromium ready  : {'yes - ' + detail if ready else 'no - ' + detail}",
    ]
    if is_linux():
        lines.append(f"desktop session : {'yes' if has_display() else 'no (headless)'}")
        for tool in ("pipx", "playwright"):
            found = shutil.which(tool)
            lines.append(f"{tool:<16}: {found or 'not on PATH'}")
    return "\n".join(lines)
