"""Screenshot discovered login pages, with the URL burned into the image.

Headless browsers have no address bar, so a raw screenshot is evidence
of a page but not of *which* page. Before capturing, a fixed banner is
injected containing the exact URL and a UTC timestamp, so every image is
self-describing in a report.

The banner is built with textContent (never innerHTML) and the URL is
passed as an evaluate() argument, so a hostile URL cannot inject script
into the page we are measuring.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from nwaa.browser import chromium_launch_kwargs
from nwaa.models import LoginPage, ScreenshotResult
from nwaa.probe import probe_open_page
from nwaa.scope import ScopeRegistry, install_scope_guard

logger = logging.getLogger("nwaa.screenshot")

_UNSAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
# Collapse ".." so a path from scan data can never form a traversal segment.
_DOT_RUN_RE = re.compile(r"\.{2,}")

_BANNER_JS = """
(payload) => {
  const existing = document.getElementById('nwaa-url-banner');
  if (existing) { existing.remove(); }
  const bar = document.createElement('div');
  bar.id = 'nwaa-url-banner';
  bar.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#101418', 'color:#ffffff', 'font:14px/1.5 monospace',
    'padding:8px 12px', 'border-bottom:3px solid #ff9800',
    'white-space:pre-wrap', 'word-break:break-all'
  ].join(';');
  bar.textContent = payload.url + '\\n' + payload.captured_at + '  |  scheme: ' + payload.scheme;
  document.documentElement.appendChild(bar);
  document.body && (document.body.style.paddingTop = '64px');
}
"""


@dataclass
class ScreenshotOptions:
    timeout_ms: int = 20_000
    full_page: bool = False
    viewport_width: int = 1366
    viewport_height: int = 900


def safe_filename(url: str, suffix: str = ".png") -> str:
    """Derive a filesystem-safe, collision-resistant name from a URL.

    The URL comes from scan data we do not control, so it is never used
    as a path component directly — it is sanitized to an allowlist and
    disambiguated with a hash of the original.
    """
    parts = urlsplit(url)
    host = parts.hostname or "unknown-host"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    stem = f"{host}_{port}_{path}"
    stem = _UNSAFE_FILENAME_RE.sub("-", stem)
    stem = _DOT_RUN_RE.sub(".", stem).strip("-")[:80]
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    return f"{stem}_{digest}{suffix}"


def screenshot_login_pages(
    login_pages: list[LoginPage],
    scope: ScopeRegistry,
    out_dir: str | Path,
    options: ScreenshotOptions | None = None,
) -> list[ScreenshotResult]:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright

    options = options or ScreenshotOptions()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[ScreenshotResult] = []
    if not login_pages:
        return results

    with sync_playwright() as p:
        browser = p.chromium.launch(**chromium_launch_kwargs())
        try:
            for login_page in login_pages:
                if not scope.is_url_in_scope(login_page.url):
                    logger.warning(
                        "Skipping out-of-scope URL", extra={"url": login_page.url}
                    )
                    results.append(
                        ScreenshotResult(
                            login_page=login_page,
                            path=None,
                            success=False,
                            error="URL outside the scope derived from the .nessus file",
                        )
                    )
                    continue

                context = browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": options.viewport_width, "height": options.viewport_height},
                )
                install_scope_guard(context, scope)
                page = context.new_page()
                try:
                    response = page.goto(
                        login_page.url, wait_until="domcontentloaded", timeout=options.timeout_ms
                    )
                    final_url = page.url
                    # Banners are read before the URL banner is injected, so
                    # fingerprinting sees the page as the device served it.
                    probe = probe_open_page(page, response, login_page.url)
                    page.evaluate(
                        _BANNER_JS,
                        {
                            "url": final_url,
                            "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "scheme": urlsplit(final_url).scheme or "unknown",
                        },
                    )
                    target = out_dir / safe_filename(login_page.url)
                    page.screenshot(path=str(target), full_page=options.full_page)
                    results.append(
                        ScreenshotResult(
                            login_page=login_page, path=str(target), success=True, probe=probe
                        )
                    )
                    logger.info("Captured screenshot", extra={"url": login_page.url, "path": str(target)})
                except PlaywrightTimeoutError as exc:
                    results.append(
                        ScreenshotResult(
                            login_page=login_page, path=None, success=False,
                            error=f"Timed out loading page: {exc}",
                        )
                    )
                except PlaywrightError as exc:
                    results.append(
                        ScreenshotResult(
                            login_page=login_page, path=None, success=False,
                            error=f"Browser/connection/TLS error: {exc}",
                        )
                    )
                finally:
                    context.close()
        finally:
            browser.close()

    return results
