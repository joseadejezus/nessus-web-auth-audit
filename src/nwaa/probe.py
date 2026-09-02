"""Read a target's banners from a page load, for fingerprinting.

Two entry points, both of which produce an ``HttpProbe``:

  * ``probe_open_page`` — called with a page the screenshot pass has
    already navigated, so fingerprinting a screenshotted login page
    costs no additional request.
  * ``probe_login_pages`` — a standalone pass for the case where
    screenshots are disabled but ``--default-creds`` still needs to know
    what the device is. One GET per login page, nothing submitted.

Nothing here authenticates or submits a form; that is
``credential_tester``'s job. Scope is enforced the same way as
everywhere else: URL check before navigation plus a route guard on the
browser context.
"""
from __future__ import annotations

import logging

from nwaa.browser import chromium_launch_kwargs
from nwaa.models import HttpProbe, LoginPage
from nwaa.scope import ScopeRegistry, install_scope_guard

logger = logging.getLogger("nwaa.probe")

# Enough of the page to catch a vendor string in a footer or a JS bundle
# name, small enough that report data stays bounded.
BODY_SNIPPET_CHARS = 4_000
TEXT_TIMEOUT_MS = 2_000


def probe_open_page(page, response, url: str) -> HttpProbe:
    """Build an HttpProbe from an already-navigated Playwright page.

    Never raises: fingerprinting is a bonus, so every signal is optional
    and a failure to read one just leaves it blank.
    """
    server = ""
    www_authenticate = ""
    status: int | None = None
    if response is not None:
        try:
            status = response.status
            headers = {k.lower(): v for k, v in (response.headers or {}).items()}
            server = str(headers.get("server", ""))[:300]
            www_authenticate = str(headers.get("www-authenticate", ""))[:300]
        except Exception as exc:  # noqa: BLE001 - never fail a scan over a banner
            logger.debug("Could not read response headers for %s: %s", url, exc)

    title = ""
    try:
        title = (page.title() or "")[:300]
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not read page title for %s: %s", url, exc)

    snippet = ""
    try:
        snippet = (page.content() or "")[:BODY_SNIPPET_CHARS]
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not read page content for %s: %s", url, exc)

    return HttpProbe(
        url=url,
        status=status,
        server=server,
        www_authenticate=www_authenticate,
        title=title,
        text_snippet=snippet,
    )


def probe_login_pages(
    login_pages: list[LoginPage],
    scope: ScopeRegistry,
    timeout_ms: int = 15_000,
) -> dict[str, HttpProbe]:
    """One unauthenticated GET per login page; returns url -> probe."""
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    probes: dict[str, HttpProbe] = {}
    if not login_pages:
        return probes

    with sync_playwright() as p:
        browser = p.chromium.launch(**chromium_launch_kwargs())
        try:
            for login_page in login_pages:
                if not scope.is_url_in_scope(login_page.url):
                    logger.warning("Skipping out-of-scope probe", extra={"url": login_page.url})
                    continue
                context = browser.new_context(ignore_https_errors=True)
                install_scope_guard(context, scope)
                page = context.new_page()
                try:
                    response = page.goto(
                        login_page.url, wait_until="domcontentloaded", timeout=timeout_ms
                    )
                    probes[login_page.url] = probe_open_page(page, response, login_page.url)
                except PlaywrightError as exc:
                    logger.debug("Probe failed for %s: %s", login_page.url, exc)
                finally:
                    context.close()
        finally:
            browser.close()
    return probes
