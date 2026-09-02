"""Credential testing against discovered login pages.

Hard rules enforced here, not just documented:
  * Credentials are never generated, permuted or guessed by this tool.
    They come either from a user-supplied JSON file (``load_credentials``)
    or from the bundled vendor default-credential profile that matches a
    device's fingerprint (``nwaa.default_creds``) — and the latter only
    for the specific profile that was detected.
  * A hard, low ceiling on attempts per page (``select_credentials_for_attempt``)
    makes password spraying / brute force structurally impossible, not
    just discouraged. It applies to the *combined* list, so adding vendor
    defaults cannot raise the number of attempts a page receives.
  * Every operator-supplied password is registered with nwaa.redaction
    as it is loaded, so it cannot appear in logs or reports even by
    accident. Bundled vendor defaults deliberately are not registered —
    they are published factory credentials, and treating words like
    "password" as secrets corrupted report text (see default_creds).
  * Every navigation is re-validated against the ScopeRegistry
    immediately before use, and a Playwright route handler aborts any
    request to an out-of-scope host (covers redirects/subresources).

Classification is best-effort/heuristic (see docs/SECURITY.md). Treat
"default_credentials_successful" results as leads to verify manually,
not as ground truth.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from nwaa.browser import chromium_launch_kwargs
from nwaa.models import AttemptVerdict, Credential, CredentialAttempt, LoginPage, SecretStr
from nwaa.redaction import register_secret, scrub_secrets
from nwaa.scope import ScopeRegistry, install_scope_guard

logger = logging.getLogger("nwaa.credential_tester")

HARD_MAX_ATTEMPTS_PER_PAGE = 20
DEFAULT_MAX_ATTEMPTS_PER_PAGE = 5

LOCKOUT_WARNING = (
    "Default-credential testing sends real failed logins. Devices with account "
    "lockout (and some MFPs with audit alerting) will react. Keep "
    "--max-attempts-per-page low and confirm the client accepts the risk."
)

FAILURE_MARKER_RE = re.compile(
    r"invalid|incorrect|denied|failed|unauthorized|not\s+authorized|"
    r"wrong\s+(username|password|credentials)|try\s+again|locked\s*out|"
    r"error\s+logging\s+in",
    re.IGNORECASE,
)

USERNAME_SELECTORS: tuple[str, ...] = (
    'input[type="email"]',
    'input[autocomplete="username"]',
    'input[name*="user" i]',
    'input[id*="user" i]',
    'input[name*="email" i]',
    'input[type="text"]',
)


class CredentialConfigError(ValueError):
    pass


def load_credentials(path: str | Path) -> list[Credential]:
    """Load explicitly-configured credentials from a JSON file.

    Expected shape (a placeholder is used below because no credential
    literal may appear in this repo's Python source)::

        {"credentials": [{"username": "admin", "password": "<secret>", "label": "site-standard"}]}

    Every password is immediately registered for log/report redaction.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CredentialConfigError(f"Could not read credentials file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CredentialConfigError(f"Credentials file {path} is not valid JSON: {exc}") from exc

    entries = data.get("credentials") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise CredentialConfigError(
            f"Credentials file {path} must contain a non-empty 'credentials' list"
        )

    credentials: list[Credential] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or "username" not in entry or "password" not in entry:
            raise CredentialConfigError(
                f"Credentials file {path}: entry {i} must have 'username' and 'password'"
            )
        password = str(entry["password"])
        register_secret(password)
        credentials.append(
            Credential(
                username=str(entry["username"]),
                password=SecretStr(password),
                label=str(entry.get("label", "unlabeled")),
            )
        )
    return credentials


def select_credentials_for_attempt(
    credentials: list[Credential], max_attempts_per_page: int = DEFAULT_MAX_ATTEMPTS_PER_PAGE
) -> tuple[list[Credential], str | None]:
    """Cap the credential list applied to a single page.

    Returns (selected, warning). ``max_attempts_per_page`` is itself
    clamped to HARD_MAX_ATTEMPTS_PER_PAGE — this tool will not spray an
    unbounded list against one login page no matter what a caller asks
    for; that is a deliberate, non-configurable ceiling.
    """
    cap = min(max_attempts_per_page, HARD_MAX_ATTEMPTS_PER_PAGE)
    if len(credentials) <= cap:
        return list(credentials), None
    warning = (
        f"{len(credentials)} credentials configured but only the first {cap} "
        f"will be tried against each page (cap={cap}). This tool refuses to "
        f"spray large credential lists against a single login page."
    )
    return list(credentials[:cap]), warning


def combine_credentials(
    user_credentials: list[Credential], default_credentials: list[Credential]
) -> list[Credential]:
    """Operator-supplied credentials first, then fingerprint-matched defaults.

    Order matters: the cap truncates the tail, so an explicitly supplied
    credential is never dropped in favour of a vendor default. Duplicates
    on (username, password) are collapsed so the same guess is not spent
    twice against one page.
    """
    combined: list[Credential] = []
    seen: set[tuple[str, str]] = set()
    for credential in list(user_credentials) + list(default_credentials):
        key = (credential.username, credential.password.reveal())
        if key in seen:
            continue
        seen.add(key)
        combined.append(credential)
    return combined


def classify_login_outcome(
    *,
    pre_url: str,
    post_url: str,
    page_text: str,
    password_field_present_after: bool,
) -> tuple[AttemptVerdict, str]:
    """Pure heuristic classifier — no I/O, fully unit testable.

    Conservative by design: SUCCESS requires the password field to have
    disappeared, the URL to have changed, and no failure text to be
    present. Anything short of that is FAILED (if failure text is
    present) or INCONCLUSIVE (ambiguous — needs human review).
    """
    has_failure_text = bool(FAILURE_MARKER_RE.search(page_text))

    if password_field_present_after:
        if has_failure_text:
            return AttemptVerdict.FAILED, "Password field still present and page shows failure text."
        return (
            AttemptVerdict.INCONCLUSIVE,
            "Password field still present after submit; outcome unclear.",
        )

    url_changed = urlsplit(post_url) != urlsplit(pre_url)
    if url_changed and not has_failure_text:
        return (
            AttemptVerdict.SUCCESS,
            "Password field gone, URL changed away from login page, no failure text detected.",
        )
    if has_failure_text:
        return AttemptVerdict.FAILED, "Failure text detected on resulting page."
    return (
        AttemptVerdict.INCONCLUSIVE,
        "Password field gone but URL unchanged and no clear signal either way.",
    )


@dataclass
class AttemptOptions:
    timeout_ms: int = 15_000
    max_attempts_per_page: int = DEFAULT_MAX_ATTEMPTS_PER_PAGE


def test_credentials_against_pages(
    login_pages: list[LoginPage],
    credentials: list[Credential],
    scope: ScopeRegistry,
    options: AttemptOptions | None = None,
    default_credentials_by_url: dict[str, list[Credential]] | None = None,
) -> list[CredentialAttempt]:
    """Try each credential against each login page, in one browser session.

    ``default_credentials_by_url`` carries the vendor defaults chosen for
    each page's device fingerprint. They are appended to the operator's
    list *per page* and the combined list is then capped, so a page never
    receives more attempts than ``options.max_attempts_per_page``.

    Deferred playwright import: this function (and only this function's
    call graph) needs an installed browser; the rest of the module is
    plain Python so tests can exercise classify_login_outcome,
    combine_credentials and select_credentials_for_attempt without
    playwright present.
    """
    from playwright.sync_api import sync_playwright

    options = options or AttemptOptions()
    by_url = default_credentials_by_url or {}
    attempts: list[CredentialAttempt] = []
    if not login_pages:
        return attempts

    with sync_playwright() as p:
        browser = p.chromium.launch(**chromium_launch_kwargs())
        try:
            for login_page in login_pages:
                selected, warning = select_credentials_for_attempt(
                    combine_credentials(credentials, by_url.get(login_page.url, [])),
                    options.max_attempts_per_page,
                )
                page_attempts = _attempts_for_page(browser, login_page, selected, scope, options)
                if warning:
                    for attempt in page_attempts:
                        attempt.detail = f"{attempt.detail} [{warning}]"
                attempts.extend(page_attempts)
        finally:
            browser.close()

    return attempts


def test_credentials_against_page(
    login_page: LoginPage,
    credentials: list[Credential],
    scope: ScopeRegistry,
    options: AttemptOptions | None = None,
    default_credentials_by_url: dict[str, list[Credential]] | None = None,
) -> list[CredentialAttempt]:
    """Single-page convenience wrapper around test_credentials_against_pages."""
    return test_credentials_against_pages(
        [login_page], credentials, scope, options, default_credentials_by_url
    )


def _attempts_for_page(
    browser,
    login_page: LoginPage,
    selected: list[Credential],
    scope: ScopeRegistry,
    options: AttemptOptions,
) -> list[CredentialAttempt]:
    if not scope.is_url_in_scope(login_page.url):
        logger.warning("Skipping out-of-scope login page", extra={"url": login_page.url})
        return [
            CredentialAttempt(
                login_page=login_page,
                username="",
                credential_label="",
                verdict=AttemptVerdict.NOT_TESTED,
                detail="URL is not within the scope derived from the supplied .nessus file; skipped.",
                credential_source="none",
            )
        ]

    attempts: list[CredentialAttempt] = []
    for credential in selected:
        # Fresh context per credential: a session cookie left over from a
        # previous attempt would otherwise make the next attempt look
        # successful.
        context = browser.new_context(ignore_https_errors=True)
        install_scope_guard(context, scope)
        page = context.new_page()
        try:
            attempts.append(_attempt_one(page, login_page, credential, options))
        finally:
            context.close()
    return attempts


def _attempt_one(
    page, login_page: LoginPage, credential: Credential, options: AttemptOptions
) -> CredentialAttempt:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    password_value = credential.password.reveal()
    try:
        page.goto(login_page.url, wait_until="domcontentloaded", timeout=options.timeout_ms)

        password_locator = page.locator('input[type="password"]').first
        if password_locator.count() == 0:
            return CredentialAttempt(
                login_page=login_page,
                username=credential.username,
                credential_label=credential.label,
                verdict=AttemptVerdict.NOT_TESTED,
                detail="No password field found on page; not a form-based login this tool can drive.",
                credential_source=credential.source,
            )

        username_locator = _find_username_field(page)
        if username_locator is not None:
            username_locator.fill(credential.username, timeout=options.timeout_ms)
        password_locator.fill(password_value, timeout=options.timeout_ms)

        submitted = _submit(page, password_locator, options.timeout_ms)
        if not submitted:
            return CredentialAttempt(
                login_page=login_page,
                username=credential.username,
                credential_label=credential.label,
                verdict=AttemptVerdict.INCONCLUSIVE,
                detail="Could not find a submit control for the login form.",
                credential_source=credential.source,
            )

        try:
            page.wait_for_load_state("networkidle", timeout=options.timeout_ms)
        except PlaywrightTimeoutError:
            # Not fatal: some apps never go idle. Classify on what we have.
            logger.debug("Page never reached networkidle", extra={"url": login_page.url})

        post_url = page.url
        password_field_present_after = page.locator('input[type="password"]').count() > 0
        page_text = ""
        try:
            page_text = page.locator("body").inner_text(timeout=2_000)[:5_000]
        except PlaywrightError:
            logger.debug("Could not read page body text", extra={"url": login_page.url})

        verdict, detail = classify_login_outcome(
            pre_url=login_page.url,
            post_url=post_url,
            page_text=page_text,
            password_field_present_after=password_field_present_after,
        )
        return CredentialAttempt(
            login_page=login_page,
            username=credential.username,
            credential_label=credential.label,
            verdict=verdict,
            detail=scrub_secrets(detail),
            credential_source=credential.source,
        )
    except PlaywrightTimeoutError as exc:
        return CredentialAttempt(
            login_page=login_page,
            username=credential.username,
            credential_label=credential.label,
            verdict=AttemptVerdict.ERROR,
            detail=scrub_secrets(f"Timed out: {exc}"),
            credential_source=credential.source,
        )
    except PlaywrightError as exc:
        return CredentialAttempt(
            login_page=login_page,
            username=credential.username,
            credential_label=credential.label,
            verdict=AttemptVerdict.ERROR,
            detail=scrub_secrets(f"Browser/connection/TLS error: {exc}"),
            credential_source=credential.source,
        )


def _find_username_field(page):
    for selector in USERNAME_SELECTORS:
        locator = page.locator(selector).first
        if locator.count() > 0:
            return locator
    return None


def _submit(page, password_locator, timeout_ms: int) -> bool:
    from playwright.sync_api import Error as PlaywrightError

    for selector in ('button[type="submit"]', 'input[type="submit"]', "button"):
        locator = page.locator(selector).first
        if locator.count() > 0:
            locator.click(timeout=timeout_ms)
            return True
    try:
        password_locator.press("Enter", timeout=timeout_ms)
        return True
    except PlaywrightError:
        return False
