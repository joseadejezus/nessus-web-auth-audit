"""Command-line interface.

One command does the whole job:

    nwaa scan --nessus scan.nessus --authorized --default-creds --open

parses the scan, finds login pages, works out what kind of device is
answering (HP printer, iDRAC, Tomcat, …), screenshots them, tries the
matching vendor default credentials and/or the operator's own list, and
writes JSON + text + a self-contained interactive HTML report, opening
the HTML at the end.

Design note: parsing/classification/reporting run with no network access
at all. Anything that actually touches a target host (screenshots,
credential testing) additionally requires the explicit --authorized flag,
so an accidental invocation can never generate traffic against a client's
estate.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from nwaa import __version__
from nwaa.browser import browser_available, has_display, install_browser, platform_report
from nwaa.classifier import identify_login_pages
from nwaa.credential_tester import (
    DEFAULT_MAX_ATTEMPTS_PER_PAGE,
    HARD_MAX_ATTEMPTS_PER_PAGE,
    LOCKOUT_WARNING,
    AttemptOptions,
    CredentialConfigError,
    load_credentials,
    test_credentials_against_pages,
)
from nwaa.default_creds import (
    credentials_for_fingerprint,
    describe_profiles,
    get_profile,
    profile_ids,
)
from nwaa.fingerprint import (
    fingerprint_from_probe,
    fingerprint_services,
    manual_fingerprint,
    merge_fingerprints,
)
from nwaa.html_report import write_html_report
from nwaa.logging_utils import configure_logging
from nwaa.models import (
    Credential,
    DeviceFingerprint,
    HttpProbe,
    LoginPage,
    ScanResult,
    service_key,
)
from nwaa.nessus_parser import NessusParseError, parse_nessus_file
from nwaa.probe import probe_login_pages
from nwaa.report import build_json_report, render_text_report, write_json_report, write_text_report
from nwaa.scope import ScopeRegistry, build_scope
from nwaa.screenshot import ScreenshotOptions, screenshot_login_pages

logger = logging.getLogger("nwaa.cli")

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_PARSE_ERROR = 2
EXIT_CREDENTIAL_CONFIG_ERROR = 3
EXIT_MISSING_DEPENDENCY = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nwaa",
        description=(
            "Identify web login pages from a .nessus scan, fingerprint the device behind "
            "each one, screenshot them, and optionally test credentials against them - "
            "either your own, or that vendor's published factory defaults. "
            "Only use against systems you have written authorization to test."
        ),
    )
    parser.add_argument("--version", action="version", version=f"nwaa {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="Parse, fingerprint, screenshot, test, report - the whole job in one command",
    )
    scan.add_argument("--nessus", required=True, help="Path to the .nessus file")
    scan.add_argument("--out", default="./nwaa-output", help="Output directory for reports/screenshots")
    scan.add_argument(
        "--authorized",
        action="store_true",
        help=(
            "Confirm you have written authorization to actively test the hosts in this "
            ".nessus file. Required for screenshots and credential testing; with it, "
            "screenshots are captured by default."
        ),
    )
    scan.add_argument(
        "--no-screenshot",
        action="store_true",
        help="Skip screenshots even when --authorized is given",
    )
    scan.add_argument("--full-page", action="store_true", help="Capture full-page (not viewport) screenshots")
    scan.add_argument(
        "--credentials",
        help="Path to a JSON file of credentials to test (see docs/USAGE.md).",
    )
    scan.add_argument(
        "--default-creds",
        action="store_true",
        help=(
            "Fingerprint each web login (HP printer, iDRAC, Tomcat, …) and try that "
            "vendor's published default credentials against it. Requires --authorized. "
            "Only the profile matching the detected device is used; the per-page attempt "
            "cap still applies. See 'nwaa profiles'."
        ),
    )
    scan.add_argument(
        "--profile",
        help=(
            "Force a default-credential profile for every login page instead of relying "
            "on fingerprinting (e.g. --profile hp-printer). Implies --default-creds."
        ),
    )
    scan.add_argument(
        "--no-fingerprint",
        action="store_true",
        help="Skip device fingerprinting entirely (disables --default-creds)",
    )
    scan.add_argument(
        "--max-attempts-per-page",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS_PER_PAGE,
        help=(
            f"Cap on credential attempts per login page "
            f"(default {DEFAULT_MAX_ATTEMPTS_PER_PAGE}, hard ceiling {HARD_MAX_ATTEMPTS_PER_PAGE})"
        ),
    )
    scan.add_argument("--timeout-ms", type=int, default=15_000, help="Per-navigation timeout in milliseconds")
    scan.add_argument(
        "--install-browser",
        action="store_true",
        help="Download Chromium first if it is missing, instead of failing",
    )
    scan.add_argument(
        "--no-embed-screenshots",
        action="store_true",
        help="Link screenshots from the HTML report instead of embedding them (smaller file)",
    )
    scan.add_argument("--open", action="store_true", help="Open the HTML report when finished")
    scan.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    scan.add_argument("--log-format", default="json", choices=["json", "text"])

    view = sub.add_parser("view", help="Rebuild the interactive HTML viewer from a saved report.json")
    view.add_argument(
        "--json", dest="json_path", required=True, help="Path to a report.json produced by scan"
    )
    view.add_argument("--html", dest="html_path", help="Output path (default: alongside the JSON)")
    view.add_argument(
        "--no-embed-screenshots",
        action="store_true",
        help="Link screenshots instead of embedding them",
    )
    view.add_argument("--open", action="store_true", help="Open the HTML report when finished")
    view.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    view.add_argument("--log-format", default="json", choices=["json", "text"])

    setup = sub.add_parser("setup", help="Download the Chromium build Playwright needs (run once)")
    setup.add_argument(
        "--with-deps",
        action="store_true",
        help="Also install the Linux system libraries Chromium needs (Debian/Kali; must run as root)",
    )
    setup.add_argument(
        "--check",
        action="store_true",
        help="Only report what nwaa sees about this machine; download nothing",
    )
    setup.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    setup.add_argument("--log-format", default="text", choices=["json", "text"])

    profiles = sub.add_parser(
        "profiles", help="List the bundled vendor default-credential profiles"
    )
    profiles.add_argument(
        "--show-passwords",
        action="store_true",
        help="Also print the exact username/password pairs each profile would submit",
    )
    profiles.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    profiles.add_argument("--log-format", default="text", choices=["json", "text"])

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(level=args.log_level, json_output=args.log_format == "json")

    if args.command == "scan":
        return run_scan(args)
    if args.command == "view":
        return run_view(args)
    if args.command == "setup":
        return run_setup(args)
    if args.command == "profiles":
        print(describe_profiles(show_passwords=args.show_passwords))
        return EXIT_OK
    parser.print_help()
    return EXIT_USAGE


def run_setup(args: argparse.Namespace) -> int:
    print(platform_report())
    if args.check:
        return EXIT_OK
    ok, detail = install_browser(with_deps=args.with_deps)
    if not ok:
        logger.error("Browser setup failed: %s", detail)
        return EXIT_MISSING_DEPENDENCY
    logger.info("Browser setup complete: %s", detail)
    return EXIT_OK


def run_view(args: argparse.Namespace) -> int:
    json_path = Path(args.json_path)
    try:
        report = json.loads(json_path.read_text(encoding="utf-8"))
    except OSError as exc:
        logger.error("Could not read %s: %s", json_path, exc)
        return EXIT_USAGE
    except json.JSONDecodeError as exc:
        logger.error("%s is not valid JSON: %s", json_path, exc)
        return EXIT_USAGE

    if not isinstance(report, dict) or report.get("tool") != "nwaa":
        logger.error("%s does not look like an nwaa report.json", json_path)
        return EXIT_USAGE

    html_path = Path(args.html_path) if args.html_path else json_path.with_suffix(".html")
    write_html_report(report, html_path, embed_screenshots=not args.no_embed_screenshots)
    logger.info("Wrote HTML report", extra={"html": str(html_path)})
    print(f"HTML report: {html_path}")
    if args.open:
        _open_in_browser(html_path)
    return EXIT_OK


def run_scan(args: argparse.Namespace) -> int:
    want_defaults = (args.default_creds or bool(args.profile)) and not args.no_fingerprint
    want_screenshots = args.authorized and not args.no_screenshot
    active_requested = want_screenshots or bool(args.credentials) or want_defaults

    if (args.credentials or want_defaults) and not args.authorized:
        logger.error(
            "Credential testing requires --authorized (written authorization to test these hosts)."
        )
        return EXIT_USAGE
    if args.profile and args.profile not in profile_ids():
        logger.error(
            "Unknown profile %r. Run 'nwaa profiles' to list the bundled profiles.", args.profile
        )
        return EXIT_USAGE
    if args.no_fingerprint and (args.default_creds or args.profile):
        logger.error("--no-fingerprint cannot be combined with --default-creds/--profile")
        return EXIT_USAGE
    if not args.authorized:
        logger.info(
            "Parse-only mode: no host will be contacted. Pass --authorized to capture "
            "screenshots and test credentials."
        )
    if args.max_attempts_per_page < 1:
        logger.error("--max-attempts-per-page must be >= 1")
        return EXIT_USAGE
    if args.timeout_ms < 1_000:
        logger.error("--timeout-ms must be >= 1000")
        return EXIT_USAGE

    try:
        scan = parse_nessus_file(args.nessus)
    except NessusParseError as exc:
        logger.error("Failed to parse Nessus file: %s", exc)
        return EXIT_PARSE_ERROR

    # Checked after parsing so a bad .nessus path fails fast, but before any
    # target is contacted so a missing browser is not discovered mid-scan.
    if active_requested and not _ensure_browser(args.install_browser):
        return EXIT_MISSING_DEPENDENCY

    services = list(scan.services)
    login_pages = identify_login_pages(scan)
    scope = build_scope(services)

    result = ScanResult(
        nessus_file=scan.source_path,
        generated_at=datetime.now(timezone.utc).isoformat(),
        services=services,
        login_pages=login_pages,
    )

    # Offline fingerprinting costs nothing and runs even in parse-only mode.
    if not args.no_fingerprint:
        result.fingerprints = fingerprint_services(scan)
        if args.profile:
            forced = manual_fingerprint(args.profile)
            for page in login_pages:
                result.fingerprints[service_key(page.service)] = forced
            logger.warning(
                "Forcing default-credential profile %s for every login page (--profile)",
                args.profile,
            )

    logger.info(
        "Parsed Nessus scan",
        extra={
            "services": len(services),
            "web_services": sum(1 for s in services if s.is_web),
            "plaintext_http": sum(1 for s in services if s.is_plaintext_http),
            "login_pages": len(login_pages),
            "devices_fingerprinted": len(result.fingerprints),
        },
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if want_screenshots:
        result.screenshots = screenshot_login_pages(
            login_pages,
            scope,
            out_dir / "screenshots",
            ScreenshotOptions(timeout_ms=args.timeout_ms, full_page=args.full_page),
        )

    if want_defaults and not args.profile:
        probes = _collect_probes(result, login_pages, scope, args.timeout_ms)
        _refine_fingerprints(result, login_pages, probes)

    try:
        credentials = load_credentials(args.credentials) if args.credentials else []
    except CredentialConfigError as exc:
        logger.error("Credential config error: %s", exc)
        return EXIT_CREDENTIAL_CONFIG_ERROR

    defaults_by_url: dict[str, list[Credential]] = {}
    if want_defaults:
        defaults_by_url = _default_credentials_by_url(result, login_pages)
        result.warnings.append(LOCKOUT_WARNING)
        logger.warning(LOCKOUT_WARNING)
        if not defaults_by_url:
            message = (
                "No login page fingerprinted to a profile with published default "
                "credentials; nothing to try. Use --profile to force one, or "
                "'nwaa profiles' to see what is available."
            )
            result.warnings.append(message)
            logger.warning(message)

    if credentials or defaults_by_url:
        options = AttemptOptions(
            timeout_ms=args.timeout_ms, max_attempts_per_page=args.max_attempts_per_page
        )
        result.attempts = test_credentials_against_pages(
            login_pages, credentials, scope, options, defaults_by_url
        )

    json_path = write_json_report(result, out_dir / "report.json")
    text_path = write_text_report(result, out_dir / "report.txt")
    html_path = write_html_report(
        build_json_report(result),
        out_dir / "report.html",
        embed_screenshots=not args.no_embed_screenshots,
    )
    logger.info(
        "Wrote reports",
        extra={"json": str(json_path), "text": str(text_path), "html": str(html_path)},
    )

    print(render_text_report(result))
    print(f"\nJSON report : {json_path}")
    print(f"Text report : {text_path}")
    print(f"HTML report : {html_path}")
    if args.open:
        _open_in_browser(html_path)
    return EXIT_OK


def _collect_probes(
    result: ScanResult, login_pages: list[LoginPage], scope: ScopeRegistry, timeout_ms: int
) -> dict[str, HttpProbe]:
    """Live banners for each login page, reusing the screenshot pass if it ran.

    Only pages the screenshot pass did not already cover get their own
    request, so enabling --default-creds never doubles the traffic.
    """
    probes: dict[str, HttpProbe] = {
        shot.login_page.url: shot.probe for shot in result.screenshots if shot.probe is not None
    }
    remaining = [page for page in login_pages if page.url not in probes]
    if remaining:
        probes.update(probe_login_pages(remaining, scope, timeout_ms))
    return probes


def _refine_fingerprints(
    result: ScanResult, login_pages: list[LoginPage], probes: dict[str, HttpProbe]
) -> None:
    """Fold live banner fingerprints into the offline ones, in place."""
    for page in login_pages:
        probe = probes.get(page.url)
        if probe is None:
            continue
        live = fingerprint_from_probe(probe)
        if live is None:
            continue
        key = service_key(page.service)
        merged = merge_fingerprints(result.fingerprints.get(key), live)
        if merged is not None:
            result.fingerprints[key] = merged


def _default_credentials_by_url(
    result: ScanResult, login_pages: list[LoginPage]
) -> dict[str, list[Credential]]:
    """Map each login page to the default credentials for its device profile."""
    by_url: dict[str, list[Credential]] = {}
    for page in login_pages:
        fingerprint: DeviceFingerprint | None = result.fingerprints.get(service_key(page.service))
        if fingerprint is None:
            continue
        credentials = credentials_for_fingerprint(fingerprint)
        if credentials:
            by_url[page.url] = credentials
            logger.info(
                "Selected vendor default profile",
                extra={
                    "url": page.url,
                    "profile": fingerprint.profile_id,
                    "confidence": fingerprint.confidence,
                    "credentials": len(credentials),
                },
            )
            continue
        profile = get_profile(fingerprint.profile_id)
        if profile is not None and profile.is_empty:
            note = (
                f"{page.url} fingerprinted as {profile.display_name}, which has no published "
                f"factory default to try. {profile.notes}".strip()
            )
            result.warnings.append(note)
            logger.info("%s", note)
    return by_url


def _ensure_browser(auto_install: bool) -> bool:
    ready, detail = browser_available()
    if ready:
        return True
    if not auto_install:
        logger.error("%s", detail)
        return False
    installed, install_detail = install_browser()
    if not installed:
        logger.error("Browser setup failed: %s", install_detail)
        return False
    return True


def _open_in_browser(path: Path) -> None:
    # On a headless Kali box (SSH, console, container) webbrowser either
    # fails or launches a text browser over the report we just printed.
    if not has_display():
        logger.info("No desktop session detected; not opening a browser. Report: %s", path)
        return
    try:
        webbrowser.open(path.resolve().as_uri())
    except (webbrowser.Error, ValueError) as exc:
        logger.warning("Could not open a browser automatically: %s", exc)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
