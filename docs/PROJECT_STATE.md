# Project state

_Last updated: 2026-09-02_

## Where to pick up

The offline half of the tool is **built, executed, and green**. The active half
(anything that drives a browser) is **written but has never run**. Closing that
is the next job — see "Exact next steps".

## How this project is developed (two machines)

| | |
| --- | --- |
| **Windows** `C:\Users\jdejesus\Documents\Scripts\nessus-web-auth-audit` | Where edits are made and committed. Has git (2.55) but **no Python** — nothing can be run here. |
| **Kali** `~/Documents/nessus-web-auth-audit` (user `jose`) | Where everything is installed, run, and tested. venv at `.venv`, editable install. |
| **GitHub** `github.com/joseadejezus/nessus-web-auth-audit` | Public. `main`. The sync point. |

Loop: edit + commit + push on Windows → `git pull && pytest` on Kali. Both
copies are real git clones; don't edit the same file on both sides between
pulls. On Kali, work as `jose` and inside the venv — as root, pipx and
Playwright use `/root` and you get a second, invisible install.

## Completed work

### Session 4 — first execution, publish, README

- **First run ever.** Installed on Kali (Python 3.14.6, Playwright 1.62.0).
  `pytest` 147 passed; `ruff` clean. Fixed what the other two found:
  `types-defusedxml` added to dev extras (mypy could not see into defusedxml
  at all before, which was hiding real errors), bandit's two `browser.py`
  findings annotated `# nosec` at the call site with justification rather than
  skipped repo-wide.
- **Real bug found by mypy**, once the stubs were in: `tree.getroot()` is
  `Element | None` and `parse_nessus_file` used it three times assuming an
  `Element`. A rootless tree would have raised `AttributeError` out of the
  parser instead of `NessusParseError` — a traceback rather than a clean exit
  code 2 on untrusted input. Guarded.
- **Published to GitHub** (public, MIT). `pipx install git+https://...` works.
- **First end-to-end offline run verified** against `tests/fixtures/devices.nessus`:
  3 services / 2 plaintext / 3 login pages / 2 devices fingerprinted, exactly
  matching the test assertions. HP printer and iDRAC both `high` confidence with
  three evidence patterns each; the plain nginx host correctly fingerprinted as
  **nothing** (the negative case that keeps this a targeted check).
- **README rewritten** for people installing the tool: banner, badges, real
  captured output, device-coverage table, safety-rails table, honest alpha
  status. CLI help text refreshed — it still described the pre-fingerprinting
  tool.

### Session 3 — Kali as the target platform, device fingerprinting, vendor defaults

Two changes, both requested for real engagement use on Kali:

**1. Device fingerprinting → matching vendor default credentials.**

- `fingerprint.py` — signature table (42 profiles: printers/MFPs, BMCs, network
  gear, cameras, NAS, app servers) plus a scoring matcher. Two sources: the
  `.nessus` plugin text and host tags (offline, weight 1), and live
  `Server` / `WWW-Authenticate` / title / body banners (weight 3).
  `merge_fingerprints` combines them without letting a generic live match
  displace a specific offline one. Every match carries the patterns that fired.
- `data/default_credentials.json` — the vendor factory credentials, keyed by
  profile id, ≤ 12 per profile, with notes. iLO/ESXi/Jenkins are deliberately
  empty (no fixed factory default) with an explanation instead of a guess.
- `default_creds.py` — loads/validates that file (`importlib.resources`), turns a
  fingerprint into `Credential`s with `source="vendor_default"`, registers every
  password for redaction, and renders `nwaa profiles`.
- `probe.py` — reads banners from the page load the screenshot pass already
  performs; standalone one-GET-per-page pass only when screenshots are off.
- `credential_tester.py` — `combine_credentials()` (operator first, then
  defaults, deduped) and the per-page cap moved inside the page loop, so vendor
  defaults cannot raise the number of attempts a page receives.
- `nessus_parser.py` — captures `HostFacts` (operating-system / system-type /
  netbios-name tags, truncated) to feed offline fingerprinting.
- CLI: `--default-creds`, `--profile ID`, `--no-fingerprint`, and a new
  `nwaa profiles [--show-passwords]` subcommand.
- Reports: `devices` array + inline `device` on login pages and web services,
  `credential_source` on every attempt, a `DEVICES IDENTIFIED` text section, a
  **Devices** tab and vendor-default badges in the HTML viewer.

**2. Kali/Linux support** (all platform logic consolidated in `browser.py`):

- `chromium_launch_kwargs()` used by all three browser passes: `--no-sandbox`
  only when euid 0 on Linux (with a warning), `--disable-dev-shm-usage` on Linux.
- `install_browser(with_deps=)` → `playwright install --with-deps chromium`,
  gated to Linux+root; failure messages name the apt/`install-deps` fix.
- `has_display()` stops `--open` from launching a text browser over headless SSH.
- `browsers_path()` + `platform_report()` (`nwaa setup --check`) expose the
  `sudo` → `/root/.cache/ms-playwright` trap.
- Docs rewritten for Kali: pipx/PEP 668, `--with-deps`, a gotchas table.

New tests: `test_fingerprint.py`, `test_default_creds.py`, `test_probe.py`,
`test_browser_platform.py`, plus additions to the parser, credential-tester,
CLI, HTML and packaging suites and a new `tests/fixtures/devices.nessus`
(HP printer, iDRAC, and a plain nginx host that must *not* fingerprint).

`CLAUDE.md`'s "no hardcoded credentials" rule was rewritten rather than broken:
credentials may now come from exactly two places (operator file, or the bundled
publicly-documented vendor profile matching a detected device), with the
wordlist ceiling, the no-credentials-in-`.py` rule and the attempt cap all
enforced by tests.

### Session 1 — initial implementation

Full `nwaa` CLI: `models.py`, `nessus_parser.py` (defusedxml, per-`host:port`
aggregation), `classifier.py` (plaintext-HTTP and login-page identification),
`scope.py` (`ScopeRegistry`), `screenshot.py` (Playwright + URL banner +
traversal-safe filenames), `credential_tester.py` (credential loading, attempt
caps, pure verdict classifier), `report.py` (JSON + text), `redaction.py`,
`logging_utils.py`, `cli.py`. Tests and fixtures for every offline module.
Docs: `CLAUDE.md`, `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `USAGE.md`.

### Session 2 — one-command UX, pipx install, HTML viewer

- `html_report.py` — self-contained interactive HTML report: inline CSS/JS,
  base64-embedded screenshots, tabs (Overview / Login pages / Plaintext HTTP /
  Credential attempts / Screenshots / Web services), live filter, verdict filter
  chips, screenshot lightbox, light/dark, print stylesheet. Report data is
  embedded as `\u`-escaped JSON and rendered exclusively via
  `createElement`/`textContent`.
- `browser.py` — `browser_available()` and `install_browser()`, running
  `sys.executable -m playwright install chromium` so the binary lands in nwaa's
  own (pipx) venv.
- `cli.py` reworked: `scan` now does everything in one go — with `--authorized`
  it screenshots by default (`--no-screenshot` to opt out), tests credentials
  when `--credentials` is given, and always writes JSON + text + HTML. Added
  `--install-browser`, `--no-embed-screenshots`, `--open`. New subcommands:
  `view` (rebuild the HTML viewer from a saved `report.json`) and `setup`
  (one-time Chromium download).
- `credential_tester.test_credentials_against_pages()` — one browser session for
  all pages (still a fresh context per credential). The single-page function is
  now a thin wrapper.
- Packaging for pipx: keywords/classifiers, `LICENSE`, and
  `tests/test_packaging.py` asserting the console-script target resolves, no
  module-scope playwright import exists, and stdlib `xml` is never imported.
- `tests/test_html_report.py` — standalone-document, no-external-resources,
  script-breakout, embedding/linking, and password-redaction tests.

## Current work

None in progress.

## Tests / results

**First execution: 2026-09-02, on Kali (Python 3.14.6, Playwright 1.62.0),
inside a venv as an unprivileged user.**

```
pytest        147 passed in 0.68s
ruff check .  All checks passed!
mypy          clean (was: 2 stub errors, then 3 real union-attr errors the stubs
              exposed in nessus_parser — all fixed)
bandit -r src clean (2 Low findings in browser.py reviewed and annotated
              `# nosec` at the call site: fixed argv, shell=False, no external input)
pip-audit     1 vulnerability: pip 26.1.2 (PYSEC-2026-3721, fixed in 26.2) — the
              venv's own pip, not a project dependency. nwaa itself skipped
              (not on PyPI). No nwaa dependency is affected.
```

End-to-end offline run, verified on Kali:

```
nwaa scan --nessus tests/fixtures/devices.nessus --out ./out
  → 3 services, 3 web, 2 plaintext, 1 TLS, 3 login pages, 2 devices
  → 10.10.10.20:80  hp-printer  [high]  3 evidence patterns
  → 10.10.10.21:443 dell-idrac  [high]  3 evidence patterns
  → 10.10.10.22:80  no fingerprint (plain nginx) — the negative case works
  → report.json + report.txt + report.html all written
```

Everything the suite covers is offline by design. **What still has no execution
coverage at all is every line that drives a browser**: `screenshot_login_pages`,
`test_credentials_against_pages`, `probe_login_pages`, and the JS in
`html_report.py`. Those need a live target — see "Exact next steps".

Re-run the full gate with:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check . && mypy && bandit -r src && pip-audit
```

pipx path to verify separately:

```bash
pipx install .        # or: pipx install git+https://github.com/joseadejezus/nessus-web-auth-audit.git
nwaa --version
nwaa setup --check
nwaa setup
nwaa profiles
nwaa scan --nessus tests/fixtures/devices.nessus --out ./out
```

## Known issues

1. The offline suite passes (147 tests), but **the browser-driving code has
   never run**. That is the single biggest remaining unknown.
2. Playwright call sites (`screenshot_login_pages`, `test_credentials_against_pages`,
   `probe_login_pages`, `browser.py`) have no automated coverage — they need a
   real browser. `docs/USAGE.md` has a manual verification procedure.
   `probe_open_page` *is* covered, via stub page/response objects.
3. The JS in `html_report.py` partially verified in a browser (2026-09-02,
   Kali/Firefox, dark mode): header, cards, tabs, Overview and the note all
   render. **The `hidden` toggle on the chips row was broken and is now fixed**
   — an author `display: flex` rule beat the UA stylesheet's `[hidden]` rule, so
   the verdict chips showed on every tab; an explicit
   `[hidden] { display: none !important; }` fixes it, with a regression test.
   Still unverified: `<dialog>.showModal()` for the screenshot lightbox, the
   verdict chips actually filtering, and lazy-loaded data-URI images — all need
   a report that contains screenshots and credential attempts, i.e. an
   `--authorized` run.
4. Login-page discovery is limited to what the Nessus scan recorded; GET-only
   probing of common login paths was deliberately not built.
5. Only form-based logins are driven; HTTP Basic/NTLM/client-cert returns
   `not_tested`.
6. `_submit()` falls back to clicking the first `<button>`, which on some pages
   is "cancel" or a language switcher. Check `inconclusive` verdicts against the
   screenshot.
7. Embedded screenshots make `report.html` large (roughly the sum of the PNGs,
   ×1.37 for base64). `--no-embed-screenshots` is the escape hatch; a single
   capture over 8 MB is linked rather than inlined.
8. `ruff` E501 is disabled for `html_report.py` because it holds the HTML/CSS/JS
   template as a string.
9. No CI configuration (no git repo on this machine to attach one to).
10. **Fingerprint signatures have never seen a real device banner.** The regexes
    were written from vendor documentation, not from captured traffic. The
    likeliest failure modes are a missed match (falls back to `generic-*`, or to
    no default credentials at all — safe) and a wrong match sending one vendor's
    defaults at another's device (`--profile` overrides; tighten the signature
    and add a regression test).
11. **The bundled defaults are vendor-published, not per-unit.** Firmware
    revisions have moved several vendors (Axis, Hikvision, Supermicro, iDRAC9)
    to per-unit or forced-set passwords. "Nothing worked" is not evidence of
    hardening.
12. `--default-creds` warns about account lockout and appends `LOCKOUT_WARNING`
    to the report on every run, even when nothing ends up being tried.
    Deliberate, but noisy.
13. Kali-specific paths (`--no-sandbox` as root, `--with-deps`, the headless
    `--open` skip) are unit-tested through stubs only; none has been exercised
    on an actual Kali box.
14. `--profile` forces one profile onto *every* login page in the scan. For a
    mixed estate, run it against a filtered `.nessus` or rely on fingerprinting.

## Security decisions

- `.nessus` input is untrusted: defusedxml only, `xml.etree` banned repo-wide
  (asserted by a test), port values range-checked, forbidden-XML surfaced as a
  clean parse failure (exit code 2).
- Scope is derived from the scan file and cannot be extended by a flag. Enforced
  twice: URL check before navigation, Playwright route abort for every request
  including redirects and subresources.
- `HARD_MAX_ATTEMPTS_PER_PAGE = 20` is a ceiling callers cannot raise; default 5.
  It applies to the operator list and the vendor defaults *combined*, per page.
  No wordlist support, no credential generation, no retry loops.
- Credentials come from exactly two places: the operator's JSON file, or the
  bundled vendor profile matching a device's fingerprint. The bundled profiles
  are public factory defaults, live in one reviewable JSON data file, are capped
  at 12 entries each, and may not appear in any `.py` file (test-enforced).
- No engagement credential values anywhere in the repo; `.gitignore` blocks
  `*credentials*.json` and `*.nessus` (except test fixtures).
- Vendor defaults are applied only to the profile that was detected — there is
  no "try every profile" mode, and detection evidence is recorded per match.
- Chromium's sandbox is dropped only when running as root on Linux, and says so.
- Passwords are wrapped in `SecretStr`, registered for redaction on load,
  scrubbed at both logger and handler level, and reports are serialized
  field-by-field. `build_json_report` is the single serialization point, so the
  text and HTML reports inherit the same redaction.
- The HTML report treats its own data as attacker-influenced: `\u`-escaped JSON
  in the data island, DOM built with `createElement`/`textContent`, no external
  resources (test-enforced).
- `browser.py` shells out with a fixed argv list and no shell.
- Active modes require `--authorized`; parse/report is network-free.

## Exact next steps

Done in session 4 (do not redo): environment setup, `pytest`/`ruff`/`mypy`/
`bandit`/`pip-audit`, publishing to GitHub, `pipx` install, and the offline
end-to-end scan. Everything below is genuinely still open, in priority order.

1. **Open `out/report.html` in a browser** and click every tab — especially the
   new **Devices** tab — plus the filter box, the verdict chips, and a
   screenshot lightbox. This JS has never been parsed by a browser. Cheapest
   remaining unknown to eliminate.
2. **Build the local lab harness** — the highest-value item, because it is the
   only thing that exercises the active half of the tool:
   - a `http.server` on 127.0.0.1 sending `Server: HP HTTP Server` and serving a
     login form that accepts `admin` with a blank password;
   - a `.nessus` pointing at that host:port (copy `tests/fixtures/devices.nessus`);
   - run `nwaa scan --authorized --default-creds` against it and confirm the full
     chain: live probe → `hp-printer` at `source: nessus+http` → screenshot with
     the URL banner → HP profile selected → `default_credentials_successful`.
   - Then the negative cases: wrong password → `authentication_failed`; a page
     with no password field → `not_tested`; an off-scope redirect → aborted.
3. **Promote that harness into the test suite** as an integration test so the
   Playwright paths stop being untested forever.
4. **Add CI** (`.github/workflows/ci.yml`) running `pytest`, `ruff check .`,
   `mypy`, `bandit -r src` on push. The repo is public now; a green badge is
   also the honest signal for the README's alpha status.
5. **Validate signatures against real devices** in a lab: at minimum an HP MFP,
   an iDRAC, and one camera. Record any banner that fails to match and tighten
   or add a signature with a regression test. Until this is done, treat the
   42 profiles as documentation-derived guesses.
6. `nwaa setup --check` as root **and** as `jose`, confirming the browsers path
   and `--no-sandbox` reporting match reality on each.
7. Perform the manual verification procedure in `docs/USAGE.md` against a lab
   target before any engagement use.
8. Consider tagging `v0.2.0` and writing release notes once 1–4 are done.
6. `git init`, commit, add CI running the four checks above.
7. Add an integration test serving a fake login page from `http.server` on
   127.0.0.1 to cover the Playwright paths (success, failure, timeout, an
   off-scope redirect that must be aborted, and a response carrying
   `Server: HP HTTP Server` so the live fingerprint path is exercised).
8. Validate the signature table against real devices in a lab: at minimum an HP
   MFP, an iDRAC, and one camera. Record any banner that fails to match and
   tighten or add a signature with a regression test.
9. Perform the manual verification procedure in `docs/USAGE.md` against a lab
   target before any engagement use.
