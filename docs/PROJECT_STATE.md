# Project state

_Last updated: 2026-09-02_

## Where to pick up

Both halves of the tool have now been executed and the **full gate is green on
Kali**: 154 tests (149 offline + 5 live), `ruff`/`mypy`/`bandit` clean. As of
2026-09-02 the browser-driving half has run against a real Chromium and did what
it was designed to do — see "Tests / results".

Next: look at the first CI run, then the manual viewer pass. See "Exact next
steps".

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

### Session 5 — a lab target, live tests, CI (written on Windows; not run)

The point of this session was to stop the browser-driving half of the tool from
being permanently untested. Nothing here has been executed — see "Tests /
results".

- **`tests/lab_server.py`** — a loopback HTTP server that impersonates an HP
  printer's embedded web server: `Server: HP HTTP Server` and an HP page title
  (the two things a live fingerprint scores), a form-based login that accepts
  `admin` with a blank password and answers everything else with "Invalid user
  name or password", and a 303 to a *different* URL with no password field on
  success — which is exactly what `classify_login_outcome` requires before it
  will say SUCCESS. It records every request it receives, so a test can assert
  that a request the scope guard should have blocked never arrived. It also
  writes the matching `.nessus` (`write_lab_nessus`), since scope comes from the
  scan file and cannot be widened by a flag. Runnable by hand:
  `python tests/lab_server.py --port 8080 --write-nessus /tmp/lab.nessus`.
- **`tests/test_integration_live.py`** — five tests, marked `integration`,
  driving a real Chromium through `cli.main()`:
  1. the whole chain — scan file → login page → screenshot (with the banner the
     fingerprint came from) → `hp-printer` at `source: nessus+http` → the HP
     profile's first credential succeeding and its second failing, with the lab
     server confirming it received exactly two POSTs;
  2. a scan file with no vendor hint at all, so `source: http` proves the live
     banner alone produced the match;
  3. a page with no password field → `not_tested`, and nothing submitted;
  4. the route guard: a login page carrying two 1x1 images, one on the
     authorized host and one on `127.0.0.2`. The in-scope one must be requested
     (proof the browser was loading images at all) and the off-scope one must
     not (proof the guard blocked it);
  5. a login URL on a port the scan never saw → refused before navigation, with
     the lab server recording zero requests.

  They skip themselves when Chromium is absent, so the offline suite stays green
  on a machine with no browser.
- **`.github/workflows/ci.yml`** — three jobs. `offline` runs
  `pytest`/`ruff`/`mypy`/`bandit` on 3.10 and 3.12 with **no** browser installed
  (which is also how the skip path gets tested); `integration` installs Chromium
  with `--with-deps`, prints `nwaa setup --check`, and runs `pytest -m
  integration` with `NWAA_REQUIRE_INTEGRATION=1` so a broken browser install
  fails loudly instead of passing as a green run with zero tests; `audit` runs
  `pip-audit` with `continue-on-error` (advisories land against the environment's
  own pip as often as against this project).
- **`CLAUDE.md`'s testing rule rewritten rather than broken.** It said live
  targets belong in a manual procedure, never the suite. It now says the suite
  stays offline *except* for live tests that bring their own loopback target,
  and that Playwright call sites must be covered by one — "it has never run" is
  not an acceptable state for the code that touches other people's devices.
- `docs/USAGE.md` gained "The local lab target" and "Automated live tests"
  sections; the manual procedure shrank to the three things a test genuinely
  cannot do (viewer lightbox/chips by hand, root vs. non-root on Kali, and real
  devices).
- **Vendor defaults are no longer registered for redaction** — the one `src/`
  change the first live run produced, and the reason the live test can now
  assert the full sentence `"No password field found on page"`. Rationale and
  the rule it replaces are under "Security decisions"; `CLAUDE.md` and
  `docs/SECURITY.md` were rewritten to match rather than left contradicting the
  code.
- **`# nosec` prose moved above the pragma** in `browser.py`. Bandit reads
  everything after `# nosec` as a list of test ids, so the B404 justification
  produced nine `Test in comment: <word> is not a test name or id` warnings on
  every run. The annotation is now `# nosec B404` with the reason on the lines
  above it. Same suppression, readable output.

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

None in progress. The full gate is green on Kali (see "Tests / results"). CI has
been pushed but its first run has not been looked at, and the manual viewer pass
has not been done.

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

**Full gate, green: 2026-09-02, on Kali as `jose` in the venv (Python 3.14.6,
Playwright 1.62.0), after the two fixes below.**

```
pytest        154 passed in 12.88s   # 149 offline + 5 live
ruff check .  All checks passed!
mypy          Success: no issues found in 17 source files
bandit -r src No issues identified (2973 LOC, 0 skipped)
pip-audit     1 vulnerability: pip 26.1.2 (PYSEC-2026-3721, fixed in 26.2) — the
              venv's own pip, unchanged since session 4. No nwaa dependency is
              affected; nwaa itself is skipped (not on PyPI).
```

**First live run: 2026-09-02, same day**, before those fixes. Chromium was
already installed, so the live tests ran as part of a plain `pytest`:

```
1 failed, 152 passed in 13.25s     # 148 offline + 5 live
```

**The browser-driving half of the tool has now been executed and behaves as
designed.** Four of the five live tests passed on the first run, with no change
to any `src/` file:

- the full default-credential chain — screenshot, live banner, `hp-printer` at
  `source: nessus+http`, the HP profile's blank-password entry returning
  `default_credentials_successful` and `admin/admin` returning
  `authentication_failed`, with the lab server confirming exactly two POSTs;
- the live-banner-only fingerprint (`source: http`);
- the route guard — the in-scope 1x1 image was requested, the `127.0.0.2` one
  was not;
- the out-of-scope login page, refused before navigation with zero requests.

The one failure was **test-side, not tool-side**: the assertion
`"No password field" in detail` failed because `password` is itself one of the
HP profile's default passwords, so the redaction registry had scrubbed the word
out of the detail string (`"No ***REDACTED*** field found on page"`). That led
to the redaction change under "Security decisions"; the live test now asserts
the full sentence, so the report text is its own regression test.

None of the predicted failure modes (the `_submit` fallback, `networkidle`
never settling, subresource timing in the scope test) materialised.

Still not run: CI.

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
   never run**. Session 5 wrote the tests that would run it; they have not been
   executed. That is still the single biggest remaining unknown.
2. Playwright call sites (`screenshot_login_pages`, `test_credentials_against_pages`,
   `probe_login_pages`, `browser.py`) now have automated coverage in
   `tests/test_integration_live.py` — pending its first run. `probe_open_page`
   was already covered via stub page/response objects.
3. The JS in `html_report.py` is **verified in a browser** for everything a
   parse-only report can exercise (2026-09-02, Kali/Firefox, dark mode): header,
   summary cards, all seven tabs, Overview, the Devices/Login pages/Plaintext/
   Web services renderers, the note, and the controls row correctly hiding on
   Overview and reappearing elsewhere.
   One real bug found and fixed in the process: an author `display: flex` rule
   beat the UA stylesheet's `[hidden]` rule, so `el.hidden = true` was a no-op
   and the verdict chips showed on every tab. Fixed with an explicit
   `[hidden] { display: none !important; }` and a regression test.
   Still unverified, because they need a report containing screenshots and
   attempts (i.e. an `--authorized` run): `<dialog>.showModal()` for the
   screenshot lightbox, the verdict chips actually filtering, and lazy-loaded
   data-URI images.
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
9. CI exists (`.github/workflows/ci.yml`) but has never run. The README badge
   will show "no status" until the first push to `main`. The `integration` job
   depends on `playwright install --with-deps chromium` working on
   `ubuntu-latest`; if it does not, that job needs pinning, not disabling.
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
15. **The route guard is host-level, the pre-navigation check is host+port.**
    `install_scope_guard` calls `is_host_in_scope`, which ignores the port, so a
    redirect or subresource pointing at an *unscanned port on a scanned host*
    is allowed through, even though the tool would never navigate there itself
    (`_attempts_for_page`/`screenshot_login_pages` check `is_url_in_scope`
    first). Noticed while writing the live scope test, not changed: tightening
    the guard to host+port would also block a device that legitimately redirects
    its login to another port on itself, which is common on BMCs. Decide
    deliberately; if it changes, the live test needs a case for it.
16. ~~Common vendor-default passwords over-redact the reports.~~ Fixed
    2026-09-02, same day it was found — see "Security decisions".
17. **Playwright prints asyncio teardown noise after the test summary.** Two
    `Task was destroyed but it is pending` / `TargetClosedError` blocks appear
    on stderr *after* `154 passed`, from `playwright/_impl/_connection.py` at
    interpreter shutdown on Python 3.14. Cosmetic: it happens after every test
    has finished, does not change the exit code, and nwaa's own teardown is
    correct (`browser.close()` in a `finally`, inside the `sync_playwright()`
    context manager). It is inside Playwright, not this repo. If it ever
    obscures a real failure in CI logs, the fix is a Playwright upgrade, not a
    change here.

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
- Passwords are wrapped in `SecretStr`, scrubbed at both logger and handler
  level, and reports are serialized field-by-field. `build_json_report` is the
  single serialization point, so the text and HTML reports inherit the same
  redaction.
- **Only operator-supplied passwords are registered with `nwaa.redaction`**
  (decided 2026-09-02, after the first live run). Bundled vendor defaults are
  not: they are factory credentials published in vendor manuals that
  `nwaa profiles --show-passwords` prints on request, and registering them meant
  the registry could not tell the string `password` in the HP profile from a
  real secret — it replaced that word in every scrubbed field it appeared in,
  producing `"No ***REDACTED*** field found on page"` in a live report and
  threatening the same for a target's own page title and `Server` banner.
  Nothing interpolates a password into a report string (`build_json_report`
  never touches `Credential.password`), so the registry was protecting nothing
  here that is not already public. `SecretStr` still covers every password. If a
  password ever does reach a report string, that call site is the bug — do not
  re-register the defaults to paper over it.
- The HTML report treats its own data as attacker-influenced: `\u`-escaped JSON
  in the data island, DOM built with `createElement`/`textContent`, no external
  resources (test-enforced).
- `browser.py` shells out with a fixed argv list and no shell.
- Active modes require `--authorized`; parse/report is network-free.

## Exact next steps

Done in session 4 (do not redo): environment setup, `pytest`/`ruff`/`mypy`/
`bandit`/`pip-audit`, publishing to GitHub, `pipx` install, and the offline
end-to-end scan. Done in session 5: the lab server, the live tests, and CI —
written, pushed, and run on Kali with the full gate green (154 tests, ruff,
mypy, bandit). Everything below is genuinely still open, in priority order.

1. **Watch the first CI run.** The `integration` job's `playwright install
   --with-deps chromium` on `ubuntu-latest` is the untested part. Fix forward;
   do not disable the job.
2. **Manual viewer pass on a lab report** — run `python tests/lab_server.py
   --port 8080 --write-nessus /tmp/lab.nessus`, scan it with `--authorized
   --default-creds`, then open `report.html` and exercise the three things
   known issue 3 still lists as unverified: `<dialog>.showModal()` for the
   screenshot lightbox, the verdict chips actually filtering, and lazy-loaded
   data-URI images.
4. `nwaa setup --check` as root **and** as `jose`, confirming the browsers path
   and `--no-sandbox` reporting match reality on each (known issue 13).
5. **Validate signatures against real devices** in a lab: at minimum an HP MFP,
   an iDRAC, and one camera. Record any banner that fails to match and tighten
   or add a signature with a regression test. Until this is done, treat the
   42 profiles as documentation-derived guesses (known issue 10).
6. Decide known issue 15 (host-level route guard) deliberately, one way or the
   other, and write the outcome down.
7. Tag `v0.2.0` with release notes once 1–2 are done.
