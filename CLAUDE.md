# CLAUDE.md — working agreement for this repository

## Start of every session

1. Read this file and `docs/PROJECT_STATE.md`.
2. Inspect the code before changing it (`src/nwaa/`, `tests/`).
3. Run the test suite: `pytest` (from the repo root, with the dev extras
   installed). If no Python interpreter exists on the machine, say so instead of
   claiming the suite passed. On Kali: `sudo apt install python3-pip pipx`, then
   `pip install -e ".[dev]" --break-system-packages` in a venv or `pipx install .`
   — Debian marks the system Python externally managed (PEP 668).
4. Continue from "Exact next steps" in `docs/PROJECT_STATE.md`. Do not restart or
   rewrite working code that already passes tests.

## After every significant change

Update `docs/PROJECT_STATE.md` with: completed work, current work, tests/results,
known issues, security decisions, and exact next steps. Keep it truthful — if
tests were not run, say so and why.

## What this project is

A CLI that reads a `.nessus` file, identifies web services and login pages,
fingerprints the device behind each one (HP printer, iDRAC, Tomcat, …),
screenshots those pages (URL burned into the image), and optionally tests
credentials against them — either an operator-supplied list, or the published
vendor defaults for the detected device. Reports in JSON, text, and HTML.

**Target platform is Kali Linux.** It runs on Windows and macOS too, but Linux
is the supported path: root-shell Chromium flags, `playwright install-deps`,
headless (no-DISPLAY) behaviour, and PEP 668 / pipx install notes all exist for
Kali specifically. Anything platform-conditional belongs in `browser.py`.

## Non-negotiable rules (enforced in code, not just prose)

- **Credentials come from exactly two places.** An operator-supplied JSON file,
  or `src/nwaa/data/default_credentials.json` — the bundled, publicly-documented
  vendor factory defaults, applied *only* to a target that fingerprinted as that
  device (or that the operator named with `--profile`). No third source. Do not
  add credentials to any `.py` file; `tests/test_packaging.py` asserts that.
- **Default-credential profiles must not become wordlists.**
  `MAX_CREDENTIALS_PER_PROFILE` (12) is validated at load time, and the per-page
  cap applies to the *combined* operator + default list. A profile with no fixed
  factory default (iLO, ESXi, Jenkins) stays deliberately empty with a note
  saying why — do not fill it with guesses.
- **No brute force or spraying.** `HARD_MAX_ATTEMPTS_PER_PAGE` in
  `credential_tester.py` is a ceiling a caller cannot raise. Do not add
  wordlist loading, credential permutation, or retry-on-failure loops.
- **Fingerprinting must be evidence-backed.** Every `DeviceFingerprint` records
  the patterns that produced it, and a signature needs a positive *and* a
  negative test (`tests/test_fingerprint.py`) — a wrong guess sends the wrong
  vendor's credentials at a live device.
- **No out-of-scope traffic.** Every navigation is checked against the
  `ScopeRegistry` built from the `.nessus` file, and a Playwright route handler
  aborts requests to hosts outside it. Do not add a "skip scope check" flag.
- **No secrets in logs or reports.** Every password is wrapped in `SecretStr`,
  so no accidental `repr`/`str`/f-string can print one. Never log a raw
  password, never serialize a `Credential` with `dataclasses.asdict`.
  **Only operator-supplied passwords are additionally registered with
  `nwaa.redaction`** (in `credential_tester.load_credentials`). The bundled
  vendor defaults deliberately are not: they are factory credentials published
  in vendor manuals that `nwaa profiles --show-passwords` prints on request, and
  registering them meant the registry could not tell the string `password` in
  the HP profile from a real secret — it scrubbed that word out of every report
  field it appeared in, a target's own page title included. If you ever
  interpolate a password into a report or log string, that is the bug; fix that
  rather than re-registering the defaults.
- **Untrusted XML.** `.nessus` files are parsed with `defusedxml` only. Never
  import `xml.etree.ElementTree` in this project.
- **No `innerHTML` in the HTML report.** Everything the viewer renders came from
  scan data. Build DOM with `createElement`/`textContent`, keep the embedded
  JSON `\u`-escaped, and keep the report free of external resources — the tests
  in `tests/test_html_report.py` and `tests/test_packaging.py` enforce all three.
- **Active modes require `--authorized`.** Parsing/reporting must stay
  network-free so it is always safe to run.

## Code conventions

- Python ≥ 3.10, type hints throughout, `from __future__ import annotations`.
- Pure logic (parsing, classification, verdicts, filenames) stays free of
  Playwright imports so it is unit-testable without a browser. Playwright is
  imported lazily inside the functions that drive it.
- Comments explain *why*, not *what*. Most code needs none.
- Lint/type/security: `ruff check .`, `mypy`, `bandit -r src`, `pip-audit`.

## Testing

- **The default suite stays offline.** No network, no browser, no external
  target — `pytest` on a machine with neither must be green.
- **The live tests are the one exception, and they bring their own target.**
  `tests/test_integration_live.py` drives a real Chromium against
  `tests/lab_server.py`, a loopback HTTP server the test starts itself. They
  are marked `integration`, skip themselves when no Chromium is installed, and
  never contact a host the test did not stand up. A live test that needs a
  target someone else operates does not belong here — that stays a manual
  procedure in `docs/USAGE.md`.
- Playwright call sites must be exercised by a live test. They are the code
  that touches other people's devices; "it has never run" is not an acceptable
  state for them.
- New heuristics (login detection, verdict classification) need a test for both
  the positive and the negative case.
- CI (`.github/workflows/ci.yml`) runs the offline suite on 3.10 and 3.12 with
  no browser installed — which is also how the skip path gets tested — plus a
  job that installs Chromium and runs `pytest -m integration` with
  `NWAA_REQUIRE_INTEGRATION=1`, so a broken browser install cannot pass as a
  green run with zero tests.
