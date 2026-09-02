# Security

## Authorization

This tool actively connects to hosts and submits credentials to login forms.
Running it against systems you do not have written authorization to test is
likely illegal. The `--authorized` flag is a deliberate speed bump: parsing and
reporting work without it, and nothing touches the network until it is passed.

Scope is not a setting. It is derived from the `.nessus` file you supply — the
assumption being that the scan itself was authorized, so its hosts and ports
define the boundary of what may be touched.

## Threat model

| Threat | Control | Where |
| --- | --- | --- |
| Malicious `.nessus` file (XXE, external DTD, entity expansion) | `defusedxml` only; `DefusedXmlException` wrapped into a clean parse error; stdlib `xml.etree` is banned in this repo | `nessus_parser.py` |
| Path traversal via URLs in scan data used as filenames | Allowlist sanitizer + dot-run collapsing + SHA-256 suffix | `screenshot.safe_filename` |
| Credentials leaking into logs, reports, tracebacks | `SecretStr` (no `__str__`/`__repr__` leak), secret registry for operator-supplied passwords (published vendor defaults are excluded on purpose — see Data protection), `RedactionFilter` on logger and handler, `scrub_secrets` on every free-text report field, field-by-field serialization instead of `asdict` | `models.py`, `redaction.py`, `report.py` |
| Engagement credentials committed to the repo | `.gitignore` excludes `*credentials*.json`; only `credentials.example.json` with placeholders is tracked; no engagement credential values exist anywhere in source | repo root |
| Bundled vendor defaults turning into a password list | One reviewable JSON data file, schema-validated at load, capped at 12 entries per profile; no `.py` file may contain credential literals (asserted by `tests/test_packaging.py`); a profile is applied only to a device that fingerprinted as it | `default_creds.py`, `data/default_credentials.json` |
| Testing drifting into brute force / spraying | `HARD_MAX_ATTEMPTS_PER_PAGE = 20` ceiling a caller cannot raise; default 5; applied to the operator list **and** vendor defaults combined, per page; no wordlist loading, no credential generation, no retry loop | `credential_tester.py` |
| A wrong fingerprint sending the wrong vendor's credentials at a device | Signatures ordered most-specific-first, scored by evidence, and every match records the patterns that fired; live device banners outweigh scan text; `--profile` lets an operator override; positive and negative tests required per signature | `fingerprint.py` |
| Chromium's sandbox being dropped unnecessarily | `--no-sandbox` is added only when the effective uid is 0 on Linux, and logs a warning telling the operator to run unprivileged | `browser.py` |
| Target redirecting the browser off-scope (SSRF-ish pivot) | Every URL re-checked against `ScopeRegistry` before navigation; Playwright route handler aborts any request to an out-of-scope host, which covers redirects and subresources | `scope.py`, `screenshot.py`, `credential_tester.py` |
| Session bleed producing a false "credentials worked" finding | A fresh browser context per credential attempt | `credential_tester.py` |
| Injection into the injected screenshot banner | Banner built with `document.createElement` + `textContent`; URL passed as an `evaluate` argument, never string-interpolated into JS | `screenshot.py` |
| Script injection into the HTML report via hostile scan data (a hostname or URL containing `</script>`) | Report data embedded as JSON with `<`, `>`, `&` escaped to `\uXXXX`; the whole UI built with `createElement`/`textContent`; report data never reaches `innerHTML` | `html_report.py` |
| A "self-contained" report silently phoning home | Inline CSS/JS and base64 screenshots only — no CDN, no external `src`/`href`, no `@import`; asserted by `tests/test_html_report.py` | `html_report.py` |
| Command injection via the browser installer | Fixed argv list, no shell, no user-supplied values; runs `sys.executable -m playwright install chromium` | `browser.py` |
| Accidental active scanning | Screenshots, `--credentials` and `--default-creds` all require `--authorized`; parse/report/fingerprint path makes no network calls | `cli.py` |
| Fingerprinting adding traffic of its own | Banners are read from the page load the screenshot pass already performs; a standalone probe runs only for pages that pass skipped, one GET each, nothing submitted | `probe.py`, `screenshot.py` |

## Project CodeGuard alignment

Mapped to CodeGuard's rule domains:

- **Input validation** — all external input is untrusted: the `.nessus` XML
  (defusedxml, root-element check, integer coercion with fallbacks), the
  credentials JSON (shape validated before use), CLI bounds (`--timeout-ms`,
  `--max-attempts-per-page`), and URLs from scan data (validated by scheme and
  scope, sanitized before touching the filesystem).
- **Authentication** — the tool tests authentication rather than implementing
  it. Controls: no credential generation or permutation, hard attempt ceiling,
  credentials only from the operator's file or the fingerprint-matched vendor
  profile, and conservative success classification so a lockout-prone target is
  not hammered and a weak signal is not reported as a compromise.
- **Data protection** — passwords live in `SecretStr` and are excluded from
  logs, reports, screenshots (never typed into a captured page before capture),
  and exception text. Operator-supplied passwords are additionally registered
  with the redaction registry the moment they are loaded, so any string
  containing one is scrubbed before it reaches a log handler or a report field.
  **Bundled vendor defaults are not registered**: they are factory credentials
  published in vendor manuals, which `nwaa profiles --show-passwords` prints on
  request, and treating a word like `password` as a secret corrupted report text
  — including a target's own page title — while protecting nothing that is not
  already public. Screenshots and reports are engagement data: treat the output
  directory as sensitive and gitignored.
- **Cryptography / transport** — plaintext HTTP services are identified and
  reported as findings, since credentials submitted to them cross the network in
  the clear. `ignore_https_errors=True` is set deliberately for capture (audit
  targets routinely have self-signed certificates); TLS validity is Nessus's job
  to report, not this tool's, and the reports never claim a certificate is valid.
- **Authorization** — `ScopeRegistry` is the single enforcement point, applied at
  both navigation and request level. There is no bypass flag.
- **Supply chain** — two runtime dependencies (`defusedxml`, `playwright`), both
  pinned to minimum versions; `pip-audit` and `bandit` are dev dependencies and
  part of the pre-release checklist.
- **Platform security** — the browser runs headless in a fresh context per page
  with no persisted profile; nothing is downloaded or executed from targets. The
  HTML report is treated as an output that renders attacker-influenced strings,
  so it is built with DOM APIs rather than string concatenation.

## Handling the output

`report.html`, `report.json`, `report.txt`, and `screenshots/` are engagement
data: hostnames, IPs, and pictures of client login portals. The output directory
is gitignored. The HTML report is deliberately self-contained so it can be
attached to a ticket without a folder of loose images — which also means one file
carries all of it. Store and share it accordingly.
- **Cloud security** — not applicable; no infrastructure is provisioned.

## Known limitations (state these when reporting findings)

- Login-page identification depends on what the Nessus scan recorded. A login
  page no plugin mentioned will not be found.
- Verdict classification is heuristic. `default_credentials_successful` means
  "manually verify this now", not "confirmed". `inconclusive` is common with
  SPAs, MFA prompts, and apps that return 200 on failure.
- Only form-based logins are driven. HTTP Basic/NTLM/client-certificate auth is
  reported as `not_tested`.
- Credential testing can trigger account lockouts on targets with aggressive
  lockout policies even at 5 attempts. Confirm lockout thresholds with the
  client before enabling `--credentials` or `--default-creds`. MFPs in
  particular log and often alert on failed administrator logins.
- Device fingerprinting is heuristic. `confidence: low` normally means only a
  category signature matched (e.g. `generic-printer`); state the confidence and
  the evidence when a finding depends on the device identity.
- The bundled defaults are what vendors published, not what any particular unit
  shipped with. Firmware revisions change them (Axis, Hikvision and Supermicro
  all moved to per-unit or forced-set passwords), so "no default worked" is not
  proof a device was hardened.
- Profiles for HPE iLO, ESXi and Jenkins are intentionally empty: those devices
  have no fixed factory password. `--default-creds` reports that rather than
  guessing, and those targets still need a manual look.

## Reporting a vulnerability in this tool

Do not open a public issue with client data attached. Strip hostnames, IPs, and
screenshots from any reproduction case before sharing it.
