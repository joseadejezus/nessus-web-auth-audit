# Architecture

## Data flow

```
.nessus file
    │
    ▼
nessus_parser.parse_nessus_file()        defusedxml; untrusted input
    │  NessusScan(report_items, services, host_facts)
    ├──────────────► classifier.identify_login_pages()      pure, no network
    │                classifier.plaintext_http_services()
    │                        │  list[LoginPage]
    ├──────────────► fingerprint.fingerprint_services()     pure, no network
    │                        │  {"host:port": DeviceFingerprint}
    ├──────────────► scope.build_scope()  ──► ScopeRegistry (host,port allowlist)
    │                                              │
    │                                              ▼  consulted before every request
    ├──────────────► screenshot.screenshot_login_pages()    Playwright, banner injection
    │                        │  list[ScreenshotResult]  (each carries an HttpProbe)
    │                        ▼
    │                probe.probe_login_pages()              only for pages the
    │                        │  {url: HttpProbe}            screenshot pass missed
    │                        ▼
    │                fingerprint.fingerprint_from_probe() ─► merge_fingerprints()
    │                        │  live banners refine the offline guess
    │                        ▼
    │                default_creds.credentials_for_fingerprint()
    │                        │  {url: [Credential(source="vendor_default")]}
    ├──────────────► credential_tester.test_credentials_against_pages()
    │                        │  operator list + per-page defaults, then capped
    │                        │  list[CredentialAttempt]
    ▼
ScanResult ──► report.build_json_report() ──► report.render_text_report()
                        │                └──► html_report.build_html_report()
                        ▼
   out/report.json, out/report.txt, out/report.html, out/screenshots/*.png
```

`build_json_report` is the single serialization point: the text report and the
HTML viewer are both rendered from its output, so a field can never appear in
one report and be missing (or unredacted) in another. `nwaa view` re-enters the
pipeline at that dict, rebuilding the viewer from a saved `report.json`.

## Module responsibilities

| Module | Responsibility | Network? |
| --- | --- | --- |
| `models.py` | Dataclasses + `SecretStr` + `AttemptVerdict` | no |
| `nessus_parser.py` | Safe XML parse; per-host:port `Service` aggregation | no |
| `classifier.py` | Web/TLS/plaintext verdicts; login-page identification | no |
| `fingerprint.py` | Signature table + matcher; device identity from scan data and live banners | no |
| `default_creds.py` | Loads/validates the packaged vendor default-credential profiles | no |
| `probe.py` | Reads banners (Server, WWW-Authenticate, title, body) from a page load | yes |
| `data/default_credentials.json` | The profiles themselves — the only place credentials live | no |
| `scope.py` | `ScopeRegistry` + `install_scope_guard` — the authorization boundary, shared by both browser-driving modules | no |
| `screenshot.py` | Playwright capture + URL banner + safe filenames | yes |
| `credential_tester.py` | Credential loading, attempt caps, login attempts, verdicts | yes |
| `report.py` | JSON + text rendering, explicit field-by-field serialization | no |
| `html_report.py` | Self-contained interactive HTML viewer (inline CSS/JS, embedded screenshots) | no |
| `browser.py` | Chromium presence check, one-shot install, and every platform quirk (root sandbox, /dev/shm, deps, DISPLAY) | download only |
| `redaction.py` | Secret registry, logging filter, `scrub_secrets` | no |
| `logging_utils.py` | JSON/plain structured logging with redaction attached | no |
| `cli.py` | Argument parsing, orchestration, exit codes | no (delegates) |

The pure/impure split is deliberate: every heuristic that determines a *finding*
(is this a web server, is this a login page, did these credentials work, what
filename does this get) is a pure function with no Playwright import, so it is
unit-tested offline. Playwright is imported lazily inside the two functions that
actually drive a browser.

## Key design decisions

**Service is an aggregate, ReportItem is raw.** A Nessus port is described by
many plugins. `Service` folds them into one web/TLS verdict per `host:port`;
`ReportItem` keeps the individual plugin rows because login-page detection needs
to read individual plugin names and outputs.

**TLS detection is evidence-based.** `svc_name == "https"` is the primary
signal, backed by any plugin on that port whose name or output mentions SSL/TLS.
A web service with neither is reported as plaintext HTTP.

**Login-page URLs prefer what Nessus printed.** If a matching plugin's output
contains a URL pointing at the same host, that exact URL is used; otherwise the
service base URL is the target. Evidence strings record which plugin fired.

**Scope is derived, never configured.** The `ScopeRegistry` is built solely from
the hosts/ports present in the supplied `.nessus` file. There is no flag to add
a host. Both the URL check (host + port) and the Playwright route handler (host)
are applied — the route handler is what contains redirects and third-party
subresources.

**Verdicts are conservative.** `classify_login_outcome` only returns
`default_credentials_successful` when the password field is gone, the URL
changed, and no failure text is present. Ambiguity resolves to `inconclusive`,
never to success — a false positive here becomes a wrong finding in a client
report.

**Screenshots are self-describing.** Headless Chromium has no address bar, so a
fixed banner containing the final URL, capture timestamp, and scheme is injected
via `textContent` (never `innerHTML`) before capture.

**The HTML report is one file, and treats its own data as untrusted.** Everything
in it (hostnames, URLs, plugin text) came from scan output. The report data is
embedded in a `<script type="application/json">` block with `<`, `>` and `&`
escaped to `\uXXXX` — valid JSON, but incapable of closing the script element —
and the UI is built entirely with `createElement`/`textContent`. No report data
is ever passed to `innerHTML`. Combined with inline CSS/JS and base64 screenshots,
the viewer needs no server, no CDN, and no network, so it works from `file://`
and stays a single attachable artifact.

**The browser is installed by the tool, not the user.** Under pipx, `sys.executable`
is the isolated venv's interpreter, so `nwaa setup` runs `python -m playwright
install chromium` there and the binary lands where the tool will actually look
for it.

**Fingerprint first, then pick credentials.** The device identity is derived
before any credential is chosen, from two sources scored differently: plugin
text and host tags in the `.nessus` file (offline, weight 1) and the live
`Server` / `WWW-Authenticate` / title / body from the page load (weight 3,
because the device said it itself). `merge_fingerprints` combines them, and a
high-confidence offline match is not displaced by a low-confidence generic live
one. Signatures are ordered most-specific-first so a tie resolves to the
concrete model rather than the category fallback.

**Live fingerprinting rides on the request that was already being made.** The
screenshot pass records an `HttpProbe` from the same `page.goto` that produced
the image, before the URL banner is injected. `probe.probe_login_pages` only
runs for pages the screenshot pass did not cover (i.e. `--no-screenshot`), so
`--default-creds` never doubles the traffic to a target.

**Default credentials are data, not code.** They live in one reviewable JSON
file that a test asserts no `.py` file duplicates. Validation happens at load:
schema version, entry shape, and a per-profile ceiling of 12 that turns "this
profile is growing into a wordlist" into a hard failure. Empty profiles (iLO,
ESXi, Jenkins) are a documented answer — "there is no factory default here" —
rather than a gap.

**Per-page credential sets, one shared ceiling.** Different pages get different
defaults because they are different devices, so the cap moved inside the
per-page loop: `combine_credentials(operator, defaults)` then
`select_credentials_for_attempt(...)`. Operator credentials sort first, so the
truncation only ever drops vendor defaults, and duplicates collapse so the same
guess is not spent twice.

**Platform quirks live in one module.** `browser.py` owns everything that
differs between Kali and a laptop: `--no-sandbox` when (and only when) running
as root, `--disable-dev-shm-usage` on Linux, `--with-deps` gated to root on
Linux, `~/.cache/ms-playwright` reporting, and the DISPLAY check that stops
`--open` from launching a text browser over a headless SSH session. Every call
site launches through `chromium_launch_kwargs()`, so a new quirk is a one-line
change in one file.

## Extension points

- **New device profile**: add a `_sig(...)` entry to `SIGNATURES` (most-specific
  first) *and* a matching key in `data/default_credentials.json` — a test fails
  if a signature has no profile. Add a positive and a negative test.
- Additional login-page evidence sources: extend `LOGIN_KEYWORD_RE` and add both
  a positive and a negative test.
- HTTP Basic/NTLM auth testing: Playwright supports `http_credentials` on a
  context; this would be a sibling of `_attempt_one` with its own verdict logic.
- Optional login-path probing (GET-only discovery of common login paths) was
  scoped out deliberately; see `docs/PROJECT_STATE.md`.
