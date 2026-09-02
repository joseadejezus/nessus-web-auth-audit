# Usage

## Install on Kali Linux

Recommended — pipx, so the tool and its browser live in their own isolated venv
and `nwaa` is on your PATH. Kali's system Python is externally managed (PEP 668),
so a plain `pip install` into it will refuse to run.

```bash
sudo apt update && sudo apt install -y pipx
pipx install .            # from a clone of this repo
pipx ensurepath           # first install only, then open a new shell
nwaa setup                # one-time Chromium download (~150 MB)
nwaa --version
```

If Chromium reports missing shared libraries, install the OS packages it links
against (this needs root, and is the one command that does):

```bash
sudo $(which nwaa) setup --with-deps
# equivalently: sudo playwright install-deps chromium
```

Check what nwaa sees about the machine at any time — platform, whether it is
running as root, the Chromium flags that implies, and where browsers are
expected:

```bash
nwaa setup --check
```

To upgrade after changing the code: `pipx reinstall nwaa` (or
`pipx install --force .`). To remove: `pipx uninstall nwaa`.

For development instead:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
playwright install chromium
pytest
```

### Kali gotchas

| Symptom | Cause | Fix |
| --- | --- | --- |
| `error: externally-managed-environment` | PEP 668 on Debian/Kali | Use `pipx`, or a venv |
| Chromium exits immediately as root | Chromium refuses its sandbox as root | nwaa adds `--no-sandbox` automatically and warns; better, run as a normal user |
| `nwaa setup` works under sudo but scans still say Chromium is missing | Browsers went to `/root/.cache/ms-playwright` | Re-run `nwaa setup` **without** sudo; compare `nwaa setup --check` |
| Renderer crashes on big pages in a container | 64 MB `/dev/shm` | Already handled (`--disable-dev-shm-usage`); raise `--shm-size` if you also run other browsers |
| `--open` does nothing over SSH | No `DISPLAY`/`WAYLAND_DISPLAY` | Expected — nwaa logs the report path instead; copy the file out and open it locally |

## Commands

```
nwaa scan --nessus <file> [options]      parse, fingerprint, screenshot, test, report
nwaa view --json <report.json>           rebuild the HTML viewer from a saved scan
nwaa setup [--with-deps] [--check]       download Chromium / report platform state
nwaa profiles [--show-passwords]         list the bundled device credential profiles
```

### `nwaa scan`

| Option | Default | Meaning |
| --- | --- | --- |
| `--nessus PATH` | required | `.nessus` file to read |
| `--out DIR` | `./nwaa-output` | Where reports and screenshots are written |
| `--authorized` | off | Confirms written authorization. **Without it nothing is contacted.** With it, screenshots run by default |
| `--no-screenshot` | off | Skip screenshots even when `--authorized` is given |
| `--full-page` | off | Full-page instead of viewport screenshots |
| `--credentials PATH` | none | JSON file of credentials to test (requires `--authorized`) |
| `--default-creds` | off | Fingerprint each device and try its published vendor defaults (requires `--authorized`) |
| `--profile ID` | none | Force one profile for every login page instead of fingerprinting; implies `--default-creds` |
| `--no-fingerprint` | off | Skip device detection entirely; incompatible with the two options above |
| `--max-attempts-per-page N` | 5 | Attempts per login page, operator list **and** vendor defaults combined (hard ceiling 20) |
| `--timeout-ms N` | 15000 | Per-navigation timeout (min 1000) |
| `--install-browser` | off | Download Chromium inline if missing instead of failing |
| `--no-embed-screenshots` | off | Link screenshots from the HTML instead of embedding them |
| `--open` | off | Open the HTML report when finished |
| `--log-level` | INFO | DEBUG / INFO / WARNING / ERROR |
| `--log-format` | json | `json` (one object per line, to stderr) or `text` |

### `nwaa view`

| Option | Default | Meaning |
| --- | --- | --- |
| `--json PATH` | required | A `report.json` produced by `nwaa scan` |
| `--html PATH` | next to the JSON | Where to write the viewer |
| `--no-embed-screenshots` | off | Link screenshots instead of embedding |
| `--open` | off | Open when finished |

Exit codes: `0` ok, `1` usage error, `2` Nessus parse error, `3` credential
config error, `4` browser/dependency missing.

## Typical run

```bash
# 1. Offline: what does the scan say, and what devices are in it?
#    Fingerprinting is free — no traffic is generated without --authorized.
nwaa scan --nessus ./engagement.nessus --out ./out

# 2. See exactly what a default-credential run would submit, before running it.
nwaa profiles --show-passwords

# 3. Everything, in one go: fingerprint + screenshots + vendor defaults + reports.
nwaa scan --nessus ./engagement.nessus --out ./out --authorized \
    --default-creds --credentials ./credentials.json --open

# 4. Re-open or regenerate the viewer later.
nwaa view --json ./out/report.json --open
```

## Device fingerprinting and vendor defaults

Step 1 above already tells you what is out there. The text report and the
**Devices** tab of the HTML viewer list every identified device with the
evidence behind the guess:

```
DEVICES IDENTIFIED (heuristic fingerprint -> default-credential profile)
------------------------------------------------------------------------
  10.10.10.20:80           HP printer / MFP (Embedded Web Server)  [high]
      profile      : hp-printer  (source: nessus+http)
      evidence     : nessus: matched /\bHP\s+HTTP\s+Server\b/
      evidence     : http: matched /\bHP\s*(Color\s+)?(LaserJet|...)\b/
```

Detection uses two sources: the plugin text and host tags already in the
`.nessus` file (works offline), and — when a page is actually loaded — the
`Server` header, `WWW-Authenticate` realm, page title and body of that same
request. No extra requests are made for fingerprinting when screenshots are on.

`--default-creds` then applies **only** the profile that matched. An HP printer
gets the HP list; it never gets the Dell or Axis list. Confidence is reported as
`high` / `medium` / `low`; a `low` result usually means only a generic category
matched (`generic-printer`), which still carries a useful list.

When nothing matches, force it:

```bash
nwaa scan --nessus ./engagement.nessus --out ./out --authorized \
    --profile xerox-printer
```

Some profiles are intentionally empty — HPE iLO, ESXi and Jenkins have no fixed
factory password (per-unit tag, installer-set, or generated at first run). Those
report a warning explaining why nothing was tried, rather than guessing.

**Before you run it:** these are real failed logins. Devices with account
lockout will lock accounts, and MFPs commonly log and alert on failed admin
logins. Keep `--max-attempts-per-page` low, and have the client's agreement.

## Credentials file

Copy `credentials.example.json` to `credentials.json` (gitignored) and fill it
in with the credentials your engagement scope authorizes you to try:

```json
{
  "credentials": [
    { "username": "admin", "password": "<from engagement scope doc>", "label": "vendor-default" },
    { "username": "root",  "password": "<from engagement scope doc>", "label": "vendor-default" }
  ]
}
```

- `username` and `password` are required; `label` is free text used in reports.
- Passwords are never written to logs, reports, or screenshots.
- Only the first `--max-attempts-per-page` entries are tried against any single
  page, and never more than 20. This tool will not accept a wordlist.
- With `--default-creds`, your entries are tried **first** and the matching
  vendor defaults fill the remaining slots up to the cap; duplicates collapse.
  Attempts record `credential_source` (`user_file` or `vendor_default`) so the
  report distinguishes "our list worked" from "the factory password still works".

## Output

```
out/
  report.html          interactive viewer, self-contained
  report.json          machine-readable, see keys below
  report.txt           human-readable summary (also printed to stdout)
  screenshots/
    10.10.10.5_80_-login.php_9f2c1a4b7d.png
```

### The HTML viewer

`report.html` is a single file with inline CSS/JS and base64-embedded
screenshots — no server, no CDN, no network. Open it by double-clicking, or
pass `--open`. It provides:

- Summary cards, with plaintext-HTTP and successful-default-credential counts
  highlighted when non-zero
- Tabs: Overview, Login pages, **Devices**, Plaintext HTTP, Credential attempts,
  Screenshots, Web services
- Attempts that used a bundled vendor default are badged as such
- A live filter box across hosts, URLs, plugin evidence, and usernames
- Verdict filter chips on the credential-attempts tab
- Click any screenshot for a full-size lightbox
- Light/dark following the OS setting, and a print stylesheet for PDF export

Use `--no-embed-screenshots` for a much smaller file; the report then references
`screenshots/*.png` relatively and must be kept alongside that folder.

### `report.json`

Top-level keys: `tool`, `version`, `generated_at`, `nessus_file`, `summary`,
`devices`, `web_services`, `plaintext_http_services`, `login_pages`,
`screenshots`, `credential_attempts`, `warnings`.

`devices` holds one entry per fingerprinted `host:port` (`profile_id`, `vendor`,
`category`, `confidence`, `source`, `evidence`); the same object is repeated
inline as `device` on each `login_pages` and `web_services` entry. Each
`credential_attempts` entry carries `credential_source`.

Each entry in `credential_attempts` has a `verdict` of:

| Verdict | Meaning |
| --- | --- |
| `default_credentials_successful` | Password field gone, URL changed, no failure text. **Verify manually.** |
| `authentication_failed` | Failure text detected on the resulting page |
| `inconclusive` | Ambiguous — password field still present with no error, or no signal either way |
| `connection_error` | Timeout, TLS failure, DNS, or browser error |
| `not_tested` | No form-based login found, or URL out of scope |

## Manual verification procedure (not covered by the automated tests)

The test suite is fully offline. Before using this on an engagement, verify the
browser path once against a lab target you control:

1. Stand up any app with a login form on a host and port you control.
2. Write a minimal `.nessus` containing that host/port with a plugin whose
   output mentions the login URL (see `tests/fixtures/sample.nessus`).
3. Run with `--authorized` and confirm the PNG shows the banner with the correct
   URL, and that the same image appears in `report.html`.
4. Run with a deliberately wrong credential and confirm `authentication_failed`.
5. Run with the correct credential and confirm `default_credentials_successful`.
6. Point a login page at an off-scope redirect and confirm the request is
   aborted rather than followed.
7. Serve a page with `Server: HP HTTP Server` and confirm the Devices tab shows
   `hp-printer` with `source: http`, and that `--default-creds` selects the HP
   profile and nothing else.
8. Repeat step 7 as root and as a normal user on Kali, confirming Chromium
   launches both times (`--no-sandbox` is logged in the root case).

## Troubleshooting

- **"Chromium is not installed for Playwright"** — run `nwaa setup`, or re-run
  the scan with `--install-browser`. If it was installed under `sudo`, compare
  `nwaa setup --check` as both users: the browsers path differs.
- **`nwaa` not found after `pipx install`** — run `pipx ensurepath` and open a
  new shell.
- **`--default-creds` tried nothing** — nothing fingerprinted. Check the Devices
  tab, then either force a profile (`--profile hp-printer`) or supply your own
  credentials file. `nwaa profiles` lists what exists.
- **The wrong device was detected** — check the `evidence` strings in the report;
  they name the exact pattern that matched. Override with `--profile`, and if
  the signature is genuinely wrong, tighten it in `fingerprint.py` with a
  regression test.
- **Everything is `inconclusive`** — likely a SPA that returns 200 on failure.
  Check the screenshot in the HTML report and verify by hand; do not raise the
  attempt cap.
- **`report.html` is enormous** — that is the embedded screenshots. Regenerate
  with `nwaa view --json out\report.json --no-embed-screenshots`.
- **Screenshots fail with TLS errors** — capture already sets
  `ignore_https_errors`; a persistent failure usually means the service is not
  actually HTTP(S) on that port, or a proxy is in the way.
- **A known login page is missing** — the Nessus scan likely never recorded it.
  Re-scan with web application tests enabled, or add the URL to the scan data.
