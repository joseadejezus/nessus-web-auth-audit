# nwaa — Nessus Web Authentication Auditor

Point it at a `.nessus` file and it does the rest in one command: finds the web
services, flags the ones carrying traffic in plaintext HTTP, identifies login
pages, works out **what device is answering** (HP printer, Dell iDRAC, Tomcat,
Axis camera, …), screenshots each page with the URL burned into the image,
tries that vendor's **published default credentials** and/or a list you supply,
and writes a self-contained interactive HTML report.

Built for **Kali Linux** (runs on Windows/macOS too).

**Authorization is required.** This tool actively connects to hosts and submits
real login attempts. Only run the active modes against systems you have written
permission to test. See [docs/SECURITY.md](docs/SECURITY.md).

## Install on Kali

```bash
sudo apt update && sudo apt install -y pipx
pipx install .                  # from a clone; or: pipx install <path-to-repo>
pipx ensurepath && exec $SHELL  # first install only

nwaa setup                      # one-time Chromium download (~150 MB) into nwaa's own venv
sudo $(which nwaa) setup --with-deps   # only if Chromium reports missing libraries
nwaa setup --check              # what nwaa sees: platform, root, browser path, flags
```

Kali notes:

- Debian marks the system Python externally managed (PEP 668), so `pip install`
  into `/usr/lib/python3` fails. Use `pipx` (recommended) or a venv.
- `nwaa setup` is not optional for screenshots or credential testing — pipx
  installs the Playwright *library*; the browser binary is a separate download.
  `nwaa scan --install-browser` does it inline on the first run instead.
- Browsers land in `~/.cache/ms-playwright`. If you download them under `sudo`
  they go to `/root` and your normal user's nwaa will not find them —
  `nwaa setup --check` prints the path actually in use.
- Running as root, nwaa launches Chromium with `--no-sandbox` (it refuses to
  start as root otherwise) and says so. Prefer an unprivileged user.
- On a headless box nwaa skips `--open` and just prints the report path.

## One command does everything

```bash
nwaa scan --nessus engagement.nessus --out ./out --authorized \
    --default-creds --open
```

That parses the scan, fingerprints each login page's device, screenshots them,
tries the matching vendor defaults, writes all three reports, and opens the
viewer. Add your own credentials alongside with `--credentials creds.json`.

See what would be tried, and against what:

```bash
nwaa profiles                    # bundled device profiles and their usernames
nwaa profiles --show-passwords   # the exact pairs that would be submitted
```

Without `--authorized` it stays completely offline — parse, classify,
fingerprint, report, and nothing is contacted:

```bash
nwaa scan --nessus engagement.nessus --out ./out
```

Rebuild the viewer later from a saved scan:

```bash
nwaa view --json ./out/report.json --open
```

## Output

```
out/
  report.html    interactive, self-contained: filter, tabs (incl. Devices), verdict chips, lightbox
  report.json    machine-readable
  report.txt     human-readable summary (also printed to stdout)
  screenshots/   PNGs, each with its URL and capture time rendered into the image
```

`report.html` inlines its CSS, JS, and screenshots, so it opens from `file://`
with no server and no network — one file to attach to a ticket or email.

## Documentation

- [CLAUDE.md](CLAUDE.md) — working agreement for AI-assisted sessions
- [docs/PROJECT_STATE.md](docs/PROJECT_STATE.md) — current state, next steps
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — module layout and data flow
- [docs/SECURITY.md](docs/SECURITY.md) — threat model and controls
- [docs/USAGE.md](docs/USAGE.md) — CLI reference and credential file format

## Default credentials, deliberately narrow

`--default-creds` is a *targeted* check, not a password attack. A profile is
applied only to a target that fingerprinted as that device, the profiles hold
the factory credentials the vendors themselves publish (capped at 12 per
profile), and the per-page attempt ceiling applies to the operator's list and
the defaults combined. Devices with no fixed factory default — HPE iLO, ESXi,
Jenkins — carry an empty profile that says so rather than a guess.

Force a profile when fingerprinting comes up empty:

```bash
nwaa scan --nessus scan.nessus --out ./out --authorized --profile hp-printer
```

## What it will not do

No brute force. No password spraying. No wordlists. No credential generation or
permutation. No traffic to hosts absent from the supplied `.nessus` file. No
passwords in logs or reports. These are enforced in code, not just documented —
see `docs/SECURITY.md`.
