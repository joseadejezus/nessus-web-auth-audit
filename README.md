```
███╗   ██╗██╗    ██╗ █████╗  █████╗
████╗  ██║██║    ██║██╔══██╗██╔══██╗
██╔██╗ ██║██║ █╗ ██║███████║███████║
██║╚██╗██║██║███╗██║██╔══██║██╔══██║
██║ ╚████║╚███╔███╔╝██║  ██║██║  ██║
╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

# nwaa — Nessus Web Auth Auditor

**Turn a `.nessus` file into a prioritized list of web logins that still answer to their factory password.**

[![CI](https://github.com/joseadejezus/nessus-web-auth-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/joseadejezus/nessus-web-auth-audit/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-MIT-blue)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94)
![profiles](https://img.shields.io/badge/device%20profiles-42-brightgreen)
![status](https://img.shields.io/badge/status-alpha-orange)

nwaa reads a Nessus scan, finds the web login pages hiding in it, works out **what kind of device is answering** — an HP MFP, a Dell iDRAC, a Tomcat manager, an Axis camera — and tries *that vendor's* published default credentials against it. Everything lands in a self-contained HTML report you can hand to a client.

> [!WARNING]
> This tool submits real login attempts to real hosts. Active modes are gated behind `--authorized` and confined to the hosts in your scan file. Only run it against systems you have **written permission** to test. See [docs/SECURITY.md](docs/SECURITY.md).

---

## Why it's different

Most default-credential tools throw the same list at everything. nwaa fingerprints first, then picks one profile:

```
Nessus scan ─► login pages ─► device fingerprint ─► that vendor's defaults ─► verdict
                                    ▲
                          scan plugin text + host tags
                          Server: / WWW-Authenticate: / <title>
```

An HP printer gets the HP list. It never sees the Dell list. That means fewer requests, fewer lockouts, and a finding you can actually write up — *"this MFP still accepts the password in its manual"* — instead of *"something guessed in."*

---

## Example

Offline run against the bundled sample scan — no host is contacted:

```console
$ nwaa scan --nessus tests/fixtures/devices.nessus --out ./out

========================================================================
nwaa - Nessus web authentication surface report
========================================================================

SUMMARY
------------------------------------------------------------------------
  Web services                  : 3
  Plaintext HTTP web services   : 2
  TLS web services              : 1
  Login pages identified        : 3
  Devices fingerprinted         : 2

DEVICES IDENTIFIED (heuristic fingerprint -> default-credential profile)
------------------------------------------------------------------------
  10.10.10.20:80           HP printer / MFP (Embedded Web Server)  [high]
      profile      : hp-printer  (source: nessus)
      evidence     : nessus: matched /\bHP\s+HTTP\s+Server\b/
      evidence     : nessus: matched /\bHP\s*(Color\s+)?(LaserJet|OfficeJet|...)\b/
      evidence     : nessus: matched /Virtual\s+Machine\s+Embedded\s+Web\s+Server/
  10.10.10.21:443          Dell Remote Access Controller (iDRAC)  [high]
      profile      : dell-idrac  (source: nessus)
      evidence     : nessus: matched /\biDRAC\s?[0-9]?\b/
      evidence     : nessus: matched /Integrated\s+Dell\s+Remote\s+Access/

LOGIN PAGES
------------------------------------------------------------------------
  [PLAINTEXT] http://10.10.10.20/hp/device/set_config_password.html
      detected via : nessus_plugin
      device       : HP printer / MFP (Embedded Web Server) (high confidence)
      evidence     : plugin[50345] Web Management Interface Administrator Login Page
  [TLS] https://10.10.10.21/login.html
      detected via : nessus_plugin
      device       : Dell Remote Access Controller (iDRAC) (high confidence)
  [PLAINTEXT] http://10.10.10.22/login
      detected via : nessus_plugin
      evidence     : plugin[42057] Web Server Allows Password Auto-Completion
```

Every guess shows its work: the third login page is a plain nginx host, so it gets **no** device and **no** default credentials rather than a hopeful guess.

Add `--authorized --default-creds` and the run also screenshots each page, submits the matching vendor defaults, and fills in a verdict per attempt:

| Verdict | Meaning |
| --- | --- |
| `default_credentials_successful` | Password field gone, URL changed, no failure text. **Verify by hand.** |
| `authentication_failed` | Failure text detected on the resulting page |
| `inconclusive` | Ambiguous — common with SPAs and apps that return 200 on failure |
| `connection_error` | Timeout, TLS failure, or browser error |
| `not_tested` | No form-based login found, or out of scope |

Plus `report.html` — one self-contained file, no server, no CDN, with tabs for devices, login pages, attempts, and screenshots with the URL burned into each image.

---

## Install

```bash
sudo apt install -y pipx
pipx install git+https://github.com/joseadejezus/nessus-web-auth-audit.git
pipx ensurepath && exec $SHELL

nwaa setup            # one-time Chromium download (~150 MB)
nwaa setup --check    # platform, root status, browser path, chromium flags
```

<details>
<summary><b>Kali notes</b> — PEP 668, root, headless</summary>

- Kali's system Python is externally managed, so plain `pip install` refuses. Use `pipx`, or a venv.
- Browsers land in `~/.cache/ms-playwright`. Download them under `sudo` and they go to `/root`, where your normal user's nwaa won't find them. `nwaa setup --check` prints the path in use.
- Running as root, nwaa launches Chromium with `--no-sandbox` (it refuses to start as root otherwise) and warns you. Prefer an unprivileged user.
- Missing shared libraries: `sudo $(which nwaa) setup --with-deps`.
- On a headless box `--open` is skipped and the report path is printed instead.

</details>

---

## Usage

```bash
# Offline. Parses, classifies, fingerprints. Contacts nothing.
nwaa scan --nessus engagement.nessus --out ./out

# See exactly what would be submitted, before submitting it.
nwaa profiles --show-passwords

# The real run: fingerprint + screenshot + vendor defaults + reports.
nwaa scan --nessus engagement.nessus --out ./out --authorized --default-creds --open

# Force a profile when fingerprinting comes up empty.
nwaa scan --nessus engagement.nessus --out ./out --authorized --profile hp-printer

# Add your own credentials; they're tried first, defaults fill the rest.
nwaa scan --nessus engagement.nessus --out ./out --authorized \
    --default-creds --credentials ./credentials.json

# Rebuild the viewer later from a saved scan.
nwaa view --json ./out/report.json --open
```

| Command | Purpose |
| --- | --- |
| `nwaa scan` | Parse, fingerprint, screenshot, test, report — one shot |
| `nwaa view` | Rebuild the HTML viewer from a saved `report.json` |
| `nwaa profiles` | List bundled device profiles (`--show-passwords` for the pairs) |
| `nwaa setup` | Download Chromium (`--check` to diagnose, `--with-deps` for OS libs) |

Full flag reference: [docs/USAGE.md](docs/USAGE.md).

---

## Device coverage

42 profiles, 108 published factory credentials.

| Category | Vendors |
| --- | --- |
| **Printers / MFPs** (13) | HP, Xerox, Lexmark, Ricoh, Brother, Canon, Konica Minolta, Kyocera, Epson, Sharp, Dell, Zebra |
| **Network** (8) | Cisco, Ubiquiti, MikroTik, NETGEAR, TP-Link, D-Link, Zyxel, HP/Aruba ProCurve |
| **BMC / lights-out** (5) | Dell iDRAC, HPE iLO, Supermicro IPMI, IBM/Lenovo IMM, generic IPMI |
| **Cameras / NVR** (5) | Axis, Hikvision, Dahua, Vivotek, generic |
| **App servers** (4) | Tomcat, JBoss/WildFly, WebLogic, GlassFish |
| **Web apps** (3) | Grafana, Jenkins, phpMyAdmin |
| **Storage / power / virt** (4) | Synology, QNAP, APC, VMware ESXi |

Three profiles — **HPE iLO, ESXi, Jenkins** — ship deliberately empty. Those devices have no fixed factory password (per-unit chassis tag, installer-set, or generated at first run), so nwaa reports that fact instead of guessing.

---

## Safety rails

These are enforced in code and asserted by tests, not just promised here:

| | |
| --- | --- |
| **No brute force** | Hard ceiling of 20 attempts per page that no flag can raise; default 5. Applies to your list and the vendor defaults *combined*. |
| **No wordlists** | Profiles are capped at 12 entries and validated at load. No credential generation, permutation, or retry loops. |
| **No off-scope traffic** | Scope is derived from your `.nessus` file and cannot be extended by a flag. Enforced twice — URL check before navigation, plus a browser route guard that kills redirects and subresources to unscanned hosts. |
| **No secrets in output** | Passwords are wrapped in `SecretStr` and reports are serialized field by field. Your own credentials are additionally registered for redaction on load and scrubbed at logger *and* handler level. (Published vendor defaults are not — `nwaa profiles --show-passwords` prints those on request.) |
| **No accidental scanning** | Screenshots, `--credentials` and `--default-creds` all require `--authorized`. Parsing, fingerprinting and reporting are network-free. |
| **Untrusted input** | `.nessus` files are parsed with `defusedxml` only; stdlib `xml.etree` is banned repo-wide by a test. |

Credentials come from exactly two places: your JSON file, or the bundled profile matching a **detected** device. There is no "try everything" mode.

---

## Project status

**Alpha.** Be clear-eyed about what has and hasn't been exercised:

| | |
| --- | --- |
| ✅ | 154 tests passing on Kali — 149 offline, 5 driving a real browser; `ruff`, `mypy`, `bandit` clean |
| ✅ | Parsing, classification, fingerprinting, and all three report formats |
| ✅ | Browser-driving code — screenshots, live probing, credential submission, the scope guard — exercised by live tests (`pytest -m integration`) against a loopback lab device. First live run on Kali, 2026-09-02 |
| ⚠️ | Fingerprint signatures were written from vendor documentation, not captured banners |

Validate against a lab device you control before using it on an engagement. The procedure is in [docs/USAGE.md](docs/USAGE.md#manual-verification-procedure-not-covered-by-any-test).

---

## Documentation

| | |
| --- | --- |
| [USAGE.md](docs/USAGE.md) | CLI reference, credential file format, Kali gotchas, troubleshooting |
| [SECURITY.md](docs/SECURITY.md) | Threat model, controls, and the limitations to state when reporting findings |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module layout, data flow, design decisions, extension points |
| [PROJECT_STATE.md](docs/PROJECT_STATE.md) | What's done, what's known-broken, what's next |

**Adding a device profile:** a `_sig(...)` entry in `src/nwaa/fingerprint.py` plus a matching key in `src/nwaa/data/default_credentials.json` — a test fails if a signature has no profile. Positive and negative tests required.

## License

MIT — see [LICENSE](LICENSE).
