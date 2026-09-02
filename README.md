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

```console
$ nwaa scan --nessus engagement.nessus --out ./out --authorized --default-creds

========================================================================
nwaa - Nessus web authentication surface report
========================================================================

SUMMARY
------------------------------------------------------------------------
  Web services                  : 34
  Plaintext HTTP web services   : 19
  Login pages identified        : 12
  Devices fingerprinted         : 9
  Credential attempts           : 27
      of which vendor defaults      : 27
      default_credentials_successful    : 2
      authentication_failed             : 23
      inconclusive                      : 2

DEVICES IDENTIFIED (heuristic fingerprint -> default-credential profile)
------------------------------------------------------------------------
  10.10.10.20:80           HP printer / MFP (Embedded Web Server)  [high]
      profile      : hp-printer  (source: nessus+http)
      evidence     : http: matched /\bHP\s+HTTP\s+Server\b/
  10.10.10.21:443          Dell iDRAC  [high]
      profile      : dell-idrac  (source: nessus)
      evidence     : nessus: matched /Integrated\s+Dell\s+Remote\s+Access/

CREDENTIAL ATTEMPTS (passwords are never recorded)
------------------------------------------------------------------------
  DEFAULT_CREDENTIALS_SUCCESSFUL
      url      : http://10.10.10.20/hp/device/set_config_password.html
      username : admin  (set: default:hp-printer (blank admin password))
      source   : vendor_default
      detail   : Password field gone, URL changed away from login page.
```

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
| **No secrets in output** | Passwords are wrapped in `SecretStr`, registered for redaction on load, scrubbed at logger *and* handler level, and reports are serialized field by field. |
| **No accidental scanning** | Screenshots, `--credentials` and `--default-creds` all require `--authorized`. Parsing, fingerprinting and reporting are network-free. |
| **Untrusted input** | `.nessus` files are parsed with `defusedxml` only; stdlib `xml.etree` is banned repo-wide by a test. |

Credentials come from exactly two places: your JSON file, or the bundled profile matching a **detected** device. There is no "try everything" mode.

---

## Project status

**Alpha.** Be clear-eyed about what has and hasn't been exercised:

| | |
| --- | --- |
| ✅ | 147 offline tests passing; `ruff`, `mypy`, `bandit` clean |
| ✅ | Parsing, classification, fingerprinting, and all three report formats |
| ⚠️ | Browser-driving code — screenshots, live probing, credential submission — **has not been run against a live target yet** |
| ⚠️ | Fingerprint signatures were written from vendor documentation, not captured banners |

Validate against a lab device you control before using it on an engagement. The procedure is in [docs/USAGE.md](docs/USAGE.md#manual-verification-procedure-not-covered-by-the-automated-tests).

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
