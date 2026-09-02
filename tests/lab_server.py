"""A local, disposable device that answers like a printer's web interface.

This exists because every line of nwaa that drives a browser
(``screenshot_login_pages``, ``probe_login_pages``,
``test_credentials_against_pages`` and the scope route guard) is
unreachable without a real target. Pointing the tool at somebody else's
device to exercise them is not an option, so this module *is* the
target: a stdlib HTTP server on the loopback interface that

  * answers with ``Server: HP HTTP Server`` and an HP page title, which
    is exactly what ``fingerprint.py`` looks for in a live banner;
  * serves a form-based login that accepts one credential pair
    (by default ``admin`` with a blank password, the HP factory state
    the bundled profile's first entry describes) and rejects everything
    else with failure text;
  * sends a *different* URL with no password field after a successful
    login, which is the signal ``classify_login_outcome`` requires;
  * records every request it receives, so a test can assert that a
    request the scope guard was supposed to block never arrived.

It is imported by ``tests/test_integration_live.py`` and can also be run
by hand for manual verification::

    python tests/lab_server.py --port 8080 --write-nessus /tmp/lab.nessus
    nwaa scan --nessus /tmp/lab.nessus --out /tmp/out --authorized --default-creds

Nothing here is part of the shipped package.
"""
from __future__ import annotations

import argparse
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DEFAULT_BANNER = "HP HTTP Server"
DEFAULT_TITLE = "HP LaserJet 4250 - HP Embedded Web Server"

LOGIN_PATH = "/hp/device/set_config_password.html"
HOME_PATH = "/hp/device/DeviceStatus.html"
NO_PASSWORD_PATH = "/hp/device/contact.html"
TRACKER_PATH = "/tracker.png"

# The smallest thing a browser will accept as an image; the bytes are
# irrelevant, only whether the request for it arrives.
_PIXEL_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)

_LOGIN_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{title}</title></head>
<body>
<h1>Embedded Web Server</h1>
<p>Device: HP LaserJet 4250 &mdash; sign in to change configuration.</p>
{notice}
<form method="post" action="{action}">
  <p><label>User Name: <input type="text" name="username" autocomplete="username"></label></p>
  <p><label>Password: <input type="password" name="password"></label></p>
  <p><button type="submit">Sign In</button></p>
</form>
{images}
</body>
</html>
"""

_HOME_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{title}</title></head>
<body>
<h1>Device Status</h1>
<p>Signed in as {username}.</p>
<p>Toner level: 42%. Tray 2: letter.</p>
</body>
</html>
"""

_NO_PASSWORD_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{title}</title></head>
<body>
<h1>Support Contact</h1>
<form method="post" action="{action}">
  <p><label>Contact name: <input type="text" name="contact"></label></p>
  <p><button type="submit">Save</button></p>
</form>
</body>
</html>
"""

# "Invalid" is one of the strings credential_tester.FAILURE_MARKER_RE looks
# for. A real device says something like this, and the tool needs to see it
# to return authentication_failed rather than inconclusive.
_FAILURE_NOTICE = "<p><strong>Invalid user name or password.</strong></p>"


@dataclass
class LabTarget:
    """A running lab server plus everything a test needs to address it."""

    server: ThreadingHTTPServer
    thread: threading.Thread
    host: str
    port: int
    requests: list[tuple[str, str]] = field(default_factory=list)

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def login_url(self) -> str:
        return f"{self.origin}{LOGIN_PATH}"

    @property
    def home_url(self) -> str:
        return f"{self.origin}{HOME_PATH}"

    @property
    def no_password_url(self) -> str:
        return f"{self.origin}{NO_PASSWORD_PATH}"

    def requests_for(self, path: str, method: str | None = None) -> list[tuple[str, str]]:
        return [
            (m, p) for m, p in list(self.requests) if p == path and (method is None or m == method)
        ]

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class _LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # The Server header is the whole point of this fixture: it is the live
    # banner that fingerprint.match_signatures scores.
    def version_string(self) -> str:
        return self.server.banner  # type: ignore[attr-defined]

    def log_message(self, fmt, *args) -> None:
        # Silence: pytest captures stderr and one scan produces a lot of it.
        pass

    # -- request handling ------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        path = self._record("GET")
        if path in (LOGIN_PATH, "/"):
            self._send_html(200, self._login_html())
        elif path == HOME_PATH:
            self._send_html(200, _HOME_HTML.format(title=self._title, username=self._username))
        elif path == NO_PASSWORD_PATH:
            self._send_html(
                200, _NO_PASSWORD_HTML.format(title=self._title, action=NO_PASSWORD_PATH)
            )
        elif path == TRACKER_PATH:
            self._send_bytes(200, _PIXEL_GIF, "image/gif")
        else:
            self._send_html(404, "<!doctype html><title>Not found</title><h1>Not found</h1>")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        path = self._record("POST")
        if path != LOGIN_PATH:
            self._send_html(404, "<!doctype html><title>Not found</title><h1>Not found</h1>")
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        fields = parse_qs(body, keep_blank_values=True)
        username = (fields.get("username") or [""])[0]
        password = (fields.get("password") or [""])[0]

        if username == self._username and password == self._password:
            # A different URL, carrying no password field: the two things
            # classify_login_outcome requires before it will say SUCCESS.
            self.send_response(303)
            self.send_header("Location", HOME_PATH)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self._send_html(200, self._login_html(notice=_FAILURE_NOTICE))

    # -- helpers ---------------------------------------------------------
    @property
    def _title(self) -> str:
        return self.server.title  # type: ignore[attr-defined]

    @property
    def _username(self) -> str:
        return self.server.valid_username  # type: ignore[attr-defined]

    @property
    def _password(self) -> str:
        return self.server.valid_password  # type: ignore[attr-defined]

    def _record(self, method: str) -> str:
        path = urlsplit(self.path).path
        self.server.recorded.append((method, path))  # type: ignore[attr-defined]
        return path

    def _login_html(self, notice: str = "") -> str:
        images = "\n".join(
            f'<p><img src="{url}" alt="" width="1" height="1"></p>'
            for url in self.server.image_urls  # type: ignore[attr-defined]
        )
        return _LOGIN_HTML.format(title=self._title, notice=notice, action=LOGIN_PATH, images=images)

    def _send_html(self, status: int, html: str) -> None:
        self._send_bytes(status, html.encode("utf-8"), "text/html; charset=utf-8")

    def _send_bytes(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def start_lab_server(
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    banner: str = DEFAULT_BANNER,
    title: str = DEFAULT_TITLE,
    username: str = "admin",
    password: str = "",
    image_urls: tuple[str, ...] = (TRACKER_PATH,),
) -> LabTarget:
    """Start a lab device on a background thread.

    ``port=0`` takes whatever the OS hands out, so a leftover socket from
    a previous run cannot collide with this one. ``image_urls`` are
    embedded in the login page as 1x1 images; a test uses them to observe
    which subresource requests the scope guard actually let through.
    """
    server = ThreadingHTTPServer((host, port), _LabHandler)
    server.daemon_threads = True
    server.banner = banner  # type: ignore[attr-defined]
    server.title = title  # type: ignore[attr-defined]
    server.valid_username = username  # type: ignore[attr-defined]
    server.valid_password = password  # type: ignore[attr-defined]
    server.image_urls = tuple(image_urls)  # type: ignore[attr-defined]
    server.recorded = []  # type: ignore[attr-defined]

    thread = threading.Thread(target=server.serve_forever, name="nwaa-lab-server", daemon=True)
    thread.start()
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    return LabTarget(
        server=server,
        thread=thread,
        host=str(bound_host),
        port=int(bound_port),
        requests=server.recorded,  # type: ignore[attr-defined]
    )


_NESSUS_TEMPLATE = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Policy>
    <policyName>nwaa lab</policyName>
  </Policy>
  <Report name="nwaa local lab">
    <ReportHost name="{host}">
      <HostProperties>
        <tag name="host-ip">{host}</tag>
{tags}
      </HostProperties>
{items}
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

_ITEM_TEMPLATE = """      <ReportItem port="{port}" svc_name="www" protocol="tcp" severity="1" pluginID="{plugin_id}" pluginName="Web Management Interface Administrator Login Page" pluginFamily="Web Servers">
        <description>The remote host runs a web management interface that presents an administrator login page.</description>
        <plugin_output>The administrator login page is : {url}</plugin_output>
      </ReportItem>"""


def write_lab_nessus(
    path: str | Path,
    host: str,
    port: int,
    login_urls: list[str],
    *,
    operating_system: str = "",
    system_type: str = "",
) -> Path:
    """Write a minimal .nessus that puts ``host:port`` in scope.

    Scope is derived from the scan file and cannot be widened by a flag,
    so this is the only way to authorize the tool to touch the lab
    server. ``operating_system``/``system_type`` decide whether the
    *offline* fingerprint fires, which is how a test tells a live-banner
    match apart from a scan-file one.
    """
    tags = "\n".join(
        f'        <tag name="{name}">{value}</tag>'
        for name, value in (
            ("operating-system", operating_system),
            ("system-type", system_type),
        )
        if value
    )
    items = "\n".join(
        _ITEM_TEMPLATE.format(port=port, plugin_id=50345 + i, url=url)
        for i, url in enumerate(login_urls)
    )
    path = Path(path)
    path.write_text(_NESSUS_TEMPLATE.format(host=host, tags=tags, items=items), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the nwaa lab device by hand")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--username", default="admin")
    parser.add_argument(
        "--password", default="", help="Password that succeeds (default: blank, as HP ships)"
    )
    parser.add_argument("--write-nessus", help="Also write a .nessus authorizing this target")
    args = parser.parse_args(argv)

    target = start_lab_server(args.host, args.port, username=args.username, password=args.password)
    print(f"lab device : {target.origin}")
    print(f"login page : {target.login_url}")
    print(f"accepts    : username={args.username!r} password={args.password!r}")
    if args.write_nessus:
        written = write_lab_nessus(
            args.write_nessus,
            target.host,
            target.port,
            [target.login_url],
            operating_system="HP LaserJet 4250 Printer",
            system_type="printer",
        )
        print(f"nessus file: {written}")
        print(f"\n  nwaa scan --nessus {written} --out ./lab-out --authorized --default-creds\n")
    print("Ctrl-C to stop.")
    try:
        target.thread.join()
    except KeyboardInterrupt:
        target.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
