"""probe_open_page works on whatever a real page hands it, including
nothing at all — a missing banner must never fail a scan."""
from __future__ import annotations

from nwaa.fingerprint import fingerprint_from_probe
from nwaa.probe import BODY_SNIPPET_CHARS, probe_open_page


class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers or {}


class FakePage:
    def __init__(self, title="", content=""):
        self._title = title
        self._content = content

    def title(self):
        return self._title

    def content(self):
        return self._content


class ExplodingPage:
    def title(self):
        raise RuntimeError("renderer gone")

    def content(self):
        raise RuntimeError("renderer gone")


def test_headers_are_read_case_insensitively():
    response = FakeResponse(headers={"SERVER": "HP HTTP Server", "WWW-Authenticate": "Basic"})
    probe = probe_open_page(FakePage(title="EWS"), response, "http://10.0.0.1/")
    assert probe.server == "HP HTTP Server"
    assert probe.www_authenticate == "Basic"
    assert probe.status == 200
    assert probe.title == "EWS"


def test_probe_feeds_the_fingerprint_matcher():
    response = FakeResponse(headers={"Server": "HP HTTP Server"})
    probe = probe_open_page(FakePage(title="HP LaserJet"), response, "http://10.0.0.1/")
    fingerprint = fingerprint_from_probe(probe)
    assert fingerprint is not None
    assert fingerprint.profile_id == "hp-printer"


def test_missing_response_is_tolerated():
    probe = probe_open_page(FakePage(title="x"), None, "http://10.0.0.1/")
    assert probe.status is None
    assert probe.server == ""
    assert probe.title == "x"


def test_page_errors_are_swallowed():
    probe = probe_open_page(ExplodingPage(), FakeResponse(), "http://10.0.0.1/")
    assert probe.title == ""
    assert probe.text_snippet == ""
    assert probe.url == "http://10.0.0.1/"


def test_body_snippet_is_bounded():
    probe = probe_open_page(FakePage(content="A" * 50_000), None, "http://10.0.0.1/")
    assert len(probe.text_snippet) == BODY_SNIPPET_CHARS


def test_signals_skip_empty_fields():
    probe = probe_open_page(FakePage(), None, "http://10.0.0.1/")
    assert probe.signals == ()
