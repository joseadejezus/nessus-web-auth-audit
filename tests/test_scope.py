from __future__ import annotations

from nwaa.scope import build_scope


def test_scan_hosts_and_ports_are_in_scope(sample_scan):
    scope = build_scope(list(sample_scan.services))
    assert scope.is_url_in_scope("http://10.10.10.5/login.php")
    assert scope.is_url_in_scope("https://10.10.10.9/admin/login")
    assert scope.is_url_in_scope("http://10.10.10.30:8080/")


def test_hostname_from_scan_is_in_scope(sample_scan):
    scope = build_scope(list(sample_scan.services))
    assert scope.is_url_in_scope("http://intranet.example.local/login.php")
    assert scope.is_host_in_scope("INTRANET.EXAMPLE.LOCAL")


def test_unscanned_host_is_out_of_scope(sample_scan):
    scope = build_scope(list(sample_scan.services))
    assert not scope.is_url_in_scope("http://10.10.10.99/login")
    assert not scope.is_url_in_scope("https://evil.example.com/steal")
    assert not scope.is_host_in_scope("evil.example.com")


def test_unscanned_port_on_scanned_host_is_out_of_scope(sample_scan):
    scope = build_scope(list(sample_scan.services))
    assert not scope.is_url_in_scope("http://10.10.10.5:9090/login")
    assert not scope.is_url_in_scope("https://10.10.10.5/login")  # 443 was not scanned on this host


def test_non_http_schemes_are_rejected(sample_scan):
    scope = build_scope(list(sample_scan.services))
    assert not scope.is_url_in_scope("file:///etc/passwd")
    assert not scope.is_url_in_scope("ftp://10.10.10.5/")
    assert not scope.is_url_in_scope("javascript:alert(1)")
    assert not scope.is_url_in_scope("not a url")
