from __future__ import annotations

from nwaa.classifier import identify_login_pages, plaintext_http_services


def test_login_pages_use_urls_reported_by_nessus(sample_login_pages):
    urls = {page.url for page in sample_login_pages}
    assert urls == {
        "http://10.10.10.5/login.php",
        "https://10.10.10.9/admin/login",
    }


def test_login_pages_carry_plugin_evidence(sample_login_pages):
    page = next(p for p in sample_login_pages if p.url.endswith("/login.php"))
    assert page.detection_method == "nessus_plugin"
    assert any("42057" in ev for ev in page.evidence)


def test_plaintext_flag_matches_scheme(sample_login_pages):
    http_page = next(p for p in sample_login_pages if p.url.startswith("http://"))
    https_page = next(p for p in sample_login_pages if p.url.startswith("https://"))
    assert http_page.is_plaintext
    assert not https_page.is_plaintext


def test_web_server_without_login_evidence_is_not_a_login_page(sample_login_pages):
    assert not any(":8080" in p.url for p in sample_login_pages)


def test_non_web_services_are_never_login_pages(sample_login_pages):
    assert all(p.service.port != 22 for p in sample_login_pages)


def test_plaintext_http_services_lists_only_non_tls_web(sample_scan):
    plaintext = plaintext_http_services(list(sample_scan.services))
    assert {(s.host_ip, s.port) for s in plaintext} == {("10.10.10.5", 80), ("10.10.10.30", 8080)}


def test_identify_login_pages_is_deterministic(sample_scan):
    assert identify_login_pages(sample_scan) == identify_login_pages(sample_scan)
