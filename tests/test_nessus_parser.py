from __future__ import annotations

import pytest

from nwaa.nessus_parser import NessusParseError, parse_nessus_file


def test_parses_hosts_ports_and_service_metadata(sample_scan):
    keys = {(s.host_ip, s.port) for s in sample_scan.services}
    assert keys == {
        ("10.10.10.5", 80),
        ("10.10.10.5", 22),
        ("10.10.10.9", 443),
        ("10.10.10.30", 8080),
    }
    assert sample_scan.report_name == "Sample Internal Scan"


def test_fqdn_is_carried_onto_services(sample_scan):
    web = next(s for s in sample_scan.services if s.host_ip == "10.10.10.5" and s.port == 80)
    assert web.hostname == "intranet.example.local"


def test_web_and_tls_classification(sample_scan):
    http_svc = next(s for s in sample_scan.services if s.host_ip == "10.10.10.5" and s.port == 80)
    https_svc = next(s for s in sample_scan.services if s.host_ip == "10.10.10.9")
    ssh_svc = next(s for s in sample_scan.services if s.port == 22)

    assert http_svc.is_web and not http_svc.is_tls
    assert http_svc.is_plaintext_http
    assert http_svc.scheme == "http"

    assert https_svc.is_web and https_svc.is_tls
    assert not https_svc.is_plaintext_http
    assert https_svc.base_url == "https://10.10.10.9"

    assert not ssh_svc.is_web


def test_non_default_port_appears_in_base_url(sample_scan):
    svc = next(s for s in sample_scan.services if s.port == 8080)
    assert svc.base_url == "http://10.10.10.30:8080"


def test_host_tags_are_captured_for_fingerprinting(devices_scan):
    facts = devices_scan.host_facts["10.10.10.20"]
    assert facts.operating_system == "HP LaserJet 4250 Printer"
    assert facts.system_type == "printer"


def test_host_facts_default_to_empty_strings(sample_scan):
    facts = sample_scan.host_facts["10.10.10.9"]
    assert facts.operating_system == ""
    assert facts.hostname is None


def test_oversized_host_tags_are_truncated(tmp_path):
    """Scan files are untrusted; tag text is bounded before it reaches the matcher."""
    path = tmp_path / "big.nessus"
    path.write_text(
        "<NessusClientData_v2><Report name='r'><ReportHost name='1.2.3.4'>"
        "<HostProperties><tag name='host-ip'>1.2.3.4</tag>"
        f"<tag name='operating-system'>{'A' * 5000}</tag>"
        "</HostProperties></ReportHost></Report></NessusClientData_v2>",
        encoding="utf-8",
    )
    scan = parse_nessus_file(path)
    assert len(scan.host_facts["1.2.3.4"].operating_system) == 512


def test_xxe_payload_is_refused(malicious_nessus_path):
    with pytest.raises(NessusParseError) as exc:
        parse_nessus_file(malicious_nessus_path)
    assert "forbidden XML" in str(exc.value)


def test_missing_file_raises(tmp_path):
    with pytest.raises(NessusParseError):
        parse_nessus_file(tmp_path / "nope.nessus")


def test_wrong_root_element_raises(tmp_path):
    path = tmp_path / "other.xml"
    path.write_text("<SomethingElse><Report/></SomethingElse>", encoding="utf-8")
    with pytest.raises(NessusParseError) as exc:
        parse_nessus_file(path)
    assert "does not look like a .nessus file" in str(exc.value)


def test_malformed_xml_raises(tmp_path):
    path = tmp_path / "broken.nessus"
    path.write_text("<NessusClientData_v2><Report>", encoding="utf-8")
    with pytest.raises(NessusParseError):
        parse_nessus_file(path)
