from __future__ import annotations

from nwaa.fingerprint import (
    SIGNATURES,
    fingerprint_from_probe,
    fingerprint_services,
    manual_fingerprint,
    match_signatures,
    merge_fingerprints,
)
from nwaa.models import HttpProbe


def test_hp_printer_is_identified_from_nessus_data(devices_scan):
    fingerprints = fingerprint_services(devices_scan)
    hp = fingerprints["10.10.10.20:80"]
    assert hp.profile_id == "hp-printer"
    assert hp.category == "printer"
    assert hp.confidence == "high"  # several patterns matched
    assert hp.source == "nessus"
    assert hp.evidence


def test_idrac_is_identified_from_nessus_data(devices_scan):
    fingerprints = fingerprint_services(devices_scan)
    assert fingerprints["10.10.10.21:443"].profile_id == "dell-idrac"


def test_plain_web_server_is_not_fingerprinted(devices_scan):
    """A generic nginx login page must not be guessed into a vendor profile."""
    assert "10.10.10.22:80" not in fingerprint_services(devices_scan)


def test_sample_scan_has_no_false_positives(sample_scan):
    assert fingerprint_services(sample_scan) == {}


def test_php_stack_is_not_mistaken_for_hp_or_phpmyadmin():
    assert match_signatures("Server: Apache/2.4.57 (Debian) PHP/8.1.2") is None


def test_live_server_header_identifies_the_device():
    probe = HttpProbe(url="http://10.0.0.5/", server="HP HTTP Server; HP LaserJet MFP M528")
    fingerprint = fingerprint_from_probe(probe)
    assert fingerprint is not None
    assert fingerprint.profile_id == "hp-printer"
    assert fingerprint.source == "http"
    assert fingerprint.confidence == "high"


def test_www_authenticate_realm_is_used():
    probe = HttpProbe(url="http://10.0.0.6/", www_authenticate='Basic realm="Webfig"')
    fingerprint = fingerprint_from_probe(probe)
    assert fingerprint is not None
    assert fingerprint.profile_id == "mikrotik-device"


def test_generic_fallback_is_low_confidence():
    probe = HttpProbe(url="http://10.0.0.7/", title="Multifunction printer status")
    fingerprint = fingerprint_from_probe(probe)
    assert fingerprint is not None
    assert fingerprint.profile_id == "generic-printer"
    assert fingerprint.confidence == "low"


def test_specific_offline_match_beats_generic_live_match(devices_scan):
    offline = fingerprint_services(devices_scan)["10.10.10.20:80"]
    generic = fingerprint_from_probe(HttpProbe(url="x", title="printer"))
    merged = merge_fingerprints(offline, generic)
    assert merged is not None
    assert merged.profile_id == "hp-printer"


def test_agreeing_sources_merge_to_high_confidence():
    offline = match_signatures("HP LaserJet 4250", source="nessus")
    live = fingerprint_from_probe(HttpProbe(url="x", server="HP HTTP Server"))
    merged = merge_fingerprints(offline, live)
    assert merged is not None
    assert merged.profile_id == "hp-printer"
    assert merged.confidence == "high"
    assert merged.source == "nessus+http"


def test_merge_handles_missing_sides():
    live = fingerprint_from_probe(HttpProbe(url="x", server="HP HTTP Server"))
    assert merge_fingerprints(None, None) is None
    assert merge_fingerprints(None, live) is live
    assert merge_fingerprints(live, None) is live


def test_manual_fingerprint_uses_the_named_profile():
    fingerprint = manual_fingerprint("xerox-printer")
    assert fingerprint.profile_id == "xerox-printer"
    assert fingerprint.source == "manual"
    assert fingerprint.vendor == "Xerox"


def test_manual_fingerprint_tolerates_an_unknown_id():
    assert manual_fingerprint("not-a-profile").profile_id == "not-a-profile"


def test_signature_profile_ids_are_unique():
    ids = [sig.profile_id for sig in SIGNATURES]
    assert len(ids) == len(set(ids))
