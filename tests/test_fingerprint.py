from __future__ import annotations

import pytest

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


# --- profiles added for a Puerto Rico cooperativa estate -------------------
#
# One representative banner per profile, written the way the device's own
# Server header or <title> reads. The table doubles as the negative test: a
# banner that selected a *different* vendor's profile would send that vendor's
# default credentials at a live device, which is the failure mode this whole
# signature table exists to avoid.
COOP_BANNERS = [
    ("fortinet-fortigate", "FortiGate-60F login | FortiOS 7.2.5"),
    ("sonicwall-firewall", "SonicWALL - Authentication (SonicOS 6.5)"),
    ("watchguard-firebox", "WatchGuard Firebox T40 - Fireware Web UI"),
    ("sophos-firewall", "Sophos Firewall (SFOS 19.5) - Admin login"),
    ("pfsense-firewall", "Login | pfSense - Netgate SG-2100"),
    ("barracuda-appliance", "Barracuda Web Application Firewall"),
    ("eaton-ups", "Eaton Network-M2 - UPS status"),
    ("tripplite-ups", "Tripp Lite PowerAlert Network Management Card"),
    ("cyberpower-ups", "CyberPower RMCARD205 Remote Management"),
    ("vertiv-liebert", "Vertiv Liebert IntelliSlot Unity card"),
    ("hanwha-camera", "Wisenet XND-6080 Network Camera (Hanwha Vision)"),
    ("uniview-camera", "Uniview NVR301-08 Network Video Recorder"),
    ("avigilon-camera", "Avigilon H4A camera web interface"),
    ("zkteco-access", "ZKTeco iClock880 attendance terminal"),
    ("hid-access", "HID VertX EVO V1000 controller"),
    ("aruba-instant", "Aruba Instant Virtual Controller - IAP-315"),
    ("ruckus-wireless", "Ruckus ZoneDirector 1200 admin"),
    ("grandstream-device", "Grandstream GXP2170 Web Configuration"),
    ("yealink-phone", "Yealink SIP-T46G Web User Interface"),
    ("polycom-phone", "Polycom VVX 411 Utilities Login"),
    ("avaya-ipoffice", "Avaya IP Office Web Manager"),
    ("cisco-cimc", "Cisco Integrated Management Controller - UCS-C220 M5"),
    ("nutanix-prism", "Nutanix Prism Element"),
    ("proxmox-ve", "Proxmox Virtual Environment 8.1"),
]


@pytest.mark.parametrize(
    ("profile_id", "banner"), COOP_BANNERS, ids=[entry[0] for entry in COOP_BANNERS]
)
def test_coop_banner_selects_exactly_its_own_profile(profile_id, banner):
    fingerprint = match_signatures(banner, source="http")
    assert fingerprint is not None, f"{profile_id}: banner matched no signature at all"
    assert fingerprint.profile_id == profile_id, (
        f"{profile_id}: banner selected {fingerprint.profile_id} instead — that would send "
        f"the wrong vendor's default credentials"
    )
    assert fingerprint.evidence


@pytest.mark.parametrize(
    "banner",
    [
        "Cooperativa de Ahorro y Crédito — Acceso de Socios",
        "Portal del Socio - inicie sesión",
        "Server: Apache/2.4.57 (Debian)",
        "Server: Microsoft-IIS/10.0",
        "Server: nginx/1.24.0",
        "Online Banking Login",
    ],
)
def test_ordinary_web_logins_are_not_fingerprinted(banner):
    """A member portal is not a device. Guessing one into a vendor profile is
    how a default-credential run ends up submitting logins to a core system."""
    assert match_signatures(banner, source="http") is None


def test_aruba_switch_and_instant_ap_stay_apart():
    """Both report ArubaOS, and they do not take the same credentials."""
    switch = match_signatures("ArubaOS ProCurve Switch 2530", source="http")
    instant = match_signatures("Aruba Instant Virtual Controller", source="http")
    assert switch is not None and switch.profile_id == "hp-procurve"
    assert instant is not None and instant.profile_id == "aruba-instant"


def test_cisco_switch_is_not_mistaken_for_a_management_controller():
    switch = match_signatures("Cisco IOS Software, C2960 Software", source="http")
    assert switch is not None and switch.profile_id == "cisco-device"


def test_coop_banner_table_names_real_signatures():
    known = {sig.profile_id for sig in SIGNATURES}
    unknown = sorted({profile_id for profile_id, _ in COOP_BANNERS} - known)
    assert not unknown, f"banner table names signatures that do not exist: {unknown}"
