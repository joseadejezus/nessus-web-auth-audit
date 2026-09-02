from __future__ import annotations

import pytest

from nwaa.default_creds import (
    MAX_CREDENTIALS_PER_PROFILE,
    VENDOR_DEFAULT_SOURCE,
    DefaultCredentialDbError,
    credentials_for_fingerprint,
    credentials_for_profile,
    describe_profiles,
    get_profile,
    load_profiles,
    parse_profiles,
    profile_ids,
)
from nwaa.fingerprint import SIGNATURES, manual_fingerprint
from nwaa.redaction import scrub_secrets


def test_every_signature_has_a_credential_profile():
    """A fingerprint that cannot select a profile is a dead end."""
    missing = [sig.profile_id for sig in SIGNATURES if sig.profile_id not in load_profiles()]
    assert not missing, f"signatures without a default-credential profile: {missing}"


def test_profile_listing_names_profiles_and_usernames():
    text = describe_profiles()
    assert "hp-printer" in text
    assert "HP printer" in text
    assert "usernames: admin" in text


@pytest.mark.parametrize("password", ["adminadmin", "weblogic1", "s3cret"])
def test_profile_listing_hides_passwords_by_default(password):
    """Distinctive passwords no profile note quotes must not leak into the listing."""
    assert password not in describe_profiles()
    assert password in describe_profiles(show_passwords=True)


def test_hp_printer_profile_yields_vendor_default_credentials():
    creds = credentials_for_profile("hp-printer")
    assert creds
    assert all(c.source == VENDOR_DEFAULT_SOURCE for c in creds)
    assert all(c.label.startswith("default:hp-printer") for c in creds)
    assert any(c.username == "admin" for c in creds)


def test_default_passwords_are_not_registered_for_redaction():
    """Published factory defaults are documentation, not engagement secrets.

    Registering them meant the registry could not tell the string
    "password" in the HP profile from a real password, and scrubbed that
    word out of every report field it appeared in — including a target's
    own page title. Operator-supplied passwords are still registered;
    see test_credential_tester.py.
    """
    creds = credentials_for_profile("hp-printer")
    common = next(c.password.reveal() for c in creds if c.password.reveal() == "password")
    assert scrub_secrets(f"No {common} field found on page") == "No password field found on page"


def test_default_passwords_are_still_wrapped_in_secretstr():
    """Not redacted is not the same as printable: SecretStr still applies."""
    cred = next(c for c in credentials_for_profile("dell-idrac") if c.password.reveal())
    assert cred.password.reveal() not in str(cred.password)
    assert cred.password.reveal() not in f"{cred.password}"


def test_default_password_never_appears_in_repr():
    cred = credentials_for_profile("dell-idrac")[0]
    assert cred.password.reveal() not in repr(cred)


def test_fingerprint_selects_only_its_own_profile():
    creds = credentials_for_fingerprint(manual_fingerprint("ubiquiti-device"))
    assert {c.username for c in creds} == {"ubnt", "ui"}


def test_no_fingerprint_means_no_credentials():
    assert credentials_for_fingerprint(None) == []


def test_unknown_profile_yields_nothing():
    assert credentials_for_profile("no-such-device") == []


@pytest.mark.parametrize("profile_id", ["hp-ilo", "vmware-esxi", "jenkins"])
def test_profiles_without_a_factory_default_are_empty_and_explained(profile_id):
    """These devices have per-unit or installer-set passwords, so there is
    nothing to try; the profile documents that rather than guessing."""
    profile = get_profile(profile_id)
    assert profile is not None
    assert profile.is_empty
    assert profile.notes
    assert credentials_for_profile(profile_id) == []


def test_no_profile_is_large_enough_to_be_a_wordlist():
    for profile_id in profile_ids():
        entries = load_profiles()[profile_id].entries
        assert len(entries) <= MAX_CREDENTIALS_PER_PROFILE, profile_id


def test_blank_passwords_are_allowed_and_preserved():
    creds = credentials_for_profile("mikrotik-device")
    assert creds[0].username == "admin"
    assert creds[0].password.reveal() == ""


def test_oversized_profile_is_rejected():
    document = {
        "schema_version": 1,
        "profiles": {
            "bloated": {
                "credentials": [
                    {"username": f"u{i}", "password": f"p{i}"}
                    for i in range(MAX_CREDENTIALS_PER_PROFILE + 1)
                ]
            }
        },
    }
    with pytest.raises(DefaultCredentialDbError, match="wordlists"):
        parse_profiles(document)


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": 1},
        {"schema_version": 1, "profiles": {}},
        {"schema_version": 1, "profiles": {"x": {"credentials": "admin:admin"}}},
        {"schema_version": 1, "profiles": {"x": {"credentials": [{"username": "a"}]}}},
        {"schema_version": 1, "profiles": {"x": "not-an-object"}},
    ],
)
def test_malformed_databases_are_rejected(document):
    with pytest.raises(DefaultCredentialDbError):
        parse_profiles(document)
