from __future__ import annotations

import json

import pytest

from nwaa.credential_tester import (
    DEFAULT_MAX_ATTEMPTS_PER_PAGE,
    HARD_MAX_ATTEMPTS_PER_PAGE,
    CredentialConfigError,
    classify_login_outcome,
    combine_credentials,
    load_credentials,
    select_credentials_for_attempt,
)
from nwaa.default_creds import credentials_for_profile
from nwaa.models import AttemptVerdict, Credential, SecretStr
from nwaa.redaction import scrub_secrets


def _write_creds(tmp_path, entries):
    path = tmp_path / "creds.json"
    path.write_text(json.dumps({"credentials": entries}), encoding="utf-8")
    return path


def test_load_credentials_reads_entries(tmp_path):
    path = _write_creds(tmp_path, [{"username": "admin", "password": "s3cr3t", "label": "vendor-default"}])
    creds = load_credentials(path)
    assert len(creds) == 1
    assert creds[0].username == "admin"
    assert creds[0].label == "vendor-default"
    assert creds[0].password.reveal() == "s3cr3t"


def test_loaded_password_is_registered_for_redaction(tmp_path):
    path = _write_creds(tmp_path, [{"username": "admin", "password": "hunter2-unique"}])
    load_credentials(path)
    assert "hunter2-unique" not in scrub_secrets("password was hunter2-unique")


def test_password_never_appears_in_repr(tmp_path):
    path = _write_creds(tmp_path, [{"username": "admin", "password": "topsecret"}])
    cred = load_credentials(path)[0]
    assert "topsecret" not in repr(cred)
    assert "topsecret" not in str(cred.password)
    assert "topsecret" not in repr(cred.password)
    assert "topsecret" not in f"{cred} {cred.password}"


@pytest.mark.parametrize(
    "payload",
    [
        {"credentials": []},
        {"credentials": "admin:admin"},
        {"creds": [{"username": "a", "password": "b"}]},
        {"credentials": [{"username": "a"}]},
    ],
)
def test_malformed_credential_files_are_rejected(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(CredentialConfigError):
        load_credentials(path)


def test_non_json_credential_file_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("admin:admin", encoding="utf-8")
    with pytest.raises(CredentialConfigError):
        load_credentials(path)


def _creds(n):
    return [Credential(username=f"u{i}", password=SecretStr(f"p{i}")) for i in range(n)]


def test_small_credential_list_is_used_as_is():
    selected, warning = select_credentials_for_attempt(_creds(3))
    assert len(selected) == 3
    assert warning is None


def test_default_cap_truncates_and_warns():
    selected, warning = select_credentials_for_attempt(_creds(50))
    assert len(selected) == DEFAULT_MAX_ATTEMPTS_PER_PAGE
    assert warning is not None and "refuses to spray" in warning


def test_hard_ceiling_cannot_be_raised_by_caller():
    selected, warning = select_credentials_for_attempt(_creds(500), max_attempts_per_page=10_000)
    assert len(selected) == HARD_MAX_ATTEMPTS_PER_PAGE
    assert warning is not None


def test_operator_credentials_come_before_vendor_defaults():
    """The cap truncates the tail, so an explicit credential must never be
    displaced by a bundled default."""
    user = _creds(2)
    combined = combine_credentials(user, credentials_for_profile("hp-printer"))
    assert [c.username for c in combined[:2]] == ["u0", "u1"]
    assert combined[2].source == "vendor_default"


def test_duplicate_credentials_are_not_tried_twice():
    duplicate = Credential(username="admin", password=SecretStr("admin"), label="mine")
    combined = combine_credentials([duplicate], credentials_for_profile("tplink-device"))
    assert len(combined) == 1
    assert combined[0].label == "mine"


def test_adding_vendor_defaults_cannot_raise_the_per_page_cap():
    combined = combine_credentials(_creds(3), credentials_for_profile("hp-printer"))
    selected, warning = select_credentials_for_attempt(combined, DEFAULT_MAX_ATTEMPTS_PER_PAGE)
    assert len(selected) == DEFAULT_MAX_ATTEMPTS_PER_PAGE
    assert warning is not None


def test_combining_with_no_defaults_is_a_no_op():
    user = _creds(3)
    assert combine_credentials(user, []) == user


def test_success_requires_url_change_no_password_field_and_no_error_text():
    verdict, _ = classify_login_outcome(
        pre_url="http://10.10.10.5/login.php",
        post_url="http://10.10.10.5/dashboard",
        page_text="Welcome back, admin. Sign out",
        password_field_present_after=False,
    )
    assert verdict is AttemptVerdict.SUCCESS


def test_failure_text_with_password_field_is_authentication_failed():
    verdict, _ = classify_login_outcome(
        pre_url="http://10.10.10.5/login.php",
        post_url="http://10.10.10.5/login.php",
        page_text="Invalid username or password",
        password_field_present_after=True,
    )
    assert verdict is AttemptVerdict.FAILED


def test_failure_text_without_password_field_is_still_failed():
    verdict, _ = classify_login_outcome(
        pre_url="http://10.10.10.5/login.php",
        post_url="http://10.10.10.5/error",
        page_text="Access denied",
        password_field_present_after=False,
    )
    assert verdict is AttemptVerdict.FAILED


def test_password_field_still_present_without_error_text_is_inconclusive():
    verdict, _ = classify_login_outcome(
        pre_url="http://10.10.10.5/login.php",
        post_url="http://10.10.10.5/login.php",
        page_text="Please log in to continue",
        password_field_present_after=True,
    )
    assert verdict is AttemptVerdict.INCONCLUSIVE


def test_same_url_and_no_signal_is_inconclusive_not_success():
    verdict, _ = classify_login_outcome(
        pre_url="http://10.10.10.5/login.php",
        post_url="http://10.10.10.5/login.php",
        page_text="Loading application",
        password_field_present_after=False,
    )
    assert verdict is AttemptVerdict.INCONCLUSIVE
