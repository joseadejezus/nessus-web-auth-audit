from __future__ import annotations

import json

import pytest

from nwaa.cli import EXIT_OK, EXIT_PARSE_ERROR, EXIT_USAGE, main


def test_parse_only_scan_writes_all_three_reports(sample_nessus_path, tmp_path, capsys):
    code = main(["scan", "--nessus", str(sample_nessus_path), "--out", str(tmp_path)])
    assert code == EXIT_OK

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["login_pages"] == 2
    assert (tmp_path / "report.txt").is_file()
    assert (tmp_path / "report.html").is_file()

    out = capsys.readouterr().out
    assert "LOGIN PAGES" in out
    assert "HTML report" in out


def test_parse_only_scan_contacts_nothing(sample_nessus_path, tmp_path):
    """No --authorized means no screenshots directory is ever created."""
    main(["scan", "--nessus", str(sample_nessus_path), "--out", str(tmp_path)])
    assert not (tmp_path / "screenshots").exists()


def test_credential_testing_requires_explicit_authorization(sample_nessus_path, tmp_path):
    creds = tmp_path / "creds.json"
    creds.write_text(json.dumps({"credentials": [{"username": "a", "password": "b"}]}), encoding="utf-8")
    code = main(
        ["scan", "--nessus", str(sample_nessus_path), "--out", str(tmp_path), "--credentials", str(creds)]
    )
    assert code == EXIT_USAGE
    assert not (tmp_path / "report.json").exists()


def test_default_credential_testing_requires_explicit_authorization(sample_nessus_path, tmp_path):
    code = main(["scan", "--nessus", str(sample_nessus_path), "--out", str(tmp_path), "--default-creds"])
    assert code == EXIT_USAGE
    assert not (tmp_path / "report.json").exists()


def test_unknown_profile_is_rejected(sample_nessus_path, tmp_path):
    code = main(
        [
            "scan", "--nessus", str(sample_nessus_path), "--out", str(tmp_path),
            "--authorized", "--profile", "not-a-real-device",
        ]
    )
    assert code == EXIT_USAGE


def test_no_fingerprint_conflicts_with_default_creds(sample_nessus_path, tmp_path):
    code = main(
        [
            "scan", "--nessus", str(sample_nessus_path), "--out", str(tmp_path),
            "--authorized", "--default-creds", "--no-fingerprint",
        ]
    )
    assert code == EXIT_USAGE


def test_parse_only_scan_still_fingerprints_devices(devices_nessus_path, tmp_path):
    """Fingerprinting is offline, so it works without --authorized."""
    assert main(["scan", "--nessus", str(devices_nessus_path), "--out", str(tmp_path)]) == EXIT_OK

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    devices = {d["target"]: d["profile_id"] for d in report["devices"]}
    assert devices["10.10.10.20:80"] == "hp-printer"
    assert devices["10.10.10.21:443"] == "dell-idrac"
    assert report["summary"]["devices_fingerprinted"] == 2
    assert report["summary"]["vendor_default_attempts"] == 0

    by_url = {p["url"]: p for p in report["login_pages"]}
    printer = by_url["http://10.10.10.20/hp/device/set_config_password.html"]
    assert printer["device"]["vendor"] == "HP"


def test_no_fingerprint_suppresses_device_detection(devices_nessus_path, tmp_path):
    code = main(
        ["scan", "--nessus", str(devices_nessus_path), "--out", str(tmp_path), "--no-fingerprint"]
    )
    assert code == EXIT_OK
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["devices"] == []


def test_profiles_subcommand_lists_bundled_profiles(capsys):
    assert main(["profiles"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "hp-printer" in out
    assert "dell-idrac" in out


def test_unparseable_nessus_file_exits_with_parse_error(tmp_path):
    bad = tmp_path / "bad.nessus"
    bad.write_text("not xml at all", encoding="utf-8")
    assert main(["scan", "--nessus", str(bad), "--out", str(tmp_path)]) == EXIT_PARSE_ERROR


def test_xxe_file_is_refused_by_cli(malicious_nessus_path, tmp_path):
    assert main(["scan", "--nessus", str(malicious_nessus_path), "--out", str(tmp_path)]) == EXIT_PARSE_ERROR


@pytest.mark.parametrize(
    "extra",
    [["--max-attempts-per-page", "0"], ["--timeout-ms", "10"]],
)
def test_invalid_bounds_are_rejected(sample_nessus_path, tmp_path, extra):
    code = main(["scan", "--nessus", str(sample_nessus_path), "--out", str(tmp_path), *extra])
    assert code == EXIT_USAGE


def test_missing_subcommand_exits_nonzero():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code != 0


def test_view_rebuilds_html_from_saved_json(sample_nessus_path, tmp_path):
    main(["scan", "--nessus", str(sample_nessus_path), "--out", str(tmp_path)])
    (tmp_path / "report.html").unlink()

    code = main(["view", "--json", str(tmp_path / "report.json")])
    assert code == EXIT_OK
    assert (tmp_path / "report.html").is_file()


def test_view_writes_to_explicit_path(sample_nessus_path, tmp_path):
    main(["scan", "--nessus", str(sample_nessus_path), "--out", str(tmp_path)])
    target = tmp_path / "custom" / "viewer.html"
    assert main(["view", "--json", str(tmp_path / "report.json"), "--html", str(target)]) == EXIT_OK
    assert target.is_file()


def test_view_rejects_foreign_json(tmp_path):
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"tool": "something-else"}), encoding="utf-8")
    assert main(["view", "--json", str(other)]) == EXIT_USAGE


def test_view_rejects_missing_file(tmp_path):
    assert main(["view", "--json", str(tmp_path / "nope.json")]) == EXIT_USAGE
