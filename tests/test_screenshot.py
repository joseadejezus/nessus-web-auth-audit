from __future__ import annotations

from pathlib import Path

from nwaa.screenshot import safe_filename


def test_filename_is_derived_from_host_port_and_path():
    name = safe_filename("http://10.10.10.5/login.php")
    assert name.startswith("10.10.10.5_80_-login.php_")
    assert name.endswith(".png")


def test_traversal_in_url_cannot_escape_the_output_directory(tmp_path):
    name = safe_filename("http://10.10.10.5/../../../../etc/passwd")
    assert "/" not in name and "\\" not in name
    assert ".." not in name
    resolved = (tmp_path / name).resolve()
    assert resolved.parent == Path(tmp_path).resolve()


def test_distinct_urls_get_distinct_filenames():
    a = safe_filename("http://10.10.10.5/login")
    b = safe_filename("http://10.10.10.5/login?next=/admin")
    assert a != b


def test_filename_is_stable_for_the_same_url():
    assert safe_filename("https://10.10.10.9/admin/login") == safe_filename("https://10.10.10.9/admin/login")


def test_long_urls_are_truncated_but_still_unique():
    long_path = "/" + "a" * 500
    a = safe_filename(f"http://10.10.10.5{long_path}1")
    b = safe_filename(f"http://10.10.10.5{long_path}2")
    assert len(a) < 120 and a != b
