"""Vendor default-credential profiles, selected by device fingerprint.

The bundled database (``data/default_credentials.json``) holds the
factory credentials vendors publish in their own manuals, keyed by the
profile ids that ``nwaa.fingerprint`` produces. Detecting an HP printer
therefore selects the HP profile and nothing else — this is a targeted
default-credential check, not a password list.

The rules that keep it that way:

  * A profile is only used when a fingerprint (or an explicit
    ``--profile``) names it. There is no "try everything" mode.
  * The result is still funnelled through
    ``credential_tester.select_credentials_for_attempt``, so
    HARD_MAX_ATTEMPTS_PER_PAGE applies exactly as it does to
    operator-supplied credentials.

These passwords are deliberately **not** registered with
``nwaa.redaction``, which is the one place they are treated differently
from an operator's. They are factory defaults published in vendor
manuals, and ``nwaa profiles --show-passwords`` prints them on request —
they are documentation, not engagement secrets. Registering them meant
the redaction registry could not tell the string ``password`` in an HP
profile from a real password, so it scrubbed that word out of every
report field it appeared in: a live run reported "No ***REDACTED***
field found on page", and a device whose own page title contained the
word would have been mangled the same way. Nothing interpolates a
password into a report string in the first place (``build_json_report``
serializes field by field and never touches ``Credential.password``), so
the net was protecting almost nothing here while corrupting real text.
Operator-supplied passwords from ``--credentials`` are still registered,
in ``credential_tester.load_credentials`` — those are the secrets.

Offline and dependency-free: this module reads one packaged JSON file
and touches nothing else.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path

from nwaa.models import Credential, DeviceFingerprint, SecretStr

logger = logging.getLogger("nwaa.default_creds")

DATA_PACKAGE = "nwaa.data"
DATA_FILENAME = "default_credentials.json"
SUPPORTED_SCHEMA_VERSION = 1
VENDOR_DEFAULT_SOURCE = "vendor_default"

# A per-profile ceiling below the global one: a vendor default list that
# grew past this is a wordlist, and this tool does not ship wordlists.
MAX_CREDENTIALS_PER_PROFILE = 12


class DefaultCredentialDbError(RuntimeError):
    """Raised when the bundled default-credential database is unusable."""


@dataclass(frozen=True)
class CredentialProfile:
    profile_id: str
    display_name: str
    vendor: str
    category: str
    notes: str
    entries: tuple[tuple[str, str, str], ...]  # (username, password, note)

    @property
    def is_empty(self) -> bool:
        return not self.entries


def _load_raw(path: str | Path | None = None) -> dict:
    if path is not None:
        text = Path(path).read_text(encoding="utf-8")
    else:
        text = resources.files(DATA_PACKAGE).joinpath(DATA_FILENAME).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:  # pragma: no cover - packaging failure
        raise DefaultCredentialDbError(f"{DATA_FILENAME} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DefaultCredentialDbError(f"{DATA_FILENAME} must contain a JSON object")
    if data.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        raise DefaultCredentialDbError(
            f"{DATA_FILENAME} schema_version {data.get('schema_version')!r} is not supported "
            f"(expected {SUPPORTED_SCHEMA_VERSION})"
        )
    return data


def parse_profiles(data: dict) -> dict[str, CredentialProfile]:
    """Validate the raw database into profile objects.

    Split out from loading so tests can validate an in-memory document.
    """
    raw_profiles = data.get("profiles")
    if not isinstance(raw_profiles, dict) or not raw_profiles:
        raise DefaultCredentialDbError("default-credential database has no 'profiles' object")

    profiles: dict[str, CredentialProfile] = {}
    for profile_id, raw in raw_profiles.items():
        if not isinstance(raw, dict):
            raise DefaultCredentialDbError(f"profile {profile_id!r} must be an object")
        raw_entries = raw.get("credentials")
        if not isinstance(raw_entries, list):
            raise DefaultCredentialDbError(f"profile {profile_id!r} must have a 'credentials' list")
        if len(raw_entries) > MAX_CREDENTIALS_PER_PROFILE:
            raise DefaultCredentialDbError(
                f"profile {profile_id!r} has {len(raw_entries)} credentials; the limit is "
                f"{MAX_CREDENTIALS_PER_PROFILE}. Default-credential profiles must not become wordlists."
            )

        entries: list[tuple[str, str, str]] = []
        for index, entry in enumerate(raw_entries):
            if not isinstance(entry, dict) or "username" not in entry or "password" not in entry:
                raise DefaultCredentialDbError(
                    f"profile {profile_id!r} entry {index} needs 'username' and 'password'"
                )
            entries.append(
                (str(entry["username"]), str(entry["password"]), str(entry.get("note", "")))
            )

        profiles[profile_id] = CredentialProfile(
            profile_id=profile_id,
            display_name=str(raw.get("display_name", profile_id)),
            vendor=str(raw.get("vendor", "unknown")),
            category=str(raw.get("category", "unknown")),
            notes=str(raw.get("notes", "")),
            entries=tuple(entries),
        )
    return profiles


@lru_cache(maxsize=1)
def load_profiles() -> dict[str, CredentialProfile]:
    """Load and validate the bundled database (cached)."""
    return parse_profiles(_load_raw())


def profile_ids() -> list[str]:
    return sorted(load_profiles())


def get_profile(profile_id: str) -> CredentialProfile | None:
    return load_profiles().get(profile_id)


def credentials_for_profile(profile_id: str) -> list[Credential]:
    """Credentials for one profile.

    Returns an empty list for an unknown profile, and for profiles that
    legitimately have no factory default (iLO, ESXi, Jenkins).

    These passwords are not registered for redaction — see the module
    docstring for why. They are still wrapped in ``SecretStr``, so no
    accidental ``repr``/``str``/f-string can print one.
    """
    profile = get_profile(profile_id)
    if profile is None:
        logger.debug("No default-credential profile named %s", profile_id)
        return []

    credentials: list[Credential] = []
    for username, password, note in profile.entries:
        label = f"default:{profile_id}" + (f" ({note})" if note else "")
        credentials.append(
            Credential(
                username=username,
                password=SecretStr(password),
                label=label,
                source=VENDOR_DEFAULT_SOURCE,
            )
        )
    return credentials


def credentials_for_fingerprint(fingerprint: DeviceFingerprint | None) -> list[Credential]:
    if fingerprint is None:
        return []
    return credentials_for_profile(fingerprint.profile_id)


def describe_profiles(show_passwords: bool = False) -> str:
    """Human-readable listing for ``nwaa profiles``.

    Usernames and counts are always shown; the passwords themselves only
    with ``show_passwords``, so a listing pasted into a ticket does not
    become a credential list by accident. Note that ``notes`` are vendor
    documentation and may quote a documented default in passing.
    """
    lines = ["Bundled default-credential profiles:", ""]
    for profile_id in profile_ids():
        profile = load_profiles()[profile_id]
        count = len(profile.entries)
        detail = f"{count} credential(s)" if count else "no factory default (see notes)"
        lines.append(f"  {profile_id:<20} {profile.display_name}")
        lines.append(f"  {'':<20} {detail}")
        if show_passwords:
            for username, password, note in profile.entries:
                pair = f"{username or '<blank>'} / {password or '<blank>'}"
                lines.append(f"  {'':<20} - {pair}" + (f"   [{note}]" if note else ""))
        elif count:
            lines.append(f"  {'':<20} usernames: {_usernames(profile)}")
        if profile.notes:
            lines.append(f"  {'':<20} {profile.notes}")
        lines.append("")
    lines.append(
        "A profile is only applied to a target that fingerprints as that device, "
        "or that you name with --profile. Re-run with --show-passwords to see the "
        "exact pairs that would be submitted."
    )
    return "\n".join(lines)


def _usernames(profile: CredentialProfile) -> str:
    names = [u or "<blank>" for u, _, _ in profile.entries]
    return ", ".join(dict.fromkeys(names)) if names else "—"
