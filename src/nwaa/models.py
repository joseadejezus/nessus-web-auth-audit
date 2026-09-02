"""Core data model shared across the pipeline.

Kept dependency-free (stdlib only) so parsing, classification, and
reporting can be unit tested without a browser or network access.
"""
from __future__ import annotations

import dataclasses
import enum
from datetime import datetime, timezone


class AttemptVerdict(str, enum.Enum):
    SUCCESS = "default_credentials_successful"
    FAILED = "authentication_failed"
    INCONCLUSIVE = "inconclusive"
    ERROR = "connection_error"
    NOT_TESTED = "not_tested"


class SecretStr:
    """Wraps a secret so it can't leak via repr/str/logging by accident.

    Callers that genuinely need the raw value must use ``reveal()``
    explicitly. Every other code path (logging, dataclasses.asdict,
    f-strings, exception messages) sees only the redacted form.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "SecretStr('***REDACTED***')"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return "***REDACTED***"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretStr):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)


@dataclasses.dataclass(frozen=True)
class ReportItem:
    """One <ReportItem> from a .nessus file, decoded to plain fields.

    Kept separate from Service (which is an aggregate per host:port)
    because login-page detection needs to inspect individual plugin
    names/outputs, not just the aggregated web/TLS verdict.
    """

    host_ip: str
    hostname: str | None
    port: int
    protocol: str
    svc_name: str
    plugin_id: int
    plugin_name: str
    plugin_family: str
    severity: int
    plugin_output: str
    description: str


@dataclasses.dataclass(frozen=True)
class Service:
    host_ip: str
    hostname: str | None
    port: int
    protocol: str  # "tcp" / "udp"
    svc_name: str  # nessus svc_name, e.g. "www", "https"
    is_web: bool
    is_tls: bool
    plugin_ids: tuple[int, ...] = ()
    evidence: tuple[str, ...] = ()

    @property
    def scheme(self) -> str:
        return "https" if self.is_tls else "http"

    @property
    def base_url(self) -> str:
        # IP, not hostname: assessment networks frequently lack working DNS for
        # scanned hosts, and the IP is what Nessus actually reached.
        host = self.host_ip
        default_port = 443 if self.is_tls else 80
        if self.port == default_port:
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{host}:{self.port}"

    @property
    def is_plaintext_http(self) -> bool:
        return self.is_web and not self.is_tls


@dataclasses.dataclass(frozen=True)
class LoginPage:
    service: Service
    url: str
    detection_method: str  # "nessus_plugin" | "path_probe"
    evidence: tuple[str, ...] = ()

    @property
    def is_plaintext(self) -> bool:
        return self.url.lower().startswith("http://")


@dataclasses.dataclass(frozen=True)
class HostFacts:
    """Host-level tags from <HostProperties>, used for device fingerprinting."""

    host_ip: str
    hostname: str | None = None
    operating_system: str = ""
    system_type: str = ""
    netbios_name: str = ""


@dataclasses.dataclass(frozen=True)
class HttpProbe:
    """What a single, unauthenticated page load told us about a target.

    Deliberately narrow: enough banner material to fingerprint the
    device, and nothing that could contain a credential. ``text_snippet``
    is truncated and is used for fingerprinting only.
    """

    url: str
    status: int | None = None
    server: str = ""
    www_authenticate: str = ""
    title: str = ""
    text_snippet: str = ""

    @property
    def signals(self) -> tuple[str, ...]:
        return tuple(
            part
            for part in (
                f"Server: {self.server}" if self.server else "",
                f"WWW-Authenticate: {self.www_authenticate}" if self.www_authenticate else "",
                f"Title: {self.title}" if self.title else "",
                self.text_snippet,
            )
            if part
        )


@dataclasses.dataclass(frozen=True)
class DeviceFingerprint:
    """A guess at what kind of device is answering on a host:port.

    ``profile_id`` is the key into the bundled default-credential
    profiles (see nwaa/data/default_credentials.json). Everything here is
    heuristic — ``evidence`` records the exact strings that produced the
    guess so a human can sanity-check it.
    """

    profile_id: str
    display_name: str
    vendor: str
    category: str  # "printer" | "network" | "bmc" | "camera" | "appserver" | ...
    confidence: str  # "high" | "medium" | "low"
    evidence: tuple[str, ...] = ()
    source: str = "nessus"  # "nessus" | "http" | "manual"


@dataclasses.dataclass(frozen=True)
class Credential:
    username: str
    password: SecretStr
    label: str = "unlabeled"
    # "user_file" = supplied by the operator; "vendor_default" = from the
    # bundled, publicly-documented default-credential profiles.
    source: str = "user_file"

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"Credential(username={self.username!r}, password=***REDACTED***, "
            f"label={self.label!r}, source={self.source!r})"
        )


@dataclasses.dataclass
class ScreenshotResult:
    login_page: LoginPage
    path: str | None
    success: bool
    error: str | None = None
    probe: HttpProbe | None = None


@dataclasses.dataclass
class CredentialAttempt:
    login_page: LoginPage
    username: str
    credential_label: str
    verdict: AttemptVerdict
    detail: str
    credential_source: str = "user_file"
    timestamp: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    screenshot_path: str | None = None


def service_key(service: Service) -> str:
    """Stable key for per-service side tables (fingerprints, probes)."""
    return f"{service.host_ip}:{service.port}"


@dataclasses.dataclass
class ScanResult:
    nessus_file: str
    generated_at: str
    services: list[Service] = dataclasses.field(default_factory=list)
    login_pages: list[LoginPage] = dataclasses.field(default_factory=list)
    screenshots: list[ScreenshotResult] = dataclasses.field(default_factory=list)
    attempts: list[CredentialAttempt] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    # keyed by service_key(); login pages inherit their service's fingerprint
    fingerprints: dict[str, DeviceFingerprint] = dataclasses.field(default_factory=dict)
