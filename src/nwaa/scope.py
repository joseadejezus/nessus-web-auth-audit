"""Authorization-scope enforcement.

Everything this tool actively connects to (screenshots, credential
attempts, optional path probing) must be confined to the hosts/ports
that were actually present in the supplied .nessus file. A ScopeRegistry
is the single source of truth for "is this URL something we're allowed
to touch", and is consulted before every navigation/redirect so a
malicious or misconfigured target can't redirect us off-scope.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from nwaa.models import Service

DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class ScopeRegistry:
    """Immutable set of (host, port) pairs authorized by the Nessus scan."""

    allowed_host_ports: frozenset[tuple[str, int]] = field(default_factory=frozenset)
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)

    def is_url_in_scope(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        host = parts.hostname.lower()
        port = parts.port or DEFAULT_PORTS[parts.scheme]
        return (host, port) in self.allowed_host_ports

    def is_host_in_scope(self, host: str) -> bool:
        return host.lower() in self.allowed_hosts


def install_scope_guard(context, scope: ScopeRegistry) -> None:
    """Abort every browser request to a host outside the authorized scope.

    This is the control that contains redirects and third-party
    subresources: a target that answers a login POST with a redirect to
    an unscanned host cannot pull the browser along with it.
    """

    def route_handler(route) -> None:
        hostname = urlsplit(route.request.url).hostname
        if hostname and scope.is_host_in_scope(hostname):
            route.continue_()
        else:
            route.abort("blockedbyclient")

    context.route("**/*", route_handler)


def build_scope(services: list[Service]) -> ScopeRegistry:
    host_ports: set[tuple[str, int]] = set()
    hosts: set[str] = set()
    for svc in services:
        hosts.add(svc.host_ip.lower())
        host_ports.add((svc.host_ip.lower(), svc.port))
        if svc.hostname:
            hosts.add(svc.hostname.lower())
            host_ports.add((svc.hostname.lower(), svc.port))
    return ScopeRegistry(
        allowed_host_ports=frozenset(host_ports),
        allowed_hosts=frozenset(hosts),
    )
