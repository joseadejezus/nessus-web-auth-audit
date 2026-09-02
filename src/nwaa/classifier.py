"""Turn parsed Nessus data into web services, plaintext findings, and
candidate login pages.

Deliberately pure / network-free so it can be unit tested against
fixture data without a browser. Anything that needs to touch the
network (screenshotting, path probing, credential testing) lives in
other modules and consumes the output of this one.
"""
from __future__ import annotations

import re

from nwaa.models import LoginPage, Service
from nwaa.nessus_parser import NessusScan

LOGIN_KEYWORD_RE = re.compile(
    r"log[\s-]?in|logon|sign[\s-]?in|authentication\s*(form|page|required)|"
    r"admin(istrator)?\s*(console|panel|login)|password\s*field|"
    r"requires?\s*authentication|credential",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>\)]+")


def plaintext_http_services(services: list[Service]) -> list[Service]:
    """Services that are web servers and do not use TLS."""
    return [s for s in services if s.is_plaintext_http]


def identify_login_pages(scan: NessusScan) -> list[LoginPage]:
    """Find login/authentication pages hinted at by Nessus plugin data.

    Matches plugin name/description/plugin_output against a keyword
    list for web services, extracting a specific URL from the plugin
    text when Nessus provided one, otherwise falling back to the
    service's base URL.
    """
    service_by_key = {(s.host_ip, s.port, s.protocol): s for s in scan.services}
    found: dict[tuple[Service, str], LoginPage] = {}

    for item in scan.report_items:
        service = service_by_key.get((item.host_ip, item.port, item.protocol))
        if service is None or not service.is_web:
            continue

        haystack = f"{item.plugin_name}\n{item.description}\n{item.plugin_output}"
        if not LOGIN_KEYWORD_RE.search(haystack):
            continue

        url = _extract_matching_url(haystack, service) or service.base_url
        key = (service, url)
        evidence = f"plugin[{item.plugin_id}] {item.plugin_name}".strip()
        existing = found.get(key)
        merged = set(existing.evidence) if existing else set()
        merged.add(evidence)
        found[key] = LoginPage(
            service=service,
            url=url,
            detection_method="nessus_plugin",
            evidence=tuple(sorted(merged)),
        )

    return sorted(found.values(), key=lambda lp: (lp.service.host_ip, lp.service.port, lp.url))


def _extract_matching_url(text: str, service: Service) -> str | None:
    """Prefer a URL Nessus actually printed that points at this service."""
    candidates = URL_RE.findall(text)
    host_markers = {service.host_ip}
    if service.hostname:
        host_markers.add(service.hostname)
    for candidate in candidates:
        if any(marker in candidate for marker in host_markers):
            return candidate.rstrip(".,;")
    return None
