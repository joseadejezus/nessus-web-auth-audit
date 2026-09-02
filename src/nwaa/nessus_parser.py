"""Safe parsing of .nessus (NessusClientData_v2 XML) files.

Uses defusedxml instead of the stdlib xml.etree so that a malicious or
corrupt .nessus file (external entities, entity-expansion "billion
laughs", external DTDs) cannot be used to attack the host running this
tool. A .nessus file is scan *output*, not scan input we control, so it
must be treated as untrusted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

from nwaa.models import HostFacts, ReportItem, Service

WEB_SVC_NAMES = {"www", "http", "https", "http-alt", "http-proxy"}
WEB_PLUGIN_FAMILIES = {"Web Servers", "CGI abuses", "CGI abuses : XSS"}
TLS_SVC_NAMES = {"https"}
TLS_HINT_RE = re.compile(r"\bssl\b|\btls\b", re.IGNORECASE)
# Host tags are attacker-influenced free text; cap them before they reach
# the fingerprint matcher.
_MAX_TAG_CHARS = 512


class NessusParseError(ValueError):
    """Raised when a file is not a well-formed .nessus report."""


@dataclass(frozen=True)
class NessusScan:
    source_path: str
    report_name: str
    report_items: tuple[ReportItem, ...]
    services: tuple[Service, ...]
    # keyed by host_ip; feeds device fingerprinting (operating-system tags
    # such as "HP LaserJet 4250" identify a device before any traffic).
    host_facts: dict[str, HostFacts] = field(default_factory=dict)


def parse_nessus_file(path: str | Path) -> NessusScan:
    path = Path(path)
    if not path.is_file():
        raise NessusParseError(f"Nessus file not found: {path}")

    try:
        tree = DefusedET.parse(str(path))
    except DefusedXmlException as exc:  # XXE / DTD / entity-expansion attempt
        raise NessusParseError(
            f"Refused to parse {path}: it contains forbidden XML constructs "
            f"(external entities/DTD). {exc}"
        ) from exc
    except DefusedET.ParseError as exc:  # malformed XML
        raise NessusParseError(f"Could not parse {path} as XML: {exc}") from exc

    root = tree.getroot()
    if root is None:
        # parse() normally raises ParseError rather than handing back a
        # rootless tree, but the API permits one — and an AttributeError
        # traceback is the wrong answer for untrusted input. Exit code 2.
        raise NessusParseError(f"{path} contains no XML root element")
    if root.tag != "NessusClientData_v2":
        raise NessusParseError(
            f"{path} does not look like a .nessus file "
            f"(root element is <{root.tag}>, expected <NessusClientData_v2>)"
        )

    report = root.find("Report")
    if report is None:
        raise NessusParseError(f"{path} has no <Report> element")
    report_name = report.get("name", path.stem)

    report_items: list[ReportItem] = []
    host_facts: dict[str, HostFacts] = {}
    for host in report.findall("ReportHost"):
        host_name_attr = host.get("name", "")
        host_ip = host_name_attr
        hostname: str | None = None
        tags: dict[str, str] = {}

        props = host.find("HostProperties")
        if props is not None:
            for tag in props.findall("tag"):
                tag_name = tag.get("name") or ""
                value = (tag.text or "").strip()
                if not value:
                    continue
                tags[tag_name] = value
                if tag_name == "host-ip":
                    host_ip = value
                elif tag_name == "host-fqdn":
                    hostname = value

        if not host_ip:
            host_ip = host_name_attr or "unknown"
        if hostname is None and host_name_attr and host_name_attr != host_ip:
            hostname = host_name_attr

        host_facts[host_ip] = HostFacts(
            host_ip=host_ip,
            hostname=hostname,
            operating_system=tags.get("operating-system", "")[:_MAX_TAG_CHARS],
            system_type=tags.get("system-type", "")[:_MAX_TAG_CHARS],
            netbios_name=tags.get("netbios-name", "")[:_MAX_TAG_CHARS],
        )

        for item in host.findall("ReportItem"):
            try:
                port = int(item.get("port", "0"))
            except ValueError:
                port = 0
            if not 0 <= port <= 65535:
                port = 0  # dropped during aggregation; scan data is untrusted
            try:
                severity = int(item.get("severity", "0"))
            except ValueError:
                severity = 0
            try:
                plugin_id = int(item.get("pluginID", "0"))
            except ValueError:
                plugin_id = 0

            plugin_output_el = item.find("plugin_output")
            description_el = item.find("description")

            report_items.append(
                ReportItem(
                    host_ip=host_ip,
                    hostname=hostname,
                    port=port,
                    protocol=item.get("protocol", "tcp"),
                    svc_name=item.get("svc_name", ""),
                    plugin_id=plugin_id,
                    plugin_name=item.get("pluginName", ""),
                    plugin_family=item.get("pluginFamily", ""),
                    severity=severity,
                    plugin_output=(plugin_output_el.text or "") if plugin_output_el is not None else "",
                    description=(description_el.text or "") if description_el is not None else "",
                )
            )

    services = tuple(_aggregate_services(report_items))
    return NessusScan(
        source_path=str(path),
        report_name=report_name,
        report_items=tuple(report_items),
        services=services,
        host_facts=host_facts,
    )


def _aggregate_services(items: list[ReportItem]) -> list[Service]:
    """Collapse per-plugin ReportItems into one Service per host:port.

    A single port is usually described by many ReportItems (one per
    plugin that fired). We fold those into a single aggregated verdict
    for "is this a web service" / "does it use TLS", carrying forward
    the evidence strings that justified each verdict.
    """
    buckets: dict[tuple[str, int, str], list[ReportItem]] = {}
    for item in items:
        if item.port == 0:
            continue
        key = (item.host_ip, item.port, item.protocol)
        buckets.setdefault(key, []).append(item)

    services: list[Service] = []
    for (host_ip, port, protocol), bucket in buckets.items():
        svc_name = next((i.svc_name for i in bucket if i.svc_name), "")
        hostname = next((i.hostname for i in bucket if i.hostname), None)

        is_web = svc_name in WEB_SVC_NAMES or any(
            i.plugin_family in WEB_PLUGIN_FAMILIES for i in bucket
        )
        tls_evidence = [
            i.plugin_name
            for i in bucket
            if TLS_HINT_RE.search(i.plugin_name) or TLS_HINT_RE.search(i.plugin_output)
        ]
        is_tls = svc_name in TLS_SVC_NAMES or bool(tls_evidence)

        evidence: list[str] = []
        if svc_name:
            evidence.append(f"svc_name={svc_name}")
        if tls_evidence:
            evidence.append(f"tls_plugins={sorted(set(tls_evidence))[:3]}")

        services.append(
            Service(
                host_ip=host_ip,
                hostname=hostname,
                port=port,
                protocol=protocol,
                svc_name=svc_name,
                is_web=is_web,
                is_tls=is_tls,
                plugin_ids=tuple(sorted({i.plugin_id for i in bucket})),
                evidence=tuple(evidence),
            )
        )

    services.sort(key=lambda s: (s.host_ip, s.port))
    return services
