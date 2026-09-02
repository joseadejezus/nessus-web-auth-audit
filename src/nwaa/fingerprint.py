"""Device fingerprinting: work out *what* is answering on a host:port.

Two sources feed the same matcher:

  * **Offline** — plugin names, descriptions and plugin_output from the
    .nessus file, plus the host's ``operating-system`` / ``system-type``
    tags. Costs no traffic and works in parse-only mode.
  * **Live** — the ``Server`` header, ``WWW-Authenticate`` realm, page
    title and a short body snippet from the single page load the
    screenshot/probe pass already performs. No extra requests.

The result (``DeviceFingerprint.profile_id``) is the key used to pick a
vendor default-credential profile. Everything here is heuristic, so each
match carries the exact strings that produced it in ``evidence``.

Pure/offline by design: no network, no browser, no I/O.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from nwaa.models import DeviceFingerprint, HostFacts, HttpProbe
from nwaa.nessus_parser import NessusScan

# A live Server/WWW-Authenticate header is far better evidence than a
# keyword buried in a plugin description, so matches are weighted by
# where they came from rather than only by how many patterns hit.
_SOURCE_WEIGHT = {"http": 3, "nessus": 1}


@dataclass(frozen=True)
class Signature:
    """One device profile and the patterns that identify it.

    ``profile_id`` must match a key in the bundled default-credential
    profiles (nwaa/data/default_credentials.json) — a test asserts that.
    """

    profile_id: str
    display_name: str
    vendor: str
    category: str
    patterns: tuple[str, ...]
    compiled: tuple[re.Pattern[str], ...] = field(default_factory=tuple, repr=False, compare=False)

    def matches(self, haystack: str) -> list[str]:
        """Return the source patterns that fired against ``haystack``."""
        hits = []
        for raw, rx in zip(self.patterns, self.compiled, strict=True):
            if rx.search(haystack):
                hits.append(raw)
        return hits


def _sig(profile_id: str, display_name: str, vendor: str, category: str, *patterns: str) -> Signature:
    return Signature(
        profile_id=profile_id,
        display_name=display_name,
        vendor=vendor,
        category=category,
        patterns=patterns,
        compiled=tuple(re.compile(p, re.IGNORECASE) for p in patterns),
    )


# Ordered most-specific first: ties in score are broken by position, so a
# concrete model beats a generic vendor or category signature.
SIGNATURES: tuple[Signature, ...] = (
    # ---- printers / MFPs -------------------------------------------------
    _sig(
        "hp-printer", "HP printer / MFP (Embedded Web Server)", "HP", "printer",
        r"\bHP\s+HTTP\s+Server\b",
        r"\bHP\s*(Color\s+)?(LaserJet|OfficeJet|DesignJet|PageWide|DeskJet|Envy)\b",
        r"\bJetDirect\b",
        r"\bHP\s+Embedded\s+Web\s+Server\b",
        r"Virtual\s+Machine\s+Embedded\s+Web\s+Server",
    ),
    _sig(
        "xerox-printer", "Xerox printer / MFP (CentreWare)", "Xerox", "printer",
        r"\bXerox\b",
        r"\bCentreWare\b",
        r"\bWorkCentre\b",
        r"\bVersaLink\b|\bAltaLink\b|\bPhaser\b",
    ),
    _sig(
        "lexmark-printer", "Lexmark printer / MFP", "Lexmark", "printer",
        r"\bLexmark\b",
        r"Lexmark\s+(MS|MX|CS|CX|E|T|X)\d+",
    ),
    _sig(
        "ricoh-printer", "Ricoh printer / MFP (Web Image Monitor)", "Ricoh", "printer",
        r"\bRicoh\b",
        r"Web\s+Image\s+Monitor",
        r"\bAficio\b|\bLanier\b|\bSavin\b",
    ),
    _sig(
        "brother-printer", "Brother printer / MFP", "Brother", "printer",
        r"\bBrother\b",
        r"Brother\s+(HL|MFC|DCP)-",
        r"\bdebut/\d",  # Brother's embedded httpd token
    ),
    _sig(
        "canon-printer", "Canon printer / MFP (Remote UI)", "Canon", "printer",
        r"\bCanon\b",
        r"\bimageRUNNER\b|\bimageCLASS\b|\biR-ADV\b",
        r"Canon\s+HTTP\s+Server",
    ),
    _sig(
        "konica-printer", "Konica Minolta printer / MFP (PageScope)", "Konica Minolta", "printer",
        r"\bKONICA\s*MINOLTA\b",
        r"\bPageScope\b",
        r"\bbizhub\b",
    ),
    _sig(
        "kyocera-printer", "Kyocera printer / MFP (Command Center)", "Kyocera", "printer",
        r"\bKyocera\b",
        r"Command\s*Cent(er|re)\s*RX",
        r"\bECOSYS\b|\bTASKalfa\b",
    ),
    _sig(
        "epson-printer", "Epson printer / MFP (Web Config)", "Epson", "printer",
        r"\bEPSON\b",
        r"EPSON\s+Web\s*Config",
        r"\bWorkForce\b|\bEcoTank\b",
    ),
    _sig(
        "sharp-printer", "Sharp printer / MFP", "Sharp", "printer",
        r"\bSHARP\s+(MX|AR|BP)-",
        r"Sharp\s+Corporation",
    ),
    _sig(
        "dell-printer", "Dell printer / MFP", "Dell", "printer",
        r"Dell\s+(Laser|Color\s+Laser|Smart)\s*(Printer|MFP)",
        r"Dell\s+\w*\s*Printer\s+Configuration",
    ),
    _sig(
        "zebra-printer", "Zebra label printer", "Zebra", "printer",
        r"\bZebra\s+Technologies\b",
        r"\bZTC\b|\bZebraNet\b",
    ),
    # ---- lights-out management / BMC ------------------------------------
    _sig(
        "hp-ilo", "HPE Integrated Lights-Out (iLO)", "HPE", "bmc",
        r"\biLO\s?[2-6]?\b",
        r"Integrated\s+Lights-?Out",
        r"HP(E)?\s+ProLiant.*(iLO|Lights)",
    ),
    _sig(
        "dell-idrac", "Dell Remote Access Controller (iDRAC)", "Dell", "bmc",
        r"\biDRAC\s?[0-9]?\b",
        r"Integrated\s+Dell\s+Remote\s+Access",
        r"Dell\s+Remote\s+Access\s+Controller",
    ),
    _sig(
        "supermicro-ipmi", "Supermicro IPMI / BMC", "Supermicro", "bmc",
        r"\bSupermicro\b",
        r"ATEN\s+International",
        r"Supermicro\s+Intelligent\s+Management",
    ),
    _sig(
        "ibm-imm", "IBM/Lenovo IMM / XClarity Controller", "IBM/Lenovo", "bmc",
        r"Integrated\s+Management\s+Module",
        r"\bIMM2?\b\s|XClarity\s+Controller",
        r"Lenovo\s+ThinkSystem.*(XCC|management)",
    ),
    _sig(
        "generic-ipmi", "IPMI / baseboard management controller", "generic", "bmc",
        r"\bIPMI\b",
        r"Baseboard\s+Management\s+Controller",
    ),
    # ---- network / infrastructure ---------------------------------------
    _sig(
        "cisco-device", "Cisco device web UI", "Cisco", "network",
        r"\bCisco\b",
        r"cisco-IOS|IOS-XE|level_15_access",
        r"Cisco\s+(Small\s+Business|RV\d|SPA\d|Systems)",
    ),
    _sig(
        "ubiquiti-device", "Ubiquiti device (airOS / UniFi)", "Ubiquiti", "network",
        r"\bUbiquiti\b|\bUniFi\b|\bairOS\b|\bairMAX\b",
        r"\bEdgeOS\b|\bEdgeRouter\b",
    ),
    _sig(
        "mikrotik-device", "MikroTik RouterOS (Webfig)", "MikroTik", "network",
        r"\bMikroTik\b|\bRouterOS\b",
        r"\bWebfig\b",
    ),
    _sig(
        "netgear-device", "NETGEAR device", "NETGEAR", "network",
        r"\bNETGEAR\b",
        r"NETGEAR\s+(ProSAFE|Smart\s+Switch|Nighthawk)",
    ),
    _sig(
        "tplink-device", "TP-Link device", "TP-Link", "network",
        r"\bTP-?LINK\b",
        r"\bArcher\s+[A-Z]\d",
    ),
    _sig(
        "dlink-device", "D-Link device", "D-Link", "network",
        r"\bD-?Link\b",
        r"\bDIR-\d{3}|\bDGS-\d{4}|\bDES-\d{4}",
    ),
    _sig(
        "zyxel-device", "Zyxel device", "Zyxel", "network",
        r"\bZyXEL\b|\bZyWALL\b",
    ),
    _sig(
        "hp-procurve", "HP/Aruba ProCurve switch", "HPE/Aruba", "network",
        r"\bProCurve\b|\bArubaOS\b|Aruba\s+\d{4}\s+Switch",
    ),
    _sig(
        "apc-ups", "APC / Schneider network management card", "APC", "power",
        r"\bAPC\b.*(Management|UPS|Web/SNMP)",
        r"Network\s+Management\s+Card",
        r"Schneider\s+Electric",
    ),
    # ---- cameras / physical security ------------------------------------
    _sig(
        "axis-camera", "Axis network camera", "Axis", "camera",
        r"\bAXIS\b",
        r"Axis\s+Communications",
        r"\bVAPIX\b",
    ),
    _sig(
        "hikvision-camera", "Hikvision camera / NVR", "Hikvision", "camera",
        r"\bHikvision\b",
        r"\bDS-\d[A-Z0-9-]+",
        r"\bwebs\b.*Hikvision",
    ),
    _sig(
        "dahua-camera", "Dahua camera / NVR", "Dahua", "camera",
        r"\bDahua\b",
        r"\bDH-[A-Z]{2,}",
    ),
    _sig(
        "vivotek-camera", "Vivotek camera", "Vivotek", "camera",
        r"\bVIVOTEK\b",
    ),
    # ---- storage / appliances -------------------------------------------
    _sig(
        "synology-nas", "Synology DiskStation", "Synology", "storage",
        r"\bSynology\b|\bDiskStation\b|\bDSM\b\s",
    ),
    _sig(
        "qnap-nas", "QNAP NAS", "QNAP", "storage",
        r"\bQNAP\b|\bQTS\b\s|\bTurbo\s*NAS\b",
    ),
    _sig(
        "vmware-esxi", "VMware ESXi / vSphere", "VMware", "virtualization",
        r"\bESXi\b|\bVMware\b.*(vSphere|Host\s+Client)",
    ),
    # ---- application servers / web apps ---------------------------------
    _sig(
        "tomcat", "Apache Tomcat manager", "Apache", "appserver",
        r"Apache[- ]Coyote",
        r"\bTomcat\b",
        r"/manager/html",
    ),
    _sig(
        "jboss-wildfly", "JBoss / WildFly console", "Red Hat", "appserver",
        r"\bJBoss\b|\bWildFly\b",
        r"JBossWeb|Undertow",
    ),
    _sig(
        "weblogic", "Oracle WebLogic console", "Oracle", "appserver",
        r"\bWebLogic\b",
        r"/console/login/LoginForm\.jsp",
    ),
    _sig(
        "glassfish", "GlassFish / Payara admin console", "Eclipse", "appserver",
        r"\bGlassFish\b|\bPayara\b",
    ),
    _sig(
        "grafana", "Grafana", "Grafana Labs", "webapp",
        r"\bGrafana\b",
    ),
    _sig(
        "jenkins", "Jenkins", "Jenkins", "webapp",
        r"\bJenkins\b|X-Jenkins",
    ),
    _sig(
        "phpmyadmin", "phpMyAdmin", "phpMyAdmin", "webapp",
        r"\bphpMyAdmin\b|\bpma_\w+",
    ),
    # ---- last-resort category fallbacks ---------------------------------
    _sig(
        "generic-printer", "Printer / MFP (vendor not identified)", "generic", "printer",
        r"\bprinter\b|\bMFP\b|\bmultifunction\b|\bIPP\b|\bJetDirect\b|\bPCL\b|\bPostScript\b",
    ),
    _sig(
        "generic-camera", "IP camera / NVR (vendor not identified)", "generic", "camera",
        r"\bIP\s*camera\b|\bnetwork\s+camera\b|\bNVR\b|\bDVR\b|\bRTSP\b",
    ),
)

SIGNATURES_BY_ID = {sig.profile_id: sig for sig in SIGNATURES}

# Profiles that only ever describe a class of device, never a product.
# They are still useful (a printer default list is better than nothing)
# but they never earn "high" confidence.
GENERIC_PROFILE_IDS = frozenset({"generic-printer", "generic-camera", "generic-ipmi"})

_MAX_EVIDENCE = 6
_MAX_HAYSTACK_CHARS = 200_000


def build_haystack(parts: list[str]) -> str:
    """Join fingerprint inputs, bounded so a hostile scan file can't blow up matching."""
    joined = "\n".join(p for p in parts if p)
    return joined[:_MAX_HAYSTACK_CHARS]


def match_signatures(haystack: str, source: str = "nessus") -> DeviceFingerprint | None:
    """Best-matching signature for a blob of banner/plugin text, or None."""
    best: tuple[int, int, Signature, list[str]] | None = None
    for index, sig in enumerate(SIGNATURES):
        hits = sig.matches(haystack)
        if not hits:
            continue
        score = len(hits) * _SOURCE_WEIGHT.get(source, 1)
        # Higher score wins; on a tie the earlier (more specific) signature wins.
        if best is None or score > best[0] or (score == best[0] and index < best[1]):
            best = (score, index, sig, hits)

    if best is None:
        return None

    score, _, sig, hits = best
    return DeviceFingerprint(
        profile_id=sig.profile_id,
        display_name=sig.display_name,
        vendor=sig.vendor,
        category=sig.category,
        confidence=_confidence(sig, hits, source),
        evidence=tuple(f"{source}: matched /{h}/" for h in hits[:_MAX_EVIDENCE]),
        source=source,
    )


def _confidence(sig: Signature, hits: list[str], source: str) -> str:
    """A category fallback is never more than a hint; a live banner, or two
    independent patterns from the scan file, is as good as this gets."""
    if sig.profile_id in GENERIC_PROFILE_IDS:
        return "low"
    if source == "http" or len(hits) >= 2:
        return "high"
    return "medium"


def fingerprint_services(scan: NessusScan) -> dict[str, DeviceFingerprint]:
    """Fingerprint every web service in a parsed scan, offline.

    Returns a mapping of ``"host:port"`` -> fingerprint, omitting
    services nothing matched.
    """
    items_by_service: dict[tuple[str, int, str], list[str]] = {}
    for item in scan.report_items:
        key = (item.host_ip, item.port, item.protocol)
        items_by_service.setdefault(key, []).append(
            f"{item.plugin_name}\n{item.plugin_output}\n{item.description}"
        )

    results: dict[str, DeviceFingerprint] = {}
    for service in scan.services:
        if not service.is_web:
            continue
        parts = list(items_by_service.get((service.host_ip, service.port, service.protocol), []))
        facts = scan.host_facts.get(service.host_ip)
        if facts is not None:
            parts.append(_host_facts_text(facts))
        fingerprint = match_signatures(build_haystack(parts), source="nessus")
        if fingerprint is not None:
            results[f"{service.host_ip}:{service.port}"] = fingerprint
    return results


def _host_facts_text(facts: HostFacts) -> str:
    return "\n".join(
        p for p in (facts.operating_system, facts.system_type, facts.netbios_name) if p
    )


def fingerprint_from_probe(probe: HttpProbe) -> DeviceFingerprint | None:
    """Fingerprint from a live page load's banners (no extra traffic)."""
    return match_signatures(build_haystack(list(probe.signals)), source="http")


_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def merge_fingerprints(
    offline: DeviceFingerprint | None, live: DeviceFingerprint | None
) -> DeviceFingerprint | None:
    """Combine an offline and a live fingerprint for the same target.

    Live banners win ties because they came from the device itself, but a
    high-confidence offline match is not discarded for a low-confidence
    live one (a generic "printer" hit should not displace "HP printer").
    """
    if offline is None:
        return live
    if live is None:
        return offline
    if offline.profile_id == live.profile_id:
        return DeviceFingerprint(
            profile_id=live.profile_id,
            display_name=live.display_name,
            vendor=live.vendor,
            category=live.category,
            confidence="high",
            evidence=tuple(dict.fromkeys(offline.evidence + live.evidence))[:_MAX_EVIDENCE],
            source="nessus+http",
        )
    if _CONFIDENCE_RANK[live.confidence] >= _CONFIDENCE_RANK[offline.confidence]:
        return live
    return offline


def manual_fingerprint(profile_id: str) -> DeviceFingerprint:
    """Fingerprint for an operator-forced ``--profile`` (skips detection)."""
    sig = SIGNATURES_BY_ID.get(profile_id)
    return DeviceFingerprint(
        profile_id=profile_id,
        display_name=sig.display_name if sig else profile_id,
        vendor=sig.vendor if sig else "unknown",
        category=sig.category if sig else "unknown",
        confidence="high",
        evidence=("operator supplied --profile",),
        source="manual",
    )
