"""JSON and human-readable reporting.

Serialization is written out field-by-field rather than via
dataclasses.asdict, so a password can never reach a report by someone
later adding a field to a dataclass. Free-text fields are additionally
run through scrub_secrets on the way out.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from nwaa import __version__
from nwaa.classifier import plaintext_http_services
from nwaa.models import DeviceFingerprint, LoginPage, ScanResult, Service, service_key
from nwaa.redaction import scrub_secrets


def _fingerprint_dict(fingerprint: DeviceFingerprint | None) -> dict | None:
    if fingerprint is None:
        return None
    return {
        "profile_id": fingerprint.profile_id,
        "display_name": fingerprint.display_name,
        "vendor": fingerprint.vendor,
        "category": fingerprint.category,
        "confidence": fingerprint.confidence,
        "source": fingerprint.source,
        "evidence": list(fingerprint.evidence),
    }


def _service_dict(service: Service, fingerprints: dict[str, DeviceFingerprint]) -> dict:
    return {
        "host_ip": service.host_ip,
        "hostname": service.hostname,
        "port": service.port,
        "protocol": service.protocol,
        "svc_name": service.svc_name,
        "is_web": service.is_web,
        "is_tls": service.is_tls,
        "transport": "https" if service.is_tls else "http",
        "plaintext_http": service.is_plaintext_http,
        "base_url": service.base_url,
        "plugin_ids": list(service.plugin_ids),
        "evidence": list(service.evidence),
        "device": _fingerprint_dict(fingerprints.get(service_key(service))),
    }


def _login_page_dict(page: LoginPage, fingerprints: dict[str, DeviceFingerprint]) -> dict:
    return {
        "url": page.url,
        "host_ip": page.service.host_ip,
        "hostname": page.service.hostname,
        "port": page.service.port,
        "transport": "https" if page.service.is_tls else "http",
        "plaintext_transmission": page.is_plaintext,
        "detection_method": page.detection_method,
        "evidence": list(page.evidence),
        "device": _fingerprint_dict(fingerprints.get(service_key(page.service))),
    }


def build_json_report(result: ScanResult) -> dict:
    verdicts = Counter(a.verdict.value for a in result.attempts)
    plaintext_services = plaintext_http_services(result.services)
    fingerprints = result.fingerprints
    return {
        "tool": "nwaa",
        "version": __version__,
        "generated_at": result.generated_at,
        "nessus_file": result.nessus_file,
        "summary": {
            "services_total": len(result.services),
            "web_services": sum(1 for s in result.services if s.is_web),
            "plaintext_http_services": len(plaintext_services),
            "tls_web_services": sum(1 for s in result.services if s.is_web and s.is_tls),
            "login_pages": len(result.login_pages),
            "screenshots_captured": sum(1 for s in result.screenshots if s.success),
            "credential_attempts": len(result.attempts),
            "attempts_by_verdict": dict(verdicts),
            "devices_fingerprinted": len(fingerprints),
            "vendor_default_attempts": sum(
                1 for a in result.attempts if a.credential_source == "vendor_default"
            ),
        },
        "devices": [
            {"target": target, **(_fingerprint_dict(fp) or {})}
            for target, fp in sorted(fingerprints.items())
        ],
        "web_services": [_service_dict(s, fingerprints) for s in result.services if s.is_web],
        "plaintext_http_services": [_service_dict(s, fingerprints) for s in plaintext_services],
        "login_pages": [_login_page_dict(p, fingerprints) for p in result.login_pages],
        "screenshots": [
            {
                "url": shot.login_page.url,
                "path": shot.path,
                "success": shot.success,
                "error": scrub_secrets(shot.error) if shot.error else None,
                # Banner evidence from the same page load, kept because it is
                # what the fingerprint was derived from.
                "server": scrub_secrets(shot.probe.server) if shot.probe else "",
                "page_title": scrub_secrets(shot.probe.title) if shot.probe else "",
            }
            for shot in result.screenshots
        ],
        "credential_attempts": [
            {
                "url": attempt.login_page.url,
                "username": attempt.username,
                "credential_label": attempt.credential_label,
                "credential_source": attempt.credential_source,
                "verdict": attempt.verdict.value,
                "detail": scrub_secrets(attempt.detail),
                "timestamp": attempt.timestamp,
                "screenshot_path": attempt.screenshot_path,
            }
            for attempt in result.attempts
        ],
        "warnings": [scrub_secrets(w) for w in result.warnings],
    }


def write_json_report(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_json_report(result), indent=2), encoding="utf-8")
    return path


def render_text_report(result: ScanResult) -> str:
    data = build_json_report(result)
    summary = data["summary"]
    lines: list[str] = []
    add = lines.append

    add("=" * 72)
    add("nwaa - Nessus web authentication surface report")
    add("=" * 72)
    add(f"Nessus file : {data['nessus_file']}")
    add(f"Generated   : {data['generated_at']}")
    add("")
    add("SUMMARY")
    add("-" * 72)
    add(f"  Services in scan              : {summary['services_total']}")
    add(f"  Web services                  : {summary['web_services']}")
    add(f"  Plaintext HTTP web services   : {summary['plaintext_http_services']}")
    add(f"  TLS web services              : {summary['tls_web_services']}")
    add(f"  Login pages identified        : {summary['login_pages']}")
    add(f"  Devices fingerprinted         : {summary['devices_fingerprinted']}")
    add(f"  Screenshots captured          : {summary['screenshots_captured']}")
    add(f"  Credential attempts           : {summary['credential_attempts']}")
    add(f"      of which vendor defaults      : {summary['vendor_default_attempts']}")
    for verdict, count in sorted(summary["attempts_by_verdict"].items()):
        add(f"      {verdict:<34}: {count}")
    add("")

    add("DEVICES IDENTIFIED (heuristic fingerprint -> default-credential profile)")
    add("-" * 72)
    if not data["devices"]:
        add("  none identified")
    for device in data["devices"]:
        add(f"  {device['target']:<24} {device['display_name']}  [{device['confidence']}]")
        add(f"      profile      : {device['profile_id']}  (source: {device['source']})")
        for ev in device.get("evidence", []):
            add(f"      evidence     : {ev}")
    add("")

    add("PLAINTEXT HTTP SERVICES (credentials would cross the network unencrypted)")
    add("-" * 72)
    if not data["plaintext_http_services"]:
        add("  none")
    for svc in data["plaintext_http_services"]:
        add(f"  {svc['base_url']:<45} svc_name={svc['svc_name']}")
    add("")

    add("LOGIN PAGES")
    add("-" * 72)
    if not data["login_pages"]:
        add("  none identified")
    for page in data["login_pages"]:
        marker = "PLAINTEXT" if page["plaintext_transmission"] else "TLS"
        add(f"  [{marker}] {page['url']}")
        add(f"      detected via : {page['detection_method']}")
        if page.get("device"):
            device = page["device"]
            add(f"      device       : {device['display_name']} ({device['confidence']} confidence)")
        for ev in page["evidence"]:
            add(f"      evidence     : {ev}")
    add("")

    add("SCREENSHOTS")
    add("-" * 72)
    if not data["screenshots"]:
        add("  none")
    for shot in data["screenshots"]:
        if shot["success"]:
            add(f"  OK    {shot['url']} -> {shot['path']}")
        else:
            add(f"  FAIL  {shot['url']} ({shot['error']})")
    add("")

    add("CREDENTIAL ATTEMPTS (passwords are never recorded)")
    add("-" * 72)
    if not data["credential_attempts"]:
        add("  none attempted")
    for attempt in data["credential_attempts"]:
        add(f"  {attempt['verdict'].upper()}")
        add(f"      url      : {attempt['url']}")
        username = attempt["username"] or "<blank>"
        add(f"      username : {username}  (set: {attempt['credential_label']})")
        add(f"      source   : {attempt['credential_source']}")
        add(f"      detail   : {attempt['detail']}")
    add("")

    if data["warnings"]:
        add("WARNINGS")
        add("-" * 72)
        for warning in data["warnings"]:
            add(f"  - {warning}")
        add("")

    add("Verdicts are heuristic. Verify any 'default_credentials_successful'")
    add("result manually before reporting it as a confirmed finding.")
    return "\n".join(lines)


def write_text_report(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_text_report(result), encoding="utf-8")
    return path
