"""Defense-in-depth credential redaction for logging.

Credentials should never reach a log call in the first place (see
SecretStr in models.py), but this filter is a second line of defense:
every configured password value is registered here once, and any log
record whose rendered message contains that exact substring has it
scrubbed before the record reaches a handler.
"""
from __future__ import annotations

import logging

_REGISTERED_SECRETS: set[str] = set()
_REDACTED = "***REDACTED***"


def register_secret(value: str) -> None:
    """Record a sensitive value so the logging filter will scrub it."""
    if value:
        _REGISTERED_SECRETS.add(value)


def clear_registered_secrets() -> None:
    """Test helper: reset the module-level secret registry."""
    _REGISTERED_SECRETS.clear()


def scrub_secrets(text: str) -> str:
    """Replace any registered secret substring in ``text`` with a marker.

    Public so call sites building user-facing strings (report details,
    exception messages) can scrub defensively, not just the logging path.
    """
    for secret in _REGISTERED_SECRETS:
        if secret in text:
            text = text.replace(secret, _REDACTED)
    return text


class RedactionFilter(logging.Filter):
    """Logging filter that scrubs registered secrets from every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not _REGISTERED_SECRETS:
            return True
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - malformed record args
            return True
        scrubbed = scrub_secrets(rendered)
        if scrubbed != rendered:
            record.msg = scrubbed
            record.args = ()
        return True


def install_redaction(target: logging.Filterer | None = None) -> None:
    """Attach the redaction filter to a logger or handler.

    Both need it: a filter on a logger only runs for records emitted
    through that logger, while a filter on a handler runs for every
    record that handler formats, whatever logger produced it.
    """
    filterer = target if target is not None else logging.getLogger()
    if not any(isinstance(f, RedactionFilter) for f in filterer.filters):
        filterer.addFilter(RedactionFilter())
