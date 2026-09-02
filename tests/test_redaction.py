from __future__ import annotations

import logging

from nwaa.logging_utils import configure_logging
from nwaa.redaction import RedactionFilter, register_secret, scrub_secrets


def test_scrub_secrets_replaces_registered_values():
    register_secret("swordfish")
    assert scrub_secrets("password=swordfish") == "password=***REDACTED***"


def test_scrub_secrets_is_a_noop_without_registrations():
    assert scrub_secrets("password=swordfish") == "password=swordfish"


def test_filter_scrubs_log_record_message():
    register_secret("swordfish")
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "trying %s", ("swordfish",), None)
    RedactionFilter().filter(record)
    assert "swordfish" not in record.getMessage()


def test_configured_logger_emits_redacted_output(capsys):
    register_secret("swordfish")
    configure_logging(level="INFO", json_output=True)
    logging.getLogger("nwaa.test").info("attempting login with %s", "swordfish")
    captured = capsys.readouterr()
    assert "swordfish" not in captured.err
    assert "***REDACTED***" in captured.err
