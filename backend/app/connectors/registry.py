"""
Parser registry — maps source_type string to the appropriate ConnectorParser.

Parsers are singletons (instantiated once at import time).
"""
from __future__ import annotations

from app.connectors.base import ConnectorParser
from app.connectors.parsers.wazuh import WazuhParser
from app.connectors.parsers.suricata import SuricataParser
from app.connectors.parsers.defender import DefenderParser
from app.connectors.parsers.syslog_parser import SyslogParser
from app.connectors.parsers.generic import GenericParser

_PARSERS: dict[str, ConnectorParser] = {
    "wazuh":    WazuhParser(),
    "suricata": SuricataParser(),
    "defender": DefenderParser(),
    "syslog":   SyslogParser(),
    "generic":  GenericParser(),
    "webhook":  GenericParser(),   # alias
}

SUPPORTED_SOURCES = sorted(_PARSERS.keys())


def parser_registry(source: str) -> ConnectorParser | None:
    """Return parser for the given source type, or None if unsupported."""
    return _PARSERS.get(source.lower())
