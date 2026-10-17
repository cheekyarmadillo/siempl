"""Pin the built-in parser registration order.

siempl.ingest.parsers is a facade over the _parsers_* modules; each module registers its parsers when
imported, so the import order in parsers.py decides list_parsers() order. isort/ruff once alphabetised
those imports and silently changed the order. This order is the one before the split.
"""

from siempl.ingest import parsers

EXPECTED_ORDER = [
    "syslog_rfc3164",
    "syslog_rfc5424",
    "cef",
    "apache_combined",
    "generic_json",
    "windows_json",
    "zeek_conn",
    "zeek_dns",
    "windows_xml",
    "ocsf",
]


def test_builtin_parser_registration_order_is_stable():
    assert list(parsers.list_parsers()) == EXPECTED_ORDER
