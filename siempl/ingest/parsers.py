"""Built-in parsers for common log formats (facade).

Each parser is a callable that takes a raw record (str or dict) and returns a list of NormalizedEvent.
The implementations live in the sibling _parsers_*.py modules, one per format; this module re-exports every
name that used to be defined here, so existing imports keep working. See docs/PARSERS.md for the layout.

Parsers:
  syslog_rfc3164  - traditional BSD syslog
  syslog_rfc5424  - IETF syslog with structured data
  sshd, sudo      - sub-parsers called by the syslog parsers (not registered themselves)
  cef             - Common Event Format (ArcSight)
  apache_combined - Apache/Nginx combined log format
  generic_json    - heuristic JSON parser (field aliasing, fallback)
  windows_json    - Windows event JSON (Winlogbeat / OTRF Security Datasets)
  windows_xml     - Windows event XML
  zeek_conn       - Zeek connection log JSON (optional)
  zeek_dns        - Zeek DNS log JSON (optional)
  ocsf            - OCSF events (registered from ocsf.py)

Auto-detection (auto_parse): sniff the first record to determine the likely format.
"""

from __future__ import annotations

# Public import path is unchanged: everything that used to be defined here is re-exported.
# isort: off
# ORDER MATTERS. Importing a _parsers_* module registers its parsers, and list_parsers() order is observable
# (the sources 'detect parser' endpoint iterates it). Keep the original registration order: syslog, cef,
# apache, generic_json, windows_json, zeek, windows_xml. tests/test_parsers_registry_order.py pins it.
from ._parsers_core import (  # noqa: F401
    Parser,
    _as_dict,
    _json_get,
    _make_extra,
    _parse_json_timestamp,
    _registry,
    _utcnow,
    get_parser,
    list_parsers,
    register,
)
from ._parsers_syslog import (  # noqa: F401
    MONTHS,
    SYSLOG_HEADER3164_RE,
    SYSLOG_PRI_RE,
    parse_syslog_rfc3164,
    parse_syslog_rfc5424,
)
from ._parsers_auth import (  # noqa: F401
    _SSHD_METHOD,
    SSHD_ACCEPT_RE,
    SSHD_FAIL_RE,
    SSHD_INVALID_USER_RE,
    SUDO_FAIL_RE,
    SUDO_RE,
    _parse_sshd,
    _parse_sudo,
)
from ._parsers_cef import (  # noqa: F401
    _CEF_EXTENSION_MAP,
    _cef_apply_extension,
    _cef_fallback_event,
    _cef_fill_event_code,
    _cef_fold_custom_label,
    _cef_fold_custom_labels,
    _cef_header_end,
    _cef_header_fields,
    _cef_is_key_boundary,
    _cef_iter_extensions,
    _cef_normalize_outcome,
    _cef_parse_timestamp,
    _cef_part,
    _cef_skip_spaces,
    _cef_starts_key,
    _cef_target_table,
    _cef_unescape,
    _cef_value_end,
    parse_cef,
)
from ._parsers_apache import (  # noqa: F401
    APACHE_COMBINED_RE,
    MONTHS_APACHE,
    parse_apache_combined,
)
from ._parsers_json import (  # noqa: F401
    JSON_ALIASES,
    parse_generic_json,
)
from ._parsers_windows import (  # noqa: F401
    _WIN_FILLERS,
    WIN_EVENT_ACTION,
    WIN_EVENT_TABLE,
    _fill_win_auth,
    _fill_win_file,
    _fill_win_network,
    _fill_win_process,
    _fill_win_process_identity,
    _fill_win_process_parent,
    _resolve_win_field,
    _win_common_fields,
    _win_event_data,
    _win_event_id,
    _win_extra,
    _win_raw_fallback,
    _win_timestamp,
    parse_windows_json,
)
from ._parsers_zeek import (  # noqa: F401
    parse_zeek_conn,
    parse_zeek_dns,
)
from ._parsers_winxml import (  # noqa: F401
    _xml_int,
    parse_windows_xml,
)
from ._parsers_auto import (  # noqa: F401
    _looks_like_apache,
    _looks_like_cef,
    _looks_like_syslog,
    _looks_like_windows,
    auto_parse,
)
# isort: on

# isort: split
# Register the OCSF parser. ocsf.py does 'from .parsers import _utcnow, register', so it MUST be imported
# after everything above has been defined here. Keep this last; the isort marker stops import sorting from
# hoisting it (which breaks with a circular-import error).
from . import ocsf as _ocsf  # noqa: E402,F401
