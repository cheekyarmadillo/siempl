"""Regression: sources created from the GUI default to parser='auto'; that must mean auto-detect,
not 'unknown parser -> generic_json' (which dumped raw syslog text into GenericEvents)."""
from siempl.db import Database
from siempl.ingest import IngestPipeline

SYSLOG = "<34>Oct 12 15:50:00 e2ehost sshd[99]: Failed password for root from 10.9.9.9 port 22 ssh2"


def _count(db, t):
    return db.query_one(f'select count(*) c from "{t}"')["c"]


def test_auto_parser_autodetects_syslog(tmp_path):
    db = Database(str(tmp_path / "t.duckdb"))
    db.execute("INSERT INTO sources(source_id,name,kind,parser,target_table,status) VALUES ('s','s','syslog','auto','Syslog','active')")
    IngestPipeline(db).ingest("s", [SYSLOG])
    assert _count(db, "GenericEvents") == 0
    assert _count(db, "Syslog") + _count(db, "AuthEvents") >= 1
