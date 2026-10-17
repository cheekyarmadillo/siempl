"""Reproduce entity process bug."""
import os
import tempfile
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient

from siempl.db import Database, utcnow


def _db():
    td = tempfile.mkdtemp(prefix="siempl_repro_")
    os.environ["SIEMPL_HOME"] = td
    return Database(str(Path(td) / "t.duckdb"))


def test_process_entity_list_and_detail():
    db = _db()
    now = utcnow()
    # Seed entities with awkward values for all types
    for etype, value in [
        ("user", "admin"),
        ("host", "web01"),
        ("ip", "10.0.0.1"),
        ("process", "powershell.exe"),
        ("file_hash", "aabbccdd"),
        ("domain", "evil.com"),
    ]:
        eid = f"{etype}:{value.lower()}"
        db.execute(
            "INSERT INTO entities(entity_id,type,value,reputation,alert_count,event_count,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
            [eid, etype, value, 50, 0, 1, now, now])

    from siempl.web import create_app
    app = create_app(db)
    client = TestClient(app)

    # List with etype=process
    r = client.get("/entities?etype=process")
    print("LIST process status:", r.status_code)
    if r.status_code != 200:
        print("LIST process text:", r.text[:500])
    assert r.status_code == 200

    # Detail for process
    r2 = client.get("/entities/process:powershell.exe")
    print("DETAIL process status:", r2.status_code)
    if r2.status_code != 200:
        print("DETAIL process text:", r2.text[:500])
    assert r2.status_code == 200

    # Test with awkward chars: colon in value, backslash, slash, space
    for etype, value, eid in [
        ("process", "C:\\Windows\\System32\\svchost.exe", "process:c:\\windows\\system32\\svchost.exe"),
        ("process", "/usr/bin/bash", "process:/usr/bin/bash"),
        ("process", "foo bar.exe", "process:foo bar.exe"),
        ("user", "domain\\user", "user:domain\\user"),
    ]:
        db.execute(
            "INSERT INTO entities(entity_id,type,value,reputation,alert_count,event_count,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
            [eid, etype, value, 50, 0, 1, now, now])

    for eid in ["process:c:\\windows\\system32\\svchost.exe", "process:/usr/bin/bash", "process:foo bar.exe", "user:domain\\user"]:
        # URL-encode the entity_id for the path
        url = f"/entities/{quote(eid, safe='')}"  # safe='' encodes everything
        r = client.get(url)
        print(f"DETAIL {eid} (url={url}) status:", r.status_code)
        if r.status_code != 200:
            print(r.text[:500])
        assert r.status_code == 200, f"Failed for {eid}"


if __name__ == "__main__":
    test_process_entity_list_and_detail()
    print("PASSED")
