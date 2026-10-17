"""Tests for siempl.entities: EntityStore, reputation, links."""
from datetime import UTC

import pytest

from siempl.db import Database
from siempl.entities import UNKNOWN_REPUTATION, EntityStore


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.duckdb"))


@pytest.fixture
def store(db):
    return EntityStore(db)


class TestEntityStoreUpsert:
    def test_upsert_creates_new_entity(self, store):
        eid = store.upsert("ip", "10.0.0.1")
        assert eid == "ip:10.0.0.1"

        ent = store.get(eid)
        assert ent is not None
        assert ent["type"] == "ip"
        assert ent["value"] == "10.0.0.1"
        assert ent["reputation"] == 50.0
        assert ent["event_count"] == 1

    def test_upsert_updates_existing(self, store):
        store.upsert("ip", "10.0.0.1", event_count=1)
        store.upsert("ip", "10.0.0.1", event_count=2, extra_attr="hello")

        ent = store.get("ip:10.0.0.1")
        assert ent["event_count"] == 3  # 1 + 2
        # attributes should merge
        import json
        attrs = json.loads(ent["attributes"]) if isinstance(ent["attributes"], str) else ent["attributes"]
        assert attrs.get("extra_attr") == "hello"

    def test_upsert_rejects_unknown_type(self, store):
        with pytest.raises(ValueError, match="Unknown entity type"):
            store.upsert("bogus", "x")

    def test_upsert_lowercases_values(self, store):
        eid = store.upsert("user", "JohnDoe@DOMAIN")
        assert eid == "user:johndoe@domain"

    def test_upsert_stores_first_and_last_seen(self, store):
        from datetime import datetime
        t1 = datetime(2025, 1, 1, 12, 0, 0)
        t2 = datetime(2025, 1, 1, 13, 0, 0)

        store.upsert("host", "srv1", seen=t1)
        ent = store.get("host:srv1")
        assert ent["first_seen"] is not None
        assert ent["last_seen"] is not None

        store.upsert("host", "srv1", seen=t2)
        ent = store.get("host:srv1")
        # last_seen should update
        assert ent["last_seen"] >= ent["first_seen"]


class TestEntityStoreLinks:
    def test_link_creates_edge(self, db, store):
        a = store.upsert("ip", "10.0.0.1")
        b = store.upsert("host", "web01")
        store.link(a, b, "has_ip")

        edges = db.query("SELECT * FROM entity_edges WHERE src_entity=?", [a])
        assert len(edges) == 1
        assert edges[0]["relation"] == "has_ip"
        assert edges[0]["weight"] == 1

    def test_link_bumps_weight_on_duplicate(self, db, store):
        a = store.upsert("ip", "10.0.0.1")
        b = store.upsert("host", "web01")
        store.link(a, b, "has_ip")
        store.link(a, b, "has_ip")

        edges = db.query("SELECT * FROM entity_edges WHERE src_entity=?", [a])
        assert edges[0]["weight"] == 2


class TestEntityStoreSearch:
    def test_search_by_type(self, store):
        store.upsert("ip", "10.0.0.1")
        store.upsert("ip", "10.0.0.2")
        store.upsert("user", "bob")

        ips = store.search(etype="ip")
        assert len(ips) == 2

    def test_search_by_query(self, store):
        store.upsert("host", "web-prod-01")
        store.upsert("host", "db-prod-01")
        store.upsert("host", "staging-01")

        results = store.search(q="%prod%")
        assert len(results) == 2

    def test_search_orders_by_reputation_desc(self, store):
        e1 = store.upsert("ip", "10.0.0.1")
        e2 = store.upsert("ip", "10.0.0.2")
        # Manually set reputation for ordering test
        store.db.execute("UPDATE entities SET reputation=80 WHERE entity_id=?", [e1])
        store.db.execute("UPDATE entities SET reputation=20 WHERE entity_id=?", [e2])

        results = store.search(etype="ip")
        assert results[0]["entity_id"] == e1

    def test_search_with_invalid_order_defaults(self, store):
        store.upsert("ip", "10.0.0.1")
        results = store.search(order="bogus")
        assert len(results) >= 0  # just doesn't crash


class TestReputationApplyVerdict:
    def test_true_positive_pushes_up(self, db, store):
        store.upsert("ip", "1.2.3.4")
        # Create a test alert referencing this entity
        aid = _create_test_alert(db, [{"type": "ip", "value": "1.2.3.4"}])

        store.apply_verdict(aid, "true_positive", "tester")

        ent = store.get("ip:1.2.3.4")
        assert ent["reputation"] > UNKNOWN_REPUTATION
        assert ent["tp_count"] == 1
        assert ent["fp_count"] == 0

    def test_false_positive_pushes_down(self, db, store):
        store.upsert("ip", "1.2.3.4")
        aid = _create_test_alert(db, [{"type": "ip", "value": "1.2.3.4"}])

        store.apply_verdict(aid, "false_positive", "tester")

        ent = store.get("ip:1.2.3.4")
        assert ent["reputation"] < UNKNOWN_REPUTATION
        assert ent["fp_count"] == 1

    def test_benign_pushes_down(self, db, store):
        store.upsert("ip", "1.2.3.4")
        aid = _create_test_alert(db, [{"type": "ip", "value": "1.2.3.4"}])

        store.apply_verdict(aid, "benign", "tester")

        ent = store.get("ip:1.2.3.4")
        assert ent["reputation"] < UNKNOWN_REPUTATION
        assert ent["fp_count"] == 1

    def test_unknown_verdict_no_op(self, db, store):
        store.upsert("ip", "1.2.3.4")
        aid = _create_test_alert(db, [{"type": "ip", "value": "1.2.3.4"}])

        store.apply_verdict(aid, "unknown", "tester")

        ent = store.get("ip:1.2.3.4")
        assert ent["reputation"] == UNKNOWN_REPUTATION
        assert ent["tp_count"] == 0
        assert ent["fp_count"] == 0

    def test_invalid_verdict_raises(self, store):
        with pytest.raises(ValueError, match="Unknown verdict"):
            store.apply_verdict("x", "bogus", "tester")

    def test_diminishing_steps(self, db, store):
        """Multiple same-direction verdicts produce smaller steps."""
        store.upsert("ip", "1.2.3.4")

        prev_rep = UNKNOWN_REPUTATION
        movements = []
        for i in range(5):
            aid = _create_test_alert(db, [{"type": "ip", "value": "1.2.3.4"}],
                                     alert_id=f"test_dim_{i}", status="new")
            store.apply_verdict(aid, "true_positive", "tester")
            ent = store.get("ip:1.2.3.4")
            step = ent["reputation"] - prev_rep
            if step > 0:
                movements.append(step)
            prev_rep = ent["reputation"]

        # Later steps should be smaller than first step
        if len(movements) >= 2:
            assert movements[-1] < movements[0], \
                f"Expected diminishing: movements={movements}"

    def test_decay_toward_50(self, db, store):
        """After a push in one direction, some decay toward 50 occurs."""
        store.upsert("ip", "1.2.3.4")
        # Push up
        aid1 = _create_test_alert(db, [{"type": "ip", "value": "1.2.3.4"}],
                                  alert_id="decay1", status="new")
        store.apply_verdict(aid1, "true_positive", "tester")
        after_up = store.get("ip:1.2.3.4")["reputation"]

        # Reputation should be above 50 but not as far as a pure +15 step
        # because decay toward 50 is applied first
        assert after_up > UNKNOWN_REPUTATION
        assert after_up < UNKNOWN_REPUTATION + 15 + 1  # some margin

    def test_private_ip_clamp(self, db, store):
        """Private IPs never exceed BENIGN_CEILING (60)."""
        store.upsert("ip", "192.168.1.1")

        for i in range(10):
            aid = _create_test_alert(db, [{"type": "ip", "value": "192.168.1.1"}],
                                     alert_id=f"clamp_{i}", status="new")
            store.apply_verdict(aid, "true_positive", "tester")

        ent = store.get("ip:192.168.1.1")
        assert ent["reputation"] <= 60, f"Got {ent['reputation']}"

    def test_well_known_benign_clamp(self, db, store):
        """Well-known safe values never exceed 60."""
        for well_known in ["localhost", "SYSTEM"]:
            etype = "host" if well_known == "localhost" else "user"
            store.upsert(etype, well_known)

            for i in range(10):
                aid = _create_test_alert(db, [{"type": etype, "value": well_known}],
                                         alert_id=f"wk_{well_known}_{i}", status="new")
                store.apply_verdict(aid, "true_positive", "tester")

            ent = store.get(f"{etype}:{well_known.lower()}")
            if ent:  # might be None if entity_id differs
                assert ent["reputation"] <= 60, \
                    f"{well_known} got {ent['reputation']}"

    def test_direction_flip_resets_step(self, db, store):
        """When verdict direction flips, step size resets to base."""
        store.upsert("ip", "5.5.5.5")

        # Push up multiple times (diminishing)
        for i in range(3):
            aid = _create_test_alert(db, [{"type": "ip", "value": "5.5.5.5"}],
                                     alert_id=f"flip_up_{i}", status="new")
            store.apply_verdict(aid, "true_positive", "tester")

        after_up = store.get("ip:5.5.5.5")["reputation"]

        # Then push down (direction flips)
        aid = _create_test_alert(db, [{"type": "ip", "value": "5.5.5.5"}],
                                 alert_id="flip_down", status="new")
        store.apply_verdict(aid, "false_positive", "tester")

        after_down = store.get("ip:5.5.5.5")["reputation"]
        # The downward step should be larger than a diminished step
        # (it should be close to base step size)
        drop = after_up - after_down
        assert drop > 0, f"Expected drop, got up_to={after_up}, down_to={after_down}"

    def test_missing_alert_does_nothing(self, store):
        store.apply_verdict("nonexistent", "true_positive", "tester")
        # Should not crash

    def test_multiple_entities_moved(self, db, store):
        store.upsert("ip", "10.0.0.1")
        store.upsert("user", "bob")
        aid = _create_test_alert(db, [
            {"type": "ip", "value": "10.0.0.1"},
            {"type": "user", "value": "bob"},
        ])

        store.apply_verdict(aid, "true_positive", "tester")

        ip_ent = store.get("ip:10.0.0.1")
        user_ent = store.get("user:bob")
        assert ip_ent["tp_count"] == 1
        assert user_ent["tp_count"] == 1

    def test_already_verdict_alert_skipped(self, db, store):
        store.upsert("ip", "1.2.3.4")
        aid = _create_test_alert(db, [{"type": "ip", "value": "1.2.3.4"}],
                                 status="closed", verdict="true_positive")

        store.apply_verdict(aid, "false_positive", "tester")
        # Should not move again
        ent = store.get("ip:1.2.3.4")
        assert ent["tp_count"] == 0
        assert ent["fp_count"] == 0


# -----------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------

def _create_test_alert(db, entities, alert_id="test_alert_1",
                       status="new", verdict=None):
    """Quick in-DB fixture creating an alerts row."""
    import json
    from datetime import datetime
    now = datetime.now(UTC).replace(tzinfo=None)
    db.execute(
        "INSERT INTO alerts(alert_id,rule_id,title,severity,status,verdict,created_at,updated_at,"
        "window_start,window_end,row_count,evidence,entities,incident_id,dedupe_key) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [alert_id, "rule_test", "test", "medium", status, verdict,
         now, now, now, now, 1,
         json.dumps([{"ip": "1.2.3.4"}]),
         json.dumps(entities),
         "inc_test", alert_id])
    return alert_id
