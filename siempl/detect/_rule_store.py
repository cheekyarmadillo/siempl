"""RuleStore: CRUD for the rules table."""
from __future__ import annotations

from ..db import Database, new_id, utcnow
from ._core import _from_json, _json, _json_list


class RuleStore:
    """CRUD for the `rules` table, with version bumps and tuning_history."""

    def __init__(self, db: Database):
        self.db = db

    def create(self, rule: dict) -> str:
        """Insert a new rule.  Returns rule_id."""
        rid = rule.get("rule_id") or new_id("rule_")
        now = utcnow()
        defaults = {
            "version": 1, "tuning_history": [], "enabled": True,
            "origin": "manual", "frequency_minutes": 5, "lookback_minutes": 5,
            "threshold": 1, "severity": "medium",
            "created_at": now, "updated_at": now,
        }
        for k, v in defaults.items():
            rule.setdefault(k, v)
        rule["query_lang"] = rule.get("query_lang") or "kql"
        rule["rule_id"] = rid

        cols = ["rule_id", "name", "description", "triage_steps", "severity", "query",
                "tables", "frequency_minutes", "lookback_minutes", "threshold",
                "mitre_tactics", "mitre_techniques", "entity_mappings",
                "enabled", "origin", "source_ref", "source_content", "expires_at",
                "version", "tuning_history", "created_at", "updated_at", "query_lang"]

        vals = {k: rule.get(k) for k in cols}
        vals["tables"] = _json_list(vals.get("tables"))
        vals["mitre_tactics"] = _json_list(vals.get("mitre_tactics"))
        vals["mitre_techniques"] = _json_list(vals.get("mitre_techniques"))
        vals["entity_mappings"] = _json(vals.get("entity_mappings"))
        vals["tuning_history"] = _json(vals.get("tuning_history", []))

        placeholders = ", ".join("?" * len(cols))
        sql = (f'INSERT INTO rules ({",".join(chr(34)+c+chr(34) for c in cols)}) '
               f'VALUES ({placeholders})')
        self.db.execute(sql, [vals[c] for c in cols])
        return rid

    def get(self, rule_id: str) -> dict | None:
        return self.db.query_one("SELECT * FROM rules WHERE rule_id=?", [rule_id])

    def list(self, enabled: bool | None = None, origin: str | None = None) -> list[dict]:
        clauses = ["1=1"]
        params: list = []
        if enabled is not None:
            clauses.append("enabled = ?")
            params.append(enabled)
        if origin is not None:
            clauses.append("origin = ?")
            params.append(origin)
        return self.db.query(
            f"SELECT * FROM rules WHERE {' AND '.join(clauses)} ORDER BY created_at DESC",
            params)

    def update(self, rule_id: str, **fields) -> bool:
        """Patch a rule.  Appends to tuning_history and bumps version."""
        row = self.get(rule_id)
        if not row:
            return False

        history = _from_json(row.get("tuning_history", "[]"))
        # Handle double-encoding: DuckDB may return JSON as a string
        if isinstance(history, str):
            history = _from_json(history)
        if not isinstance(history, list):
            history = []
        history.append({
            "ts": utcnow().isoformat(),
            "changes": dict.fromkeys(fields, "<set>"),
        })

        fields["version"] = int(row.get("version", 1)) + 1
        fields["tuning_history"] = _json(history)
        fields["updated_at"] = utcnow()

        sets = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(
            f"UPDATE rules SET {sets} WHERE rule_id=?",
            list(fields.values()) + [rule_id])
        return True

    def enable(self, rule_id: str) -> bool:
        return self.update(rule_id, enabled=True)

    def disable(self, rule_id: str) -> bool:
        return self.update(rule_id, enabled=False)

    def delete(self, rule_id: str) -> bool:
        self.db.execute("DELETE FROM rules WHERE rule_id=?", [rule_id])
        return True
