# siempl Entities

## Purpose
The entity store is the memory of the SIEM: every IP, user, host, process, file hash,
and domain observed in events is tracked as an entity. Entities accumulate reputation
scores based on alert verdicts, forming a threat-intelligence graph that future alerts
and agents query.

## Architecture

```
Entities ──┬── EntityStore.upsert()      ← called by ingest pipeline, alert creation
           ├── EntityStore.link()         ← ingest pipeline builds entity graph
           ├── EntityStore.search()       ← triage agent, entity detail UI
           └── EntityStore.apply_verdict() ← alert feedback moves reputation
```

### Entity Identifiers
Format: `type:value` (lowercased). Types from `schema.ENTITY_TYPES`:
`user`, `host`, `ip`, `process`, `file_hash`, `domain`.

### Reputation Model
- Range: 0.0 (benign) to 100.0 (malicious), 50.0 = unknown.
- `true_positive` verdict pushes reputation up; `false_positive` / `benign` pushes down.
- **Diminishing returns**: step size shrinks with each same-direction move (`STEP_BASE=15`, `DIMINISH_FACTOR=0.75`, `MIN_STEP=2.5`).
- **Neutral decay**: each verdict applies a 10% pull toward 50 before the step.
- **Private-IP clamp**: RFC1918 / loopback / link-local IPs never exceed 60.
- **Well-known benign clamp**: localhost, SYSTEM, root, Administrator, 127.0.0.1 clamped to 60.

### Graph Edges
`entity_edges(src_entity, dst_entity, relation, weight)` tracks relationships
like `host:web01 → has_ip → ip:10.0.0.1`. Weight increments on repeated observations.

## Public API

```python
from siempl.entities import EntityStore

store = EntityStore(db)
store.upsert("ip", "10.0.0.1")                          # → "ip:10.0.0.1"
store.link("ip:10.0.0.1", "host:web01", "has_ip")       # edge created
store.get("ip:10.0.0.1")                                 # → dict or None
store.search(q="%prod%", etype="host", limit=100)        # → list[dict]
store.apply_verdict(alert_id, "true_positive", "tester") # moves entity reputation
```

## Extension Points
- Add new entity types in `schema.ENTITY_TYPES`.
- Reputation constants (`STEP_BASE`, `DECAY_FRACTION`, `BENIGN_CEILING`) are module-level;
  a future config pass could make them settings.
- `WELL_KNOWN_BENIGN` is a frozenset; extend for additional known-safe identifiers.

## Known Limitations
- NXDOMAIN DNS tracking not yet implemented for domain entities.
- Entity graph queries (neighbors, paths) not yet built; raw SQL on `entity_edges` works.
- `watch` flag on entities is stored but not acted upon automatically.

## Testing
```bash
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_entities.py -q
```
All tests use temporary DuckDB databases; no network calls.