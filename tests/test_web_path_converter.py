"""Test if Starlette/FastAPI path converter works with trailing segments."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

app = FastAPI()

@app.get("/entities/{entity_id:path}")
def entity_detail(entity_id: str):
    return {"entity_id": entity_id}

@app.put("/api/entities/{entity_id:path}/watch")
def entity_watch(entity_id: str):
    return {"entity_id": entity_id}

@app.post("/api/entities/{entity_id:path}/notes")
def entity_notes(entity_id: str):
    return {"entity_id": entity_id}

client = TestClient(app)

for url in [
    "/entities/process:/usr/bin/bash",
    "/entities/process:powershell.exe",
    "/api/entities/process:/usr/bin/bash/watch",
    "/api/entities/process:/usr/bin/bash/notes",
]:
    method = "get" if "/entities/" in url and "/api/" not in url else ("put" if "/watch" in url else "post")
    r = getattr(client, method)(url)
    print(f"{method.upper()} {url} -> {r.status_code}: {r.json()}")
