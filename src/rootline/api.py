"""FastAPI service + attack-replay UI (optional extra: ``pip install 'rootline[api]'``).

    rootline serve [capture ...] --host 127.0.0.1 --port 8000

Endpoints (JSON unless noted):

    GET  /                          attack-replay UI (static page, no CDN)
    GET  /api/health
    GET  /api/stories               analyses held in memory
    POST /api/analyze?format=auto&name=...   body = raw capture text
    POST /api/demo                  synthetic end-to-end run
    GET  /api/stories/{id}          rootline.story/v1 + alerts + stats
    GET  /api/stories/{id}/stix     STIX 2.1 bundle
    GET  /api/stories/{id}/mermaid  text/plain
    GET  /api/stories/{id}/cypher   text/plain (Neo4j import)

Binds to localhost by default. Uploaded text is parsed by the same hardened
loaders as the CLI (size-capped here at 50 MB); nothing is executed.
"""
from __future__ import annotations

import os
import tempfile
import threading
import uuid
from importlib import resources
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from . import __version__
from .export import to_cypher, to_mermaid, to_stix, to_story
from .loaders import FORMATS, load_many
from .pipeline import Analysis, analyze
from .synth import generate

MAX_BODY = 50 * 1024 * 1024
_LOCK = threading.Lock()


class Store:
    def __init__(self) -> None:
        self.items: dict[str, tuple[str, Analysis]] = {}

    def add(self, name: str, a: Analysis) -> str:
        sid = uuid.uuid4().hex[:12]
        with _LOCK:
            self.items[sid] = (name, a)
        return sid

    def get(self, sid: str) -> Analysis:
        try:
            return self.items[sid][1]
        except KeyError:
            raise HTTPException(404, "unknown story id") from None


def summary(sid: str, name: str, a: Analysis) -> dict[str, Any]:
    r = a.reconstruction
    return {"id": sid, "name": name, "events": len(a.raw.events), "vertices": len(a.raw.nodes),
            "alerts": len(a.alerts), "story_vertices": len(r.nodes) if r else 0,
            "root_causes": [a.graph.nodes[n].label for n in r.root_causes] if r else []}


def create_app(preload: list[str] | None = None) -> FastAPI:
    app = FastAPI(title="ROOTLINE", version=__version__,
                  description="Provenance-graph attack reconstruction (lab use only)")
    store = Store()
    app.state.store = store
    for path in preload or []:
        store.add(os.path.basename(path), analyze(load_many([path])))

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return resources.files("rootline").joinpath("web/index.html").read_text(encoding="utf-8")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/stories")
    def stories() -> list[dict[str, Any]]:
        return [summary(sid, name, a) for sid, (name, a) in store.items.items()]

    @app.post("/api/demo")
    def demo(benign: int = Query(300, ge=10, le=5000)) -> dict[str, Any]:
        base, _ = generate(benign, attack=False, seed=1)
        recs, _ = generate(benign, attack=True, seed=7)
        a = analyze(recs, base)
        return summary(store.add("synthetic demo", a), "synthetic demo", a)

    @app.post("/api/analyze")
    async def analyze_upload(request: Request, format: str = Query("auto"),
                             name: str = Query("upload", max_length=120)) -> dict[str, Any]:
        if format not in FORMATS:
            raise HTTPException(400, f"format must be one of {FORMATS}")
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413, "capture too large (50 MB max)")
        if not body.strip():
            raise HTTPException(400, "empty body")
        fd, tmp = tempfile.mkstemp(suffix=".log")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(body)
            recs = load_many([tmp], format)
        finally:
            os.unlink(tmp)
        a = analyze(recs)
        if not a.raw.events:
            raise HTTPException(422, "no usable events in capture")
        return summary(store.add(name, a), name, a)

    @app.get("/api/stories/{sid}")
    def story(sid: str) -> dict[str, Any]:
        a = store.get(sid)
        out: dict[str, Any] = {"summary": summary(sid, store.items[sid][0], a),
                               "stats": a.raw.stats(), "reduction": a.reduction.to_dict(),
                               "alerts": [al.to_dict() | {"label": a.graph.nodes[al.node_id].label}
                                          for al in a.alerts if al.node_id in a.graph.nodes][:500]}
        if a.reconstruction:
            out["story"] = to_story(a.graph, a.reconstruction)
        return out

    def _need(a: Analysis):
        if a.reconstruction is None:
            raise HTTPException(409, "no alert to reconstruct from in this capture")
        return a.reconstruction

    @app.get("/api/stories/{sid}/stix")
    def stix(sid: str) -> dict[str, Any]:
        a = store.get(sid)
        return to_stix(a.graph, _need(a))

    @app.get("/api/stories/{sid}/mermaid", response_class=PlainTextResponse)
    def mermaid(sid: str) -> str:
        a = store.get(sid)
        return to_mermaid(a.graph, _need(a))

    @app.get("/api/stories/{sid}/cypher", response_class=PlainTextResponse)
    def cypher(sid: str) -> str:
        a = store.get(sid)
        return to_cypher(a.graph, _need(a))

    return app


def serve(paths: list[str], host: str = "127.0.0.1", port: int = 8000) -> None:  # pragma: no cover
    import uvicorn
    uvicorn.run(create_app(paths), host=host, port=port)
