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

Lab use only: the API has **no authentication**. It binds to localhost by
default and only answers requests whose Host header is a loopback name
(DNS-rebinding guard); POST routes also require the header ``X-Rootline: 1``
(cross-site pages cannot send it without a preflight). Uploads are streamed to
a temp file and cut off at ``max_body`` bytes (default 50 MB); parsing runs in
a worker thread so one large upload does not stall other requests. At most
``max_stories`` analyses are kept (oldest evicted). Nothing is executed.
"""
from __future__ import annotations

import os
import tempfile
import threading
import uuid
from collections import OrderedDict
from importlib import resources
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, PlainTextResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .export import to_cypher, to_mermaid, to_stix, to_story
from .loaders import FORMATS, load_many
from .pipeline import Analysis, analyze
from .synth import generate

MAX_BODY = 50 * 1024 * 1024
MAX_STORIES = 32
LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "[::1]", "::1"]
_LOCK = threading.Lock()


class Store:
    """In-memory analyses, bounded: the oldest is evicted past ``limit``."""

    def __init__(self, limit: int = MAX_STORIES) -> None:
        self.items: OrderedDict[str, tuple[str, Analysis]] = OrderedDict()
        self.limit = limit

    def add(self, name: str, a: Analysis) -> str:
        """Store an analysis and return its id."""
        sid = uuid.uuid4().hex[:12]
        with _LOCK:
            self.items[sid] = (name, a)
            while len(self.items) > self.limit:
                self.items.popitem(last=False)
        return sid

    def get(self, sid: str) -> Analysis:
        try:
            return self.items[sid][1]
        except KeyError:
            raise HTTPException(404, "unknown story id") from None


def _csrf(x_rootline: str | None = Header(None)) -> None:
    if x_rootline != "1":
        raise HTTPException(403, "missing X-Rootline: 1 header")


def summary(sid: str, name: str, a: Analysis) -> dict[str, Any]:
    r = a.reconstruction
    return {"id": sid, "name": name, "events": len(a.raw.events), "vertices": len(a.raw.nodes),
            "alerts": len(a.alerts), "story_vertices": len(r.nodes) if r else 0,
            "root_causes": [a.graph.nodes[n].label for n in r.root_causes] if r else []}


def create_app(preload: list[str | list[str]] | None = None, *, allowed_hosts: list[str] | None = None,
               max_body: int = MAX_BODY, max_stories: int = MAX_STORIES, docs: bool = False) -> FastAPI:
    """Build the FastAPI app.

    Args:
        preload: captures to analyse at start-up; a list entry is fused (several sensors, one host).
        allowed_hosts: accepted Host headers (default: loopback names only).
        max_body: upload cap in bytes.
        max_stories: analyses kept in memory.
        docs: expose /docs, /redoc and /openapi.json (off by default).
    """
    app = FastAPI(title="ROOTLINE", version=__version__,
                  description="Provenance-graph attack reconstruction (lab use only, no authentication)",
                  docs_url="/docs" if docs else None, redoc_url="/redoc" if docs else None,
                  openapi_url="/openapi.json" if docs else None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or LOOPBACK_HOSTS)
    store = Store(max_stories)
    app.state.store = store
    for item in preload or []:
        paths = item if isinstance(item, list) else [item]
        store.add(" + ".join(os.path.basename(p) for p in paths), analyze(load_many(paths)))

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return resources.files("rootline").joinpath("web/index.html").read_text(encoding="utf-8")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/stories")
    def stories() -> list[dict[str, Any]]:
        return [summary(sid, name, a) for sid, (name, a) in store.items.items()]

    @app.post("/api/demo", dependencies=[Depends(_csrf)])
    def demo(benign: int = Query(300, ge=10, le=5000)) -> dict[str, Any]:
        base, _ = generate(benign, attack=False, seed=1)
        recs, _ = generate(benign, attack=True, seed=7)
        a = analyze(recs, base)
        return summary(store.add("synthetic demo", a), "synthetic demo", a)

    @app.post("/api/analyze", dependencies=[Depends(_csrf)])
    async def analyze_upload(request: Request, format: str = Query("auto"),
                             name: str = Query("upload", max_length=120)) -> dict[str, Any]:
        if format not in FORMATS:
            raise HTTPException(400, f"format must be one of {FORMATS}")
        too_big = HTTPException(413, f"capture too large ({max_body // (1024 * 1024)} MB max)")
        try:
            declared = int(request.headers.get("content-length") or 0)
        except ValueError:
            raise HTTPException(400, "bad Content-Length") from None
        if declared > max_body:
            raise too_big
        fd, tmp = tempfile.mkstemp(suffix=".log")
        try:
            total, nonblank = 0, False
            with os.fdopen(fd, "wb") as fh:
                async for chunk in request.stream():  # also covers chunked bodies
                    total += len(chunk)
                    if total > max_body:
                        raise too_big
                    nonblank = nonblank or bool(chunk.strip())
                    fh.write(chunk)
            if not nonblank:
                raise HTTPException(400, "empty body")
            a = await run_in_threadpool(lambda: analyze(load_many([tmp], format)))
        finally:
            os.unlink(tmp)
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


def serve(paths: list[str | list[str]], host: str = "127.0.0.1", port: int = 8000,
          allowed_hosts: list[str] | None = None) -> None:  # pragma: no cover
    """Run the API with uvicorn.

    A non-loopback ``host`` prints a warning (there is no authentication) and,
    unless ``allowed_hosts`` is given, accepts any Host header for that bind.
    """
    import sys

    import uvicorn
    hosts = list(allowed_hosts or LOOPBACK_HOSTS)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[rootline] WARNING: binding {host}: the API has no authentication; "
              "keep it on a private network or behind an authenticating proxy", file=sys.stderr)
        if not allowed_hosts:
            hosts = ["*"]
    uvicorn.run(create_app(paths, allowed_hosts=hosts), host=host, port=port, limit_concurrency=32)
