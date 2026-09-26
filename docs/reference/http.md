# HTTP API

`rootline serve` (or the Docker image) exposes, on port 8000:

| Method | Path | Returns |
|---|---|---|
| GET | `/` | Replay UI |
| GET | `/api/health` | `{"status": "ok"}` |
| GET | `/api/stories` | Summaries of loaded stories |
| POST | `/api/demo?benign=300` | Analyse a synthetic intrusion |
| POST | `/api/analyze?name=&format=auto` | Analyse an uploaded capture (request body) |
| GET | `/api/stories/{id}` | Story, alerts, reduction stats, timeline |
| GET | `/api/stories/{id}/stix` | STIX 2.1 bundle |
| GET | `/api/stories/{id}/mermaid` | Mermaid text |
| GET | `/api/stories/{id}/cypher` | Neo4j Cypher script |

Interactive OpenAPI docs are at `/docs` on a running server.
