# Security Policy

## Scope and intended use
ROOTLINE is a **defensive, observe-only** research and education tool. Use the eBPF probe only on systems you own or are explicitly authorised to monitor. The synthetic attack generator emits *event records*; it does not execute anything, contact any network, or contain exploit code.

## Reporting a vulnerability
Please use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on the repository (<https://github.com/rakshit-737/rootline/security/advisories/new>). Do not open a public issue. Include reproduction steps and the affected version. You should get an acknowledgement within 7 days.

## The HTTP API has no authentication
`rootline serve` is a lab tool. It binds to `127.0.0.1` by default, accepts only loopback `Host` headers (a DNS-rebinding guard), and requires the header `X-Rootline: 1` on POST routes (so a web page in your browser cannot post to it cross-site). If you bind it to another address, `serve` prints a warning: keep it on a private network or behind an authenticating reverse proxy. The Docker image listens on `0.0.0.0` *inside* the container; publish it as `-p 127.0.0.1:8000:8000`.

## Hardening notes
- Treat every ingested record as untrusted. `rootline.normalize` type-checks and bounds fields, makes control characters visible, rejects non-finite timestamps, and counts malformed records as rejected instead of crashing. Probe output is parsed with an anchored pattern so crafted file or process names cannot change an event's kind or pids.
- Exporters escape for their target: Cypher string literals (no telemetry text in comments), Mermaid entity codes, JSON via the json module, HTML escaping in the UI.
- Uploads are streamed to a temp file with a size cap (50 MB by default), parsed in a worker thread, and the in-memory store keeps at most 32 analyses.
- Ship the hash-chain head (`rootline verify`) off-host if you rely on it for tamper evidence.
- The core runtime has no third-party dependencies. Optional extras: `api` (FastAPI, uvicorn, httpx), `ml` (scikit-learn), `stix` (stix2), `bench` (matplotlib, scikit-learn), `repro` (torch, numpy, rapidfuzz). `dev` adds pytest and ruff.
