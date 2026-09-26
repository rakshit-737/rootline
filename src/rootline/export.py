"""Exporters: JSON attack story (REVENANT handoff), STIX 2.1 bundle, Mermaid.

STIX objects are built by hand (spec-shaped dicts) to avoid a heavy
dependency; validate with ``python-stix2`` in CI later (TODO).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .graph import ProvenanceGraph
from .models import NodeType, Reconstruction

NS = uuid.UUID("6f1b3c5e-0000-4000-8000-526f6f746c6e")  # deterministic ids


def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, kind + ':' + key)}"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def to_story(g: ProvenanceGraph, r: Reconstruction) -> dict[str, Any]:
    """REVENANT-compatible JSON: nodes, edges, timeline, iocs, integrity head."""
    return {
        "schema": "rootline.story/v1",
        "alert": r.alert.to_dict(),
        "root_causes": [g.nodes[n].label for n in r.root_causes],
        "root_cause_ids": r.root_causes,
        "kill_chain": r.kill_chain,
        "nodes": [{"id": n, "type": g.nodes[n].type.value, "label": g.nodes[n].label,
                   "role": "root" if n in r.root_causes else "backward" if n in r.backward
                   else "forward" if n in r.forward else "accessed",
                   "attrs": g.nodes[n].attrs} for n in sorted(r.nodes)],
        "edges": [{"src": e.src, "dst": e.dst, "rel": e.rel.value, "ts": e.ts, "count": e.count}
                  for e in r.edges],
        "timeline": r.timeline,
        "iocs": r.iocs,
        "integrity": {"hash_chain_head": g.head, "events": len(g.events)},
    }


def to_stix(g: ProvenanceGraph, r: Reconstruction) -> dict[str, Any]:
    now = _iso(r.alert.ts)
    objs: list[dict[str, Any]] = []
    identity = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", "rootline"),
                "created": now, "modified": now, "name": "ROOTLINE", "identity_class": "system"}
    objs.append(identity)
    refs = []
    for ip in r.iocs.get("ipv4", []):
        kind = "ipv6-addr" if ":" in ip else "ipv4-addr"
        o = {"type": kind, "spec_version": "2.1", "id": _sid(kind, ip), "value": ip}
        objs.append(o)
        refs.append(o["id"])
        objs.append({"type": "indicator", "spec_version": "2.1", "id": _sid("indicator", ip),
                     "created": now, "modified": now, "created_by_ref": identity["id"],
                     "name": f"C2 endpoint {ip}", "indicator_types": ["malicious-activity"],
                     "pattern": f"[{kind}:value = '{ip}']", "pattern_type": "stix", "valid_from": now})
    for path in r.iocs.get("files", []):
        name = path.rsplit("/", 1)[-1]
        o = {"type": "file", "spec_version": "2.1", "id": _sid("file", path), "name": name}
        objs.append(o)
        refs.append(o["id"])
    for h in r.iocs.get("sha256", []):
        objs.append({"type": "indicator", "spec_version": "2.1", "id": _sid("indicator", h),
                     "created": now, "modified": now, "created_by_ref": identity["id"],
                     "name": f"payload {h[:12]}", "indicator_types": ["malicious-activity"],
                     "pattern": f"[file:hashes.'SHA-256' = '{h}']", "pattern_type": "stix", "valid_from": now})
    if refs:
        first = min(e.ts for e in r.edges) if r.edges else r.alert.ts
        last = max(e.end_ts for e in r.edges) if r.edges else r.alert.ts
        objs.append({"type": "observed-data", "spec_version": "2.1", "id": _sid("observed-data", g.head),
                     "created": now, "modified": now, "created_by_ref": identity["id"],
                     "first_observed": _iso(first), "last_observed": _iso(last),
                     "number_observed": 1, "object_refs": refs})
    techs = sorted({t["attack_technique"] for t in [r.alert.to_dict()] if t["attack_technique"]})
    for t in techs:
        objs.append({"type": "attack-pattern", "spec_version": "2.1", "id": _sid("attack-pattern", t),
                     "created": now, "modified": now, "name": t,
                     "external_references": [{"source_name": "mitre-attack", "external_id": t}]})
    return {"type": "bundle", "id": _sid("bundle", g.head + r.alert.node_id), "objects": objs}


def to_mermaid(g: ProvenanceGraph, r: Reconstruction) -> str:
    ids = {n: f"n{i}" for i, n in enumerate(sorted(r.nodes))}
    shape = {NodeType.PROCESS: ("([", "])"), NodeType.FILE: ("[/", "/]"), NodeType.SOCKET: ("{{", "}}")}
    lines = ["flowchart LR"]
    for n, i in ids.items():
        a, b = shape[g.nodes[n].type]
        label = g.nodes[n].label.replace('"', "'")
        lines.append(f'  {i}{a}"{label}"{b}')
    seen = set()
    for e in r.edges:
        key = (e.src, e.dst, e.rel)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"  {ids[e.src]} -->|{e.rel.value}| {ids[e.dst]}")
    for n in r.root_causes:
        lines.append(f"  style {ids[n]} stroke:#d33,stroke-width:3px")
    lines.append(f"  style {ids[r.alert.node_id]} fill:#fdd")
    return "\n".join(lines)


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=False, default=str)
