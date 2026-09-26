"""Benchmarks on public, labelled data.

ATLAS (attack investigation)
    For each scenario we start where an analyst would: from the attacker
    IOC ATLAS itself hands the investigator (``user_artifact.txt``, the
    attacker IP), and reconstruct. Ground truth is ATLAS' per-line label
    (``+`` = the line involves a malicious entity). We score on *events*:
    a raw event is "in the story" when both endpoints of its provenance edge
    are story vertices. Three methods, same pivot, same graph:

    * ``ioc-grep``  - every event touching the IOC vertices (what grep/SIEM gives)
    * ``naive-bfs`` - backward + forward reachability ignoring time and session
      roots (the textbook dependency-explosion baseline)
    * ``rootline``  - reduced graph, time-respecting traversal, session-root
      stops, causal-spine trimming (this project)

Tagger coverage (Sysmon for Linux)
    Splunk attack_data / OTRF captures, one ATT&CK technique each. Coverage =
    share of captures where >= 1 alert fires. Reported separately for the
    ``dev`` split (inspected while writing rules - in-sample) and the
    ``holdout`` split (never inspected).
"""
from __future__ import annotations

import json
import os
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from .detect import RULES_V01, detect
from .graph import ProvenanceGraph
from .loaders import load_records
from .loaders.atlas import AtlasScenario, discover, entity_matches, load_scenario
from .models import Alert, NodeType, Severity
from .pipeline import build_graph
from .reconstruct import contact_window, reconstruct
from .reduce import reduce_graph


# ------------------------------------------------------------------- tracing
def ioc_seeds(g: ProvenanceGraph, ioc: str) -> list[str]:
    ioc = ioc.strip().lower()
    if not ioc:
        return []
    out = []
    for n in g.nodes.values():
        a = n.attrs
        if n.type is NodeType.SOCKET and (a.get("ip") == ioc or ioc in a.get("domains", [])):
            out.append(n.id)
        elif n.type is NodeType.FILE and str(a.get("path", "")).lower().endswith(ioc):
            out.append(n.id)
    return sorted(out)


def trace_grep(g: ProvenanceGraph, seeds: list[str]) -> set[str]:
    nodes = set(seeds)
    for s in seeds:
        nodes |= {e.src for e in g.in_edges.get(s, [])} | {e.dst for e in g.out_edges.get(s, [])}
    return nodes


def trace_naive(g: ProvenanceGraph, seeds: list[str]) -> set[str]:
    """Plain reachability: ancestors via in-edges + descendants via out-edges, no time."""
    seen = set(seeds)
    for adj, nxt in ((g.in_edges, "src"), (g.out_edges, "dst")):
        q = deque(seeds)
        vis = set(seeds)
        while q:
            n = q.popleft()
            for e in adj.get(n, []):
                m = getattr(e, nxt)
                if m not in vis:
                    vis.add(m)
                    q.append(m)
        seen |= vis
    return seen


def trace_rootline(g: ProvenanceGraph, seeds: list[str]) -> set[str]:
    win = [(s, *contact_window(g, s)) for s in seeds]
    spec = [(s, last, first) for s, first, last in win]
    t = max(x[1] for x in spec)
    r = reconstruct(g, Alert("IOC", seeds[0], t, Severity.MEDIUM, "analyst IOC pivot"), seeds=spec)
    return r.nodes


# ------------------------------------------------------------------- scoring
def story_seqs(raw: ProvenanceGraph, nodes: set[str]) -> set[int]:
    return {e.seq for e in raw.edges if e.src in nodes and e.dst in nodes}


def prf(pred: set[int], gt: set[int]) -> dict[str, float]:
    tp = len(pred & gt)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(gt) if gt else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}


@dataclass
class AtlasResult:
    scenario: str
    method: str
    events: int
    gt_events: int
    story_nodes: int
    story_events: int
    precision: float
    recall: float
    f1: float
    entity_recall: float
    seconds: float


def run_atlas_scenario(sc: AtlasScenario, ioc: str | None = None,
                       raw: ProvenanceGraph | None = None) -> list[AtlasResult]:
    raw = raw if raw is not None else build_graph(sc.records)[0]
    gt = {ev.seq for ev in raw.events if ev.label == "attack" and ev.kind.value != "dns"}
    ioc = ioc or (sc.artifacts[0] if sc.artifacts else "")
    seeds = ioc_seeds(raw, ioc)
    if not seeds:
        raise ValueError(f"{sc.name}: IOC {ioc!r} matches no vertex")
    out = []
    for method in ("ioc-grep", "naive-bfs", "rootline-noreduce", "rootline"):
        t0 = time.perf_counter()
        if method == "ioc-grep":
            nodes = trace_grep(raw, seeds)
        elif method == "naive-bfs":
            nodes = trace_naive(raw, seeds)
        elif method == "rootline-noreduce":
            nodes = trace_rootline(raw, seeds)
        else:
            red, _ = reduce_graph(raw, set(seeds))
            nodes = trace_rootline(red, seeds)
        dt = time.perf_counter() - t0
        pred = story_seqs(raw, nodes)
        ents = sc.host_labels
        hit = sum(1 for lab in ents if any(entity_matches(raw.nodes[n].label, raw.nodes[n].attrs, lab)
                                           for n in nodes if n in raw.nodes))
        out.append(AtlasResult(sc.name, method, len(raw.events), len(gt), len(nodes), len(pred),
                               **prf(pred, gt), entity_recall=round(hit / max(1, len(ents)), 4),
                               seconds=round(dt, 3)))
    return out


def reduction_stats(sc: AtlasScenario, raw: ProvenanceGraph | None = None) -> dict[str, Any]:
    raw = raw if raw is not None else build_graph(sc.records)[0]
    gt_keys = {(e.src, e.dst, e.rel) for e in raw.edges
               if e.seq in {ev.seq for ev in raw.events if ev.label == "attack"}}
    t0 = time.perf_counter()
    red, rep = reduce_graph(raw)
    dt = time.perf_counter() - t0
    kept = {(e.src, e.dst, e.rel) for e in red.edges}
    return {"scenario": sc.name, **rep.to_dict(), "node_ratio": round(rep.nodes_before / max(1, rep.nodes_after), 2),
            "attack_edge_keys": len(gt_keys),
            "attack_edges_preserved": round(len(gt_keys & kept) / max(1, len(gt_keys)), 4),
            "seconds": round(dt, 3)}


def run_atlas(root: str) -> dict[str, Any]:
    rows, red, anom = [], [], []
    for d, s in discover(root):
        sc = load_scenario(d, s)
        raw, _ = build_graph(sc.records)  # built once; every benchmark only reads it
        rows += [r.__dict__ for r in run_atlas_scenario(sc, raw=raw)]
        red.append(reduction_stats(sc, raw))
        try:
            anom += run_anomaly_scenario(sc, g=raw)
        except ImportError:
            pass
    return {"atlas": rows, "reduction": red, "anomaly": anom}


# ------------------------------------------------------------- tagger cover
def technique_of(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for p in parts:
        if p.startswith("T1") and p[1:2].isdigit():
            return p
    return "malware/" + parts[parts.index("malware") + 1] if "malware" in parts else "?"


def run_coverage(manifest: str, data_root: str) -> list[dict[str, Any]]:
    with open(manifest, encoding="utf-8") as fh:
        items = json.load(fh)["files"]
    rows = []
    for it in items:
        if it["source"] not in ("splunk", "otrf") or not it.get("split"):
            continue
        path = os.path.join(data_root, it["dest"])
        if it["dest"].endswith(".zip"):
            continue  # OTRF zips: their extracted logs are listed via the OTRF compound demo instead
        if not os.path.exists(path):
            continue
        recs = load_records(path)
        g, _ = build_graph(recs)
        v01 = detect(g, rules=RULES_V01)
        v02 = detect(g)
        rows.append({"dataset": it["dest"].split("/", 1)[1], "technique": technique_of(it["dest"]),
                     "split": it["split"], "events": len(g.events),
                     "v01_alerts": len(v01), "v02_alerts": len(v02),
                     "v02_rules": sorted({a.rule_id for a in v02}),
                     "v02_techniques": sorted({a.attack_technique for a in v02 if a.attack_technique})})
    return rows


def summarize_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out = {}
    for split in ("dev", "holdout"):
        rs = [r for r in rows if r["split"] == split]
        if not rs:
            continue
        loaded = [r for r in rs if r["events"] > 0]
        out[split] = {
            "datasets": len(rs), "with_events": len(loaded),
            "v01_detected": sum(1 for r in loaded if r["v01_alerts"]),
            "v02_detected": sum(1 for r in loaded if r["v02_alerts"]),
            "v02_technique_match": sum(1 for r in loaded if any(
                t.split(".")[0] == r["technique"].split(".")[0] for t in r["v02_techniques"])),
        }
    return out


# ------------------------------------------------------------ vertex tagging
def run_anomaly_scenario(sc: AtlasScenario, k: int = 10, g: ProvenanceGraph | None = None) -> list[dict[str, Any]]:
    """Rank process vertices; GT = processes whose image is an ATLAS malicious entity."""
    from .anomaly import IForestTagger, degree_ranking

    g = g if g is not None else build_graph(sc.records)[0]
    names = [lab for lab in sc.host_labels if "." in lab and not lab[0].isdigit()]
    bad = {n for n, v in g.nodes.items() if v.type is NodeType.PROCESS
           and any(entity_matches(v.label, v.attrs, lab) for lab in names)}
    procs = sum(1 for v in g.nodes.values() if v.type is NodeType.PROCESS)
    rows = []
    for method, ranking in (("iforest", IForestTagger().score(g)), ("degree", degree_ranking(g))):
        ids = [n for n, _ in ranking]
        first = next((i + 1 for i, n in enumerate(ids) if n in bad), None)
        hits = sum(1 for n in ids[:k] if n in bad)
        rows.append({"scenario": sc.name, "method": method, "processes": procs, "malicious": len(bad),
                     "first_hit_rank": first, f"hits@{k}": hits,
                     f"recall@{k}": round(hits / max(1, len(bad)), 3)})
    rows.append({"scenario": sc.name, "method": "random (expected)", "processes": procs, "malicious": len(bad),
                 "first_hit_rank": round((procs + 1) / (len(bad) + 1), 1) if bad else None,
                 f"hits@{k}": round(k * len(bad) / max(1, procs), 3),
                 f"recall@{k}": round(k / max(1, procs), 3)})
    return rows
