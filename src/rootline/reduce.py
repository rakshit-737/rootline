"""Graph reduction: collapse benign repetition while preserving causality.

Two heuristics (simplified from the provenance-reduction literature, e.g.
Xu et al. "CPR" CCS'16 and LogGC):

1. **Edge merge** - repeated identical (src, dst, rel) edges are merged into
   one edge with ``count``/``last_ts``, *unless* the source vertex received new
   information in between (an in-edge whose timestamp falls inside the gap),
   which would change what flows (the CPR causality-preservation rule).
2. **Benign leaf pruning** - read-only system files (shared libs, locale,
   /proc, ld cache) that nothing wrote during capture are dropped; they are
   noise for attack stories. Anything in ``keep`` is never pruned.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .graph import ProvenanceGraph
from .models import Edge, NodeType, Relation

BENIGN_READ_PATTERNS = [
    re.compile(p) for p in (
        r"^/(usr/)?lib(32|64)?/", r"\.so(\.\d+)*$", r"^/proc/", r"^/sys/", r"^/etc/ld\.so\.cache$",  # NOT ld.so.preload (rootkit vector)
        r"^/usr/share/(locale|zoneinfo|fonts|icons)/",
        r"^/etc/(localtime|nsswitch\.conf|hosts|resolv\.conf)$",
        r"^/dev/(null|urandom|tty)",
    )
]


@dataclass
class ReductionReport:
    edges_before: int
    edges_after: int
    nodes_before: int
    nodes_after: int

    @property
    def edge_ratio(self) -> float:
        return self.edges_before / max(1, self.edges_after)

    def to_dict(self) -> dict:
        return {**self.__dict__, "edge_ratio": round(self.edge_ratio, 2)}


def is_benign_readonly(g: ProvenanceGraph, nid: str) -> bool:
    n = g.nodes[nid]
    if n.type is not NodeType.FILE:
        return False
    path = n.attrs.get("path", "")
    if not any(p.search(path) for p in BENIGN_READ_PATTERNS):
        return False
    return all(e.rel is Relation.READ for e in g.out_edges.get(nid, [])) and not g.in_edges.get(nid)


def reduce_graph(g: ProvenanceGraph, keep: set[str] | None = None) -> tuple[ProvenanceGraph, ReductionReport]:
    keep = keep or set()
    before_e, before_n = len(g.edges), len(g.nodes)
    drop = {nid for nid in g.nodes if nid not in keep and is_benign_readonly(g, nid)}

    r = ProvenanceGraph()
    r.events, r.head = g.events, g.head
    r.nodes = {k: v for k, v in g.nodes.items() if k not in drop}
    last: dict[tuple[str, str, Relation], Edge] = {}
    for e in g.edges:  # already in time order
        if e.src in drop or e.dst in drop:
            continue
        key = (e.src, e.dst, e.rel)
        prev = last.get(key)
        src_in = r.in_edges.get(e.src)
        # in-edges are appended in time order, so the latest one suffices
        fresh_input = bool(src_in) and src_in[-1].ts > prev.end_ts if prev is not None else False
        if prev is not None and not fresh_input:
            prev.count += e.count
            prev.last_ts = e.end_ts
            continue
        ne = Edge(e.src, e.dst, e.rel, e.ts, e.seq, e.count, e.last_ts)
        r.edges.append(ne)
        r.out_edges[ne.src].append(ne)
        r.in_edges[ne.dst].append(ne)
        last[key] = ne
    # drop now-isolated nodes
    for nid in [n for n in r.nodes if not r.in_edges.get(n) and not r.out_edges.get(n) and n not in keep]:
        del r.nodes[nid]
    return r, ReductionReport(before_e, len(r.edges), before_n, len(r.nodes))
