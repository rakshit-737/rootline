"""IsolationForest vertex tagger (optional: needs ``scikit-learn``).

Each *process* vertex becomes a small, explainable behaviour vector computed
from its provenance neighbourhood. IsolationForest (unsupervised) scores how
easily a vertex is isolated from the rest of the host's processes; the most
isolated ones are surfaced as candidate pivots (``RL-A03``). This is the
"rules + anomaly" tagger from the spec; reconstruction stays pure traversal.

Features (per process vertex):
    files_written, files_read, files_deleted, distinct_remote_ips, connects,
    children, exec_from_user_dir, image_in_system_dir, argv_len, lifetime_edges
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .graph import ProvenanceGraph
from .models import Alert, NodeType, Relation, Severity

FEATURES = ["files_written", "files_read", "files_deleted", "remote_ips", "connects", "children",
            "exec_user_dir", "image_system_dir", "argv_len", "edges"]
_USER = re.compile(r"^/(home/[^/]+|root|tmp|dev/shm|var/tmp)/|^c:/users/", re.I)
_SYS = re.compile(r"^/(usr|bin|sbin|lib|opt)/|^c:/(windows|program files)", re.I)


def features(g: ProvenanceGraph, nid: str) -> list[float]:
    """Per-process feature vector (see ``FEATURES``): log-scaled fan-in/fan-out counts plus
    flags such as an executable under a user-writable directory.
    """
    outs, ins = g.out_edges.get(nid, []), g.in_edges.get(nid, [])
    wrote = {e.dst for e in outs if e.rel is Relation.WROTE}
    deleted = {e.dst for e in outs if e.rel is Relation.DELETED}
    read = {e.src for e in ins if e.rel is Relation.READ}
    socks = [e.dst for e in outs if e.rel is Relation.CONNECTED]
    ips = {g.nodes[s].attrs.get("ip") for s in socks}
    children = {e.dst for e in outs if e.rel is Relation.FORKED}
    exe = str(g.nodes[nid].attrs.get("exe") or "")
    argv = str(g.nodes[nid].attrs.get("argv") or "")
    raw = [len(wrote), len(read), len(deleted), len(ips), len(socks), len(children),
           float(bool(_USER.search(exe))), float(bool(_SYS.search(exe))), len(argv), len(outs) + len(ins)]
    # log-scale counts so one chatty process does not dominate the split space
    return [math.log1p(v) if i not in (6, 7) else v for i, v in enumerate(raw)]


@dataclass
class IForestTagger:
    """IsolationForest over per-process features (``[ml]`` extra). ``drop`` removes features by name."""

    contamination: float = 0.02
    seed: int = 0
    min_score: float = 0.0
    drop: tuple[str, ...] = ()

    def score(self, g: ProvenanceGraph) -> list[tuple[str, float]]:
        """Rank process vertices by IsolationForest anomaly score, most anomalous first.

        Returns an empty list for graphs with fewer than 8 processes.
        """
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError as e:  # pragma: no cover - exercised only without the extra
            raise ImportError("IForestTagger needs scikit-learn: pip install 'rootline[ml]'") from e
        procs = [n for n, v in g.nodes.items() if v.type is NodeType.PROCESS]
        if len(procs) < 8:
            return []
        keep = [i for i, f in enumerate(FEATURES) if f not in self.drop]
        X = [[row[i] for i in keep] for row in (features(g, n) for n in procs)]
        m = IsolationForest(n_estimators=200, contamination=self.contamination, random_state=self.seed).fit(X)
        s = -m.score_samples(X)  # higher = more anomalous
        return sorted(zip(procs, (float(x) for x in s), strict=True), key=lambda t: -t[1])

    def tag(self, g: ProvenanceGraph, top_k: int = 10) -> list[Alert]:
        """Turn the ``top_k`` most anomalous processes into low-severity ``RL-A03`` alerts."""
        out = []
        for nid, sc in self.score(g)[:top_k]:
            if sc < self.min_score:
                continue
            t = max((e.ts for e in g.out_edges.get(nid, [])), default=g.nodes[nid].first_ts)
            out.append(Alert("RL-A03", nid, t, Severity.LOW,
                             f"isolation-forest outlier {g.nodes[nid].label} (score {sc:.2f})", None, None,
                             round(sc, 3), []))
        return out


def userdir_ranking(g: ProvenanceGraph) -> list[tuple[str, float]]:
    """Baseline: processes whose image lives in a user-writable directory first, then by degree."""
    procs = [n for n, v in g.nodes.items() if v.type is NodeType.PROCESS]

    def key(n: str) -> float:
        exe = str(g.nodes[n].attrs.get("exe") or "")
        return 1e9 * bool(_USER.search(exe)) + len(g.out_edges.get(n, [])) + len(g.in_edges.get(n, []))
    return sorted(((n, float(key(n))) for n in procs), key=lambda t: -t[1])


def degree_ranking(g: ProvenanceGraph) -> list[tuple[str, float]]:
    """Baseline: rank processes by raw edge count (the 'busiest process' heuristic)."""
    procs = [n for n, v in g.nodes.items() if v.type is NodeType.PROCESS]
    return sorted(((n, float(len(g.out_edges.get(n, [])) + len(g.in_edges.get(n, [])))) for n in procs),
                  key=lambda t: -t[1])
