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

    Scenarios: S1-S4 (single host; the v0.2 traversal heuristics were designed
    on them, so they are in-sample) and the per-host logs of M1-M6 (held out).

Tagger coverage (Splunk attack_data Linux captures)
    Coverage = share of parsed captures where >= 1 alert fires, and where an
    alert names the capture's ATT&CK technique. Splits ``dev`` / ``dev2`` /
    ``sealed`` follow docs/protocol.md.
"""
from __future__ import annotations

import json
import os
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from .detect import RULES_V01, RULES_V02, detect
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
    attack_seqs = {ev.seq for ev in raw.events if ev.label == "attack"}  # hoisted: was rebuilt per edge (O(E*N))
    gt_keys = {(e.src, e.dst, e.rel) for e in raw.edges if e.seq in attack_seqs}
    t0 = time.perf_counter()
    red, rep = reduce_graph(raw)
    dt = time.perf_counter() - t0
    kept = {(e.src, e.dst, e.rel) for e in red.edges}
    return {"scenario": sc.name, **rep.to_dict(), "node_ratio": round(rep.nodes_before / max(1, rep.nodes_after), 2),
            "attack_edge_keys": len(gt_keys),
            "attack_edges_preserved": round(len(gt_keys & kept) / max(1, len(gt_keys)), 4),
            "seconds": round(dt, 3)}


def run_atlas(root: str) -> dict[str, Any]:
    rows, red, anom, skipped = [], [], [], []
    for d, s in discover(root):
        sc = load_scenario(d, s)
        raw, _ = build_graph(sc.records)  # built once; every benchmark only reads it
        try:
            rows += [r.__dict__ for r in run_atlas_scenario(sc, raw=raw)]
        except ValueError as e:  # e.g. an M-scenario host the attacker IOC never touched
            skipped.append({"scenario": sc.name, "reason": str(e)})
            continue
        red.append(reduction_stats(sc, raw))
        try:
            anom += run_anomaly_scenario(sc, g=raw)
        except ImportError:
            pass
    return {"atlas": rows, "reduction": red, "anomaly": anom, "skipped": skipped}


# ------------------------------------------------------------- tagger cover
def technique_of(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    for p in parts:
        if p.startswith("T1") and p[1:2].isdigit():
            return p
    return "malware/" + parts[parts.index("malware") + 1] if "malware" in parts else "?"


SPLITS = ("dev", "dev2", "sealed")


def _tech_match(techs: list[str], want: str) -> bool:
    return any(t.split(".")[0] == want.split(".")[0] for t in techs)


def coverage_row(path: str, dest: str, split: str) -> dict[str, Any]:
    recs = load_records(path)
    g, _ = build_graph(recs)
    row: dict[str, Any] = {"dataset": dest.split("/", 1)[1], "technique": technique_of(dest), "split": split,
                           "events": len(g.events)}
    for tag, rules in (("v01", RULES_V01), ("v02", RULES_V02), ("v03", None)):
        al = detect(g, rules=rules)
        techs = [a.attack_technique for a in al if a.attack_technique]
        row[f"{tag}_alerts"] = len(al)
        row[f"{tag}_on_technique"] = sum(1 for t in techs if _tech_match([t], row["technique"]))
        row[f"{tag}_rules"] = sorted({a.rule_id for a in al})
        row[f"{tag}_techniques"] = sorted(set(techs))
    return row


def run_coverage(manifest: str, data_root: str, splits: tuple[str, ...] = SPLITS) -> list[dict[str, Any]]:
    with open(manifest, encoding="utf-8") as fh:
        items = json.load(fh)["files"]
    rows = []
    for it in items:
        if it["source"] not in ("splunk", "otrf") or it.get("split") not in splits:
            continue
        path = os.path.join(data_root, it["dest"])
        if it["dest"].endswith(".zip"):
            continue  # OTRF zips: their extracted logs are listed via the OTRF compound demo instead
        if not os.path.exists(path):
            continue
        rows.append(coverage_row(path, it["dest"], it["split"]))
    return rows


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (stdlib only)."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return max(0.0, c - h), min(1.0, c + h)


def summarize_coverage(rows: list[dict[str, Any]], dev_techniques: set[str] | None = None) -> dict[str, Any]:
    """Per split and rule version: captures detected (any alert), captures whose technique was
    matched, the share of alerts that name the capture's technique (a precision proxy: the
    captures carry lots of benign background), each with a 95 % Wilson interval.
    ``unseen`` restricts the sealed split to techniques that never occur in dev/dev2."""
    dev_techniques = dev_techniques if dev_techniques is not None else {
        r["technique"].split(".")[0] for r in rows if r["split"] in ("dev", "dev2")}
    out: dict[str, Any] = {}
    groups = [(s, [r for r in rows if r["split"] == s]) for s in SPLITS]
    groups.append(("sealed-unseen-technique", [r for r in rows if r["split"] == "sealed"
                                               and r["technique"].split(".")[0] not in dev_techniques]))
    for split, rs in groups:
        loaded = [r for r in rs if r["events"] > 0]
        if not rs:
            continue
        d: dict[str, Any] = {"datasets": len(rs), "with_events": len(loaded)}
        n = len(loaded)
        for tag in ("v01", "v02", "v03"):
            if f"{tag}_alerts" not in (loaded[0] if loaded else {}):
                continue
            det = sum(1 for r in loaded if r[f"{tag}_alerts"])
            tm = sum(1 for r in loaded if _tech_match(r[f"{tag}_techniques"], r["technique"]))
            al = sum(r[f"{tag}_alerts"] for r in loaded)
            on = sum(r[f"{tag}_on_technique"] for r in loaded)
            d[f"{tag}_detected"] = det
            d[f"{tag}_detected_ci95"] = [round(x, 3) for x in wilson(det, n)]
            d[f"{tag}_technique_match"] = tm
            d[f"{tag}_technique_match_ci95"] = [round(x, 3) for x in wilson(tm, n)]
            d[f"{tag}_alerts"] = al
            d[f"{tag}_alert_precision"] = round(on / al, 3) if al else None
        out[split] = d
    return out


# ------------------------------------------------------------ vertex tagging
_T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
         10: 2.228, 15: 2.131, 20: 2.086, 30: 2.042}


def mean_ci(vals: list[float], lower: float | None = None,
            upper: float | None = None) -> tuple[float, float, float]:
    """Mean and two-sided 95 % Student-t confidence interval (stdlib only).

    ``lower``/``upper`` are the metric's natural bounds (e.g. 0 and 1 for a
    recall, 1 for a rank). The symmetric t-interval can spill past them when
    the sample sits near a bound; the interval is then clipped to the valid
    range, so it never reports impossible values such as recall 1.06.
    """
    n = len(vals)
    m = sum(vals) / n
    if n < 2:
        return m, m, m
    sd = (sum((v - m) ** 2 for v in vals) / (n - 1)) ** 0.5
    df = n - 1
    t = _T975.get(df) or _T975[max(d for d in _T975 if d <= df)]
    h = t * sd / n ** 0.5
    return m, clip_ci(m - h, lower, upper), clip_ci(m + h, lower, upper)


def clip_ci(v: float, lower: float | None = None, upper: float | None = None) -> float:
    """Clamp one interval bound into ``[lower, upper]`` (either side optional)."""
    if lower is not None:
        v = max(v, lower)
    if upper is not None:
        v = min(v, upper)
    return v


def metric_bounds(key: str, k: int, malicious: int, procs: int) -> tuple[float, float]:
    """Valid range of an anomaly metric: rank in [1, procs+1], hits in [0, min(k, bad)], recall in [0, 1]."""
    if key == "first_hit_rank":
        return 1.0, float(procs + 1)
    if key.startswith("hits@"):
        return 0.0, float(min(k, malicious))
    return 0.0, 1.0


def clip_anomaly_rows(rows: list[dict[str, Any]], k: int = 10) -> list[dict[str, Any]]:
    """Clip stored ``*_ci95`` intervals to each metric's valid range (for re-rendering old results)."""
    for r in rows:
        for key in [c for c in r if c.endswith("_ci95")]:
            lo, hi = metric_bounds(key[:-5], k, r["malicious"], r["processes"])
            r[key] = [round(clip_ci(b, lo, hi), 3) for b in r[key]]
    return rows


def run_anomaly_scenario(sc: AtlasScenario, k: int = 10, g: ProvenanceGraph | None = None,
                         seeds: int = 10) -> list[dict[str, Any]]:
    """Rank process vertices; GT = processes whose image is an ATLAS malicious entity."""
    from .anomaly import IForestTagger, degree_ranking, userdir_ranking

    g = g if g is not None else build_graph(sc.records)[0]
    names = [lab for lab in sc.host_labels if "." in lab and not lab[0].isdigit()]
    bad = {n for n, v in g.nodes.items() if v.type is NodeType.PROCESS
           and any(entity_matches(v.label, v.attrs, lab) for lab in names)}
    procs = sum(1 for v in g.nodes.values() if v.type is NodeType.PROCESS)
    rows = []

    def row(method: str, ranking: list[tuple[str, float]]) -> dict[str, Any]:
        ids = [n for n, _ in ranking]
        first = next((i + 1 for i, n in enumerate(ids) if n in bad), None)
        hits = sum(1 for n in ids[:k] if n in bad)
        return {"scenario": sc.name, "method": method, "processes": procs, "malicious": len(bad),
                "first_hit_rank": first, f"hits@{k}": hits,
                f"recall@{k}": round(hits / max(1, len(bad)), 3)}

    # IsolationForest is stochastic: report mean and 95 % t-interval over `seeds` forests,
    # clipped to each metric's valid range.
    # The interval covers seed variance on this one graph only, not data or scenario variance.
    for method, drop in (("iforest", ()), ("iforest-no-userdir", ("exec_user_dir",))):
        per_seed = [row(method, IForestTagger(seed=s, drop=drop).score(g)) for s in range(seeds)]
        agg = dict(per_seed[0])
        agg["seeds"] = seeds
        for key in ("first_hit_rank", f"hits@{k}", f"recall@{k}"):
            vals = [r[key] if r[key] is not None else procs + 1 for r in per_seed]
            m, lo, hi = mean_ci(vals, *metric_bounds(key, k, len(bad), procs))
            agg[key] = round(m, 3)
            agg[f"{key}_ci95"] = [round(lo, 3), round(hi, 3)]
        rows.append(agg)
    rows.append(row("user-dir image first (heuristic)", userdir_ranking(g)))
    rows.append(row("degree", degree_ranking(g)))
    rows.append({"scenario": sc.name, "method": "random (expected)", "processes": procs, "malicious": len(bad),
                 "first_hit_rank": round((procs + 1) / (len(bad) + 1), 1) if bad else None,
                 f"hits@{k}": round(k * len(bad) / max(1, procs), 3),
                 f"recall@{k}": round(k / max(1, procs), 3)})
    return rows
