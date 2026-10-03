"""Ablation of the reconstructor on ATLAS: which component buys the precision?

Every variant runs the same :func:`rootline.reconstruct.reconstruct` on the same
raw graph from the same pivot, with one or more components switched off:

==================  ======  =====  =====  ========
variant             timed   stops  spine  accessed
==================  ======  =====  =====  ========
naive               no      no     no     no
naive+stops         no      yes    no     no
time                yes     no     no     no
time+stops          yes     yes    no     no
time+spine          yes     no     yes    no
time+stops+spine    yes     yes    yes    no
full (ROOTLINE)     yes     yes    yes    yes
==================  ======  =====  =====  ========

Pivots: ATLAS's own starting IOC (``user_artifact.txt``) plus every
host-observable ground-truth entity that maps to a vertex - the "random
symptom" protocol of the ATLAS paper, so the result does not hinge on one
lucky starting point.

Scenarios are reported in two groups: ``S`` (S1-S4, the four single-host
attacks the v0.2 traversal heuristics were designed on - in-sample) and ``M``
(the 12 per-host logs of the multi-host attacks M1-M6, never used for design -
held out). Pivots within one log share a graph and are not independent, so
uncertainty is computed over logs: a log-cluster bootstrap and a t-interval over
per-log means, and paired differences against ``naive`` are tested with exact
sign and sign-flip tests over logs (see :func:`summarize`). With only the four
S logs no distribution-free test can reach p < 0.125.
"""
from __future__ import annotations

import re
import time
from typing import Any

from .bench import ioc_seeds, prf, story_seqs
from .graph import ProvenanceGraph
from .loaders.atlas import AtlasScenario, entity_matches
from .models import Alert, Severity
from .reconstruct import contact_window, reconstruct
from .stats import cluster_bootstrap, mean, paired_log_test, sign_test, t_interval  # noqa: F401

VARIANTS: dict[str, dict[str, bool]] = {
    "naive": {"timed": False, "stops": False, "spine": False, "accessed": False},
    "naive+stops": {"timed": False, "stops": True, "spine": False, "accessed": False},
    "time": {"timed": True, "stops": False, "spine": False, "accessed": False},
    "time+stops": {"timed": True, "stops": True, "spine": False, "accessed": False},
    "time+spine": {"timed": True, "stops": False, "spine": True, "accessed": False},
    "time+stops+spine": {"timed": True, "stops": True, "spine": True, "accessed": False},
    "full": {"timed": True, "stops": True, "spine": True, "accessed": True},
}
METRICS = ("precision", "recall", "f1", "entity_recall", "rc_hit3")
MAX_SEEDS = 64


def entity_vertices(g: ProvenanceGraph, label: str) -> list[str]:
    """Vertices that correspond to one ATLAS ground-truth entity."""
    return sorted(n.id for n in g.nodes.values() if entity_matches(n.label, n.attrs, label))


def pivots(sc: AtlasScenario, g: ProvenanceGraph) -> list[tuple[str, list[str]]]:
    """(name, seed vertices): the analyst IOC first, then every mappable ground-truth entity."""
    out: list[tuple[str, list[str]]] = []
    ioc = sc.artifacts[0] if sc.artifacts else ""
    seeds = ioc_seeds(g, ioc)
    if seeds:
        out.append((f"ioc:{ioc}", seeds))
    for lab in sc.host_labels:
        if lab == ioc:
            continue
        vs = entity_vertices(g, lab)
        if vs:
            out.append((lab, vs[:MAX_SEEDS]))
    return out


def run_variant(g: ProvenanceGraph, seeds: list[str], flags: dict[str, bool]):
    win = [(s, *contact_window(g, s)) for s in seeds]
    spec = [(s, last, first) for s, first, last in win]
    t = max(x[1] for x in spec)
    return reconstruct(g, Alert("PIVOT", seeds[0], t, Severity.MEDIUM, "ablation pivot"), seeds=spec, **flags)


def run_scenario(sc: AtlasScenario, g: ProvenanceGraph, group: str) -> list[dict[str, Any]]:
    gt = {ev.seq for ev in g.events if ev.label == "attack" and ev.kind.value != "dns"}
    labels = sc.host_labels
    rows = []
    for pname, seeds in pivots(sc, g):
        seed_set = set(seeds)
        # entities the pivot itself already covers do not count as "found"
        other = [lab for lab in labels if not any(entity_matches(g.nodes[s].label, g.nodes[s].attrs, lab)
                                                  for s in seeds)]
        for vname, flags in VARIANTS.items():
            t0 = time.perf_counter()
            r = run_variant(g, seeds, flags)
            dt = time.perf_counter() - t0
            nodes = r.nodes | seed_set
            pred = story_seqs(g, nodes)
            hit = sum(1 for lab in other if any(entity_matches(g.nodes[n].label, g.nodes[n].attrs, lab) for n in nodes))
            rc_hit = any(entity_matches(g.nodes[n].label, g.nodes[n].attrs, lab)
                         for n in r.root_causes[:3] for lab in sc.labels)
            rows.append({"group": group, "scenario": sc.name, "pivot": pname, "variant": vname,
                         "story_nodes": len(nodes), "story_events": len(pred), **prf(pred, gt),
                         "entity_recall": round(hit / len(other), 4) if other else None,
                         "rc_hit3": float(rc_hit), "root_causes": [g.nodes[n].label for n in r.root_causes],
                         "seconds": round(dt, 3)})
    return rows


# ------------------------------------------------------------------ statistics
def _mean(xs: list[float]) -> float:
    return mean(xs)


def scenario_means(rows: list[dict[str, Any]], variant: str, metric: str) -> dict[str, float]:
    """Per-log mean of ``metric`` for one variant (pivots averaged within each log)."""
    by: dict[str, list[float]] = {}
    for r in rows:
        if r["variant"] == variant and r[metric] is not None:
            by.setdefault(r["scenario"], []).append(r[metric])
    return {k: _mean(v) for k, v in by.items()}


def exploit_of(scenario: str) -> str:
    """The CVE in an ATLAS log name (``M4-CVE_2018_8174_windows_h1`` -> ``CVE-2018-8174``)."""
    m = re.search(r"CVE[-_](\d{4})[-_](\d+)", scenario)
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else "?"


def summarize(rows: list[dict[str, Any]], base: str = "naive") -> dict[str, Any]:
    """Aggregate ablation rows per group (``S`` design data, ``M`` held out).

    For every variant and metric: the mean of per-log means with a 95 %
    log-cluster bootstrap interval (``ci95``), a Student-t interval over the
    per-log means (``t_ci95``) and, for precision/recall/F1, the per-log values.
    Paired differences against ``base`` are tested at the **log** level, the unit
    that is independent: exact sign test, exact sign-flip test and paired t
    (``logs``). Pivot counts (``pivots``) are descriptive only, because pivots
    in one log share a graph. p-values are stored unrounded.
    """
    out: dict[str, Any] = {}
    for group in sorted({r["group"] for r in rows}):
        g_rows = [r for r in rows if r["group"] == group]
        logs = sorted({r["scenario"] for r in g_rows})
        d: dict[str, Any] = {"scenarios": len(logs),
                             "pivots": len({(r["scenario"], r["pivot"]) for r in g_rows}),
                             "logs": {s: exploit_of(s) for s in logs}}
        for v in VARIANTS:
            vd: dict[str, Any] = {}
            for m in METRICS + ("story_nodes",):
                per = scenario_means(g_rows, v, m)
                mu, lo, hi = cluster_bootstrap(per)
                vd[m] = {"mean": round(mu, 4), "ci95": [round(lo, 4), round(hi, 4)]}
                if m in ("precision", "recall", "f1"):
                    _, tlo, thi = t_interval(list(per.values()))
                    vd[m]["t_ci95"] = [round(tlo, 4), round(thi, 4)]
                    vd[m]["per_log"] = {s: round(per[s], 4) for s in sorted(per)}
            if v != base:
                for m in ("precision", "f1", "recall"):
                    key = {(r["scenario"], r["pivot"]): r[m] for r in g_rows if r["variant"] == base}
                    diffs = [(r["scenario"], r[m] - key[(r["scenario"], r["pivot"])])
                             for r in g_rows if r["variant"] == v]
                    per_sc: dict[str, list[float]] = {}
                    for s, x in diffs:
                        per_sc.setdefault(s, []).append(x)
                    per_log = {s: _mean(x) for s, x in per_sc.items()}
                    mu, lo, hi = cluster_bootstrap(per_log)
                    lt = paired_log_test(per_log)
                    piv = sign_test([x for _, x in diffs])
                    vd[f"delta_{m}_vs_{base}"] = {
                        "mean": round(mu, 4), "ci95": [round(lo, 4), round(hi, 4)],
                        "t_ci95": [round(x, 4) for x in lt["t_ci95"]],
                        "logs": {k: lt[k] for k in ("n", "higher", "lower", "tied", "sign_test_p", "sign_flip_p",
                                                   "t", "df", "t_p", "min_attainable_p")},
                        "pivots": {k: piv[k] for k in ("higher", "lower", "tied")}}
            d[v] = vd
        out[group] = d
    return out
