"""End-to-end pipeline: records -> events -> graph -> reduce -> tag -> reconstruct."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .detect import RareTransitionModel, detect, primary_alert
from .graph import ProvenanceGraph
from .models import Alert, Event, Reconstruction, Severity
from .normalize import Normalizer
from .reconstruct import reconstruct
from .reduce import ReductionReport, reduce_graph


@dataclass
class Analysis:
    """Result of :func:`analyze`: raw and reduced graphs, alerts, the reconstruction and rejected records."""
    raw: ProvenanceGraph
    graph: ProvenanceGraph
    reduction: ReductionReport
    alerts: list[Alert]
    reconstruction: Reconstruction | None
    rejected: list[tuple[int, str]] = field(default_factory=list)


def build_graph(records: Iterable[dict[str, Any]]) -> tuple[ProvenanceGraph, list[tuple[int, str]]]:
    """Normalise raw records and build the provenance graph; returns ``(graph, rejected records)``."""
    n = Normalizer()
    events: list[Event] = sorted(n.normalize(records), key=lambda e: (e.ts, e.seq))
    return ProvenanceGraph().ingest(events), n.errors


def analyze(records: Iterable[dict[str, Any]], baseline: Iterable[dict[str, Any]] | None = None,
            reduce: bool = True, alert_node: str | None = None) -> Analysis:
    """Full pipeline: normalise, build the graph, tag, reduce and reconstruct around the top alert (or ``alert_node``). ``baseline`` is a benign capture for the rarity rules."""
    raw, errors = build_graph(records)
    model = None
    if baseline is not None:
        bg, _ = build_graph(baseline)
        model = RareTransitionModel().fit(bg)
    alerts = detect(raw, model)
    keep = {a.node_id for a in alerts} | ({alert_node} if alert_node else set())
    g, rep = reduce_graph(raw, keep) if reduce else (raw, ReductionReport(len(raw.edges), len(raw.edges),
                                                                           len(raw.nodes), len(raw.nodes)))
    pivot: Alert | None
    if alert_node:
        matches = [a for a in alerts if a.node_id == alert_node]
        if alert_node not in g.nodes:
            raise KeyError(f"unknown node {alert_node!r}")
        touching = g.in_edges.get(alert_node, []) + g.out_edges.get(alert_node, [])
        t = max((e.end_ts for e in touching), default=g.nodes[alert_node].first_ts)
        pivot = matches[0] if matches else Alert("MANUAL", alert_node, t, Severity.MEDIUM,
                                                 "analyst-selected pivot (IOC)")
    else:
        pivot = primary_alert(alerts)
    rec = reconstruct(g, pivot, alerts) if pivot else None
    return Analysis(raw, g, rep, alerts, rec, errors)
