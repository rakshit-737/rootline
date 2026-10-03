"""Metrics against ground truth: root-cause accuracy, blast-radius recall,
attack-path preservation under reduction, reduction ratio."""
from __future__ import annotations

from typing import Any

from .graph import ProvenanceGraph
from .models import Relation
from .pipeline import Analysis
from .reduce import BENIGN_READ_PATTERNS


def _lib(g: ProvenanceGraph, nid: str) -> bool:
    path = g.nodes[nid].attrs.get("path", "")
    return bool(path) and any(p.search(path) for p in BENIGN_READ_PATTERNS)


def attack_edges(g: ProvenanceGraph) -> set[tuple[str, str, Relation]]:
    """Attack-labelled edges, excluding loader noise (shared libs, /proc...)."""
    seqs = {e.seq for e in g.events if e.label == "attack"}
    return {(e.src, e.dst, e.rel) for e in g.edges
            if e.seq in seqs and not _lib(g, e.src) and not _lib(g, e.dst)}


def attack_nodes(g: ProvenanceGraph) -> set[str]:
    """Vertices touched by an attack-labelled edge."""
    return {n for s, d, _ in attack_edges(g) for n in (s, d)}


def evaluate(a: Analysis, truth: dict[str, Any]) -> dict[str, Any]:
    """Score an analysis against synthetic ground truth: root-cause accuracy, blast-radius
    recall, attack-path preservation under reduction and the reduction ratio.
    """
    r = a.reconstruction
    gt_edges = attack_edges(a.raw)
    kept = {(e.src, e.dst, e.rel) for e in a.graph.edges}
    gt_nodes = attack_nodes(a.raw)
    out: dict[str, Any] = {
        "events": len(a.raw.events),
        "alerts": len(a.alerts),
        "reduction": a.reduction.to_dict(),
        "attack_edges_preserved": len(gt_edges & kept) / max(1, len(gt_edges)),
    }
    if r is None:
        return out | {"root_cause_correct": False, "blast_recall": 0.0, "precision": 0.0}
    labels = [a.graph.nodes[n].label for n in r.root_causes]
    story = r.nodes
    out |= {
        "root_cause_correct": bool(labels) and labels[0] == truth.get("root_cause"),
        "root_cause_top3": truth.get("root_cause") in labels,
        "blast_recall": len(gt_nodes & story) / max(1, len(gt_nodes)),
        "precision": len(gt_nodes & story) / max(1, len(story)),
        "story_nodes": len(story),
        "touched_recall": sum(1 for p in truth.get("touched", []) if any(
            a.graph.nodes[n].label == p for n in story)) / max(1, len(truth.get("touched", []))),
    }
    return out
