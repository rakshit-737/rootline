from conftest import rec

from rootline.evaluate import attack_edges
from rootline.graph import ProvenanceGraph
from rootline.models import Relation
from rootline.normalize import Normalizer
from rootline.reduce import reduce_graph


def build(records):
    return ProvenanceGraph().ingest(Normalizer().normalize(records))


def test_repeated_edges_merged():
    g = build([rec(i, "read", 1, comm="py", path="/data.csv") for i in range(1, 51)])
    r, rep = reduce_graph(g)
    reads = [e for e in r.edges if e.rel is Relation.READ]
    assert len(reads) == 1 and reads[0].count == 50 and reads[0].last_ts == 50
    assert rep.edge_ratio == 50


def test_merge_respects_causality():
    # proc writes /out, then receives new input, then writes /out again:
    # the second write carries different information -> must NOT be merged
    g = build([
        rec(1, "write", 1, comm="p", path="/out"),
        rec(2, "read", 1, comm="p", path="/secret"),
        rec(3, "write", 1, comm="p", path="/out"),
    ])
    r, _ = reduce_graph(g)
    assert len([e for e in r.edges if e.rel is Relation.WROTE]) == 2


def test_benign_libs_pruned_but_kept_if_written_or_pinned():
    g = build([
        rec(1, "read", 1, comm="p", path="/usr/lib/x86_64-linux-gnu/libc.so.6"),
        rec(2, "read", 1, comm="p", path="/etc/ld.so.preload"),
        rec(3, "write", 2, comm="evil", path="/usr/lib/libevil.so"),
        rec(4, "read", 1, comm="p", path="/usr/lib/libevil.so"),
    ])
    r, _ = reduce_graph(g)
    labels = {n.label for n in r.nodes.values()}
    assert "/usr/lib/x86_64-linux-gnu/libc.so.6" not in labels
    assert "/usr/lib/libevil.so" in labels  # written during capture -> not benign
    assert "/etc/ld.so.preload" in labels
    pinned = next(n for n in g.nodes if n.endswith("libc.so.6"))
    r2, _ = reduce_graph(g, keep={pinned})
    assert pinned in r2.nodes


def test_reduction_preserves_all_attack_paths(attack_run):
    _, _, a = attack_run
    kept = {(e.src, e.dst, e.rel) for e in a.graph.edges}
    gt = attack_edges(a.raw)
    assert gt and gt <= kept
    assert a.reduction.edges_after < a.reduction.edges_before
