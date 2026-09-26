import dataclasses

import pytest
from conftest import rec

from rootline.graph import ProvenanceGraph, verify_chain
from rootline.models import NodeType, Relation
from rootline.normalize import Normalizer


def build(records):
    return ProvenanceGraph().ingest(Normalizer().normalize(records))


def test_fork_exec_creates_distinct_vertices():
    g = build([
        rec(1, "fork", 10, comm="bash", child_pid=11),
        rec(2, "exec", 11, path="/usr/bin/curl", comm="curl"),
        rec(3, "connect", 11, dst_ip="192.0.2.5", dst_port=80),
        rec(4, "write", 11, path="/tmp/p"),
    ])
    procs = [n for n in g.nodes.values() if n.type is NodeType.PROCESS]
    assert {p.attrs["comm"] for p in procs} == {"bash", "curl"}
    assert len(procs) == 3  # bash, forked child image, curl image
    rels = {(g.nodes[e.src].label, e.rel, g.nodes[e.dst].label) for e in g.edges}
    assert ("/usr/bin/curl", Relation.EXECUTED, "curl[11]") in rels
    assert ("curl[11]", Relation.WROTE, "/tmp/p") in rels
    assert ("192.0.2.5:80", Relation.RECEIVED, "curl[11]") in rels


def test_pid_reuse_after_exit_is_new_vertex():
    g = build([rec(1, "read", 7, comm="a", path="/x"), rec(2, "exit", 7, comm="a"),
               rec(3, "read", 7, comm="b", path="/y")])
    assert len([n for n in g.nodes.values() if n.type is NodeType.PROCESS]) == 2


def test_out_of_order_rejected():
    g = build([rec(5, "exit", 1)])
    ev = g.events[0]
    with pytest.raises(ValueError):
        g.add_event(dataclasses.replace(ev, ts=1.0, seq=9))


def test_hash_chain_detects_tampering(attack_run):
    _, _, a = attack_run
    evs = a.raw.events
    assert verify_chain(evs, a.raw.head)
    # attacker "deletes" the auth.log unlink event from the record
    doctored = [e for e in evs if e.path != "/var/log/auth.log"]
    assert not verify_chain(doctored, a.raw.head)
    # or edits a field
    doctored = list(evs)
    doctored[5] = dataclasses.replace(doctored[5], comm="innocent")
    assert not verify_chain(doctored, a.raw.head)


def test_stats_and_find(attack_run):
    _, _, a = attack_run
    s = a.raw.stats()
    assert s["events"] == len(a.raw.events) and s["process"] > 0
    assert a.raw.find("invoice.docm", NodeType.FILE)
