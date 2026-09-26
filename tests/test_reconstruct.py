from conftest import rec

from rootline.evaluate import evaluate
from rootline.graph import ProvenanceGraph
from rootline.models import Alert, Severity
from rootline.normalize import Normalizer
from rootline.pipeline import analyze
from rootline.reconstruct import backward, forward
from rootline.synth import C2_IP, PAYLOAD_SHA


def test_root_cause_is_malicious_document(attack_run):
    _, truth, a = attack_run
    r = a.reconstruction
    assert a.graph.nodes[r.root_causes[0]].label == truth["root_cause"]


def test_blast_radius_covers_everything_touched(attack_run):
    _, truth, a = attack_run
    labels = {a.graph.nodes[n].label for n in a.reconstruction.nodes}
    assert set(truth["touched"]) <= labels


def test_story_is_compact_and_accurate(attack_run):
    _, truth, a = attack_run
    m = evaluate(a, truth)
    assert m["root_cause_correct"] and m["touched_recall"] == 1.0
    assert m["blast_recall"] >= 0.85 and m["precision"] >= 0.85
    assert m["story_nodes"] <= 40 < len(a.raw.nodes)
    assert m["attack_edges_preserved"] == 1.0


def test_kill_chain_and_iocs(attack_run):
    _, _, a = attack_run
    r = a.reconstruction
    assert list(r.kill_chain)[0] == "initial-access"
    for stage in ("execution", "persistence", "credential-access", "defense-evasion", "command-and-control"):
        assert stage in r.kill_chain
    assert r.iocs["ipv4"] == [C2_IP]
    assert PAYLOAD_SHA in r.iocs["sha256"]
    assert "/tmp/.x" in r.iocs["files"]
    ts = [t["ts"] for t in r.timeline]
    assert ts == sorted(ts)


def test_traversal_is_time_respecting():
    g = ProvenanceGraph().ingest(Normalizer().normalize([
        rec(1, "read", 1, comm="a", path="/early"),
        rec(2, "write", 1, comm="a", path="/f"),
        rec(3, "read", 1, comm="a", path="/late"),   # after the flow into /f
        rec(4, "read", 2, comm="b", path="/f"),
        rec(5, "write", 2, comm="b", path="/out"),
    ]))
    fnode = "file:h:/f"
    back, _ = backward(g, fnode, 2)
    labels = {g.nodes[n].label for n in back}
    assert "/early" in labels and "/late" not in labels
    fwd, _ = forward(g, "file:h:/early", 1)
    assert "file:h:/out" in fwd
    fwd2, _ = forward(g, "file:h:/late", 3)
    assert "file:h:/f" not in fwd2  # /f was written before /late was read


def test_ioc_pivot_manual(attack_run):
    recs, truth, _ = attack_run
    a = analyze(recs, alert_node=f"sock:{C2_IP}:4444")
    r = a.reconstruction
    assert r.alert.rule_id == "MANUAL"
    labels = {a.graph.nodes[n].label for n in r.nodes}
    assert truth["root_cause"] in labels


def test_stop_at_session_root():
    g = ProvenanceGraph().ingest(Normalizer().normalize([
        rec(1, "read", 1, comm="systemd", path="/etc/systemd/system.conf"),
        rec(2, "fork", 1, comm="systemd", child_pid=2),
        rec(3, "exec", 2, path="/bin/sh"),
    ]))
    sh = next(n for n, v in g.nodes.items() if v.label == "sh[2]")
    back, _ = backward(g, sh, 3)
    assert not any("system.conf" in n for n in back)


def test_alert_dataclass_roundtrip():
    a = Alert("X", "n", 1.0, Severity.LOW, "d")
    assert a.to_dict()["severity"] == "low"
