from rootline.detect import RareTransitionModel, detect, primary_alert
from rootline.models import Severity
from rootline.pipeline import analyze, build_graph
from rootline.synth import generate


def test_all_rules_fire_on_attack(attack_run):
    _, _, a = attack_run
    fired = {al.rule_id for al in a.alerts}
    assert {"RL-001", "RL-002", "RL-003", "RL-004", "RL-005", "RL-006", "RL-007"} <= fired
    techs = {al.attack_technique for al in a.alerts}
    assert {"T1204.002", "T1071", "T1003.008", "T1053.003", "T1070.002"} <= techs


def test_no_rule_alerts_on_benign_only():
    recs, _ = generate(300, attack=False, seed=3)
    a = analyze(recs)
    # sshd reading /etc/shadow and logrotate deleting logs are allowlisted
    assert a.alerts == []
    assert a.reconstruction is None


def test_anomaly_model_flags_unseen_transitions_only():
    base, _ = generate(200, attack=False, seed=1)
    other, _ = generate(200, attack=False, seed=2)
    bg, _ = build_graph(base)
    m = RareTransitionModel().fit(bg)
    og, _ = build_graph(other)
    assert m.tag(og) == []  # same benign workload -> nothing rare
    recs, _ = generate(200, attack=True, seed=7)
    ag, _ = build_graph(recs)
    descs = " ".join(al.description for al in m.tag(ag))
    assert "soffice -> sh" in descs


def test_unfitted_model_scores_zero():
    assert RareTransitionModel().score_pair("exec", ("a", "b")) == 0.0


def test_primary_alert_is_earliest_critical(attack_run):
    _, _, a = attack_run
    p = primary_alert(a.alerts)
    assert p.severity is Severity.CRITICAL and p.rule_id == "RL-003"
    assert primary_alert([]) is None


def test_detect_is_deterministic(attack_run):
    _, _, a = attack_run
    assert [x.to_dict() for x in detect(a.raw)] == [x.to_dict() for x in detect(a.raw)]
