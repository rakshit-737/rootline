import json

from rootline.cli import main
from rootline.export import to_mermaid, to_stix, to_story
from rootline.synth import C2_IP


def test_story_json_roundtrips(attack_run):
    _, truth, a = attack_run
    s = json.loads(json.dumps(to_story(a.graph, a.reconstruction), default=str))
    assert s["schema"] == "rootline.story/v1"
    assert s["root_causes"][0] == truth["root_cause"]
    assert s["integrity"]["hash_chain_head"] == a.raw.head
    roles = {n["role"] for n in s["nodes"]}
    assert {"root", "backward", "forward"} <= roles


def test_stix_bundle_shape(attack_run):
    _, _, a = attack_run
    b = to_stix(a.graph, a.reconstruction)
    assert b["type"] == "bundle" and b["id"].startswith("bundle--")
    types = {o["type"] for o in b["objects"]}
    assert {"identity", "ipv4-addr", "indicator", "file", "observed-data"} <= types
    ind = [o for o in b["objects"] if o["type"] == "indicator"]
    assert any(C2_IP in o["pattern"] for o in ind)
    for o in b["objects"]:
        assert o["id"].split("--")[0] == o["type"]
        if o["type"] != "ipv4-addr" and o["type"] != "file":
            assert o["spec_version"] == "2.1"
    # deterministic ids
    assert b == to_stix(a.graph, a.reconstruction)


def test_mermaid(attack_run):
    _, _, a = attack_run
    m = to_mermaid(a.graph, a.reconstruction)
    assert m.startswith("flowchart LR") and "invoice.docm" in m


def test_cli_synth_analyze_verify(tmp_path, capsys):
    ev, story, stix = tmp_path / "e.jsonl", tmp_path / "s.json", tmp_path / "x.json"
    assert main(["synth", "--out", str(ev), "--benign", "80"]) == 0
    assert main(["analyze", str(ev), "--story", str(story), "--stix", str(stix)]) == 0
    assert "invoice.docm" in capsys.readouterr().out
    assert json.loads(story.read_text())["iocs"]["ipv4"] == [C2_IP]
    assert main(["verify", str(ev)]) == 0
    head = capsys.readouterr().out.strip()
    assert main(["verify", str(ev), "--head", head]) == 0
    # tamper: drop the log-deletion line -> chain mismatch
    lines = [ln for ln in ev.read_text().splitlines() if "auth.log" not in ln]
    ev.write_text("\n".join(lines) + "\n")
    assert main(["verify", str(ev), "--head", head]) == 2


def test_cli_ioc_pivot(tmp_path, capsys):
    ev = tmp_path / "e.jsonl"
    main(["synth", "--out", str(ev), "--benign", "60"])
    assert main(["analyze", str(ev), "--ioc", "/tmp/.loot.tar"]) == 0
    assert "MANUAL" in capsys.readouterr().out


def test_cli_demo(tmp_path, capsys):
    assert main(["demo", "--outdir", str(tmp_path), "--benign", "100"]) == 0
    out = capsys.readouterr().out
    assert "root_cause_correct: True" in out
    assert (tmp_path / "stix.json").exists() and (tmp_path / "story.mmd").exists()
