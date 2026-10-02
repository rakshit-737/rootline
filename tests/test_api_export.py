import json
from pathlib import Path

import pytest

from rootline.cli import main
from rootline.export import to_cypher, to_stix

FX = Path(__file__).parent / "fixtures"


def test_cypher_export(attack_run):
    _, truth, a = attack_run
    cy = to_cypher(a.graph, a.reconstruction)
    assert cy.count("MERGE (n:Rootline:") == len(a.reconstruction.nodes)
    assert ":WROTE" in cy and ":FORKED" in cy and truth["root_cause"] in cy
    assert "role = 'root'" in cy
    # quotes / backslashes in labels are escaped
    from rootline.export import _cy
    assert _cy(r"a'b\c") == r"'a\'b\\c'"


def test_stix_bundle_validates_with_stix2(attack_run):
    stix2 = pytest.importorskip("stix2")
    _, _, a = attack_run
    bundle = stix2.parse(json.dumps(to_stix(a.graph, a.reconstruction)), allow_custom=False)
    assert bundle.type == "bundle" and len(bundle.objects) >= 5


def test_cli_analyze_fuses_real_captures(tmp_path, capsys):
    cy = tmp_path / "s.cypher"
    rc = main(["analyze", str(FX / "log4shell_sysmon.json"), str(FX / "log4shell_auoms.json"),
               "--cypher", str(cy)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "192.168.2.6:1389" in out and "java" in cy.read_text()


def test_api_roundtrip():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from rootline.api import create_app
    c = TestClient(create_app([str(FX / "sysmon_t1548_find.log")]), base_url="http://127.0.0.1",
                   headers={"X-Rootline": "1"})
    assert c.get("/api/health").json()["status"] == "ok"
    assert "ROOTLINE" in c.get("/").text
    [pre] = c.get("/api/stories").json()
    assert pre["alerts"] >= 1
    s = c.post("/api/demo", params={"benign": 60}).json()
    full = c.get(f"/api/stories/{s['id']}").json()
    assert full["story"]["schema"] == "rootline.story/v1"
    assert c.get(f"/api/stories/{s['id']}/stix").json()["type"] == "bundle"
    assert c.get(f"/api/stories/{s['id']}/mermaid").text.startswith("flowchart")
    assert "MERGE" in c.get(f"/api/stories/{s['id']}/cypher").text
    up = c.post("/api/analyze", params={"name": "l4s"},
                content=(FX / "log4shell_sysmon.json").read_bytes()).json()
    assert up["alerts"] >= 1 and up["story_vertices"] > 0
    assert c.post("/api/analyze", content=b"   ").status_code == 400
    assert c.post("/api/analyze", params={"format": "nope"}, content=b"x").status_code == 400
    assert c.post("/api/analyze", content=b"garbage\n").status_code == 422
    assert c.get("/api/stories/nope").status_code == 404


def test_static_demo_build(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_demo", Path(__file__).parent.parent / "scripts" / "build_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    names = mod.build(tmp_path)
    assert len(names) == 2
    assert 'data-static="1"' in (tmp_path / "index.html").read_text(encoding="utf-8")
    stories = json.loads((tmp_path / "api" / "stories.json").read_text(encoding="utf-8"))
    for s in stories:
        assert (tmp_path / "api" / "stories" / f"{s['id']}.json").exists()
