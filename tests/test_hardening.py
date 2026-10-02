"""Regression tests for untrusted-input handling (exporters, parsers, API, CLI)."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from rootline.cli import main as cli
from rootline.export import _cy, to_cypher, to_mermaid
from rootline.loaders.sysmon import _xml_from_line
from rootline.normalize import NormalizationError, normalize_record, parse_bpftrace_line, read_jsonl
from rootline.pipeline import analyze

EVIL = "/tmp/update\nMATCH (n) DETACH DELETE n;"


def _chain(path: str) -> list[dict]:
    return [
        {"ts": 1, "kind": "connect", "pid": 10, "ppid": 1, "comm": "curl", "dst_ip": "203.0.113.5", "dst_port": 80},
        {"ts": 2, "kind": "write", "pid": 10, "ppid": 1, "comm": "curl", "path": path},
        {"ts": 3, "kind": "fork", "pid": 1, "ppid": 0, "comm": "bash", "child_pid": 11},
        {"ts": 4, "kind": "exec", "pid": 11, "ppid": 1, "comm": "sh", "path": path},
    ]


def test_cypher_and_mermaid_escape_control_chars_and_quotes():
    a = analyze(_chain(EVIL))
    assert a.reconstruction is not None
    cy = to_cypher(a.graph, a.reconstruction)
    assert not any(line.startswith("MATCH (n) DETACH") for line in cy.splitlines())
    assert "// root causes" not in cy
    mm = to_mermaid(a.graph, a.reconstruction)
    assert all(line.startswith(("flowchart", "  ")) for line in mm.splitlines())
    assert _cy("a\nb'c") == "'a\\u000ab\\'c'"
    assert _cy(float("inf")) == "null"


def test_normalizer_makes_control_chars_visible_and_rejects_bad_ts():
    ev = normalize_record({"ts": 1, "kind": "write", "pid": 1, "path": EVIL}, 0)
    assert "\n" not in ev.path and "\\x0a" in ev.path
    for ts in (float("inf"), float("nan"), -1, 1e300):
        with pytest.raises(NormalizationError):
            normalize_record({"ts": ts, "kind": "exit", "pid": 1}, 0)


def test_strict_probe_records_resist_injected_tokens():
    def j(data: str) -> str:
        return json.dumps({"type": "printf", "data": data + "\n"})
    r = parse_bpftrace_line(j("tsns=5 kind=execve pid=7 ppid=1 uid=0 path=/home/u/My Docs/a b.sh comm=sh"))
    assert r["kind"] == "execve" and r["path"] == "/home/u/My Docs/a b.sh" and r["pid"] == "7"
    # a hostile comm / path cannot change kind or pid
    r = parse_bpftrace_line(j("tsns=5 kind=execve pid=7 ppid=1 uid=0 path=/tmp/x kind=exit pid=1 comm=x"))
    assert r["kind"] == "execve" and r["pid"] == "7"
    r = parse_bpftrace_line(j("tsns=5 kind=fork pid=7 ppid=1 uid=0 child_pid=9 comm=a pid=1 c=4"))
    assert r["pid"] == "7" and r["child_pid"] == "9" and r["comm"] == "a pid=1 c=4"
    with pytest.raises(ValueError):  # longer than a kernel comm can be
        parse_bpftrace_line(j("tsns=5 kind=fork pid=7 ppid=1 uid=0 child_pid=9 comm=a pid=1 child_pid=4243"))
    with pytest.raises(ValueError):
        parse_bpftrace_line(j("tsns=x kind=exit pid=1 ppid=0 uid=0 comm=a"))
    assert parse_bpftrace_line(json.dumps({"type": "attached_probes", "data": {"probes": 3}})) == {}


def test_malformed_lines_are_rejected_not_crashing(tmp_path: Path):
    f = tmp_path / "bad.log"
    f.write_text("ts=abc kind=exit pid=1\ntsns=1e3 kind=exit pid=1\n" + '{"a": ' + "[" * 100000 + "\n", encoding="utf-8")
    recs = list(read_jsonl(str(f)))
    assert len(recs) == 3 and all("_invalid" in r for r in recs)


def test_sysmon_event_scan_is_linear():
    line = "May 13 host sysmon: " + "<Event " * 40000  # ~280 KB, no closing tag
    t = time.perf_counter()
    assert _xml_from_line(line) is None
    assert time.perf_counter() - t < 1.0


def test_verify_refuses_zero_events(tmp_path: Path, capsys):
    f = tmp_path / "empty.log"
    f.write_text("\n", encoding="utf-8")
    assert cli(["verify", str(f)]) == 1
    assert cli(["verify", str(tmp_path / "missing.log")]) == 1
    assert "error" in capsys.readouterr().err


def test_api_guards():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from rootline.api import create_app
    app = create_app(max_body=1000, max_stories=2)
    ok = TestClient(app, base_url="http://127.0.0.1", headers={"X-Rootline": "1"})
    # DNS rebinding: a foreign Host header is refused
    assert TestClient(app, base_url="http://attacker.example").get("/api/stories").status_code == 400
    # cross-site simple POST (no custom header) is refused
    assert TestClient(app, base_url="http://127.0.0.1").post("/api/demo").status_code == 403
    assert ok.post("/api/analyze", content=b"x" * 2000).status_code == 413
    for _ in range(3):
        assert ok.post("/api/demo", params={"benign": 10}).status_code == 200
    assert len(ok.get("/api/stories").json()) == 2  # bounded store
    assert ok.get("/docs").status_code == 404
    assert ok.post("/api/analyze", content=b"ts=inf kind=exit pid=1\n").status_code == 422
