#!/usr/bin/env python3
"""Assert that ROOTLINE recovers the scripted live chain from a real bpftrace capture.

    python scripts/live/assert_chain.py live-out/capture.log --out live-out/result.json

Checks (each recorded in the JSON artefact; exit 1 if any fails):
  probe      - the probe emitted fork/execve/openat/write/connect/exit lines
  self_pid   - no line was emitted by or about bpftrace itself
  fd_to_path - write() lines carry the path of the fd (curl's download, the unit file)
  ipv6       - the IPv6 connect to [::1]:4445 was captured with its address
  chain      - pivoting on the stage process, the dropped script is the root cause, the
               story holds the credential read, the persistence write and the listener
               connection, and a backward query from the script reaches the downloader
               and the download socket
  alerts     - exec-from-/tmp, credential read and persistence rules fire on the live data
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from rootline.export import dumps, to_mermaid, to_story  # noqa: E402
from rootline.models import NodeType  # noqa: E402
from rootline.normalize import parse_bpftrace_line  # noqa: E402
from rootline.pipeline import analyze  # noqa: E402

STAGE = "/tmp/rootline-lab-stage.sh"
CREDS = "/.aws/credentials"
UNIT = "/.config/systemd/user/rootline-lab.service"


def check_chain(lines: list[str]) -> dict:
    recs = [parse_bpftrace_line(ln) for ln in lines if ln.startswith(("ts=", "tsns="))]
    kinds = Counter(r.get("kind") for r in recs)
    res: dict = {"lines": len(recs), "kinds": dict(kinds), "checks": {}}
    c = res["checks"]
    c["probe"] = all(kinds.get(k) for k in ("fork", "execve", "openat", "write", "connect", "exit"))
    c["self_pid"] = not any(r.get("comm") == "bpftrace" for r in recs)
    writes = [r for r in recs if r.get("kind") == "write"]
    c["fd_to_path"] = (any(r.get("path") == STAGE and r.get("comm") == "curl" for r in writes)
                       and any(str(r.get("path", "")).endswith(UNIT) for r in writes))
    c["ipv6"] = any(r.get("kind") == "connect" and r.get("dst_ip") == "::1" and r.get("dst_port") == "4445"
                    for r in recs)

    stage_recs = [r for r in recs if r.get("kind") == "execve" and r.get("path") == STAGE]
    if not stage_recs:
        c["chain"] = c["alerts"] = False
        res["error"] = "stage exec not captured"
        return res
    # the graph vertex created by that exec
    from rootline.pipeline import build_graph
    raw, _ = build_graph(recs)
    pivot = next(n.id for n in raw.nodes.values()
                 if n.type is NodeType.PROCESS and n.attrs.get("exe") == STAGE)
    a = analyze(recs, alert_node=pivot)
    r = a.reconstruction
    g = a.graph
    labels = {g.nodes[n].label for n in r.nodes}
    back = {g.nodes[n].label for n in r.backward}
    # loopback sockets never rank as root causes (score 0), so the story stops at the dropped
    # script; the analyst's next question - where did that file come from? - is one more
    # backward query from it
    from rootline.reconstruct import backward, contact_window
    fid = next(n for n in g.nodes if g.nodes[n].label == STAGE)
    origin = {g.nodes[n].label for n in backward(g, fid, contact_window(g, fid)[1])[0]}
    want = {
        "dropped_script_in_backward": STAGE in back,
        "dropped_script_is_root_cause": STAGE in {g.nodes[n].label for n in r.root_causes},
        "downloader_is_origin_of_script": any(lab.startswith("curl[") for lab in origin),
        "download_socket_is_origin_of_script": "127.0.0.1:8081" in origin,
        "credential_read": any(lab.endswith(CREDS) for lab in labels),
        "persistence_write": any(lab.endswith(UNIT) for lab in labels),
        "listener_connect": "127.0.0.1:4444" in labels,
        "ipv6_connect": "::1:4445" in labels,
    }
    res["story"] = {**want, "vertices": len(r.nodes), "root_causes": [g.nodes[n].label for n in r.root_causes],
                    "labels": sorted(labels)}
    c["chain"] = all(v for k, v in want.items() if k != "ipv6_connect")
    rules = sorted({al.rule_id for al in a.alerts})
    res["alerts"] = rules
    c["alerts"] = {"RL-002", "RL-004", "RL-005"} <= set(rules)
    res["graph"] = a.raw.stats()
    res["_story_json"] = to_story(g, r)
    res["_mermaid"] = to_mermaid(g, r)
    return res


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("capture")
    p.add_argument("--out", default="result.json")
    ns = p.parse_args(argv)
    lines = Path(ns.capture).read_text(encoding="utf-8", errors="replace").splitlines()
    res = check_chain(lines)
    out = Path(ns.out)
    story, mmd = res.pop("_story_json", None), res.pop("_mermaid", None)
    if story is not None:
        out.with_name("live_story.json").write_text(dumps(story), encoding="utf-8")
        out.with_name("live_story.mmd").write_text(mmd + "\n", encoding="utf-8")
    res["passed"] = all(res["checks"].values())
    out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "story"}, indent=1))
    if "story" in res:
        print("story:", json.dumps({k: v for k, v in res["story"].items() if k != "labels"}))
    return 0 if res["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
