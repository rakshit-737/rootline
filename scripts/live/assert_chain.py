#!/usr/bin/env python3
"""Assert that ROOTLINE recovers the scripted live chain from a real bpftrace capture.

    python scripts/live/assert_chain.py live-out/capture.jsonl --out live-out/result.json \\
        --probe-pid "$(cat live-out/probe.pid)" --chain live-out/chain.json

Checks (each recorded in the JSON artefact; exit 1 if any fails):
  probe        - the probe emitted fork/execve/openat/write/connect/exit records
  self_pid     - no record carries the probe's own PID, and the decoy process that
                 renamed itself "bpftrace" WAS captured (filtering is by PID, not name)
  fork_parents - every fork parent is a process (TGID) seen elsewhere in the capture
  fd_to_path   - write() records carry the path of the fd (curl's download, the unit file)
  ipv6         - the IPv6 connect to [::1]:4445 was captured with its address
  chain        - ONE backward/forward query from the stage process finds the download
                 socket as a root cause, and the story holds curl, the dropped script,
                 the credential read, the unit and cron-style writes and the listener
  alerts       - exec-from-/tmp, credential read, persistence and log-deletion rules fire
  no_lost      - bpftrace reported no lost events

Captures from the v1.0/v1.1 probe (plain key=value lines, 127.0.0.1 server, no decoy)
are checked with the older criteria: the story stops at the dropped script and a
second backward query from it finds the download.
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
from rootline.pipeline import analyze, build_graph  # noqa: E402
from rootline.reconstruct import backward, contact_window  # noqa: E402

STAGE = "/tmp/rootline-lab-stage.sh"
CREDS = "/.aws/credentials"
UNIT = "/.config/systemd/user/rootline-lab.service"
CRON = "/lab/cron.d/rootline-lab"


def parse(lines: list[str]) -> tuple[list[dict], dict]:
    recs, meta = [], {"lost_events": 0, "invalid": 0, "json": False}
    for ln in lines:
        ln = ln.strip()
        if ln.startswith("{"):
            meta["json"] = True
            try:
                obj = json.loads(ln)
                if obj.get("type") == "lost_events":
                    meta["lost_events"] += int((obj.get("data") or {}).get("events", 1))
                    continue
                r = parse_bpftrace_line(ln)
            except (ValueError, TypeError):
                meta["invalid"] += 1
                continue
            if r:
                recs.append(r)
        elif ln.startswith(("ts=", "tsns=")):
            recs.append(parse_bpftrace_line(ln))
        elif ln.startswith("Lost "):
            meta["lost_events"] += int(ln.split()[1]) if ln.split()[1].isdigit() else 1
    return recs, meta


def check_chain(lines: list[str], probe_pid: int | None = None, lab_ip: str = "198.51.100.7",
                decoy: str | None = None) -> dict:
    recs, meta = parse(lines)
    v12 = meta["json"]
    server = lab_ip if v12 else "127.0.0.1"
    kinds = Counter(r.get("kind") for r in recs)
    res: dict = {"format": "v1.2-json" if v12 else "legacy-kv", "lines": len(recs), "kinds": dict(kinds),
                 "lost_events": meta["lost_events"], "invalid_lines": meta["invalid"], "checks": {}}
    c = res["checks"]
    c["probe"] = all(kinds.get(k) for k in ("fork", "execve", "openat", "write", "connect", "exit"))
    if probe_pid is not None:
        decoy_seen = decoy is None or any(r.get("kind") == "execve" and r.get("path") == decoy for r in recs)
        c["self_pid"] = decoy_seen and not any(str(r.get("pid")) == str(probe_pid) for r in recs)
        res["decoy_captured"] = decoy_seen
    else:
        c["self_pid"] = not any(r.get("comm") == "bpftrace" for r in recs)
    if v12:
        known = {str(r.get("pid")) for r in recs if r.get("kind") != "fork"} | \
                {str(r.get("child_pid")) for r in recs if r.get("kind") == "fork"}
        parents = [str(r.get("pid")) for r in recs if r.get("kind") == "fork"]
        orphans = sorted({p for p in parents if p not in known})
        res["fork_parents_unseen"] = orphans
        c["fork_parents"] = not orphans
        c["no_lost"] = meta["lost_events"] == 0
    writes = [r for r in recs if r.get("kind") == "write"]
    c["fd_to_path"] = (any(r.get("path") == STAGE and r.get("comm") == "curl" for r in writes)
                       and any(str(r.get("path", "")).endswith(UNIT) for r in writes))
    c["ipv6"] = any(r.get("kind") == "connect" and r.get("dst_ip") == "::1" and str(r.get("dst_port")) == "4445"
                    for r in recs)

    if not any(r.get("kind") == "execve" and r.get("path") == STAGE for r in recs):
        c["chain"] = c["alerts"] = False
        res["error"] = "stage exec not captured"
        return res
    raw, _ = build_graph(recs)
    pivot = next(n.id for n in raw.nodes.values() if n.type is NodeType.PROCESS and n.attrs.get("exe") == STAGE)
    a = analyze(recs, alert_node=pivot)
    r = a.reconstruction
    g = a.graph
    labels = {g.nodes[n].label for n in r.nodes}
    roots = [g.nodes[n].label for n in r.root_causes]
    want = {
        "dropped_script_in_story": STAGE in labels,
        "credential_read": any(lab.endswith(CREDS) for lab in labels),
        "persistence_write": any(lab.endswith(UNIT) for lab in labels),
        "listener_connect": f"{server}:4444" in labels,
    }
    if v12:
        want["download_socket_is_root_cause"] = f"{server}:8081" in roots
        want["downloader_in_story"] = any(lab.startswith("curl[") for lab in labels)
        want["cron_style_write"] = any(lab.endswith(CRON) for lab in labels)
    else:  # legacy: loopback server scores 0 as an entry point; one more backward query from the script
        fid = next(n for n in g.nodes if g.nodes[n].label == STAGE)
        origin = {g.nodes[n].label for n in backward(g, fid, contact_window(g, fid)[1])[0]}
        want["dropped_script_is_root_cause"] = STAGE in roots
        want["downloader_is_origin_of_script"] = any(lab.startswith("curl[") for lab in origin)
        want["download_socket_is_origin_of_script"] = f"{server}:8081" in origin
    res["story"] = {**want, "ipv6_connect": "[::1]:4445" in labels or "::1:4445" in labels,
                    "vertices": len(r.nodes), "root_causes": roots, "labels": sorted(labels)}
    c["chain"] = all(want.values())
    rules = sorted({al.rule_id for al in a.alerts})
    res["alerts"] = rules
    need = {"RL-002", "RL-004", "RL-005"} | ({"RL-006"} if v12 else set())
    c["alerts"] = need <= set(rules)
    res["graph"] = a.raw.stats()
    res["_story_json"] = to_story(g, r)
    res["_mermaid"] = to_mermaid(g, r)
    return res


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("capture")
    p.add_argument("--out", default="result.json")
    p.add_argument("--probe-pid", type=int, help="bpftrace's own PID (live-out/probe.pid)")
    p.add_argument("--chain", help="live-out/chain.json written by run_chain.sh (lab IP, decoy path)")
    ns = p.parse_args(argv)
    lines = Path(ns.capture).read_text(encoding="utf-8", errors="replace").splitlines()
    meta = json.loads(Path(ns.chain).read_text()) if ns.chain else {}
    res = check_chain(lines, ns.probe_pid, meta.get("lab_ip", "198.51.100.7"), meta.get("decoy"))
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
