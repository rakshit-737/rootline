"""ATLAS (USENIX Security '21) pre-processed audit logs -> raw records + truth.

The ATLAS artefact (github.com/purseclab/ATLAS, Apache-2.0) ships, for each
attack scenario, a pre-processed CSV built from Windows Security Auditing,
DNS (Wireshark) and Firefox logs. Every line ends with a label suffix:
``-LA`` (audit), ``-LB`` (browser), ``-LD`` (DNS) followed by ``+`` (line
matches a ground-truth attack entity) or ``-``. Columns (0-based)::

    0 ts   1 dns_domain  2 dns_ip  3 pid  4 ppid  5 process_image
    6 src_ip  7 src_port  8 dst_ip  9 dst_port  10-16 browser fields
    17 file_access (e.g. file_readdata_..., file_writedata_...)  18 object path

Mapping to ROOTLINE:

* first sighting of (pid, image) -> ``fork`` from ppid + ``exec`` of image;
* ``readdata``/``execute`` -> ``read`` (module/image load is information
  flowing *into* the process), ``writedata``/``appenddata`` -> ``write``,
  ``delete`` -> ``unlink``;
* a flow whose src is the host IP -> ``connect`` to dst; whose dst is the
  host IP -> ``accept`` from src (socket keyed by remote IP + service port);
* DNS rows -> ``dns`` (domain -> IP), so sockets carry their domain names.

Browser (-LB) rows carry no pid and are dropped: ROOTLINE is a syscall-level
engine. That means ATLAS' *web-object* ground-truth entities (e.g.
``aalsahee/index.html``) are out of scope, and are reported as such.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterator

_VOL = re.compile(r"^/device/harddiskvolume\d+")


def _image(p: str) -> str:
    return _VOL.sub("c:", p.strip().lower().replace("\\", "/"))


@dataclass
class AtlasScenario:
    name: str
    log_path: str
    host_ip: str
    attacker_ips: list[str]
    labels: list[str]            # malicious_labels.txt (entity ground truth)
    artifacts: list[str] = field(default_factory=list)  # user_artifact.txt: the analyst's starting IOC
    records: list[dict[str, Any]] = field(default_factory=list)
    dropped: dict[str, int] = field(default_factory=dict)

    @property
    def host_labels(self) -> list[str]:
        """Ground-truth entities a host-level engine can observe (no web objects)."""
        return [lab for lab in self.labels if "/" not in lab]


def parse_lines(lines: Iterator[str], host_ip: str, host: str = "atlas") -> tuple[list[dict[str, Any]], dict[str, int]]:
    recs: list[dict[str, Any]] = []
    dropped = {"browser": 0, "no_pid": 0, "short": 0, "other_flow": 0}
    seen: dict[str, str] = {}  # pid -> image currently running there
    for raw in lines:
        raw = raw.rstrip("\n")
        if not raw.strip():
            continue
        lab_m = re.search(r"-L([ABD])([+-])$", raw)
        if not lab_m:
            dropped["short"] += 1
            continue
        src, plus = lab_m.group(1), lab_m.group(2) == "+"
        body = raw[: lab_m.start()]
        f = body.split(",")
        if len(f) < 19:
            dropped["short"] += 1
            continue
        try:
            ts = float(f[0])
        except ValueError:
            dropped["short"] += 1
            continue
        label = {"label": "attack"} if plus else {}
        if f[1] and f[2]:
            recs.append({"ts": ts, "host": host, "kind": "dns", "pid": 0, "domain": f[1].strip().lower(),
                         "dst_ip": f[2].strip(), **label})
            continue
        if src == "B":
            dropped["browser"] += 1
            continue
        pid_s, ppid_s, img = f[3].strip(), f[4].strip(), _image(f[5])
        if not pid_s.isdigit() or pid_s == "0" or not img or img == "-":
            dropped["no_pid"] += 1
            continue
        pid = int(pid_s)
        ppid = int(ppid_s) if ppid_s.isdigit() else 0
        comm = img.rsplit("/", 1)[-1]
        base = {"ts": ts, "host": host, "pid": pid, "ppid": ppid, "comm": comm, "exe": img, **label}
        if seen.get(pid_s) != img:
            seen[pid_s] = img
            if ppid:
                recs.append({"ts": ts, "host": host, "kind": "fork", "pid": ppid, "child_pid": pid,
                             "comm": seen.get(ppid_s, "").rsplit("/", 1)[-1], "exe": seen.get(ppid_s, ""), **label})
            recs.append({**base, "kind": "exec", "path": img})
        if f[8].strip():
            sip, dip, dport = f[6].strip(), f[8].strip(), f[9].strip()
            if sip == host_ip:
                recs.append({**base, "kind": "connect", "dst_ip": dip, "dst_port": int(dport or 0)})
            elif dip == host_ip:
                recs.append({**base, "kind": "accept", "dst_ip": sip, "dst_port": int(dport or 0)})
            else:
                dropped["other_flow"] += 1
        acc, obj = f[17].strip(), _image(f[18]) if len(f) > 18 else ""
        if acc.startswith("file_") and obj:
            if "writedata" in acc or "appenddata" in acc:
                recs.append({**base, "kind": "write", "path": obj})
            if "readdata" in acc or "execute" in acc:
                recs.append({**base, "kind": "read", "path": obj})
            if "delete" in acc and "delete_child" not in acc:
                recs.append({**base, "kind": "unlink", "path": obj})
    recs.sort(key=lambda r: r["ts"])
    return recs, dropped


def _read_list(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [ln.strip().lower() for ln in fh if ln.strip()]


def load_scenario(exp_dir: str, scenario: str) -> AtlasScenario:
    """``exp_dir`` = an extracted ``paper_experiments/<X>`` folder; ``scenario``
    e.g. ``S1-CVE-2015-5122_windows`` (looked up under testing_ and training_)."""
    for phase in ("testing", "training"):
        meta = os.path.join(exp_dir, f"{phase}_logs", scenario)
        log = os.path.join(exp_dir, "output", f"{phase}_preprocessed_logs_{scenario}")
        if os.path.exists(log):
            break
    else:
        raise FileNotFoundError(f"no preprocessed log for {scenario} in {exp_dir}")
    ips = _read_list(os.path.join(meta, "ips.txt"))
    labels = _read_list(os.path.join(meta, "malicious_labels.txt"))
    host_ip = ips[0] if ips else ""
    artifacts = _read_list(os.path.join(meta, "user_artifact.txt"))
    sc = AtlasScenario(scenario, log, host_ip, ips[1:], labels, artifacts)
    with open(log, encoding="utf-8", errors="replace") as fh:
        sc.records, sc.dropped = parse_lines(fh, host_ip, host=scenario.split("-")[0].lower())
    return sc


def discover(root: str) -> list[tuple[str, str]]:
    """Find (exp_dir, scenario) pairs under an ATLAS download root, deduplicated
    by scenario name (the same scenario is bundled in several experiment zips)."""
    found: dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            m = re.match(r"(?:testing|training)_preprocessed_logs_(.+)$", fn)
            if m and os.path.basename(dirpath) == "output":
                found.setdefault(m.group(1), os.path.dirname(dirpath))
    return sorted((d, s) for s, d in found.items())


def entity_matches(node_label: str, attrs: dict[str, Any], lab: str) -> bool:
    """Does a ROOTLINE vertex correspond to an ATLAS ground-truth entity?"""
    path = str(attrs.get("path") or attrs.get("exe") or "")
    if "ip" in attrs:
        return attrs["ip"] == lab or lab in attrs.get("domains", [])
    return bool(path) and (path == lab or path.endswith("/" + lab))
