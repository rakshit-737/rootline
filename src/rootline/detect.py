"""Tagger: rule-based + anomaly-based suspicion over the provenance graph.

Rules are explainable, each mapped to a MITRE ATT&CK technique and a
kill-chain stage. The anomaly scorer is a deliberately simple, dependency-free
rare-transition model (parent image -> child image, image -> remote port)
learned from a benign baseline; it stands in for IsolationForest, which is a
documented TODO (see README).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .graph import ProvenanceGraph
from .models import Alert, Edge, NodeType, Relation, Severity

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "busybox"}
DOC_HANDLERS = {"soffice", "soffice.bin", "libreoffice", "evince", "okular", "thunderbird",
                "firefox", "chrome", "chromium", "acroread", "xdg-open"}
WRITABLE_DIRS = re.compile(r"^/(tmp|dev/shm|var/tmp|run/user)/")
SENSITIVE = re.compile(r"(^/etc/shadow$|^/etc/gshadow$|/\.ssh/id_[a-z0-9]+$|/\.aws/credentials$|"
                       r"/\.kube/config$|/\.docker/config\.json$|/\.gnupg/)")
CRED_READERS = {"sshd", "login", "passwd", "sudo", "su", "unix_chkpwd", "chpasswd", "ssh", "ssh-agent", "gpg-agent"}
PERSISTENCE = re.compile(r"(^/var/spool/cron/|^/etc/cron|^/etc/systemd/|/\.config/systemd/|/\.bashrc$|"
                         r"/\.profile$|/\.ssh/authorized_keys$|^/etc/rc\.local$|^/etc/ld\.so\.preload$)")
PERSIST_WRITERS = {"crontab", "systemctl", "dpkg", "apt", "rpm", "dnf", "vim", "nano"}
LOGS = re.compile(r"(^/var/log/|/\.bash_history$)")
LOG_WRITERS = {"logrotate", "rsyslogd", "systemd-journald", "journald", "syslog-ng"}


def comm(g: ProvenanceGraph, nid: str) -> str:
    a = g.nodes[nid].attrs
    c = a.get("comm") or ""
    return c or (a.get("exe") or "").rsplit("/", 1)[-1]


def ancestors(g: ProvenanceGraph, nid: str, max_depth: int = 6) -> list[str]:
    out, cur = [], nid
    for _ in range(max_depth):
        parents = [e.src for e in g.in_edges.get(cur, []) if e.rel is Relation.FORKED]
        if not parents:
            break
        cur = parents[0]
        out.append(cur)
    return out


def _alert(rule, nid, e: Edge, sev, desc, tech, stage, score=1.0) -> Alert:
    return Alert(rule, nid, e.ts, sev, desc, tech, stage, score, [e.seq])


# --------------------------------------------------------------------- rules
def r_doc_spawns_shell(g: ProvenanceGraph, e: Edge) -> Alert | None:
    if e.rel is not Relation.EXECUTED or g.nodes[e.dst].type is not NodeType.PROCESS:
        return None
    if comm(g, e.dst) not in SHELLS:
        return None
    for a in ancestors(g, e.dst):
        if comm(g, a) in DOC_HANDLERS:
            return _alert("RL-001", e.dst, e, Severity.HIGH,
                          f"document handler {comm(g, a)} spawned shell {comm(g, e.dst)}",
                          "T1204.002", "execution")
    return None


def r_exec_from_writable(g: ProvenanceGraph, e: Edge) -> Alert | None:
    if e.rel is Relation.EXECUTED and WRITABLE_DIRS.search(g.nodes[e.src].attrs.get("path", "")):
        return _alert("RL-002", e.dst, e, Severity.HIGH,
                      f"execution from world-writable path {g.nodes[e.src].label}", "T1059.004", "execution")
    return None


def r_suspicious_connect(g: ProvenanceGraph, e: Edge) -> Alert | None:
    if e.rel is not Relation.CONNECTED:
        return None
    ip = g.nodes[e.dst].attrs.get("ip", "")
    if ip.startswith("127.") or ip == "::1":
        return None
    a = g.nodes[e.src].attrs
    c = comm(g, e.src)
    if c in SHELLS or WRITABLE_DIRS.search(a.get("exe", "")):
        return _alert("RL-003", e.src, e, Severity.CRITICAL,
                      f"{c} opened outbound connection to {g.nodes[e.dst].label} (reverse shell / C2)",
                      "T1071", "command-and-control")
    return None


def r_cred_access(g: ProvenanceGraph, e: Edge) -> Alert | None:
    if e.rel is Relation.READ and SENSITIVE.search(g.nodes[e.src].attrs.get("path", "")) \
            and comm(g, e.dst) not in CRED_READERS:
        tech = "T1003.008" if "shadow" in g.nodes[e.src].label else "T1552.004"
        return _alert("RL-004", e.dst, e, Severity.HIGH,
                      f"{comm(g, e.dst)} read credential material {g.nodes[e.src].label}", tech, "credential-access")
    return None


def r_persistence(g: ProvenanceGraph, e: Edge) -> Alert | None:
    if e.rel is Relation.WROTE and PERSISTENCE.search(g.nodes[e.dst].attrs.get("path", "")) \
            and comm(g, e.src) not in PERSIST_WRITERS:
        tech = "T1053.003" if "cron" in g.nodes[e.dst].label else "T1546.004"
        return _alert("RL-005", e.src, e, Severity.HIGH,
                      f"{comm(g, e.src)} wrote persistence location {g.nodes[e.dst].label}", tech, "persistence")
    return None


def r_log_tamper(g: ProvenanceGraph, e: Edge) -> Alert | None:
    if e.rel is Relation.DELETED and LOGS.search(g.nodes[e.dst].attrs.get("path", "")) \
            and comm(g, e.src) not in LOG_WRITERS:
        return _alert("RL-006", e.src, e, Severity.CRITICAL,
                      f"{comm(g, e.src)} deleted log {g.nodes[e.dst].label}", "T1070.002", "defense-evasion")
    return None


def r_download(g: ProvenanceGraph, e: Edge) -> Alert | None:
    if e.rel is Relation.WROTE and comm(g, e.src) in {"curl", "wget"} \
            and WRITABLE_DIRS.search(g.nodes[e.dst].attrs.get("path", "")):
        return _alert("RL-007", e.src, e, Severity.MEDIUM,
                      f"{comm(g, e.src)} downloaded payload to {g.nodes[e.dst].label}", "T1105", "delivery", 0.6)
    return None


RULES: list[Callable[[ProvenanceGraph, Edge], Alert | None]] = [
    r_doc_spawns_shell, r_exec_from_writable, r_suspicious_connect, r_cred_access,
    r_persistence, r_log_tamper, r_download,
]


# ------------------------------------------------------------------- anomaly
@dataclass
class RareTransitionModel:
    """Counts benign (parent_image -> child_image) and (image -> port) transitions.

    ``score`` = -log((count + 1) / (total + V)) normalised to [0, 1];
    unseen transitions score highest. Explainable: the transition *is* the reason.
    """
    exec_pairs: Counter = field(default_factory=Counter)
    net_pairs: Counter = field(default_factory=Counter)
    threshold: float = 0.8

    def _pairs(self, g: ProvenanceGraph) -> Iterable[tuple[str, tuple[str, str], Edge]]:
        for e in g.edges:
            if e.rel is Relation.FORKED and g.nodes[e.dst].type is NodeType.PROCESS:
                p, c = comm(g, e.src), comm(g, e.dst)
                if p != c:  # exec transition
                    yield "exec", (p, c), e
            elif e.rel is Relation.CONNECTED:
                yield "net", (comm(g, e.src), str(g.nodes[e.dst].attrs.get("port"))), e

    def fit(self, g: ProvenanceGraph) -> "RareTransitionModel":
        for kind, pair, _ in self._pairs(g):
            (self.exec_pairs if kind == "exec" else self.net_pairs)[pair] += 1
        return self

    def score_pair(self, kind: str, pair: tuple[str, str]) -> float:
        c = self.exec_pairs if kind == "exec" else self.net_pairs
        total, v = sum(c.values()), len(c) + 1
        if total == 0:
            return 0.0
        p = (c[pair] + 0.01) / (total + 0.01 * v)
        worst = -math.log(0.01 / (total + 0.01 * v))
        return min(1.0, -math.log(p) / worst)

    def tag(self, g: ProvenanceGraph) -> list[Alert]:
        out = []
        for kind, pair, e in self._pairs(g):
            s = self.score_pair(kind, pair)
            if s >= self.threshold:
                nid = e.dst if kind == "exec" else e.src
                out.append(Alert("RL-A01" if kind == "exec" else "RL-A02", nid, e.ts, Severity.MEDIUM,
                                 f"rare {kind} transition {pair[0]} -> {pair[1]} (score {s:.2f})",
                                 None, None, s, [e.seq]))
        return out


def detect(g: ProvenanceGraph, model: RareTransitionModel | None = None) -> list[Alert]:
    alerts = [a for e in g.edges for r in RULES if (a := r(g, e)) is not None]
    if model is not None:
        alerts += model.tag(g)
    alerts.sort(key=lambda a: (a.ts, a.rule_id))
    return alerts


SEV_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def primary_alert(alerts: list[Alert]) -> Alert | None:
    """Highest severity, earliest first - the natural pivot for reconstruction."""
    if not alerts:
        return None
    return sorted(alerts, key=lambda a: (-SEV_RANK[a.severity], a.ts))[0]
