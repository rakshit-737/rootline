"""Frozen contracts / typed models for ROOTLINE.

All data flowing between stages uses these types. Keep them stable: the
normalizer, graph, detectors, reconstructor and exporters depend on them.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class EventKind(str, Enum):
    FORK = "fork"
    EXEC = "exec"
    OPEN = "open"      # open for read unless flags say write
    READ = "read"
    WRITE = "write"
    CONNECT = "connect"
    ACCEPT = "accept"
    UNLINK = "unlink"
    EXIT = "exit"


class NodeType(str, Enum):
    PROCESS = "process"
    FILE = "file"
    SOCKET = "socket"


class Relation(str, Enum):
    FORKED = "forked"        # parent proc -> child proc
    EXECUTED = "executed"    # binary file -> proc (image load)
    READ = "read"            # file -> proc
    WROTE = "wrote"          # proc -> file
    CONNECTED = "connected"  # proc -> socket
    RECEIVED = "received"    # socket -> proc (data flow back in)
    DELETED = "deleted"      # proc -> file


@dataclass(frozen=True)
class Event:
    """A normalized kernel-level event (one syscall of interest)."""
    seq: int
    ts: float
    host: str
    kind: EventKind
    pid: int
    ppid: int = 0
    uid: int = 0
    comm: str = ""
    exe: str = ""
    path: str | None = None
    child_pid: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    argv: tuple[str, ...] = ()
    sha256: str | None = None
    label: str | None = None  # ground truth (synthetic/datasets only)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["argv"] = list(self.argv)
        return {k: v for k, v in d.items() if v not in (None, (), [])}


@dataclass
class Node:
    id: str
    type: NodeType
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)
    first_ts: float = 0.0


@dataclass
class Edge:
    src: str
    dst: str
    rel: Relation
    ts: float
    seq: int
    count: int = 1
    last_ts: float | None = None

    @property
    def end_ts(self) -> float:
        return self.last_ts if self.last_ts is not None else self.ts


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    rule_id: str
    node_id: str
    ts: float
    severity: Severity
    description: str
    attack_technique: str | None = None  # MITRE ATT&CK id
    kill_chain: str | None = None
    score: float = 1.0
    evidence: list[int] = field(default_factory=list)  # event seqs

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Reconstruction:
    alert: Alert
    root_causes: list[str]
    backward: set[str]
    forward: set[str]
    edges: list[Edge]
    timeline: list[dict[str, Any]]
    iocs: dict[str, list[str]]
    kill_chain: dict[str, list[str]]
    accessed: set[str] = field(default_factory=set)  # read by forward procs (e.g. creds)

    @property
    def nodes(self) -> set[str]:
        return self.backward | self.forward | self.accessed
