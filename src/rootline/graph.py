"""Streaming, append-only provenance graph.

Vertices: processes (one vertex per process *image*: fork and exec each create
a new vertex so PID reuse and exec-chains stay distinguishable), files,
sockets. Edges point in the direction of information flow, so backward
traversal == "what could have influenced this", forward == "what did this
influence". Every ingested event extends a SHA-256 hash chain, giving a
tamper-evident, append-only record.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Iterable

from .models import Edge, Event, EventKind, Node, NodeType, Relation

GENESIS = "0" * 64


def chain_hash(prev: str, ev: Event) -> str:
    """Next hash-chain head: SHA-256 over the previous head and the event's canonical JSON."""
    payload = json.dumps(ev.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + payload).encode()).hexdigest()


class ProvenanceGraph:
    """Append-only provenance graph: one vertex per process image, file or socket, edges in the direction of information flow, every event extending a SHA-256 hash chain."""
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.out_edges: dict[str, list[Edge]] = defaultdict(list)
        self.in_edges: dict[str, list[Edge]] = defaultdict(list)
        self.events: list[Event] = []
        self.head: str = GENESIS
        self._proc: dict[tuple[str, int], str] = {}  # (host, pid) -> current proc vertex
        self.dns: dict[str, set[str]] = defaultdict(set)  # ip -> domains that resolved to it
        self._socks_by_ip: dict[str, list[str]] = defaultdict(list)
        self._last_ts = float("-inf")

    # ------------------------------------------------------------------ nodes
    def _node(self, nid: str, ntype: NodeType, label: str, ts: float, **attrs) -> Node:
        n = self.nodes.get(nid)
        if n is None:
            n = Node(nid, ntype, label, dict(attrs), ts)
            self.nodes[nid] = n
        else:
            for k, v in attrs.items():
                if v and not n.attrs.get(k):
                    n.attrs[k] = v
        return n

    def _new_proc(self, ev: Event, pid: int, comm: str, exe: str, uid: int, ppid: int) -> str:
        nid = f"proc:{ev.host}:{pid}:{ev.seq}"
        self._node(nid, NodeType.PROCESS, f"{comm or exe or '?'}[{pid}]", ev.ts,
                   pid=pid, ppid=ppid, comm=comm, exe=exe, uid=uid, host=ev.host)
        self._proc[(ev.host, pid)] = nid
        return nid

    def proc_of(self, ev: Event) -> str:
        """Current process-image vertex of ``pid`` on ``host`` (created on first sight)."""
        nid = self._proc.get((ev.host, ev.pid))
        if nid is None:  # first sighting of a pre-existing process
            nid = self._new_proc(ev, ev.pid, ev.comm, ev.exe, ev.uid, ev.ppid)
            parent = self._proc.get((ev.host, ev.ppid))
            if parent:
                self._edge(parent, nid, Relation.FORKED, ev)
        return nid

    def file_node(self, host: str, path: str, ts: float) -> str:
        """Vertex for a file path (one per host and path)."""
        nid = f"file:{host}:{path}"
        self._node(nid, NodeType.FILE, path, ts, path=path, host=host)
        return nid

    def sock_node(self, ip: str, port: int, ts: float) -> str:
        """Vertex for a remote endpoint ``ip:port``."""
        nid = f"sock:{ip}:{port}"
        if nid not in self.nodes:
            self._socks_by_ip[ip].append(nid)
        label = f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"
        self._node(nid, NodeType.SOCKET, label, ts, ip=ip, port=port)
        if ip in self.dns:
            self.nodes[nid].attrs["domains"] = sorted(self.dns[ip])
        return nid

    def _edge(self, src: str, dst: str, rel: Relation, ev: Event) -> Edge:
        e = Edge(src, dst, rel, ev.ts, ev.seq)
        self.edges.append(e)
        self.out_edges[src].append(e)
        self.in_edges[dst].append(e)
        return e

    # ----------------------------------------------------------------- ingest
    def add_event(self, ev: Event) -> None:
        """Add one normalised event: update vertices and edges and extend the hash chain."""
        if ev.ts < self._last_ts:
            raise ValueError("events must be ingested in timestamp order (append-only)")
        self._last_ts = ev.ts
        self.events.append(ev)
        self.head = chain_hash(self.head, ev)
        k = ev.kind
        if k is EventKind.FORK:
            parent = self.proc_of(ev)
            pa = self.nodes[parent].attrs
            child = self._new_proc(ev, ev.child_pid or 0, pa.get("comm", ""), pa.get("exe", ""), ev.uid, ev.pid)
            self._edge(parent, child, Relation.FORKED, ev)
        elif k is EventKind.EXEC:
            prev = self.proc_of(ev)
            assert ev.path is not None
            new = self._new_proc(ev, ev.pid, ev.comm or ev.path.rsplit("/", 1)[-1], ev.path, ev.uid,
                                 self.nodes[prev].attrs.get("ppid", ev.ppid))
            self.nodes[new].attrs["argv"] = " ".join(ev.argv)
            self._edge(prev, new, Relation.FORKED, ev)
            f = self.file_node(ev.host, ev.path, ev.ts)
            if ev.sha256:
                self.nodes[f].attrs["sha256"] = ev.sha256
            self._edge(f, new, Relation.EXECUTED, ev)
        elif k in (EventKind.OPEN, EventKind.READ):
            self._edge(self.file_node(ev.host, ev.path, ev.ts), self.proc_of(ev), Relation.READ, ev)
        elif k is EventKind.WRITE:
            f = self.file_node(ev.host, ev.path, ev.ts)
            if ev.sha256:
                self.nodes[f].attrs["sha256"] = ev.sha256
            self._edge(self.proc_of(ev), f, Relation.WROTE, ev)
        elif k is EventKind.UNLINK:
            f = self.file_node(ev.host, ev.path, ev.ts)
            self.nodes[f].attrs["deleted"] = True
            self._edge(self.proc_of(ev), f, Relation.DELETED, ev)
        elif k in (EventKind.CONNECT, EventKind.ACCEPT):
            p, s = self.proc_of(ev), self.sock_node(ev.dst_ip, ev.dst_port, ev.ts)
            self._edge(p, s, Relation.CONNECTED, ev)
            self._edge(s, p, Relation.RECEIVED, ev)
        elif k is EventKind.DNS:
            if ev.domain and ev.dst_ip:
                self.dns[ev.dst_ip].add(ev.domain)
                for nid in self._socks_by_ip.get(ev.dst_ip, []):
                    self.nodes[nid].attrs["domains"] = sorted(self.dns[ev.dst_ip])
        elif k is EventKind.EXIT:
            self.proc_of(ev)
            self._proc.pop((ev.host, ev.pid), None)

    def ingest(self, events: Iterable[Event]) -> "ProvenanceGraph":
        """Add events in order and return the graph (chainable)."""
        for ev in events:
            self.add_event(ev)
        return self

    # ------------------------------------------------------------------ misc
    def find(self, needle: str, ntype: NodeType | None = None) -> list[str]:
        """Vertex ids whose label or id contains ``needle`` (optionally of one type)."""
        return [n.id for n in self.nodes.values()
                if (ntype is None or n.type is ntype) and (needle in n.label or needle in n.id)]

    def stats(self) -> dict[str, int]:
        """Counts of events, vertices, edges and vertices per type."""
        by: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            by[n.type.value] += 1
        return {"events": len(self.events), "nodes": len(self.nodes), "edges": len(self.edges), **by}


def verify_chain(events: Iterable[Event], expected_head: str) -> bool:
    """True when replaying ``events`` reproduces ``head`` (any edit, drop or reorder breaks it)."""
    h = GENESIS
    for ev in events:
        h = chain_hash(h, ev)
    return h == expected_head
