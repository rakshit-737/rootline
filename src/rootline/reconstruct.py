"""Backward root-cause + forward blast-radius reconstruction.

Traversal is *time-respecting*: walking backward from a vertex observed at
time t only follows in-edges that happened at or before t (information cannot
flow from the future), and forward traversal only follows out-edges at or
after the time influence arrived. This is the standard trick (King & Chen,
"Backtracking Intrusions", SOSP'03) that keeps the dependency explosion in
check. Pure graph traversal - no ML - so every step is explainable.
"""
from __future__ import annotations

import heapq
import ipaddress
import re
from collections import defaultdict

from .detect import comm
from .graph import ProvenanceGraph
from .models import Alert, Edge, NodeType, Reconstruction, Relation

# processes at which backward expansion stops (session roots, not causes)
STOP_COMMS = {"systemd", "init", "sshd", "gnome-session", "gdm", "lightdm", "cron", "kthreadd", "login",
              # Windows session/service roots (ATLAS traces are Windows audit logs)
              "services.exe", "wininit.exe", "winlogon.exe", "smss.exe", "csrss.exe", "explorer.exe",
              "svchost.exe", "lsass.exe", "system"}
ENTRY_EXT = re.compile(r"\.(docm?|xlsm?|pptm?|pdf|rtf|odt|zip|rar|7z|iso|lnk|js|hta|jar|sh|py|elf|bin|deb)$", re.I)
USER_DIRS = re.compile(r"^/(home/[^/]+|root)/(Downloads|Desktop|Documents|tmp)/|^/tmp/|"
                       r"^c:/users/[^/]+/(downloads|desktop|documents|appdata/local/temp)/", re.I)
SYSTEM_PATHS = re.compile(r"^/(usr|bin|sbin|lib|etc|opt|proc|sys)/|^/dev/(null|zero|u?random|full|tty\w*|ptmx|pts/)|"
                          r"^c:/(windows|program files|programdata)/", re.I)
APP_STATE = re.compile(r"/(\.mozilla|\.config|\.cache)/|/appdata/(roaming|locallow)/|/appdata/local/(?!temp/)", re.I)

NON_IOC_PATHS = re.compile(r"^/(dev|proc|sys|run)/")


def is_local_ip(ip: str) -> bool:
    """Loopback, unspecified or link-local (IPv4, IPv6 and IPv4-mapped IPv6): never an external IOC."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return a.is_loopback or a.is_unspecified or a.is_link_local


STAGE_ORDER = ["initial-access", "delivery", "execution", "persistence", "privilege-escalation",
               "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection",
               "command-and-control", "exfiltration", "impact"]


def backward(g: ProvenanceGraph, start: str, t: float, max_nodes: int = 5000,
             stop: frozenset[str] | set[str] | None = None, timed: bool = True) -> tuple[set[str], list[Edge]]:
    """Time-respecting ancestors of ``start`` as of time ``t``.

    Session/service roots in ``stop`` (default :data:`STOP_COMMS`) are not expanded.
    ``timed=False`` ignores time (plain reachability); it exists for the ablation study.
    """
    stop = STOP_COMMS if stop is None else stop
    if not timed:
        t = float("inf")
    best: dict[str, float] = {start: t}
    heap = [(-t, start)]
    edges: list[Edge] = []
    while heap and len(best) < max_nodes:
        nt, nid = heapq.heappop(heap)
        bound = -nt
        if bound < best.get(nid, float("-inf")):
            continue
        n = g.nodes[nid]
        if nid != start and n.type is NodeType.PROCESS and comm(g, nid) in stop:
            continue
        for e in g.in_edges.get(nid, []):
            if e.ts > bound:
                continue
            edges.append(e)
            nb = min(bound, e.end_ts) if timed else bound
            if nb > best.get(e.src, float("-inf")):
                best[e.src] = nb
                heapq.heappush(heap, (-nb, e.src))
    return set(best), edges


def forward(g: ProvenanceGraph, start: str, t: float, max_nodes: int = 5000,
            stop: frozenset[str] | set[str] | None = None, timed: bool = True) -> tuple[set[str], list[Edge]]:
    """Time-respecting descendants of ``start``. Session/service roots in ``stop``
    (default :data:`STOP_COMMS`) are included but not expanded: a system service
    that merely *touched* a malicious file (indexer, AV, crash reporter) must not
    pull its entire lifetime into the blast radius."""
    stop = STOP_COMMS if stop is None else stop
    if not timed:
        t = float("-inf")
    best: dict[str, float] = {start: t}
    heap = [(t, start)]
    edges: list[Edge] = []
    while heap and len(best) < max_nodes:
        bound, nid = heapq.heappop(heap)
        if bound > best.get(nid, float("inf")):
            continue
        if nid != start and g.nodes[nid].type is NodeType.PROCESS and comm(g, nid) in stop:
            continue
        for e in g.out_edges.get(nid, []):
            if e.end_ts < bound:
                continue
            if e.rel is Relation.RECEIVED and nid != start:  # don't infect the remote peer's other clients
                continue
            edges.append(e)
            nb = max(bound, e.ts) if timed else bound
            if nb < best.get(e.dst, float("inf")):
                best[e.dst] = nb
                heapq.heappush(heap, (nb, e.dst))
    return set(best), edges


def score_entry(g: ProvenanceGraph, nid: str) -> float:
    """Heuristic entry-point score of a file or socket vertex (higher = more likely an attack entry)."""
    n = g.nodes[nid]
    if n.type is NodeType.SOCKET:
        ip = n.attrs.get("ip", "")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return 1.0
        return 0.0 if is_local_ip(ip) else 2.0
    if n.type is NodeType.FILE:
        path = n.attrs.get("path", "")
        s = 0.0
        if ENTRY_EXT.search(path):
            s += 3
        if USER_DIRS.search(path):
            s += 2
        if SYSTEM_PATHS.search(path):
            s -= 5
        if APP_STATE.search(path):  # browser profiles / app caches: churn, not entry points
            s -= 4
        # written by a process that received network data -> downloaded artifact
        for e in g.in_edges.get(nid, []):
            if e.rel is Relation.WROTE and any(i.rel is Relation.RECEIVED for i in g.in_edges.get(e.src, [])):
                s += 1
                break
        return s
    return -1.0


def root_causes(g: ProvenanceGraph, back: set[str], back_edges: list[Edge], k: int = 3,
                t: float = float("inf")) -> list[str]:
    """Rank candidate entry points: files/sockets in the backward slice.

    A candidate must have fed information into the slice strictly *before* the
    pivot time ``t``: a C2 socket the pivot process itself opened is an effect
    of the intrusion, not its cause."""
    # an image executed exactly at the pivot time is still its cause (pivot = exec alert)
    fed = {e.src for e in back_edges if e.ts < t or (e.rel is Relation.EXECUTED and e.ts <= t)}
    cands = [n for n in back if g.nodes[n].type is not NodeType.PROCESS and n in fed]
    scored = sorted(((score_entry(g, n), g.nodes[n].first_ts, n) for n in cands), reverse=True)
    return [n for s, _, n in scored if s > 0][:k]  # ties: most recent first


def _describe(g: ProvenanceGraph, e: Edge) -> str:
    s, d = g.nodes[e.src].label, g.nodes[e.dst].label
    verb = {Relation.FORKED: "spawned", Relation.EXECUTED: "was executed as", Relation.READ: "was read by",
            Relation.WROTE: "wrote", Relation.CONNECTED: "connected to", Relation.RECEIVED: "sent data to",
            Relation.DELETED: "deleted"}[e.rel]
    x = f" (x{e.count})" if e.count > 1 else ""
    return f"{s} {verb} {d}{x}"


def contact_window(g: ProvenanceGraph, nid: str) -> tuple[float, float]:
    """First and last time anything flowed into or out of a vertex."""
    touching = g.in_edges.get(nid, []) + g.out_edges.get(nid, [])
    if not touching:
        return g.nodes[nid].first_ts, g.nodes[nid].first_ts
    return min(e.ts for e in touching), max(e.end_ts for e in touching)


def reconstruct(g: ProvenanceGraph, alert: Alert, alerts: list[Alert] | None = None,
                seeds: list[tuple[str, float, float]] | None = None, *, timed: bool = True,
                stops: bool = True, spine: bool = True, accessed: bool = True) -> Reconstruction:
    """Reconstruct around ``alert`` (backward from, and forward after, alert.ts).

    ``seeds`` = extra ``(vertex, t_backward, t_forward)`` pivots traced together
    with the alert - used for IOC pivots, where an attacker IP maps to several
    socket vertices and influence starts at first contact, not last.

    The keyword switches turn off one component each, for the ablation study
    (``rootline.ablation``): ``timed`` (time-respecting traversal), ``stops``
    (session-root stops), ``spine`` (causal-spine trimming of the backward slice)
    and ``accessed`` (data read by intrusion-created processes and executed images).
    """
    stop_set = STOP_COMMS if stops else frozenset()
    seeds = seeds or [(alert.node_id, alert.ts, alert.ts)]
    back: set[str] = set()
    bedges: list[Edge] = []
    fwd: set[str] = set()
    for nid, tb, _ in seeds:
        b, be = backward(g, nid, tb, stop=stop_set, timed=timed)
        back |= b
        bedges += be
    t0 = min(tf for _, _, tf in seeds)
    rc = root_causes(g, back, bedges, t=max(tb for _, tb, _ in seeds) if len(seeds) > 1 else alert.ts)
    # keep only the causal spine: backward nodes that can reach a pivot from a root cause
    if rc and spine:
        spine_set: set[str] = set()
        for r in rc:
            f, _ = forward(g, r, g.nodes[r].first_ts, stop=stop_set, timed=timed)
            spine_set |= f & back
        back = spine_set | {nid for nid, _, _ in seeds}
    for nid, _, tf in seeds:
        f, _ = forward(g, nid, tf, stop=stop_set, timed=timed)
        fwd |= f
    acc: set[str] = set()
    for p in fwd if accessed else ():
        # "accessed" (e.g. credentials read) only for processes the intrusion created;
        # a long-lived process that was merely tainted (a browser) reads its whole cache
        if g.nodes[p].type is NodeType.PROCESS and g.nodes[p].first_ts >= t0:
            for e in g.in_edges.get(p, []):
                if e.rel is Relation.READ and e.ts >= t0:
                    acc.add(e.src)
    for p in back | fwd if accessed else ():  # binary images that story processes were executed from
        for e in g.in_edges.get(p, []):
            if e.rel is Relation.EXECUTED:
                acc.add(e.src)
    acc -= back | fwd
    nodes = back | fwd | acc
    edges = sorted({id(e): e for e in g.edges if e.src in nodes and e.dst in nodes
                    and (e.src in back and e.dst in back or e.ts >= t0 or e.dst == alert.node_id
                         or e.rel is Relation.EXECUTED)}.values(),
                   key=lambda e: (e.ts, e.seq))

    alerts = alerts or [alert]
    by_seq: dict[int, list[Alert]] = defaultdict(list)
    for a in alerts:
        for s in a.evidence:
            by_seq[s].append(a)
    kill_chain: dict[str, list[str]] = defaultdict(list)
    for r in rc:
        kill_chain["initial-access"].append(g.nodes[r].label)
    timeline = []
    for e in edges:
        stage = next((a.kill_chain for a in by_seq.get(e.seq, []) if a.kill_chain), None)
        if stage:
            kill_chain[stage].append(_describe(g, e))
        timeline.append({"ts": e.ts, "seq": e.seq, "rel": e.rel.value, "src": e.src, "dst": e.dst,
                         "text": _describe(g, e), "stage": stage,
                         "alerts": [a.rule_id for a in by_seq.get(e.seq, [])]})

    # "ip" holds every external address; "ipv4"/"ipv6" split it by family (schema v1 kept "ipv4")
    iocs: dict[str, list[str]] = {"ip": [], "ipv4": [], "ipv6": [], "files": [], "sha256": []}
    for nid in sorted(nodes):
        n = g.nodes[nid]
        if n.type is NodeType.SOCKET and not is_local_ip(n.attrs.get("ip", "")):
            if nid in fwd or nid in rc or any(e.dst == nid for e in edges if e.src in fwd):
                ip = n.attrs["ip"]
                iocs["ip"].append(ip)
                iocs["ipv6" if ":" in ip else "ipv4"].append(ip)
        elif n.type is NodeType.FILE:
            if NON_IOC_PATHS.search(n.label):  # pseudo-files (/dev/null, /proc/...) are sinks, not indicators
                continue
            wrote_by_attack = any(e.rel in (Relation.WROTE, Relation.DELETED) and e.src in fwd
                                  for e in g.in_edges.get(nid, []))
            if nid in rc or wrote_by_attack or (nid in back and ENTRY_EXT.search(n.label)):
                iocs["files"].append(n.label)
            if n.attrs.get("sha256"):
                iocs["sha256"].append(n.attrs["sha256"])
    iocs = {k: sorted(set(v)) for k, v in iocs.items()}
    ordered_kc = {s: kill_chain[s] for s in STAGE_ORDER if s in kill_chain}
    return Reconstruction(alert, rc, back, fwd, edges, timeline, iocs, ordered_kc, acc)
