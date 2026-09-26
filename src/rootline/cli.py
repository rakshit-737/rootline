"""ROOTLINE command line.

  rootline synth   --out events.jsonl [--benign 300] [--no-attack] [--seed 7]
  rootline analyze CAPTURE [CAPTURE ...] [--format auto|jsonl|sysmon|auditd]
                   [--baseline base.jsonl] [--pivot NODE|--ioc STR] [--iforest]
                   [--story out.json] [--stix out.json] [--mermaid out.mmd] [--cypher out.cypher]
                   [--no-reduce]
  rootline serve   [CAPTURE ...] [--fuse] [--host 127.0.0.1] [--port 8000]
  rootline verify  events.jsonl --head HASH
  rootline demo    [--outdir out]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import __version__
from .evaluate import evaluate
from .export import dumps, to_cypher, to_mermaid, to_stix, to_story
from .graph import ProvenanceGraph, verify_chain
from .loaders import FORMATS, load_many
from .normalize import Normalizer, read_jsonl
from .pipeline import Analysis, analyze
from .synth import generate, write_jsonl


def _write(path: str | None, text: str) -> None:
    if path:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)


def _print_analysis(a: Analysis) -> None:
    print(f"[+] graph: {a.raw.stats()}  (rejected records: {len(a.rejected)})")
    print(f"[+] reduction: {a.reduction.to_dict()}")
    print(f"[+] alerts: {len(a.alerts)}")
    for al in a.alerts[:15]:
        print(f"    {al.rule_id:7} {al.severity.value:8} {al.attack_technique or '-':10} {al.description}")
    r = a.reconstruction
    if r is None:
        print("[-] no alert to pivot on; graph looks clean")
        return
    g = a.graph
    print(f"\n[*] pivot: {r.alert.rule_id} on {g.nodes[r.alert.node_id].label}")
    print(f"[*] root cause(s): {[g.nodes[n].label for n in r.root_causes]}")
    print(f"[*] story: {len(r.nodes)} nodes / {len(r.edges)} edges "
          f"(backward {len(r.backward)}, forward {len(r.forward)}, accessed {len(r.accessed)})")
    print("[*] kill chain:")
    for stage, items in r.kill_chain.items():
        print(f"    {stage}: {items[0]}" + (f"  (+{len(items) - 1} more)" if len(items) > 1 else ""))
    print(f"[*] IOCs: {json.dumps(r.iocs)}")
    print(f"[*] integrity head: {g.head}")


def _resolve_pivot(records: list[dict[str, Any]], ioc: str) -> str:
    from .pipeline import build_graph
    g, _ = build_graph(records)
    hits = g.find(ioc)
    if not hits:
        raise SystemExit(f"IOC {ioc!r} matched no vertex")
    return hits[-1]


def cmd_synth(ns: argparse.Namespace) -> int:
    recs, truth = generate(ns.benign, attack=not ns.no_attack, seed=ns.seed)
    write_jsonl(recs, ns.out)
    if ns.truth:
        _write(ns.truth, json.dumps(truth, indent=2))
    print(f"wrote {len(recs)} synthetic events to {ns.out}")
    return 0


def cmd_analyze(ns: argparse.Namespace) -> int:
    recs = load_many(ns.events, ns.format)
    base = list(read_jsonl(ns.baseline)) if ns.baseline else None
    pivot = ns.pivot or (_resolve_pivot(recs, ns.ioc) if ns.ioc else None)
    a = analyze(recs, base, reduce=not ns.no_reduce, alert_node=pivot)
    _print_analysis(a)
    if ns.iforest:
        from .anomaly import IForestTagger
        print("[*] isolation-forest outliers (process vertices):")
        for nid, sc in IForestTagger().score(a.raw)[:10]:
            print(f"    {sc:.3f}  {a.raw.nodes[nid].label}  {a.raw.nodes[nid].attrs.get('exe', '')}")
    if a.reconstruction:
        _write(ns.story, dumps(to_story(a.graph, a.reconstruction)))
        _write(ns.stix, dumps(to_stix(a.graph, a.reconstruction)))
        _write(ns.mermaid, to_mermaid(a.graph, a.reconstruction))
        _write(ns.cypher, to_cypher(a.graph, a.reconstruction))
    return 0


def cmd_serve(ns: argparse.Namespace) -> int:  # pragma: no cover - starts a server
    try:
        from .api import serve
    except ImportError:
        raise SystemExit("serve needs the api extra: pip install 'rootline[api]'") from None
    serve([ns.captures] if ns.fuse and ns.captures else ns.captures, ns.host, ns.port)
    return 0


def cmd_verify(ns: argparse.Namespace) -> int:
    n = Normalizer()
    evs = sorted(n.normalize(read_jsonl(ns.events)), key=lambda e: (e.ts, e.seq))
    g = ProvenanceGraph().ingest(evs)
    if ns.head is None:
        print(g.head)
        return 0
    ok = verify_chain(evs, ns.head)
    print("OK: provenance record intact" if ok else "TAMPERED: hash chain mismatch")
    return 0 if ok else 2


def cmd_demo(ns: argparse.Namespace) -> int:
    os.makedirs(ns.outdir, exist_ok=True)
    base, _ = generate(ns.benign, attack=False, seed=1)
    recs, truth = generate(ns.benign, attack=True, seed=7)
    write_jsonl(recs, os.path.join(ns.outdir, "events.jsonl"))
    a = analyze(recs, base)
    _print_analysis(a)
    assert a.reconstruction is not None
    _write(os.path.join(ns.outdir, "story.json"), dumps(to_story(a.graph, a.reconstruction)))
    _write(os.path.join(ns.outdir, "stix.json"), dumps(to_stix(a.graph, a.reconstruction)))
    _write(os.path.join(ns.outdir, "story.mmd"), to_mermaid(a.graph, a.reconstruction))
    print("\n[=] evaluation vs ground truth:")
    for k, v in evaluate(a, truth).items():
        print(f"    {k}: {v}")
    # anti-forensics: auth.log deletion is itself in the provenance record
    deleted = [n.label for n in a.raw.nodes.values() if n.attrs.get("deleted") and "auth.log" in n.label]
    print(f"\n[=] anti-forensics: log deletion captured in provenance -> {deleted}")
    print(f"[=] outputs written to {ns.outdir}/ (story.json, stix.json, story.mmd)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="rootline", description="Provenance-graph attack reconstruction")
    p.add_argument("--version", action="version", version=__version__)
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("synth", help="generate synthetic kernel events")
    s.add_argument("--out", required=True)
    s.add_argument("--truth")
    s.add_argument("--benign", type=int, default=300)
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--no-attack", action="store_true")
    s.set_defaults(fn=cmd_synth)

    a = sp.add_parser("analyze", help="build graph, tag, reconstruct")
    a.add_argument("events", nargs="+", help="one or more captures (several sensors are fused)")
    a.add_argument("--format", choices=FORMATS, default="auto")
    a.add_argument("--iforest", action="store_true", help="also rank process vertices with IsolationForest")
    a.add_argument("--cypher", help="write a Neo4j import script for the story")
    a.add_argument("--baseline")
    grp = a.add_mutually_exclusive_group()
    grp.add_argument("--pivot", help="vertex id to reconstruct from")
    grp.add_argument("--ioc", help="substring (path/ip) of a vertex to pivot on")
    a.add_argument("--story")
    a.add_argument("--stix")
    a.add_argument("--mermaid")
    a.add_argument("--no-reduce", action="store_true")
    a.set_defaults(fn=cmd_analyze)

    v = sp.add_parser("verify", help="print or check the provenance hash-chain head")
    v.add_argument("events")
    v.add_argument("--head")
    v.set_defaults(fn=cmd_verify)

    sv = sp.add_parser("serve", help="FastAPI + attack-replay UI (needs rootline[api])")
    sv.add_argument("captures", nargs="*")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--fuse", action="store_true", help="fuse all captures into one story (several sensors, one host)")
    sv.set_defaults(fn=cmd_serve)

    d = sp.add_parser("demo", help="synthetic end-to-end demo")
    d.add_argument("--outdir", default="out")
    d.add_argument("--benign", type=int, default=400)
    d.set_defaults(fn=cmd_demo)

    ns = p.parse_args(argv)
    return ns.fn(ns)


if __name__ == "__main__":
    sys.exit(main())
