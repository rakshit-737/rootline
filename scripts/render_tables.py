#!/usr/bin/env python3
"""Render the headline tables from committed result files into results/TABLES.md.

    python scripts/render_tables.py

Inputs (all committed): results/ablation.json, results/atlas.json, results/coverage.json,
results/live_ebpf.json, results/atlas_repro.json. The README and the Evaluation page
quote these tables, so every number there can be traced to a JSON file.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "results"
VARS = ["naive", "naive+stops", "time", "time+stops", "time+spine", "time+stops+spine", "full"]

# ATLAS paper (Alsaheel et al., USENIX Security 2021): Table 4 event-level averages over the
# 10 attacks, and Table 5's graph-traversal baseline (event level, 10-attack average).
PAPER_EVENT_AVG = (0.9988, 0.9989, 0.9988)
PAPER_TRAVERSAL = (0.1782, 1.0000, 0.3026)


def load(name: str) -> dict:
    return json.loads((R / name).read_text(encoding="utf-8"))


def ci(x: dict) -> str:
    return f"{x['mean']:.2f} [{x['ci95'][0]:.2f}, {x['ci95'][1]:.2f}]"


def table(rows: list[list[str]], head: list[str]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def ablation() -> str:
    a = load("ablation.json")
    parts = []
    for grp, title in (("S", "ATLAS S1-S4, design data (in-sample)"), ("M", "ATLAS M1-M6 host logs, held out")):
        s = a["summary"][grp]
        rows = []
        for v in VARS:
            x = s[v]
            d = x.get("delta_f1_vs_naive")
            dp = x.get("delta_precision_vs_naive")
            rows.append([f"**{v}**" if v == "full" else v, ci(x["precision"]), ci(x["recall"]), ci(x["f1"]),
                         ci(x["entity_recall"]), f"{x['rc_hit3']['mean']:.2f}", f"{x['story_nodes']['mean']:,.0f}",
                         "" if d is None else f"{d['mean']:+.2f} [{d['ci95'][0]:+.2f}, {d['ci95'][1]:+.2f}]",
                         "" if dp is None else f"{dp['sign_test']['pos']}/{dp['sign_test']['pos'] + dp['sign_test']['neg']}"
                                                f" (p={dp['sign_test']['p']:.2g})"])
        parts.append(f"**{title}**: {s['scenarios']} logs, {s['pivots']} pivots. Mean of scenario means, "
                     "95 % scenario-cluster bootstrap.\n")
        parts.append(table(rows, ["variant", "precision", "recall", "F1", "entity recall", "root-cause hit@3",
                                  "story vertices", "ΔF1 vs naive", "pivots with higher precision (sign test)"]))
        parts.append("")
    return "\n".join(parts)


def atlas_ioc() -> str:
    a = load("atlas.json")
    rows = a["atlas"]
    groups: dict[str, dict[str, list[dict]]] = {}
    for r in rows:
        g = "M (held out)" if r["scenario"].startswith("M") else "S1-S4 (in-sample)"
        groups.setdefault(g, {}).setdefault(r["method"], []).append(r)
    out = []
    for g, ms in groups.items():
        for m in ("ioc-grep", "naive-bfs", "rootline"):
            if m not in ms:
                continue
            rs = ms[m]
            mean = lambda k, rs=rs: sum(r[k] for r in rs) / len(rs)  # noqa: E731
            out.append([g, m, str(len(rs)), f"{mean('precision'):.3f}", f"{mean('recall'):.3f}", f"{mean('f1'):.3f}",
                        f"{mean('story_nodes'):,.0f}"])
    note = ""
    if a.get("skipped"):
        note = "\n\nSkipped (the starting IOC matches no vertex on that host): " + ", ".join(
            s["scenario"] for s in a["skipped"]) + "."
    return table(out, ["scenarios", "method", "logs", "precision", "recall", "F1", "story vertices"]) + note


def event_universe() -> str:
    a = load("ablation.json")
    rows = []
    for s in a["scenarios"]:
        rows.append([s["scenario"].split("_windows")[0], f"{s['events']:,}", f"{s['atlas_attack_lines']:,}",
                     f"{s['scored_attack_events']:,}", f"{s['scored_attack_events'] / s['atlas_attack_lines']:.2f}"])
    return table(rows, ["log", "ROOTLINE events", "ATLAS '+' lines", "scored attack events", "ratio"])


def published() -> str:
    a = load("ablation.json")
    s, m = a["summary"]["S"], a["summary"]["M"]
    rp = load("atlas_repro.json")
    rows = [
        ["ATLAS paper, Table 5: graph traversal (10 attacks)", "event", "no",
         f"{PAPER_TRAVERSAL[0]:.3f}", f"{PAPER_TRAVERSAL[1]:.3f}", f"{PAPER_TRAVERSAL[2]:.3f}"],
        ["ROOTLINE naive reachability (S1-S4 / M hosts, all pivots)", "event", "no",
         f"{s['naive']['precision']['mean']:.3f} / {m['naive']['precision']['mean']:.3f}",
         f"{s['naive']['recall']['mean']:.3f} / {m['naive']['recall']['mean']:.3f}",
         f"{s['naive']['f1']['mean']:.3f} / {m['naive']['f1']['mean']:.3f}"],
        ["ROOTLINE full (S1-S4 / M hosts, all pivots)", "event", "no",
         f"{s['full']['precision']['mean']:.3f} / {m['full']['precision']['mean']:.3f}",
         f"{s['full']['recall']['mean']:.3f} / {m['full']['recall']['mean']:.3f}",
         f"{s['full']['f1']['mean']:.3f} / {m['full']['f1']['mean']:.3f}"],
        ["ATLAS paper, Table 4: LSTM (10 attacks)", "event", "yes",
         f"{PAPER_EVENT_AVG[0]:.3f}", f"{PAPER_EVENT_AVG[1]:.3f}", f"{PAPER_EVENT_AVG[2]:.3f}"],
    ]
    for sc in rp["scenarios"]:
        pap = sc["paper"]
        reg = sc["summary"]["regenerated"]
        shp = sc["summary"].get("shipped_resampling")
        raw = sc["shipped_artefact"]["raw_model_output"]
        rows.append([f"{sc['scenario']}: paper Table 4 / ATLAS shipped raw output / our repro (regen; shipped set)",
                     "entity", "yes",
                     f"{pap['precision'] / 100:.2f} / {raw['precision']:.2f} / {reg['precision']['mean']:.2f}; "
                     f"{shp['precision']['mean']:.2f}" if shp else "",
                     f"{pap['recall'] / 100:.2f} / {raw['recall']:.2f} / {reg['recall']['mean']:.2f}; "
                     f"{shp['recall']['mean']:.2f}" if shp else "",
                     f"{pap['f1'] / 100:.2f} / {raw['f1']:.2f} / {reg['f1']['mean']:.2f}; "
                     f"{shp['f1']['mean']:.2f}" if shp else ""])
    return table(rows, ["system", "level", "trained on labels", "precision", "recall", "F1"])


def coverage() -> str:
    c = load("coverage.json")["summary"]
    rows = []
    for k in ("dev", "dev2", "sealed", "sealed-unseen-technique", "sealed-excluding-v03-target-techniques"):
        if k not in c:
            continue
        v = c[k]
        n = v["with_events"]

        def f(key: str, v=v, n=n) -> str:
            if f"v03_{key}" not in v:
                return ""
            lo, hi = v.get(f"v03_{key}_ci95", [0, 0])
            return f"{v[f'v03_{key}']}/{n} ({v[f'v03_{key}'] / n:.0%}) [{lo:.2f}, {hi:.2f}]"
        rows.append([k, str(v["datasets"]), str(v["datasets"] - n), f("detected"), f("technique_match"),
                     str(v.get("v03_alert_precision", ""))])
    return table(rows, ["split", "captures", "unparsed", "v0.3 detected", "v0.3 same technique",
                        "alert precision (proxy)"])


def live() -> str:
    lv = load("live_ebpf.json")
    lo, hi = lv["pass_rate_ci95"]
    r1 = lv["run1_detail"]
    return table([[str(lv["run_id"]), f"{lv['passed']}/{lv['repeats']} [{lo:.2f}, {hi:.2f}]",
                   ", ".join(r1["story"]["root_causes"]), str(r1["story"]["vertices"]), ", ".join(r1["alerts"]),
                   str(sum(p["lost_events"] for p in lv["per_run"]))]],
                 ["CI run", "runs passed", "root causes (one query)", "story vertices", "alerts", "lost events"])


def main() -> int:
    parts = ["<!-- Generated by scripts/render_tables.py; do not edit by hand. -->", "", "Generated by `python scripts/render_tables.py` from the committed JSON in "
             "`results/`. Do not edit by hand.", "",
             "### Ablation (ATLAS, every ground-truth entity as a pivot)", "", ablation(),
             "### ATLAS from the analyst IOC (one pivot per log)", "", atlas_ioc(), "",
             "### Comparison with published ATLAS results", "", published(), "",
             "### Event universe: what ROOTLINE can score vs what ATLAS labels", "", event_universe(), "",
             "### Rule coverage, Splunk attack_data (v0.3 rules)", "", coverage(), "",
             "### Live eBPF in CI", "", live(), ""]
    (R / "TABLES.md").write_text("\n".join(parts), encoding="utf-8")
    print(f"wrote {R / 'TABLES.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
