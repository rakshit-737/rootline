#!/usr/bin/env python3
"""Reproduce the README "Results" numbers that come from the downloaded public data.

    python scripts/download_data.py && python scripts/download_data.py --source atlas --all
    python scripts/bench.py                       # atlas + log4shell (the default run)
    python scripts/bench.py --only atlas          # one of: atlas | log4shell | coverage
    python scripts/bench.py --render-only         # RESULTS.md + figures from results/*.json

Writes results/*.json (raw, each with a ``provenance`` block: commit, run id,
Python), results/RESULTS.md and results/figures/*.png. IsolationForest runs
seeds 0-9 and reports mean + 95 % CI; everything else is deterministic.

Rule coverage is NOT part of the default run. ``--only coverage`` first runs
``scripts/verify_freeze.py``: the dev/dev2/sealed numbers in
results/coverage.json are the sealed-protocol record (docs/protocol.md) and may
only be rewritten by the frozen code. At any other commit, ``--only coverage
--allow-unfrozen`` scores the in-sample dev and dev2 splits (never sealed) into
results/coverage_head.json, labelled in-sample.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rootline.bench import clip_anomaly_rows, run_atlas, run_coverage, summarize_coverage  # noqa: E402
from rootline.export import dumps, to_mermaid, to_story  # noqa: E402
from rootline.loaders import load_many  # noqa: E402
from rootline.loaders.atlas import discover  # noqa: E402
from rootline.pipeline import analyze  # noqa: E402
from rootline.provenance import describe, provenance  # noqa: E402

OUT = ROOT / "results"
MANIFEST = ROOT / "scripts" / "data_manifest.json"


class BenchError(SystemExit):
    """A benchmark cannot run on the data present; nothing is written."""

    def __init__(self, msg: str) -> None:
        print(f"[bench] error: {msg}", file=sys.stderr)
        super().__init__(2)


def data_dir() -> Path:
    env = os.environ.get("ROOTLINE_DATA")
    if env:
        return Path(env)
    legacy = (ROOT.parent.parent / "datasets" / "rootline").resolve()
    return legacy if legacy.is_dir() else Path.home() / ".cache" / "rootline"


def md_table(rows: list[dict], cols: list[str]) -> str:
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    return "\n".join(out)


def bench_atlas(data: Path) -> dict:
    """ATLAS IOC-pivot reconstruction, reduction and anomaly ranking -> results/atlas.json."""
    root = data / "atlas"
    if not discover(str(root)):
        raise BenchError(f"no ATLAS scenarios under {root}; run "
                         "python scripts/download_data.py --source atlas --all")
    prov = provenance("scripts/bench.py --only atlas", ROOT)
    t = time.perf_counter()
    res = run_atlas(str(root))
    if not res["atlas"]:
        raise BenchError(f"ATLAS produced no result rows under {root}; results/atlas.json left unchanged")
    res["wall_seconds"] = round(time.perf_counter() - t, 1)
    res["provenance"] = prov
    (OUT / "atlas.json").write_text(json.dumps(res, indent=1))
    return res


def manifest_files(splits: tuple[str, ...]) -> dict[str, list[str]]:
    """Manifest entries (non-zip Splunk/OTRF captures) the coverage bench scores, per split."""
    items = json.loads(MANIFEST.read_text(encoding="utf-8"))["files"]
    out: dict[str, list[str]] = {s: [] for s in splits}
    for it in items:
        if it["source"] in ("splunk", "otrf") and it.get("split") in splits and not it["dest"].endswith(".zip"):
            out[it["split"]].append(it["dest"])
    return out


def freeze_ok() -> bool:
    """Run scripts/verify_freeze.py (pre-registered hashes of the sealed-protocol sources)."""
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "verify_freeze.py")], cwd=ROOT)
    return r.returncode == 0


def bench_coverage(data: Path, allow_unfrozen: bool = False) -> dict:
    """Rule coverage on the Splunk splits.

    With the frozen sources (the freeze check passes) all three splits are scored
    into results/coverage.json. Otherwise only ``--allow-unfrozen`` proceeds, and it
    scores dev and dev2 (never sealed) into results/coverage_head.json, labelled
    in-sample. Every scored split must be fully downloaded.
    """
    frozen = freeze_ok()
    if not frozen and not allow_unfrozen:
        raise BenchError("the freeze check failed, so this code is not the pre-registered v0.3 version and "
                         "must not rewrite results/coverage.json; pass --allow-unfrozen to score the "
                         "in-sample dev/dev2 splits into results/coverage_head.json instead")
    splits = ("dev", "dev2", "sealed") if frozen else ("dev", "dev2")
    for split, files in manifest_files(splits).items():
        missing = [f for f in files if not (data / f).exists()]
        if not files or missing:
            raise BenchError(f"split {split!r}: {len(missing)} of {len(files)} manifest captures are not "
                             f"downloaded under {data}; run python scripts/download_data.py --split {split}")
    prov = provenance("scripts/bench.py --only coverage" + ("" if frozen else " --allow-unfrozen"), ROOT)
    prov["freeze_check"] = "passed (scripts/verify_freeze.py)" if frozen else "failed: post-freeze sources"
    rows = run_coverage(str(MANIFEST), str(data), splits)
    res = {"rows": rows, "summary": summarize_coverage(rows), "provenance": prov}
    if frozen:
        (OUT / "coverage.json").write_text(json.dumps(res, indent=1))
    else:
        res["label"] = ("in-sample: dev and dev2 re-scored with the post-freeze code at this commit; "
                        "sealed is never re-scored here (docs/protocol.md)")
        (OUT / "coverage_head.json").write_text(json.dumps(res, indent=1))
    return res


def otrf_file(data: Path, pattern: str) -> Path:
    """Find an extracted OTRF capture (the downloader extracts next to the zip)."""
    for d in (data / "otrf", data / "otrf" / "x"):
        hit = sorted(d.glob(pattern)) if d.is_dir() else []
        if hit:
            return hit[0]
    raise BenchError(f"no {pattern} under {data / 'otrf'}; run python scripts/download_data.py --source otrf")


def bench_log4shell(data: Path) -> dict:
    """OTRF Log4Shell, Sysmon alone vs Sysmon + AUOMS fused -> results/log4shell.json and the story files."""
    sysmon = otrf_file(data, "syslog_sysmon_log4shell*.json")
    auoms = otrf_file(data, "syslog_auoms_auditd_log4shell*.json")
    prov = provenance("scripts/bench.py --only log4shell", ROOT)
    out = {}
    for name, paths in (("sysmon-only", [sysmon]), ("sysmon+auoms", [sysmon, auoms])):
        t = time.perf_counter()
        a = analyze(load_many([str(p) for p in paths]))
        r = a.reconstruction
        labels = {a.graph.nodes[n].label for n in r.nodes} if r else set()
        out[name] = {"events": len(a.raw.events), "vertices": len(a.raw.nodes), "alerts": len(a.alerts),
                     "story_vertices": len(r.nodes) if r else 0,
                     "root_causes": [a.graph.nodes[n].label for n in r.root_causes] if r else [],
                     "reaches_java": "java[1340]" in labels,
                     "reaches_ldap_1389": any(lab.endswith(":1389") for lab in labels),
                     "seconds": round(time.perf_counter() - t, 3)}
        if name == "sysmon+auoms" and r:
            story = to_story(a.graph, r)
            story["generated_by"] = prov
            (OUT / "log4shell_story.json").write_text(dumps(story))
            (OUT / "log4shell_story.mmd").write_text(to_mermaid(a.graph, r) + "\n")
    res = {"inputs": out, "provenance": prov}
    (OUT / "log4shell.json").write_text(json.dumps(res, indent=1))
    return res


def figures(atlas: dict | None, cov: dict | None) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[bench] matplotlib not installed: skipping figures")
        return
    fig_dir = OUT / "figures"
    fig_dir.mkdir(exist_ok=True)
    # rootline-noreduce is a check (stories with and without reduction are identical by design),
    # not a separate method, so it is left out of the figure; it stays in atlas.json.
    colors = {"ioc-grep": "#9aa5b1", "naive-bfs": "#e0a458", "rootline": "#1f618d"}
    if atlas:
        rows = atlas["atlas"]
        scen = sorted({r["scenario"] for r in rows})
        methods = [m for m in colors if any(r["method"] == m for r in rows)]
        fig, axes = plt.subplots(1, 3, figsize=(15, 4.0), sharey=True)
        for ax, metric in zip(axes, ("precision", "recall", "f1"), strict=True):
            w = 0.8 / len(methods)
            for i, m in enumerate(methods):
                vals = [next(r[metric] for r in rows if r["scenario"] == s and r["method"] == m) for s in scen]
                ax.bar([x + i * w for x in range(len(scen))], vals, w, label=m, color=colors[m])
            ax.set_xticks([x + 0.4 - w / 2 for x in range(len(scen))],
                          [s.split("-")[0] + ("-" + s[-2:] if s.endswith(("_h1", "_h2")) else "") for s in scen],
                          fontsize=7, rotation=90 if len(scen) > 6 else 0)
            ax.set_title(f"event-level {metric}")
            ax.set_ylim(0, 1.05)
            ax.grid(axis="y", alpha=0.3)
        handles, labels = axes[0].get_legend_handles_labels()
        fig.legend(handles, labels, fontsize=8, loc="lower center", ncol=len(methods), frameon=False)
        fig.suptitle("ATLAS: reconstruction from the analyst IOC vs ATLAS event labels "
                     "(S1-S4 design data, M hosts held out)", fontsize=10)
        fig.tight_layout(rect=(0, 0.07, 1, 1))
        fig.savefig(fig_dir / "atlas_prf.png", dpi=110)
        plt.close(fig)
    if cov:
        s = cov["summary"]
        splits = [k for k in ("dev", "dev2", "sealed", "sealed-unseen-technique") if k in s]
        fig, ax = plt.subplots(figsize=(8, 3.6))
        bars = (("v02_detected", "v0.2 (any alert)", "#7fb3d5"),
                ("v03_detected", "v0.3 (any alert)", "#1f618d"),
                ("v03_technique_match", "v0.3, same ATT&CK technique", "#76b041"))
        bars = tuple(b for b in bars if any(b[0] in s[k] for k in splits))
        w = 0.8 / max(1, len(bars))
        for i, (key, lab, col) in enumerate(bars):
            xs, vals, lo, hi = [], [], [], []
            for x, k in enumerate(splits):
                n = s[k]["with_events"]
                if key not in s[k] or not n:
                    continue
                v = s[k][key] / n
                ci = s[k].get(key + "_ci95", [v, v])
                xs.append(x + i * w)
                vals.append(v)
                lo.append(v - ci[0])
                hi.append(ci[1] - v)
            ax.bar(xs, vals, w, yerr=[lo, hi], capsize=3, label=lab, color=col)
        ax.set_xticks([x + w * (len(bars) - 1) / 2 for x in range(len(splits))],
                      [f"{k}\n(n={s[k]['with_events']})" for k in splits], fontsize=8)
        ax.set_ylim(0, 1)
        ax.set_ylabel("share of parsed captures")
        ax.legend(fontsize=8)
        ax.grid(axis="y", alpha=0.3)
        ax.set_title("Tagger coverage on Splunk attack_data Linux captures (95 % Wilson CI)", fontsize=10)
        fig.tight_layout()
        fig.savefig(fig_dir / "tagger_coverage.png", dpi=110)
        plt.close(fig)

def write_md(atlas: dict | None, cov: dict | None, l4s: dict | None) -> None:
    parts = ["# ROOTLINE benchmark results\n",
             "Rendered by `python scripts/bench.py` from results/*.json. Each section names the run that "
             "produced it.\n"]
    if atlas:
        parts.append("## ATLAS: attack reconstruction from the analyst IOC (S1-S4 in-sample, M hosts held out)\n")
        parts.append(f"Source: {describe(atlas.get('provenance'))}.\n")
        parts.append(md_table(atlas["atlas"], ["scenario", "method", "events", "gt_events", "story_nodes",
                                                "story_events", "precision", "recall", "f1", "entity_recall",
                                                "seconds"]))
        parts.append("\n## ATLAS: graph reduction (research question: shrink while preserving attack edges)\n")
        parts.append(md_table(atlas["reduction"], ["scenario", "edges_before", "edges_after", "edge_ratio",
                                                   "nodes_before", "nodes_after", "attack_edges_preserved",
                                                   "seconds"]))
        if atlas.get("anomaly"):
            parts.append("\n## ATLAS: anomaly tagging of process vertices (unsupervised)\n")
            parts.append("IsolationForest rows are the mean over 10 seeds with a 95 % t-interval clipped to the "
                         "metric's valid range (recall in [0, 1], rank >= 1). The interval covers seed variance "
                         "on one fixed graph only, not data or scenario variance. `iforest-no-userdir` drops the "
                         "`exec_user_dir` feature, which was written alongside the ATLAS benchmark; the user-dir "
                         "heuristic (images under a user-writable directory first, then by degree) and degree "
                         "ranking are deterministic baselines.\n")
            parts.append(md_table(atlas["anomaly"], ["scenario", "method", "processes", "malicious", "seeds",
                                                     "first_hit_rank", "first_hit_rank_ci95", "hits@10",
                                                     "recall@10", "recall@10_ci95"]))
    if cov:
        parts.append("\n## Tagger coverage: Splunk attack_data Linux captures (dev / dev2 / sealed)\n")
        parts.append(f"Source: {describe(cov.get('provenance'))}.\n")
        parts.append("Protocol: docs/protocol.md. *dev* and *dev2* are in-sample for v0.3; *sealed* was scored "
                     "once with the frozen rules. Technique match is at parent-technique level. Intervals are "
                     "95 % Wilson. Alert precision is the share of alerts naming the capture's technique "
                     "(a lower-bound proxy). *unparsed* captures yielded zero events and are excluded.\n")
        summ = []
        for k, v in cov["summary"].items():
            row = {"split": k, "captures": v["datasets"], "unparsed": v["datasets"] - v["with_events"],
                   "parsed": v["with_events"]}
            for tag in ("v01", "v02", "v03"):
                if f"{tag}_detected" not in v:
                    continue
                n = v["with_events"]
                ci, cj = v.get(f"{tag}_detected_ci95", [0, 0]), v.get(f"{tag}_technique_match_ci95", [0, 0])
                row[f"{tag} detected"] = f"{v[f'{tag}_detected']}/{n} [{ci[0]:.2f}, {ci[1]:.2f}]"
                row[f"{tag} technique"] = f"{v[f'{tag}_technique_match']}/{n} [{cj[0]:.2f}, {cj[1]:.2f}]"
                row[f"{tag} alert prec."] = v.get(f"{tag}_alert_precision")
            summ.append(row)
        cols = ["split", "captures", "unparsed", "parsed"] + [c for c in (
            f"{t} {m}" for t in ("v01", "v02", "v03") for m in ("detected", "technique", "alert prec."))
            if any(c in r for r in summ)]
        parts.append(md_table(summ, cols))
        parts.append('\n<details markdown="1"><summary>Per-dataset</summary>\n')
        parts.append(md_table(cov["rows"], ["split", "technique", "dataset", "events", "v01_alerts",
                                            "v02_alerts", "v03_alerts", "v03_rules"]))
        parts.append("\n</details>")
    if l4s:
        parts.append("\n## OTRF Log4Shell (CVE-2021-44228): single sensor vs fused sensors\n")
        parts.append(f"Source: {describe(l4s.get('provenance'))}.\n")
        inputs = l4s.get("inputs", {k: v for k, v in l4s.items() if k != "provenance"})
        parts.append(md_table([{"input": k, **v} for k, v in inputs.items()],
                              ["input", "events", "vertices", "alerts", "story_vertices", "root_causes",
                               "reaches_java", "reaches_ldap_1389", "seconds"]))
    (OUT / "RESULTS.md").write_text("\n".join(parts) + "\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--only", choices=["atlas", "coverage", "log4shell"],
                   help="run one benchmark (default: atlas and log4shell; coverage only when named)")
    p.add_argument("--allow-unfrozen", action="store_true",
                   help="with --only coverage at a post-freeze commit: score dev/dev2 into "
                        "results/coverage_head.json (in-sample) instead of refusing")
    p.add_argument("--render-only", action="store_true",
                   help="re-render RESULTS.md and figures from results/*.json without re-running")
    ns = p.parse_args(argv)
    if ns.allow_unfrozen and ns.only != "coverage":
        p.error("--allow-unfrozen only applies to --only coverage")
    data = data_dir()
    if not data.exists() and not ns.render_only:
        print(f"[bench] no data at {data}; run scripts/download_data.py first", file=sys.stderr)
        return 1
    OUT.mkdir(exist_ok=True)

    def cached(name: str) -> dict | None:
        f = OUT / f"{name}.json"
        return json.loads(f.read_text()) if f.exists() else None

    if ns.render_only:
        atlas, cov, l4s = cached("atlas"), cached("coverage"), cached("log4shell")
        if atlas and atlas.get("anomaly"):
            clip_anomaly_rows(atlas["anomaly"])
            (OUT / "atlas.json").write_text(json.dumps(atlas, indent=1))
        figures(atlas, cov)
        write_md(atlas, cov, l4s)
        print(f"[bench] re-rendered {OUT / 'RESULTS.md'} from cached results")
        return 0
    wanted = {"atlas", "log4shell"} if ns.only is None else {ns.only}
    runners = {"atlas": lambda: bench_atlas(data),
               "coverage": lambda: bench_coverage(data, ns.allow_unfrozen),
               "log4shell": lambda: bench_log4shell(data)}
    res: dict[str, dict | None] = {}
    for name in ("atlas", "coverage", "log4shell"):
        if name in wanted:
            t = time.perf_counter()
            res[name] = runners[name]()
            print(f"[bench] {name} done ({time.perf_counter() - t:.0f} s)")
        else:
            res[name] = cached(name)
            print(f"[bench] {name}: " + (f"reused results/{name}.json (not re-run)" if res[name]
                                         else "no cached result (not run)"))
    if ns.only == "coverage" and ns.allow_unfrozen:
        res["coverage"] = cached("coverage")  # the tables and figure keep showing the sealed record
        print("[bench] coverage: wrote results/coverage_head.json (in-sample); results/coverage.json untouched")
    figures(res["atlas"], res["coverage"])
    write_md(res["atlas"], res["coverage"], res["log4shell"])
    print(f"[bench] wrote {OUT / 'RESULTS.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
