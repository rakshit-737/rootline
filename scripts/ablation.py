#!/usr/bin/env python3
"""Run the reconstructor ablation on ATLAS S1-S4 (design data) and M1-M6 hosts (held out).

    python scripts/ablation.py                 # -> results/ablation.json, results/figures/ablation.png
    python scripts/ablation.py --render-only   # redraw the figure from results/ablation.json

Needs ``python scripts/download_data.py --source atlas --all`` (S1.zip and M1.zip).
About 6 minutes and < 1.5 GB RAM on a laptop (one scenario graph in memory at a time).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rootline import __version__  # noqa: E402
from rootline.ablation import VARIANTS, run_scenario, summarize  # noqa: E402
from rootline.loaders.atlas import discover, load_scenario  # noqa: E402
from rootline.pipeline import build_graph  # noqa: E402

OUT = ROOT / "results"


def data_dir() -> Path:
    env = os.environ.get("ROOTLINE_DATA")
    if env:
        return Path(env)
    legacy = (ROOT.parent.parent / "datasets" / "rootline").resolve()
    return legacy if legacy.is_dir() else Path.home() / ".cache" / "rootline"


def attack_lines(log_path: str) -> int:
    """Lines ATLAS labels as attack ('+' suffix), whatever ROOTLINE can represent."""
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        return sum(1 for ln in fh if ln.rstrip().endswith("+"))


def figure(res: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    groups = [g for g in ("S", "M") if g in res["summary"]]
    fig, axes = plt.subplots(1, len(groups), figsize=(6.2 * len(groups), 3.8), sharey=True, squeeze=False)
    names = list(VARIANTS)
    for ax, grp in zip(axes[0], groups, strict=True):
        s = res["summary"][grp]
        for i, (metric, col) in enumerate((("precision", "#1f618d"), ("recall", "#76b041"), ("f1", "#e0a458"))):
            m = [s[v][metric]["mean"] for v in names]
            lo = [s[v][metric]["mean"] - s[v][metric]["ci95"][0] for v in names]
            hi = [s[v][metric]["ci95"][1] - s[v][metric]["mean"] for v in names]
            ax.bar([x + i * 0.27 for x in range(len(names))], m, 0.27, yerr=[lo, hi], capsize=2,
                   label=metric, color=col)
        ax.set_xticks([x + 0.27 for x in range(len(names))], names, rotation=30, ha="right", fontsize=8)
        title = {"S": "ATLAS S1-S4 (design data)", "M": "ATLAS M1-M6 hosts (held out)"}[grp]
        ax.set_title(f"{title}: {s['scenarios']} logs, {s['pivots']} pivots", fontsize=9)
        ax.set_ylim(0, 1.05)
        ax.grid(axis="y", alpha=0.3)
    axes[0][0].set_ylabel("event-level score (95 % scenario bootstrap)")
    axes[0][0].legend(fontsize=8)
    fig.tight_layout()
    (OUT / "figures").mkdir(exist_ok=True)
    fig.savefig(OUT / "figures" / "ablation.png", dpi=110)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--render-only", action="store_true")
    ns = p.parse_args(argv)
    if ns.render_only:
        figure(json.loads((OUT / "ablation.json").read_text()))
        return 0
    root = data_dir() / "atlas"
    t0 = time.perf_counter()
    rows, scen = [], []
    for d, name in discover(str(root)):
        sc = load_scenario(d, name)
        g, _ = build_graph(sc.records)
        group = "M" if name.startswith("M") else "S"
        gt = sum(1 for ev in g.events if ev.label == "attack" and ev.kind.value != "dns")
        scen.append({"scenario": name, "group": group, "events": len(g.events), "scored_attack_events": gt,
                     "atlas_attack_lines": attack_lines(sc.log_path), "host_labels": len(sc.host_labels),
                     "dropped": sc.dropped})
        rows += run_scenario(sc, g, group)
        print(f"[ablation] {name}: {len({r['pivot'] for r in rows if r['scenario'] == name})} pivots", flush=True)
        del g, sc
    res = {"generated_by": f"scripts/ablation.py - rootline {__version__}, Python {platform.python_version()}, "
                           f"{platform.system()}", "variants": VARIANTS, "scenarios": scen,
           "summary": summarize(rows), "rows": rows, "wall_seconds": round(time.perf_counter() - t0, 1)}
    OUT.mkdir(exist_ok=True)
    (OUT / "ablation.json").write_text(json.dumps(res, indent=1))
    try:
        figure(res)
    except ImportError:
        print("[ablation] matplotlib missing: no figure")
    print(json.dumps({g: {v: {m: s[v][m] for m in ("precision", "recall", "f1")} for v in VARIANTS}
                      for g, s in res["summary"].items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
