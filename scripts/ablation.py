#!/usr/bin/env python3
"""Run the reconstructor ablation on ATLAS S1-S4 (design data) and M1-M6 hosts (held out).

    python scripts/ablation.py                 # -> results/ablation.json, results/figures/ablation*.png
    python scripts/ablation.py --render-only   # redraw the figures from results/ablation.json
    python scripts/ablation.py --resummarize   # recompute the summary from the committed rows

Needs ``python scripts/download_data.py --source atlas --all`` (S1.zip and M1.zip).
About 13 minutes on a laptop; one scenario graph is held in memory at a time.
The output carries a ``provenance`` block (commit, workflow run id, Python).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rootline.ablation import VARIANTS, exploit_of, run_scenario, summarize  # noqa: E402
from rootline.loaders.atlas import discover, load_scenario  # noqa: E402
from rootline.pipeline import build_graph  # noqa: E402
from rootline.provenance import provenance  # noqa: E402

OUT = ROOT / "results"
# reference categorical palette (validated: CVD dE 24.7, normal-vision dE 33.6), neutral text inks
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"


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


def short(scenario: str) -> str:
    """``M4-CVE_2018_8174_windows_h1`` -> ``M4 h1``; ``S2-CVE-2015-3105_windows`` -> ``S2``."""
    head = scenario.split("-", 1)[0]
    return head + (" " + scenario[-2:] if scenario.endswith(("_h1", "_h2")) else "")


def _style(ax) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=8)


def figure(res: dict) -> None:
    """ablation.png: per-log values for every variant; ablation_stops.png: the stops effect per held-out log."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    summ = res["summary"]
    groups = [g for g in ("S", "M") if g in summ]
    names = list(VARIANTS)
    metrics = (("precision", BLUE), ("recall", AQUA), ("f1", ORANGE))
    fig, axes = plt.subplots(len(groups), 3, figsize=(13, 3.3 * len(groups)), sharey=True, squeeze=False)
    fig.patch.set_facecolor(SURFACE)
    for row, grp in zip(axes, groups, strict=True):
        s = summ[grp]
        for ax, (metric, col) in zip(row, metrics, strict=True):
            _style(ax)
            for x, v in enumerate(names):
                per = list(s[v][metric]["per_log"].values())
                jit = [((i % 6) - 2.5) * 0.045 for i in range(len(per))]
                ax.scatter([x + j for j in jit], per, s=16, color=col, alpha=0.55, linewidths=0, zorder=2)
                m = s[v][metric]["mean"]
                ax.plot([x - 0.3, x + 0.3], [m, m], color=INK, lw=2, solid_capstyle="round", zorder=3)
                if grp == "M":  # 12 logs: a bootstrap interval is meaningful; 4 S logs are shown as dots only
                    lo, hi = s[v][metric]["ci95"]
                    ax.plot([x + 0.36, x + 0.36], [lo, hi], color=MUTED, lw=1, zorder=1)
            ax.set_xticks(range(len(names)), names, rotation=30, ha="right", fontsize=8)
            ax.set_ylim(-0.02, 1.05)
            ax.grid(axis="y", color=GRID, lw=0.8)
            ax.set_axisbelow(True)
            ax.set_title(f"{metric}", fontsize=9, color=INK, loc="left")
        lab = {"S": f"S1-S4 (design data)\n{s['scenarios']} logs: dots = logs",
               "M": f"M1-M6 hosts (held out)\n{s['scenarios']} logs, 95 % log bootstrap"}[grp]
        row[0].set_ylabel(lab, fontsize=8.5, color=MUTED)
    fig.suptitle("Ablation on ATLAS: one dot per log (mean over its pivots); black tick = mean of logs",
                 fontsize=10, color=INK, x=0.01, ha="left")
    fig.tight_layout()
    (OUT / "figures").mkdir(exist_ok=True)
    fig.savefig(OUT / "figures" / "ablation.png", dpi=100, facecolor=SURFACE)
    plt.close(fig)

    if "M" not in summ:
        return
    m = summ["M"]
    s_exploits = {exploit_of(x) for x in summ.get("S", {}).get("logs", {})}
    logs = sorted(m["naive"]["precision"]["per_log"])
    dp = {lg: m["naive+stops"]["precision"]["per_log"][lg] - m["naive"]["precision"]["per_log"][lg] for lg in logs}
    dr = {lg: m["naive+stops"]["recall"]["per_log"][lg] - m["naive"]["recall"]["per_log"][lg] for lg in logs}
    order = sorted(logs, key=lambda lg: dp[lg])
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), sharey=True, gridspec_kw={"width_ratios": [3, 2]})
    fig.patch.set_facecolor(SURFACE)
    for ax, d, key, title in ((axes[0], dp, "delta_precision_vs_naive", "precision gain"),
                              (axes[1], dr, "delta_recall_vs_naive", "recall change")):
        _style(ax)
        new = [lg for lg in order if exploit_of(lg) not in s_exploits]
        old = [lg for lg in order if exploit_of(lg) in s_exploits]
        ax.scatter([d[lg] for lg in old], [order.index(lg) for lg in old], s=40, color=BLUE, zorder=3,
                   edgecolors=SURFACE, linewidths=1.5, label="exploit also used in S1-S4")
        ax.scatter([d[lg] for lg in new], [order.index(lg) for lg in new], s=48, marker="D", color=ORANGE, zorder=3,
                   edgecolors=SURFACE, linewidths=1.5, label="new exploit (M2, M4)")
        ax.axvline(0, color=MUTED, lw=1)
        dd = m["naive+stops"][key]
        ax.axvspan(dd["ci95"][0], dd["ci95"][1], color=BLUE, alpha=0.08, lw=0)
        ax.axvline(dd["mean"], color=INK, lw=1.5)
        lg_t = dd["logs"]
        ax.set_title(f"{title}: mean {dd['mean']:+.4f} [{dd['ci95'][0]:+.4f}, {dd['ci95'][1]:+.4f}]\n"
                     f"higher on {lg_t['higher']}, lower on {lg_t['lower']}, tied on {lg_t['tied']} of {lg_t['n']} logs",
                     fontsize=8.5, color=INK, loc="left")
        ax.grid(axis="x", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
    axes[0].set_yticks(range(len(order)), [short(lg) for lg in order], fontsize=8)
    axes[0].set_xlabel("naive+stops minus naive, event precision", fontsize=8, color=MUTED)
    axes[1].set_xlabel("naive+stops minus naive, event recall", fontsize=8, color=MUTED)
    axes[0].legend(fontsize=7.5, loc="lower right", frameon=False)
    fig.suptitle("Session-root stops on the 12 held-out ATLAS host logs, per log (shaded: 95 % log bootstrap)",
                 fontsize=10, color=INK, x=0.01, ha="left")
    fig.tight_layout()
    fig.savefig(OUT / "figures" / "ablation_stops.png", dpi=100, facecolor=SURFACE)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--render-only", action="store_true", help="redraw the figures from results/ablation.json")
    p.add_argument("--resummarize", action="store_true",
                   help="recompute the summary block from the committed rows (no traversal re-run)")
    ns = p.parse_args(argv)
    if ns.render_only or ns.resummarize:
        res = json.loads((OUT / "ablation.json").read_text())
        if ns.resummarize:
            res["summary"] = summarize(res["rows"])
            (OUT / "ablation.json").write_text(json.dumps(res, indent=1))
        figure(res)
        return 0
    root = data_dir() / "atlas"
    found = discover(str(root))
    if not found:
        print(f"[ablation] error: no ATLAS scenarios under {root}; run "
              "python scripts/download_data.py --source atlas --all (results/ablation.json left unchanged)",
              file=sys.stderr)
        return 2
    prov = provenance("scripts/ablation.py", ROOT)
    t0 = time.perf_counter()
    rows, scen = [], []
    for d, name in found:
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
    if not rows:
        print("[ablation] error: no pivots produced any row; results/ablation.json left unchanged", file=sys.stderr)
        return 2
    res = {"provenance": prov, "variants": VARIANTS, "scenarios": scen,
           "summary": summarize(rows), "rows": rows, "wall_seconds": round(time.perf_counter() - t0, 1)}
    OUT.mkdir(exist_ok=True)
    (OUT / "ablation.json").write_text(json.dumps(res, indent=1))
    try:
        figure(res)
    except ImportError:
        print("[ablation] matplotlib missing: no figure")
    print(json.dumps({g: {v: {m: s[v][m]["mean"] for m in ("precision", "recall", "f1")} for v in VARIANTS}
                      for g, s in res["summary"].items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
