#!/usr/bin/env python3
"""Render the headline tables from committed result files into results/TABLES.md.

    python scripts/render_tables.py           # rewrite results/TABLES.md
    python scripts/render_tables.py --check   # exit 1 if results/TABLES.md is out of date

Inputs (all committed): results/ablation.json, results/atlas.json,
results/coverage.json, results/live_ebpf.json, results/atlas_repro.json. The
README and the Evaluation page quote these tables (the README's headline table
is the "Headline results" block verbatim; a test checks it), so every number
there can be traced to a JSON file and the run that wrote it.

Statistics are computed here from the committed counts and per-log values, and
rounded once: Wilson intervals from k/n (never from stored, already-rounded
bounds), log-level paired tests, p-values that never print as 0.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from rootline.ablation import exploit_of  # noqa: E402
from rootline.bench import sealed_excluding_v03_targets  # noqa: E402
from rootline.stats import cluster_bootstrap, fmt_p, paired_log_test, sign_test, wilson  # noqa: E402

R = ROOT / "results"
VARS = ["naive", "naive+stops", "time", "time+stops", "time+spine", "time+stops+spine", "full"]

# ATLAS paper (Alsaheel et al., USENIX Security 2021): Table 4 event-level averages over the
# 10 attacks, and Table 5's graph-traversal baseline (event level, 10-attack average).
PAPER_EVENT_AVG = (0.9988, 0.9989, 0.9988)
PAPER_TRAVERSAL = (0.1782, 1.0000, 0.3026)


def load(name: str) -> dict:
    """Read one committed result file."""
    return json.loads((R / name).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ formatting
def num(x: float | None, dp: int = 2, signed: bool = False) -> str:
    """Round once for display; values that would print as 0.00 or 1.00 without being 0 or 1 get more digits."""
    if x is None:
        return "-"
    sign = "+" if signed else ""
    if x != 0 and abs(x) < 0.5 * 10 ** -dp:
        return f"{x:{sign}.1g}" if abs(x) >= 1e-4 else f"{x:{sign}.1e}"
    r = round(x, dp)
    if (abs(r) == 1 and abs(x) != 1) or (r == 0 and x != 0):
        return f"{x:{sign}.{dp + 1}f}"
    return f"{x:{sign}.{dp}f}"


def _dp_for(xs: tuple[float, ...], dp: int) -> int:
    """Decimals so that no value prints as 0 or 1 (or +-1) unless it is exactly that."""
    for x in xs:
        r = round(x, dp)
        if (abs(r) == 1 and abs(x) != 1) or (r == 0 and x != 0 and abs(x) >= 0.5 * 10 ** -(dp + 1)):
            return dp + 1
    return dp


def iv(lo: float, hi: float, dp: int = 2, signed: bool = False) -> str:
    """A 95 % interval as ``[lo, hi]``, both bounds with the same number of decimals."""
    d = _dp_for((lo, hi), dp)
    return f"[{num(lo, d, signed)}, {num(hi, d, signed)}]"


def rng(lo: float, hi: float, dp: int = 2) -> str:
    """A range over logs or seeds as ``lo-hi``, both ends with the same number of decimals."""
    d = _dp_for((lo, hi), dp)
    return f"{num(lo, d)}-{num(hi, d)}"


def frac(k: int, n: int) -> str:
    """``k/n`` with a Wilson 95 % interval computed from the counts."""
    lo, hi = wilson(k, n)
    return f"{k}/{n} {iv(lo, hi)}"


def table(rows: list[list[str]], head: list[str]) -> str:
    """A Markdown table."""
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def short(scenario: str) -> str:
    """``M4-CVE_2018_8174_windows_h1`` -> ``M4 h1``."""
    return scenario.split("-", 1)[0] + (" " + scenario[-2:] if scenario.endswith(("_h1", "_h2")) else "")


def run_of(res: dict) -> str:
    """``bench run 37092501921`` from a provenance block."""
    p = res.get("provenance") or {}
    return f"{p.get('workflow', 'local')} run {p['run_id']}" if p.get("run_id") else "local run"


# ------------------------------------------------------------------- ablation
def stops_split(m: dict) -> dict[str, dict]:
    """Session-root stop effect (naive+stops minus naive) on held-out logs, by whether the exploit is new."""
    s_exploits = {exploit_of(x) for x in load("ablation.json")["summary"]["S"]["logs"]}
    out = {}
    for name, keep in (("exploit not in S1-S4 (M2, M4)", lambda lg: exploit_of(lg) not in s_exploits),
                       ("exploit also used in S1-S4 (M1, M3, M5, M6)", lambda lg: exploit_of(lg) in s_exploits)):
        logs = [lg for lg in m["naive"]["precision"]["per_log"] if keep(lg)]
        dp = [m["naive+stops"]["precision"]["per_log"][lg] - m["naive"]["precision"]["per_log"][lg] for lg in logs]
        dr = [m["naive+stops"]["recall"]["per_log"][lg] - m["naive"]["recall"]["per_log"][lg] for lg in logs]
        out[name] = {"logs": logs, "dp": dp, "dr": dr}
    return out


def ablation() -> str:
    """S1-S4 and held-out M tables plus the per-log detail behind the contribution claim."""
    a = load("ablation.json")
    src = f"`results/ablation.json`, {run_of(a)}"
    parts = []
    s = a["summary"]["S"]
    rows = []
    for v in VARS:
        x = s[v]
        lims = {m: (min(x[m]["per_log"].values()), max(x[m]["per_log"].values())) for m in ("precision", "recall", "f1")}
        d = x.get("delta_f1_vs_naive")
        dp = x.get("delta_precision_vs_naive")
        rows.append([f"**{v}**" if v == "full" else v]
                    + [f"{num(x[m]['mean'])} ({rng(*lims[m])})" for m in ("precision", "recall", "f1")]
                    + [num(x["rc_hit3"]["mean"]), f"{x['story_nodes']['mean']:,.0f}",
                       "" if d is None else f"{num(d['mean'], signed=True)} {iv(*d['t_ci95'], signed=True)}",
                       "" if dp is None else f"{dp['logs']['higher']}/{dp['logs']['n']}"])
    parts.append(f"**ATLAS S1-S4, design data (in-sample)**: {s['scenarios']} logs, {s['pivots']} pivots ({src}). "
                 "Mean of per-log means with the range over the four logs in brackets. Four logs are too few for "
                 "a useful interval per variant (a 4-log bootstrap cannot extend past the extreme logs) or for a "
                 "distribution-free test (the smallest attainable exact p is 0.125); the ΔF1 column gives a "
                 "t(3) 95 % interval.\n")
    parts.append(table(rows, ["variant", "precision (range)", "recall (range)", "F1 (range)", "root-cause hit@3",
                              "story vertices", "ΔF1 vs naive [t(3) 95 % CI]", "logs with higher precision"]))
    full, naive = s["full"]["f1"]["per_log"], s["naive"]["f1"]["per_log"]
    dfl = s["full"]["delta_f1_vs_naive"]["logs"]
    parts.append("\nPer-log F1, full vs naive: " + "; ".join(
        f"{short(lg)} {num(full[lg])} vs {num(naive[lg])}" for lg in sorted(full))
        + f" (higher on {dfl['higher']} of {dfl['n']} logs, paired t({dfl['df']}) = {num(dfl['t'])}, "
          f"{fmt_p(dfl['t_p'])}).\n")

    m = a["summary"]["M"]
    rows = []
    for v in VARS:
        x = m[v]
        d = x.get("delta_f1_vs_naive")
        dp = x.get("delta_precision_vs_naive")
        rows.append([f"**{v}**" if v == "full" else v]
                    + [f"{num(x[k]['mean'])} {iv(*x[k]['ci95'])}" for k in ("precision", "recall", "f1",
                                                                          "entity_recall")]
                    + [num(x["rc_hit3"]["mean"]), f"{x['story_nodes']['mean']:,.0f}",
                       "" if d is None else (f"{num(d['mean'], signed=True)} {iv(*d['ci95'], signed=True)}; "
                                             f"{d['logs']['higher']}/{d['logs']['n']} logs, sign-flip "
                                             f"{fmt_p(d['logs']['sign_flip_p'])}"),
                       "" if dp is None else (f"{dp['logs']['higher']}/{dp['logs']['n']} "
                                              f"(sign test {fmt_p(dp['logs']['sign_test_p'])})")])
    parts.append(f"**ATLAS M1-M6 host logs, held out**: {m['scenarios']} logs, {m['pivots']} pivots ({src}). "
                 "Mean of per-log means, 95 % log-cluster bootstrap. Paired tests are over logs (pivots in one "
                 f"log share a graph); with {m['scenarios']} logs the smallest attainable exact p is "
                 f"{fmt_p(2 / 2 ** m['scenarios'])[4:]}.\n")
    parts.append(table(rows, ["variant", "precision", "recall", "F1", "entity recall", "root-cause hit@3",
                              "story vertices", "ΔF1 vs naive", "logs with higher precision"]))
    st = m["naive+stops"]
    dpr, drc = st["delta_precision_vs_naive"], st["delta_recall_vs_naive"]
    parts.append(f"\n**Session-root stops alone (naive+stops vs naive), held out**: precision "
                 f"{num(dpr['mean'], signed=True)} {iv(*dpr['ci95'], signed=True)}, higher on {dpr['logs']['higher']} "
                 f"of {dpr['logs']['n']} logs (exact sign test {fmt_p(dpr['logs']['sign_test_p'])}; "
                 f"{dpr['pivots']['higher']} of {sum(dpr['pivots'].values())} pivots higher, "
                 f"{dpr['pivots']['lower']} lower); recall {num(drc['mean'], 4, signed=True)} "
                 f"{iv(*drc['ci95'], 4, signed=True)}, lower on {drc['logs']['lower']} of {drc['logs']['n']} logs "
                 f"({drc['logs']['tied']} tied).\n")
    ts, fu = m["time+stops"]["f1"]["per_log"], m["full"]["f1"]["per_log"]
    diff = {lg: ts[lg] - fu[lg] for lg in sorted(fu)}
    mu, lo, hi = cluster_bootstrap(diff)
    lt = paired_log_test(diff)
    rc = [x["rc_hit3"]["mean"] for g in ("S", "M") for v, x in a["summary"][g].items() if v in VARS]
    parts.append(f"**Highest held-out F1 point estimate**: time+stops {num(m['time+stops']['f1']['mean'])} vs full "
                 f"{num(m['full']['f1']['mean'])}; difference {num(mu, signed=True)} {iv(lo, hi, signed=True)}, "
                 f"higher on {lt['higher']} of {lt['n']} logs (sign-flip {fmt_p(lt['sign_flip_p'])}), so it is the "
                 f"highest point estimate, not a significant winner. Root-cause hit@3 ranges "
                 f"{num(min(rc))}-{num(max(rc))} over all variants and both groups.\n")
    rows = []
    for name, d in stops_split(m).items():
        lt = sign_test(d["dp"])
        rows.append([name, str(len(d["logs"])), f"{num(sum(d['dp']) / len(d['dp']), 3, signed=True)}",
                     f"{num(min(d['dp']), 3, signed=True)} to {num(max(d['dp']), 3, signed=True)}",
                     f"{lt['higher']}/{len(d['dp'])}", f"{num(sum(d['dr']) / len(d['dr']), 4, signed=True)}"])
    parts.append("The held-out logs are unseen *host logs* from the same ATLAS testbed; 8 of the 12 replay an "
                 "exploit that one of S1-S4 also uses (the CVE is in each log's name). The strictest check of the "
                 "claim is the two multi-host attacks with a new exploit (descriptive, 4 logs):\n")
    parts.append(table(rows, ["held-out logs", "logs", "Δ precision (mean)", "Δ precision (range)",
                              "logs higher", "Δ recall (mean)"]))
    parts.append("")
    return "\n".join(parts)


# --------------------------------------------------------------- IOC pivot
def group_of(scenario: str) -> str:
    """``M (held out)`` or ``S1-S4 (in-sample)``."""
    return "M (held out)" if scenario.startswith("M") else "S1-S4 (in-sample)"


def spread(vals: list[float], held_out: bool, dp: int = 3) -> str:
    """Mean with a 95 % log bootstrap (12 held-out logs) or the range (4 in-sample logs)."""
    mean, lo, hi = cluster_bootstrap(vals)
    if held_out:
        return f"{num(mean, dp)} {iv(lo, hi, dp)}"
    return f"{num(mean, dp)} ({rng(min(vals), max(vals), dp)})"


def atlas_ioc() -> str:
    """One pivot per log (the analyst IOC), three methods."""
    a = load("atlas.json")
    groups: dict[str, dict[str, list[dict]]] = {}
    for r in a["atlas"]:
        groups.setdefault(group_of(r["scenario"]), {}).setdefault(r["method"], []).append(r)
    out = []
    for g, ms in groups.items():
        held = g.startswith("M")
        for m in ("ioc-grep", "naive-bfs", "rootline"):
            if m not in ms:
                continue
            rs = ms[m]
            out.append([g, m, str(len(rs))] + [spread([r[k] for r in rs], held) for k in ("precision", "recall", "f1")]
                       + [f"{sum(r['story_nodes'] for r in rs) / len(rs):,.0f}"])
    note = (f"\n\nSource: `results/atlas.json`, {run_of(a)}. Means over logs; held-out rows give a 95 % log "
            "bootstrap, in-sample rows the range over the four logs. `rootline-noreduce` rows in the JSON are "
            "identical to `rootline` (reduction is lossless by design) and are not shown.")
    if a.get("skipped"):
        note += " Skipped (the starting IOC matches no vertex on that host): " + ", ".join(
            s["scenario"] for s in a["skipped"]) + "."
    return table(out, ["scenarios", "method", "logs", "precision", "recall", "F1", "story vertices"]) + note


def reduction_range() -> tuple[float, float]:
    """Smallest and largest edge reduction over the ATLAS logs."""
    red = load("atlas.json")["reduction"]
    return min(r["edge_ratio"] for r in red), max(r["edge_ratio"] for r in red)


def event_universe() -> str:
    """What ROOTLINE can score vs what ATLAS labels, per log."""
    a = load("ablation.json")
    rows = []
    for s in a["scenarios"]:
        rows.append([short(s["scenario"]) + " (" + exploit_of(s["scenario"]) + ")", f"{s['events']:,}",
                     f"{s['atlas_attack_lines']:,}", f"{s['scored_attack_events']:,}",
                     f"{s['scored_attack_events'] / s['atlas_attack_lines']:.2f}"])
    return table(rows, ["log", "ROOTLINE events", "ATLAS '+' lines", "scored attack events", "ratio"])


# --------------------------------------------------------- published work
def published() -> str:
    """Paper numbers next to ours, with the like-for-like ATLAS reference under our scorer."""
    a = load("ablation.json")
    s, m = a["summary"]["S"], a["summary"]["M"]
    rp = load("atlas_repro.json")
    rows = [
        ["ATLAS paper, Table 5: graph traversal (10 attacks)", "event", "no",
         num(PAPER_TRAVERSAL[0], 3), num(PAPER_TRAVERSAL[1], 3), num(PAPER_TRAVERSAL[2], 3)],
        ["ROOTLINE naive reachability (S1-S4 / M hosts, all pivots)", "event", "no",
         f"{num(s['naive']['precision']['mean'], 3)} / {num(m['naive']['precision']['mean'], 3)}",
         f"{num(s['naive']['recall']['mean'], 3)} / {num(m['naive']['recall']['mean'], 3)}",
         f"{num(s['naive']['f1']['mean'], 3)} / {num(m['naive']['f1']['mean'], 3)}"],
        ["ROOTLINE full (S1-S4 / M hosts, all pivots)", "event", "no",
         f"{num(s['full']['precision']['mean'], 3)} / {num(m['full']['precision']['mean'], 3)}",
         f"{num(s['full']['recall']['mean'], 3)} / {num(m['full']['recall']['mean'], 3)}",
         f"{num(s['full']['f1']['mean'], 3)} / {num(m['full']['f1']['mean'], 3)}"],
        ["ATLAS paper, Table 4: LSTM (10 attacks)", "event", "yes",
         num(PAPER_EVENT_AVG[0], 3), num(PAPER_EVENT_AVG[1], 3), num(PAPER_EVENT_AVG[2], 3)],
    ]
    t1 = table(rows, ["system", "level", "trained on labels", "precision", "recall", "F1"])
    rows = []
    for sc in rp["scenarios"]:
        pap, art = sc["paper"], sc["shipped_artefact"]
        cl, raw = art["with_cleaned_list"], art["raw_model_output"]

        def seeds(variant: str, metric: str, sc=sc) -> str:
            vals = [r[metric] for r in sc["runs"] if r["variant"] == variant]
            return f"{num(sum(vals) / len(vals))} ({rng(min(vals), max(vals))})"
        rows.append([sc["scenario"],
                     f"{pap['tp'] + pap['tn'] + pap['fp'] + pap['fn']:,} ({pap['tp'] + pap['fn']})",
                     f"{cl['entities']:,} ({cl['malicious_entities']})",
                     num(pap["f1"] / 100), num(cl["f1"]), num(raw["f1"]),
                     seeds("regenerated", "f1"), seeds("shipped_resampling", "f1")])
    t2 = table(rows, ["scenario", "entities in paper Table 4 (malicious)", "entities under our scorer (malicious)",
                      "paper F1", "ATLAS cleaned list, our scorer", "ATLAS shipped raw output, our scorer",
                      "our LSTM, regenerated training set: mean (5-seed range)",
                      "our LSTM, ATLAS's shipped training set: mean (5-seed range)"])
    prov = rp.get("provenance", {})
    return (t1 + "\n\n**ATLAS LSTM reproduction, entity level** (`results/atlas_repro.json`, "
            f"{prov.get('workflow', '?')} run {prov.get('run_id', '?')}). Our scorer counts ROOTLINE's abstracted "
            "entity set, which is about a tenth of the paper's; the like-for-like reference is therefore ATLAS's "
            "own cleaned list scored by our scorer, not the paper's number. ATLAS's released `evaluate.py` scores a "
            "manually entered cleaned list (the script stops until one is filled in); for S1 the shipped list "
            "equals the ground truth.\n\n" + t2)


# ---------------------------------------------------------------- anomaly
def anomaly() -> str:
    """Unsupervised process ranking: means with across-log uncertainty, and paired tests on the held-out logs."""
    a = load("atlas.json")
    by: dict[tuple[str, str], dict[str, dict]] = {}
    for r in a.get("anomaly", []):
        if r["method"].startswith("random"):
            continue
        by.setdefault((group_of(r["scenario"]), r["method"]), {})[r["scenario"]] = r
    rows = []
    for (g, m), rs in by.items():
        held = g.startswith("M")
        fh = [r["first_hit_rank"] for r in rs.values() if r["first_hit_rank"] is not None]
        rows.append([g, m, str(len(rs)), spread(fh, held, 2) if fh else "-",
                     spread([r["recall@10"] for r in rs.values()], held)])
    t1 = table(rows, ["logs", "ranking", "n", "first malicious process at rank", "recall@10"])
    m = "M (held out)"
    heur, ifo, nou = by[(m, "user-dir image first (heuristic)")], by[(m, "iforest")], by[(m, "iforest-no-userdir")]
    tests = []
    for name, x, y in (("user-dir heuristic minus IsolationForest", heur, ifo),
                       ("IsolationForest minus IsolationForest without exec_user_dir", ifo, nou)):
        d = {lg: x[lg]["recall@10"] - y[lg]["recall@10"] for lg in sorted(x)}
        lt = paired_log_test(d)
        tests.append([name, f"{num(lt['mean'], signed=True)} {iv(*lt['t_ci95'], signed=True)}",
                      f"{lt['higher']} / {lt['lower']} / {lt['tied']}", fmt_p(lt["sign_test_p"])])
    t2 = table(tests, ["held-out recall@10, paired over 12 logs", "mean difference [t(11) 95 % CI]",
                       "logs higher / lower / tied", "exact sign test"])
    return (t1 + f"\n\nSource: `results/atlas.json`, {run_of(a)}. IsolationForest per log is the mean over 10 "
            "seeds. Held-out rows give a 95 % log bootstrap, in-sample rows the range over the four logs.\n\n" + t2)


# --------------------------------------------------------------- coverage
def coverage() -> str:
    """Rule coverage with Wilson intervals computed once from the committed counts."""
    c = load("coverage.json")
    rows_all, summ = c["rows"], c["summary"]
    dev_t = {r["technique"].split(".")[0] for r in rows_all if r["split"] in ("dev", "dev2")}
    select = {
        "dev": lambda r: r["split"] == "dev", "dev2": lambda r: r["split"] == "dev2",
        "sealed": lambda r: r["split"] == "sealed",
        "sealed-unseen-technique": lambda r: r["split"] == "sealed" and r["technique"].split(".")[0] not in dev_t,
    }
    derived = sealed_excluding_v03_targets(rows_all)
    out = []
    for k in ("dev", "dev2", "sealed", "sealed-unseen-technique", "sealed-excluding-v03-target-techniques"):
        if k == "sealed-excluding-v03-target-techniques":
            assert derived == summ[k], "derived sealed view no longer matches coverage.json"
            out.append([k + " (derived, see note)", str(derived["datasets"]),
                        str(derived["datasets"] - derived["with_events"]),
                        frac(derived["v03_detected"], derived["with_events"]),
                        frac(derived["v03_technique_match"], derived["with_events"]), "-"])
            continue
        loaded = [r for r in rows_all if select[k](r) and r["events"] > 0]
        n = len(loaded)
        det = sum(1 for r in loaded if r["v03_alerts"])
        tm = sum(1 for r in loaded if any(t.split(".")[0] == r["technique"].split(".")[0]
                                          for t in r["v03_techniques"]))
        assert (det, tm, n) == (summ[k]["v03_detected"], summ[k]["v03_technique_match"], summ[k]["with_events"])
        on = sum(r["v03_on_technique"] for r in loaded)
        al = sum(r["v03_alerts"] for r in loaded)
        out.append([k, str(summ[k]["datasets"]), str(summ[k]["datasets"] - n), frac(det, n), frac(tm, n),
                    frac(on, al) if al else "-"])
    prov = c.get("provenance", {})
    return (table(out, ["split", "captures", "unparsed", "v0.3 detected [Wilson 95 %]",
                        "v0.3 same technique [Wilson 95 %]", "alert precision proxy: on-technique / all alerts"])
            + f"\n\nSource: `results/coverage.json`, {prov.get('workflow')} run {prov.get('run_id')} at "
              f"{str(prov.get('commit', ''))[:7]} (scored once; never re-scored). Wilson intervals are computed "
              "here from the counts. The alert-precision interval treats alerts as independent, but alerts "
              "cluster within captures, so it is too narrow. The derived row excludes sealed captures whose "
              "parent technique a v0.3 rule names (`rootline.bench.sealed_excluding_v03_targets`); it was added "
              "after the scoring run, computed from that run's committed rows, and does not appear in the "
              "run's own artefact.")


# ------------------------------------------------------------------ live
def live() -> str:
    """One row for the detailed run, one for the repeatability window."""
    lv = load("live_ebpf.json")
    rep = lv["repeatability"]
    r1 = lv["run1_detail"]
    first = next(r for r in rep["runs"] if r["run_id"] == lv["run_id"])
    lo, hi = wilson(lv["passed"], lv["repeats"])
    rows = [[f"run {lv['run_id']} ({lv['commit'][:7]}; run conclusion {first['run_conclusion']}: lint failed, "
             "live-ebpf 5/5)", f"{lv['passed']}/{lv['repeats']} {iv(lo, hi)}", f"{lv['passed']}/{lv['repeats']}",
             ", ".join(r1["story"]["root_causes"]), str(r1["story"]["vertices"]), ", ".join(r1["alerts"]),
             str(sum(p["lost_events"] for p in lv["per_run"]))]]
    done = [j for j in rep["jobs"] if j["conclusion"] in ("success", "failure")]
    lo, hi = wilson(rep["passed_jobs"], rep["completed_jobs"])
    clo, chi = wilson(rep["chain_recovered"], rep["jobs_with_result"])
    rcs = {", ".join(j["root_causes"]) for j in done if j["root_causes"]}
    verts = sorted({j["story_vertices"] for j in done if j["story_vertices"] is not None})
    rows.append([f"repeatability: {len(rep['runs'])} push runs on main, {rep['selection']['first_run_id']}.."
                 f"{rep['selection']['last_run_id']} ({rep['runs'][0]['head_sha']}..{rep['runs'][-1]['head_sha']})",
                 f"{rep['passed_jobs']}/{rep['completed_jobs']} {iv(lo, hi)}",
                 f"{rep['chain_recovered']}/{rep['jobs_with_result']} {iv(clo, chi)}",
                 " or ".join(sorted(rcs)), f"{verts[0]}-{verts[-1]}" if len(verts) > 1 else str(verts[0]),
                 "same in every job" if len({tuple(j['alerts']) for j in done if j['alerts']}) == 1 else "varies",
                 str(sum(j["lost_events"] or 0 for j in done))])
    dep = rep.get("dependabot_runs", [])
    note = ""
    if dep:
        ok = sum(d["live_ebpf"]["success"] for d in dep)
        tot = sum(sum(d["live_ebpf"].values()) for d in dep)
        note = (f" Dependabot-branch runs in the same period (not in the window): {len(dep)} runs "
                f"({', '.join(str(d['run_id']) for d in dep)}), {ok}/{tot} live-ebpf jobs passed.")
    return (table(rows, ["CI evidence", "jobs passed [Wilson 95 %]", "chain recovered [Wilson 95 %]",
                         "root causes (one query)", "story vertices", "alerts", "lost events"])
            + f"\n\nSource: `results/live_ebpf.json`; one row per job in `repeatability.jobs`, collected from the "
              f"CI artefacts by `{rep['collector']}`. Cancelled jobs ({rep['cancelled_jobs']}) are excluded. The "
              f"one failure: run {rep['failures'][0]['run_id']} matrix {rep['failures'][0]['matrix']} (fork-parent "
              "check, since corrected; chain recovered)." + note)


# --------------------------------------------------------------- headline
def headline() -> str:
    """The README's headline table: one row per claim, each with its source file and run."""
    a = load("ablation.json")
    s, m = a["summary"]["S"], a["summary"]["M"]
    ab = f"`ablation.json`, bench run {a['provenance']['run_id']}"
    sf, sn = s["full"]["f1"], s["naive"]["f1"]
    sd = s["full"]["delta_f1_vs_naive"]
    md = m["full"]["delta_f1_vs_naive"]
    st = m["naive+stops"]
    dpr, drc = st["delta_precision_vs_naive"], st["delta_recall_vs_naive"]
    split = stops_split(m)
    new = split["exploit not in S1-S4 (M2, M4)"]
    rp = load("atlas_repro.json")
    pap = [sc["paper"]["f1"] / 100 for sc in rp["scenarios"]]
    cl = [sc["shipped_artefact"]["with_cleaned_list"]["f1"] for sc in rp["scenarios"]]
    ours = [sc["summary"][v]["f1"]["mean"] for sc in rp["scenarios"] for v in ("regenerated", "shipped_resampling")]
    c = load("coverage.json")["summary"]
    lv = load("live_ebpf.json")["repeatability"]
    rlo, rhi = reduction_range()
    atl = load("atlas.json")
    rows = [
        ["ATLAS S1-S4 (design data): full method vs naive reachability, event F1",
         f"**{num(sf['mean'])}** vs {num(sn['mean'])}, higher on {sd['logs']['higher']} of {sd['logs']['n']} logs "
         f"(per-log {rng(min(sf['per_log'].values()), max(sf['per_log'].values()))} vs "
         f"{rng(min(sn['per_log'].values()), max(sn['per_log'].values()))}; ΔF1 "
         f"{num(sd['mean'], signed=True)}, t(3) 95 % CI {iv(*sd['t_ci95'], signed=True)})", ab],
        ["ATLAS M1-M6 host logs (**held out**): precision / recall / F1, full vs naive",
         f"{num(m['full']['precision']['mean'])} / {num(m['full']['recall']['mean'])} / "
         f"{num(m['full']['f1']['mean'])} vs {num(m['naive']['precision']['mean'])} / "
         f"{num(m['naive']['recall']['mean'])} / {num(m['naive']['f1']['mean'])}; F1 higher on "
         f"{md['logs']['higher']} of {md['logs']['n']} logs, ΔF1 {num(md['mean'], signed=True)} "
         f"{iv(*md['ci95'], signed=True)} (sign-flip {fmt_p(md['logs']['sign_flip_p'])}, not significant)", ab],
        ["Session-root stops alone, held out",
         f"precision **{num(dpr['mean'], signed=True)}** {iv(*dpr['ci95'], signed=True)}, higher on "
         f"{dpr['logs']['higher']} of {dpr['logs']['n']} logs (exact sign test {fmt_p(dpr['logs']['sign_test_p'])}); "
         f"recall {num(drc['mean'], 4, signed=True)} {iv(*drc['ci95'], 4, signed=True)}", ab],
        ["Same, only the 4 held-out logs whose exploit is not in S1-S4 (M2, M4)",
         f"precision {num(sum(new['dp']) / len(new['dp']), signed=True)}, higher on "
         f"{sum(1 for x in new['dp'] if x > 0)} of {len(new['dp'])} logs (descriptive)", ab],
        ["ATLAS paper's graph-traversal baseline vs ROOTLINE naive reachability, event precision",
         f"{num(PAPER_TRAVERSAL[0])} vs {num(s['naive']['precision']['mean'])} / "
         f"{num(m['naive']['precision']['mean'])}: consistent", "paper Table 5; " + ab],
        ["ATLAS LSTM, our reproduction (entity F1, S1-S4, mean of 5 seeds)",
         f"{rng(min(ours), max(ours))} vs ATLAS's cleaned list under our scorer "
         f"{rng(min(cl), max(cl))} (paper {rng(min(pap), max(pap))}): **not reproduced**",
         f"`atlas_repro.json`, atlas-repro run {rp['provenance']['run_id']}"],
        ["Rule tagger v0.3: in-sample dev2 vs sealed, captures detected",
         f"{frac(c['dev2']['v03_detected'], c['dev2']['with_events'])} vs "
         f"**{frac(c['sealed']['v03_detected'], c['sealed']['with_events'])}**",
         "`coverage.json`, sealed-coverage run 36994398382"],
        ["Live bpftrace probe on a GitHub-hosted kernel",
         f"{lv['passed_jobs']}/{lv['completed_jobs']} CI jobs pass over {len(lv['runs'])} pushes "
         f"{iv(*wilson(lv['passed_jobs'], lv['completed_jobs']))}; chain recovered in **one query** in "
         f"{lv['chain_recovered']}/{lv['jobs_with_result']} "
         f"{iv(*wilson(lv['chain_recovered'], lv['jobs_with_result']))}",
         f"`live_ebpf.json`, ci runs {lv['selection']['first_run_id']}..{lv['selection']['last_run_id']}"],
        ["Graph reduction (16 ATLAS logs)", f"{rlo:.1f}-{rlo if False else rhi:.1f}x fewer edges, lossless by design",
         f"`atlas.json`, bench run {atl['provenance']['run_id']}"],
    ]
    return table(rows, ["Result", "Number", "Source (`results/`)"])


def render() -> str:
    """The full TABLES.md text."""
    parts = ["<!-- Generated by scripts/render_tables.py; do not edit by hand. -->", "",
             "Generated by `python scripts/render_tables.py` from the committed JSON in `results/`. "
             "Do not edit by hand.", "",
             "### Headline results", "", headline(), "",
             "### Ablation (ATLAS, every ground-truth entity as a pivot)", "", ablation(),
             "### ATLAS from the analyst IOC (one pivot per log)", "", atlas_ioc(), "",
             "### Comparison with published ATLAS results", "", published(), "",
             "### Event universe: what ROOTLINE can score vs what ATLAS labels", "", event_universe(), "",
             "### Unsupervised process ranking (ATLAS)", "", anomaly(), "",
             "### Rule coverage, Splunk attack_data (v0.3 rules)", "", coverage(), "",
             "### Live eBPF in CI", "", live(), ""]
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--check", action="store_true", help="do not write; exit 1 if results/TABLES.md is stale")
    ns = p.parse_args(argv)
    text = render()
    target = R / "TABLES.md"
    if ns.check:
        current = target.read_text(encoding="utf-8").replace("\r\n", "\n") if target.exists() else ""
        if current != text:
            print("results/TABLES.md is out of date: run python scripts/render_tables.py", file=sys.stderr)
            return 1
        print("results/TABLES.md is up to date")
        return 0
    target.write_text(text, encoding="utf-8", newline="\n") if sys.version_info >= (3, 10) else None
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
