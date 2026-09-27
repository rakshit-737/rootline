import json
import os
from pathlib import Path

import pytest

from rootline.bench import (
    ioc_seeds,
    prf,
    run_atlas_scenario,
    summarize_coverage,
    technique_of,
    trace_grep,
    trace_naive,
)
from rootline.loaders.atlas import discover, load_scenario
from rootline.pipeline import build_graph

FX = Path(__file__).parent / "fixtures"
DATA = Path(os.environ.get("ROOTLINE_DATA", Path(__file__).resolve().parents[3] / "datasets" / "rootline"))


@pytest.fixture(scope="module")
def mini():
    [(d, s)] = discover(str(FX / "atlas_mini"))
    return load_scenario(d, s)


def test_prf():
    assert prf({1, 2, 3, 4}, {3, 4, 5, 6}) == {"precision": 0.5, "recall": 0.5, "f1": 0.5}
    assert prf(set(), {1}) == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_ioc_seeds_and_baselines(mini):
    g, _ = build_graph(mini.records)
    seeds = ioc_seeds(g, "192.168.223.3")
    assert seeds and all(s.startswith("sock:192.168.223.3:") for s in seeds)
    assert ioc_seeds(g, "") == []
    assert ioc_seeds(g, "0xalsaheel.com") == seeds  # domain resolves to the same sockets
    grep, naive = trace_grep(g, seeds), trace_naive(g, seeds)
    assert set(seeds) <= grep <= naive


def test_rootline_beats_naive_on_mini_atlas(mini):
    rows = {r.method: r for r in run_atlas_scenario(mini)}
    assert set(rows) == {"ioc-grep", "naive-bfs", "rootline-noreduce", "rootline"}
    rl, naive = rows["rootline"], rows["naive-bfs"]
    assert rl.recall >= 0.9 and rl.entity_recall == 1.0
    assert rl.precision >= naive.precision
    assert rl.story_nodes <= naive.story_nodes


def test_anomaly_ranking_on_mini(mini):
    pytest.importorskip("sklearn")
    from rootline.bench import run_anomaly_scenario
    rows = {r["method"]: r for r in run_anomaly_scenario(mini)}
    assert rows["iforest"]["malicious"] >= 1
    assert rows["iforest"]["first_hit_rank"] is not None


def test_coverage_helpers():
    assert technique_of("splunk/attack_techniques/T1548.003/doas/sysmon_linux.log") == "T1548.003"
    assert technique_of("splunk/malware/acidrain/sysmon_linux.log") == "malware/acidrain"
    def row(split, tech, events, techs):
        r = {"split": split, "events": events, "technique": tech}
        for v in ("v01", "v02", "v03"):
            r.update({f"{v}_alerts": len(techs), f"{v}_techniques": techs,
                      f"{v}_on_technique": sum(t.split(".")[0] == tech.split(".")[0] for t in techs)})
        return r
    rows = [row("dev", "T1548", 3, ["T1548.003", "T1105"]), row("dev", "T1", 0, []),
            row("sealed", "T1547.006", 5, ["T1547.006"]), row("sealed", "T1548", 5, [])]
    s = summarize_coverage(rows)
    assert s["dev"]["with_events"] == 1 and s["dev"]["v03_detected"] == 1 and s["dev"]["v03_technique_match"] == 1
    assert s["dev"]["v03_alert_precision"] == 0.5
    assert s["sealed"]["v03_detected"] == 1 and s["sealed"]["v03_detected_ci95"][0] > 0
    assert s["sealed-unseen-technique"]["datasets"] == 1  # T1547 never occurs in dev


def test_wilson():
    from rootline.bench import wilson
    lo, hi = wilson(5, 10)
    assert 0.23 < lo < 0.24 and 0.76 < hi < 0.77
    assert wilson(0, 0) == (0.0, 0.0)


@pytest.mark.realdata
def test_full_atlas_s1_reconstruction():
    root = DATA / "atlas"
    if not root.exists():
        pytest.skip("ATLAS data not downloaded (scripts/download_data.py)")
    d, s = next((d, s) for d, s in discover(str(root)) if s.startswith("S1"))
    rows = {r.method: r for r in run_atlas_scenario(load_scenario(d, s))}
    assert rows["rootline"].recall > 0.99 and rows["rootline"].entity_recall == 1.0
    assert rows["rootline"].precision > 2 * rows["naive-bfs"].precision


@pytest.mark.realdata
def test_committed_results_match_schema():
    f = Path(__file__).resolve().parents[1] / "results" / "atlas.json"
    if not f.exists():
        pytest.skip("results/atlas.json not generated")
    res = json.loads(f.read_text())
    assert {"atlas", "reduction"} <= set(res)


def test_mean_ci():
    from rootline.bench import mean_ci
    assert mean_ci([2.0]) == (2.0, 2.0, 2.0)
    m, lo, hi = mean_ci([1.0, 2.0, 3.0])
    assert m == 2.0 and lo < 2.0 < hi and abs((hi - m) - 4.303 / 3 ** 0.5) < 1e-9


def test_mean_ci_respects_bounds():
    from rootline.bench import clip_anomaly_rows, mean_ci
    # Near-ceiling recall: the raw t-interval would exceed 1.
    vals = [1.0] * 9 + [0.5]
    m, lo, hi = mean_ci(vals, 0.0, 1.0)
    assert m == 0.95 and 0.0 <= lo < m and hi == 1.0
    assert mean_ci(vals)[2] > 1.0  # unbounded call keeps the old behaviour
    # Ranks cannot go below 1.
    _, lo, _ = mean_ci([1, 1, 1, 1, 1, 1, 1, 1, 1, 2], 1.0, None)
    assert lo == 1.0
    rows = clip_anomaly_rows([{"malicious": 2, "processes": 324, "first_hit_rank_ci95": [0.874, 1.3],
                               "hits@10_ci95": [1.674, 2.126], "recall@10_ci95": [0.837, 1.063]}])
    assert rows[0]["first_hit_rank_ci95"] == [1.0, 1.3]
    assert rows[0]["hits@10_ci95"] == [1.674, 2.0]
    assert rows[0]["recall@10_ci95"] == [0.837, 1.0]
