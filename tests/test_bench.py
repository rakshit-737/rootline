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
    rows = [{"split": "dev", "events": 3, "v01_alerts": 0, "v02_alerts": 2, "technique": "T1548",
             "v02_techniques": ["T1548.003"]},
            {"split": "dev", "events": 0, "v01_alerts": 0, "v02_alerts": 0, "technique": "T1", "v02_techniques": []}]
    assert summarize_coverage(rows) == {"dev": {"datasets": 2, "with_events": 1, "v01_detected": 0,
                                                "v02_detected": 1, "v02_technique_match": 1}}


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
