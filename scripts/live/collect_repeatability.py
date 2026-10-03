#!/usr/bin/env python3
"""Collect the per-job results of the live-eBPF CI job into results/live_ebpf.json.

    python scripts/live/collect_repeatability.py --first 36996901332 --last 37003827535

Selection rule: every run of the ``ci`` workflow triggered by a push to ``main``
whose run id lies in [--first, --last] (run ids increase with time). For each
run the five ``live-ebpf (N)`` jobs are listed through the GitHub API, the
``live-ebpf-N`` artefacts are downloaded with ``gh run download`` into a
scratch directory (never into the repository), and each job's ``result.json``
(written by scripts/live/assert_chain.py) is reduced to one row:
run id, job id, matrix index, head SHA, conclusion, ``passed``, every check,
the story's root causes and vertex count, lost events and the alerts.
Cancelled jobs are listed and excluded from the rates. Dependabot-branch runs
in the same period are listed separately (run ids and job conclusions only).

Needs an authenticated ``gh``. Calls are paced (``--pause`` seconds apart) so
the shared API quota is not hammered; about 3 calls per run. Artefacts expire
90 days after their run (2026-12-31 for the runs above).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from rootline.stats import wilson  # noqa: E402

REPO = "rakshit-737/rootline"
OUT = ROOT / "results" / "live_ebpf.json"


def gh_json(path: str, pause: float) -> dict:
    """GET one GitHub API path through ``gh api`` (paced)."""
    time.sleep(pause)
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def runs_in_window(first: int, last: int, pause: float) -> list[dict]:
    """ci.yml push runs on main with first <= id <= last, oldest first."""
    runs: list[dict] = []
    page = 1
    while True:
        r = gh_json(f"repos/{REPO}/actions/workflows/ci.yml/runs?branch=main&event=push&per_page=100&page={page}",
                    pause)
        batch = r["workflow_runs"]
        runs += [x for x in batch if first <= x["id"] <= last]
        if len(batch) < 100 or min(x["id"] for x in batch) < first:
            break
        page += 1
    return sorted(runs, key=lambda x: x["id"])


def live_jobs(run_id: int, pause: float) -> list[dict]:
    """The live-ebpf matrix jobs of one run."""
    jobs = gh_json(f"repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100", pause)["jobs"]
    return [j for j in jobs if j["name"].startswith("live-ebpf")]


def matrix_of(job_name: str) -> int:
    """``live-ebpf (3)`` -> 3."""
    return int(job_name.split("(")[1].rstrip(")"))


def job_row(run: dict, job: dict, art_dir: Path) -> dict:
    """One row per job; result fields are None when the job has no result.json."""
    k = matrix_of(job["name"])
    row = {"run_id": run["id"], "job_id": job["id"], "matrix": k, "head_sha": run["head_sha"][:7],
           "conclusion": job["conclusion"], "passed": None, "checks": None, "root_causes": None,
           "story_vertices": None, "lost_events": None, "alerts": None, "fork_parents_unseen": None}
    res_file = art_dir / f"live-ebpf-{k}" / "result.json"
    if res_file.exists():
        r = json.loads(res_file.read_text(encoding="utf-8"))
        story = r.get("story", {})
        row.update({"passed": r.get("passed"), "checks": r.get("checks"),
                    "root_causes": story.get("root_causes"), "story_vertices": story.get("vertices"),
                    "lost_events": r.get("lost_events"), "alerts": r.get("alerts"),
                    "fork_parents_unseen": r.get("fork_parents_unseen")})
    return row


def dependabot_runs(since: str, until: str, pause: float) -> list[dict]:
    """ci runs on dependabot/* branches created in [since, until] with their live-ebpf job conclusions."""
    out = []
    r = gh_json(f"repos/{REPO}/actions/workflows/ci.yml/runs?per_page=100&created={since}..{until}", pause)
    for run in sorted(r["workflow_runs"], key=lambda x: x["id"]):
        if not run["head_branch"].startswith("dependabot/"):
            continue
        jobs = live_jobs(run["id"], pause)
        out.append({"run_id": run["id"], "event": run["event"], "branch": run["head_branch"],
                    "head_sha": run["head_sha"][:7],
                    "live_ebpf": {c: sum(1 for j in jobs if j["conclusion"] == c)
                                  for c in ("success", "failure", "cancelled")}})
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--first", type=int, required=True, help="first run id of the window (inclusive)")
    p.add_argument("--last", type=int, required=True, help="last run id of the window (inclusive)")
    p.add_argument("--dependabot-window", nargs=2, metavar=("SINCE", "UNTIL"),
                   help="also list Dependabot-branch ci runs created in this date range (YYYY-MM-DD)")
    p.add_argument("--pause", type=float, default=2.0, help="seconds between GitHub API calls (default 2)")
    p.add_argument("--scratch", type=Path, default=None, help="where to put downloaded artefacts (default: temp)")
    ns = p.parse_args(argv)

    scratch = ns.scratch or Path(tempfile.mkdtemp(prefix="rootline-live-"))
    runs = runs_in_window(ns.first, ns.last, ns.pause)
    rows, per_run = [], []
    for run in runs:
        jobs = sorted(live_jobs(run["id"], ns.pause), key=lambda j: matrix_of(j["name"]))
        art = scratch / str(run["id"])
        if not art.exists() and any(j["conclusion"] in ("success", "failure") for j in jobs):
            time.sleep(ns.pause)
            subprocess.run(["gh", "run", "download", str(run["id"]), "-R", REPO, "-p", "live-ebpf-*",
                            "-D", str(art)], check=True)
        rs = [job_row(run, j, art) for j in jobs]
        rows += rs
        per_run.append({"run_id": run["id"], "head_sha": run["head_sha"][:7], "created": run["created_at"],
                        "run_conclusion": run["conclusion"],
                        "live_ebpf": {c: sum(1 for j in jobs if j["conclusion"] == c)
                                      for c in ("success", "failure", "cancelled")}})
        print(f"[collect] {run['id']} {run['head_sha'][:7]}: "
              + " ".join(f"{r['matrix']}:{r['conclusion']}" for r in rs), flush=True)

    done = [r for r in rows if r["conclusion"] in ("success", "failure")]
    passed = [r for r in done if r["conclusion"] == "success"]
    with_result = [r for r in done if r["checks"] is not None]
    chain = [r for r in with_result if r["checks"].get("chain")]
    lo, hi = wilson(len(passed), len(done))
    clo, chi = wilson(len(chain), len(with_result))
    rep = {
        "collector": "scripts/live/collect_repeatability.py",
        "collected_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": (f"every push run of the ci workflow on main with run id {ns.first}..{ns.last} "
                  f"({runs[0]['head_sha'][:7]}..{runs[-1]['head_sha'][:7]}), "
                  f"{len(runs)} runs x 5 live-ebpf matrix jobs"),
        "selection": {"workflow": "ci.yml", "branch": "main", "event": "push", "first_run_id": ns.first,
                      "last_run_id": ns.last},
        "runs": per_run,
        "completed_jobs": len(done),
        "passed_jobs": len(passed),
        "cancelled_jobs": sum(1 for r in rows if r["conclusion"] == "cancelled"),
        "cancelled_note": ("cancelled jobs (the concurrency group cancels a run when a newer commit is pushed) "
                           "are excluded from the rates; of those, "
                           f"{sum(1 for r in rows if r['conclusion'] == 'cancelled' and r['passed'])} had already "
                           "written a passing result.json, which is kept in 'jobs'"),
        "pass_rate_ci95": [round(lo, 3), round(hi, 3)],
        "jobs_with_result": len(with_result),
        "chain_recovered": len(chain),
        "chain_recovered_ci95": [round(clo, 3), round(chi, 3)],
        "failures": [{k: r[k] for k in ("run_id", "job_id", "matrix", "head_sha", "checks", "fork_parents_unseen")}
                     for r in done if r["conclusion"] == "failure"],
        "jobs": rows,
    }
    if ns.dependabot_window:
        rep["dependabot_runs"] = dependabot_runs(*ns.dependabot_window, ns.pause)
    live = json.loads(OUT.read_text(encoding="utf-8"))
    live["repeatability"] = rep
    live["scope_note"] = ("Top-level run_id/passed/per_run/run1_detail describe run 36996901332 only (5 jobs). "
                          "'repeatability' covers every push run in its stated window, one row per job "
                          "(repeatability.jobs), collected from the CI artefacts by " + rep["collector"] + ".")
    OUT.write_text(json.dumps(live, indent=1) + "\n", encoding="utf-8")
    print(f"[collect] {len(passed)}/{len(done)} completed jobs passed, Wilson 95 % [{lo:.3f}, {hi:.3f}]; "
          f"chain recovered in {len(chain)}/{len(with_result)} jobs with a result; wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
