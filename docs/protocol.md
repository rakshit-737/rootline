# Rule-evaluation protocol (v1.1): dev / dev2 / sealed

The v1.0 README reported tagger coverage on a 27-capture "holdout" and then
listed which holdout captures were missed. Once those misses were published
(and used to plan new rules), the holdout could no longer serve as one. v1.1
replaces it with a three-way protocol that makes the leak explicit.

| Split | Captures | Role | Status |
|---|---|---|---|
| `dev` | 46 Splunk Sysmon-for-Linux captures (the OTRF captures are used only as case studies) | v0.2 rules (RL-008..018) were written from these | in-sample |
| `dev2` | the 27 v1.0 holdout captures | v0.3 rules (RL-019..024) were written from these | **burned** (in-sample for v0.3) |
| `sealed` | every Splunk attack_data Linux log under `datasets/attack_techniques/` not already in the manifest (160 files in the git tree of `splunk/attack_data` at commit `b4573ed3`, the `master` head on 2026-09-27) | scored **once** with frozen rules | out-of-sample |

## Pre-registration (written before the sealed files were scored)

1. **Frozen rules.** v0.3 was frozen at commit `153eadeec29c9cdd757051cefe3989eae0c9fe63`
   (SHA-256 of LF-normalised sources: `rules_v03.py` `cc3c1995…`, `rules_linux.py`
   `c69413a1…`, `detect.py` `3d3b628e…`). v0.1 and v0.2 are scored as well, as fixed
   earlier baselines.
2. **Selection rule.** `sealed` = all `*.log` files under `datasets/attack_techniques/`
   of `splunk/attack_data` whose path contains `linux` and which were not in the
   manifest, minus plain-text `auth.log`, `kern.log` and `syslog.log` (no process
   events). Selection used only the git tree listing; no file content was opened
   before scoring. Each file is pinned in `scripts/data_manifest.json` by URL at commit
   `b4573ed3b6bf05473b01048dd36380dbd52288c0` and by the SHA-256 recorded in its Git LFS
   pointer (so the hash was obtained without reading the content). Together the 160 files
   are 1.8 MB.
3. **Loader rule.** The existing loaders are used unchanged. A file from which they
   parse zero events is counted as *unparsed* and reported separately, not dropped
   silently. Any loader or rule change made after scoring becomes a new version,
   and its sealed numbers are then labelled in-sample.
4. **Metrics** (per split and rule version), each with a 95 % Wilson interval:
   - *detected*: share of parsed captures with at least one alert;
   - *technique match*: share whose alerts include the capture's ATT&CK technique
     (parent level: T1548.003 counts for T1548);
   - *alert precision (proxy)*: share of all alerts whose technique matches the
     capture's technique. Captures carry a lot of benign background activity, so
     this is the closest available stand-in for a false-positive rate;
   - `sealed-unseen-technique`: sealed captures whose parent technique never occurs
     in `dev` or `dev2` (pure generalisation).

## Timeline, stated plainly

- 2026-09-27 17:52: v0.3 rules committed (`aed680b`, pushed). Its docstring already said
  "sealed was scored exactly once"; that sentence was written ahead of time and was
  **not true** until the scoring run below.
- 2026-09-27 18:02: freeze commit `153eade`. It stayed **local (unpushed) until
  2026-10-02**, so its timestamp is the author's claim, not a public record.
- 2026-09-27 18:02-18:16: 142 of the 160 sealed files were downloaded to the local data
  folder (after the freeze) and were neither opened nor scored.
- 2026-10-02: the manifest entries above were generated, the remaining 18 files fetched,
  and the loader / normaliser / graph sources were added to the pre-registered hashes in
  `scripts/freeze_v03.json` (they equal their state at `153eade`; `git diff 153eade -- src`
  was empty). `scripts/verify_freeze.py` checks all of them.
- Scoring: once, in the manual `sealed-coverage` GitHub Actions workflow, which runs the
  freeze check first. The run id is recorded in the README and in `results/coverage.json`.

## State after scoring

*Addendum, 2026-10-03. The sections above are unchanged since the scoring run.*

The sealed split was scored once, in `sealed-coverage` run 36994398382 (2026-10-02 10:14 UTC)
at commit `60e3561`, after `scripts/verify_freeze.py` passed. **The sealed numbers belong to
60e3561.** Afterwards, the following commits touched files listed in `scripts/freeze_v03.json`:

| Commit (2026-10-02, UTC) | Frozen files touched | Kind of change |
|---|---|---|
| `284c125` (10:25) | `rules_v03.py`, `detect.py` | docstrings only (the "sealed was scored" sentences) |
| `f1e71e6` (10:36) | `normalize.py`, `loaders/sysmon.py`, `loaders/auditd.py` | **logic**: strict probe-record parsing, visible control characters, bounded timestamps, linear Sysmon scan, malformed numbers skipped |
| `bc6984d` (10:36) | `graph.py` | **logic**: `[v6]:port` socket labels (with the reconstructor's loopback/link-local and IOC fixes) |
| `580470b` (11:09) | `graph.py`, `models.py`, `pipeline.py`, `loaders/__init__.py` | docstrings only |

What this means:

- At v1.1.0 and later, `python scripts/verify_freeze.py` reports 9 of 10 files changed; only
  `rules_linux.py` is byte-identical. The pre-registered hashes still hold at the freeze commit
  and at the scored commit: `python scripts/verify_freeze.py --ref 153eade` and
  `--ref 60e3561` both print "freeze intact".
- The **rule logic is unchanged**: comparing syntax trees with docstrings removed,
  `rules_v03.py`, `rules_linux.py` and `detect.py` at HEAD equal the freeze
  (`python scripts/verify_freeze.py --ast 153eade --files ...`). So do `models.py`,
  `pipeline.py` and `loaders/__init__.py`. `normalize.py`, `graph.py` and the Sysmon and
  auditd loaders differ in logic.
- By rule 3 above, those loaders and the normaliser are a **post-freeze version**. Any sealed
  re-score at a commit after 60e3561 is in-sample and must be labelled so. `scripts/bench.py`
  enforces this: it refuses to rewrite `results/coverage.json` unless the freeze check passes,
  and `--allow-unfrozen` scores only `dev` and `dev2`, into `results/coverage_head.json`.
- Check on in-sample data: re-scoring `dev` and `dev2` with the post-freeze code (bench run
  37092501921 at cde2a39) reproduces all 73 committed rows exactly (34/45, 27/45; 23/27,
  14/27), so the hardening is neutral on the captures the rules were written from. It says
  nothing about sealed, which is not re-scored.
- `results/coverage.json`'s summary key `sealed-excluding-v03-target-techniques` (3/51
  detected) was added after the scoring run. It is computed from that run's committed rows by
  `rootline.bench.sealed_excluding_v03_targets()`; it is not in the run's own artefact.
- CI (`freeze-record` job) checks on every push that the freeze holds at 153eade and 60e3561,
  that the rule logic at HEAD equals the freeze, and that `freeze_v03.json` and
  `results/coverage.json` are unchanged since scoring. The frozen files are no longer edited,
  not even for docstrings.

## Known leaks, stated up front

- The sealed file **paths** (which contain technique IDs and short names such as
  `linux_auditd_insmod`) were visible in the tree listing while v0.3 was written.
  The rules were derived from `dev2` captures and ATT&CK semantics, but the author
  had seen that list.
- Most sealed files are **auditd** captures, a different sensor from the Sysmon dev
  data. That makes the test harder (cross-sensor).
- Splunk labels a whole capture with one technique, and a capture can legitimately
  contain others, so *technique match* is a lower bound.

## Results

See the README ("Rule coverage") and `results/coverage.json`.
