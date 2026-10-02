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
