# ADR 0009: dev / dev2 / sealed protocol for the rule tagger

- Status: accepted (v1.1). Supersedes the tagging-coverage part of [ADR 0004](0004-evaluation-protocol.md).

## Context

v1.0 reported rule coverage on a 27-capture holdout and then published which holdout
captures were missed. v0.3 rules were written to close exactly those misses, so the
holdout became training data. Quoting it afterwards would overstate generalisation.

## Decision

Three splits, defined in [the protocol page](../protocol.md):

- `dev` (46 captures): v0.2 rules were written from them.
- `dev2` (the burned v1.0 holdout, 27 captures): v0.3 rules were written from them.
- `sealed` (160 captures): every remaining Linux log in `splunk/attack_data` at commit
  `b4573ed3`, selected from the git tree listing only and pinned by the SHA-256 in each
  file's Git LFS pointer.

v0.3 was frozen at commit `153eade`; the freeze (rules, loaders, normaliser, graph) is
checked by `scripts/verify_freeze.py` at the start of the manual `sealed-coverage`
workflow, which scored `sealed` once (run 36994398382). Any later change is v0.4 and its
sealed numbers count as in-sample.

## Consequences

- The sealed result is poor: v0.3 detects 4 of 64 parsed sealed captures (6 %,
  Wilson 95 % [3 %, 15 %]) and matches the technique in 1 of 64; 96 of 160 captures
  are not parsed by the frozen loaders at all (mostly auditd variants). In-sample dev2
  was 23 of 27. The rules do not generalise beyond the captures they were written from,
  and the README says so.
- The freeze commit was pushed only on 2026-10-02, so its date is the author's claim.
  The sealed files and selection rule are public and pinned, so anyone can re-score.

## Addendum (2026-10-03): state after scoring, and an erratum

- After the scoring run, docstrings were edited in `rules_v03.py` and `detect.py` (284c125)
  and in `graph.py`, `models.py`, `pipeline.py` and `loaders/__init__.py` (580470b), and the
  normaliser, graph and Sysmon/auditd loaders were hardened with logic changes (f1e71e6,
  bc6984d). By this ADR's own rule the loaders shipped since v1.1.0 are a post-freeze version:
  the sealed numbers belong to 60e3561, and any sealed re-score at a later commit is in-sample.
  The rule logic itself is unchanged (docstring-free syntax trees equal the freeze), and
  re-scoring dev/dev2 at HEAD reproduces every committed row. Details and the CI checks are in
  [the protocol](../protocol.md#state-after-scoring).
- Erratum: the Wilson interval above was rounded twice. Computed once from 4/64 it is
  [2 %, 15 %] (0.0246, 0.1500), not [3 %, 15 %].
