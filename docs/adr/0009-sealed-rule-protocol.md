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
