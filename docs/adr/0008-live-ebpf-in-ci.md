# ADR 0008: Run the bpftrace probe live in CI

- Status: accepted (v1.1). Supersedes [ADR 0007](0007-ebpf-probe-as-reference.md).

## Context

ADR 0007 kept the probe as an untested reference because the development machine is
Windows. GitHub-hosted Ubuntu runners, however, give `sudo`, a recent kernel with BTF,
and `bpftrace` from the distribution archive. That is enough to load the probe on a
real kernel, as long as everything it observes stays inside the throwaway runner.

## Decision

The `live-ebpf` job in `ci.yml` (ubuntu-24.04, five matrix runs per push):

1. creates a throwaway `HOME=/tmp/rl-home` with a dummy credential file (AWS's documented
   example key) and a dummy shell history, and a dummy network interface `rl0` with the
   TEST-NET address 198.51.100.7, so the "remote" server is not loopback but never leaves
   the runner;
2. starts the probe as `sudo sh -c 'exec bpftrace -f json probes/rootline.bt $$'`, so the
   probe knows its own PID and filters on it (a decoy process that renames itself
   `bpftrace` must still be captured);
3. runs a benign chain from a worker thread of a Python parent: download a shell script
   from 198.51.100.7:8081, run it from `/tmp`, read the dummy credentials, write a
   never-enabled unit file and a comment-only cron-style file, delete the dummy history,
   connect to listeners on 198.51.100.7:4444 and `[::1]:4445`;
4. stops the probe and runs `scripts/live/assert_chain.py`, which requires, from **one**
   query on the stage process, the download socket among the root causes and every chain
   step in the story; alerts RL-002/004/005/006; zero lost events; fd→path on writes; the
   IPv6 connect; and that no fork parent is a thread ID.

An EXIT trap removes the interface and every file. The script refuses to run outside
GitHub Actions unless `ROOTLINE_LAB=1` is set.

## Consequences

- The probe is now tested on a real kernel on every push. Over the 15 pushes to main with
  probe v1.2 from 0e86829 to 2aad2d0, 71 of 72 completed jobs passed (Wilson 95 %
  [0.925, 0.998]) and the chain was recovered in all 72; the failure was an over-strict
  fork-parent check, since corrected. One row per job, collected from the CI artefacts by
  `scripts/live/collect_repeatability.py`, is in `results/live_ebpf.json`. (Corrected
  2026-10-03: the earlier count, 41 of 42 over 9 pushes, missed run 36998890924.)
- This is bpftrace on a GitHub-hosted Azure kernel, not a libbpf CO-RE probe, and the
  chain is scripted and benign. It shows the sensor-to-story path works; it says nothing
  about evasion-resistant collection.
- Known gaps stay documented in the probe header: relative paths are not resolved against
  the cwd, fds duplicated with `dup()`/`fcntl` or inherited across `fork` are not mapped,
  argv is not captured, and paths are cut at 64 bytes.
