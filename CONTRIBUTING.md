# Contributing to ROOTLINE

Thanks for helping. ROOTLINE is small on purpose: every step of the reconstruction
should be explainable as graph edges. Please keep changes in that spirit.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,bench]"
python -m pytest -q                                # unit + fixture tests; realdata tests skip without data
python -m ruff check src tests scripts repro
mkdocs build --strict                              # docs (pip install -r requirements-docs.txt); docs/hooks.py builds the demo
```

Optional, for the real-data benchmarks:

```bash
python scripts/download_data.py        # ~0.74 GB into $ROOTLINE_DATA (default ~/.cache/rootline)
python scripts/download_data.py --only atlas/S1.zip atlas/M1.zip
python -m pytest -q -m realdata        # tests that need the downloads
python scripts/bench.py --only atlas   # results/atlas.json
python scripts/bench.py --only log4shell
python scripts/render_tables.py        # results/TABLES.md (the README headline table must match it)
```

Commit regenerated results with your change, preferably from the manual `bench` workflow so the
files carry its run id. Do not regenerate `results/coverage.json`: it is the sealed-protocol
record, and `scripts/bench.py --only coverage` refuses to rewrite it unless the frozen sources
are checked out (`--allow-unfrozen` writes the in-sample `results/coverage_head.json` instead).

`make` targets (`make test`, `make bench`, ...) wrap the same commands.

## Ground rules

- **The core stays standard-library only.** New heavy dependencies go behind an
  extra (`ml`, `api`, `stix`, `bench`) with `pytest.importorskip` in their tests.
  CI checks this with the `core-no-extras` job.
- **Parsers treat input as hostile.** Bound sizes, reject DTDs, and skip and count
  malformed records instead of raising. Add a test for each new malformed case.
- **No live malware, no exploit code, no scanning.** Fixtures are event logs. Add
  new public excerpts under `tests/fixtures/` (each file under 1 MB, attribution in
  `SOURCES.txt`). Datasets themselves are never committed. Add them to
  `scripts/data_manifest.json` with a SHA-256.
- **Rules need a reason and a counter-example.** Each new rule maps to an ATT&CK
  technique and has a test that shows it firing, plus one that shows a benign
  look-alike staying quiet. If you read benchmark captures while writing a rule,
  add those captures to the `dev` split. The `sealed` split was scored once with the
  frozen v0.3 rules (docs/protocol.md); any rule or loader change is a new version, and its
  sealed numbers must then be labelled in-sample. Do not edit the files listed in
  `scripts/freeze_v03.json` for cosmetic reasons (docstrings included).
- **Report results honestly.** If a change moves a benchmark number, update
  `results/` and the README table in the same PR, including numbers that got worse.

## Commits and PRs

- Use conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`,
  `refactor:`, `ci:`, `build:`. Keep each one small and logical.
- Record design decisions in `docs/adr/NNNN-title.md`. Copy the format of the
  existing ADRs.
- Add a line to `CHANGELOG.md` under *Unreleased*.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open public issues for
vulnerabilities in the parsers.
