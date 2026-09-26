# ADR 0005: Standard-library core, optional extras

- Status: accepted (v0.2)

## Decision

- The engine is standard-library Python only: normalizer, loaders, graph,
  reduction, rules, reconstruction, STIX/Mermaid/Cypher export and the CLI. A
  sensor host or a forensic workstation can run it without pip access. CI
  enforces this with a `core-no-extras` job.
- Optional extras:
  - `ml`: scikit-learn, for the IsolationForest tagger.
  - `api`: FastAPI and uvicorn, for the service and replay UI.
  - `stix`: `stix2`, used in tests to validate the hand-built bundle.
  - `bench`: matplotlib, for figures.
- **Neo4j** is supported through an exported Cypher script (`--cypher`) and not
  through a driver dependency. `cypher-shell < story.cypher` loads a story, or
  the whole graph with `to_cypher(g)`, into any Neo4j 5.x. Neither CI nor the
  analysis path needs a database.
- The replay UI is one static HTML file with inline SVG. It uses no CDN, no
  build step and no React. The spec's React suggestion was dropped as
  disproportionate for a single view.

## Consequences

- Tests that need an extra call `pytest.importorskip` and skip cleanly.
- The in-memory graph limits capture size to what fits in RAM (the largest
  benchmark capture, ATLAS S4, is 71k events). Streaming persistence is roadmap work.
