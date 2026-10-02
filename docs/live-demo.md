# Live demo

The [attack-replay UI](demo/index.html) is published here as a **static** build: the real FastAPI app
is run in-process at docs build time (`scripts/build_demo.py`) on the committed OTRF Log4Shell
excerpt (Sysmon + AUOMS fused) and one synthetic intrusion, and every endpoint the UI reads is
written out as a file. Uploads and the "synthetic demo" button need the live server
(`rootline serve` or the Docker image) and are hidden in the static build.

[Open the replay UI](demo/index.html){ .md-button .md-button--primary }

Use **Play** / **Step** or the slider to walk the timeline; `#step=N` links are shareable.
