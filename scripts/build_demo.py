#!/usr/bin/env python3
"""Render the attack-replay UI as a static site (for GitHub Pages).

    python scripts/build_demo.py docs/demo

Runs the real FastAPI app in-process on the committed OTRF Log4Shell excerpt
(Sysmon + AUOMS, fused) plus one synthetic intrusion, and writes every GET
endpoint the UI needs as a file next to a copy of ``index.html`` that is
switched into static mode (no uploads).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient  # noqa: E402

from rootline.api import create_app  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def build(out: Path) -> list[str]:
    app = create_app([[str(FIX / "log4shell_sysmon.json"), str(FIX / "log4shell_auoms.json")]])
    c = TestClient(app)
    c.post("/api/demo", params={"benign": 300}).raise_for_status()
    stories = c.get("/api/stories").json()
    api = out / "api" / "stories"
    api.mkdir(parents=True, exist_ok=True)
    (out / "api" / "stories.json").write_text(json.dumps(stories), encoding="utf-8")
    for s in stories:
        sid = s["id"]
        for suffix, ext in (("", ".json"), ("/stix", ".json"), ("/mermaid", ".mmd"), ("/cypher", ".cypher")):
            r = c.get(f"/api/stories/{sid}{suffix}")
            if r.status_code == 404:
                continue
            r.raise_for_status()
            target = api / f"{sid}{suffix}{ext}"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(r.text, encoding="utf-8")
    html = c.get("/").text.replace('<html lang="en">', '<html lang="en" data-static="1">', 1)
    (out / "index.html").write_text(html, encoding="utf-8")
    return [s["name"] for s in stories]


if __name__ == "__main__":
    dest = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/demo")
    print("static demo:", build(dest), "->", dest)
