"""MkDocs hooks: generate everything the docs need, so ``mkdocs build --strict`` works on a fresh clone.

* ``docs/demo/``            static replay UI built from the committed fixtures (scripts/build_demo.py)
* ``docs/img/results/``     the benchmark figures from ``results/figures``
* ``docs/reference/cli.md`` the CLI reference, rendered from the argparse parser itself
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cli_markdown() -> str:
    """Render ``rootline --help`` and every sub-command's help as Markdown."""
    sys.path.insert(0, str(ROOT / "src"))
    from rootline.cli import main

    def helptext(args: list[str]) -> str:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
            main(args + ["--help"])
        return buf.getvalue().rstrip()

    out = ["# CLI reference", "",
           "Generated from the argparse parser at docs build time (`docs/hooks.py`), so it always matches "
           "`rootline --help`.", "", "```text", helptext([]), "```", ""]
    for cmd in ("synth", "analyze", "verify", "serve", "demo"):
        out += [f"## rootline {cmd}", "", "```text", helptext([cmd]), "```", ""]
    return "\n".join(out)


def on_pre_build(config) -> None:  # noqa: ANN001 - mkdocs hook signature
    figs = DOCS / "img" / "results"
    figs.mkdir(parents=True, exist_ok=True)
    for f in (ROOT / "results" / "figures").glob("*.png"):
        shutil.copy2(f, figs / f.name)
    cli = DOCS / "reference" / "cli.md"
    text = cli_markdown()
    if not cli.exists() or cli.read_text(encoding="utf-8") != text:
        cli.write_text(text, encoding="utf-8")
    if not (DOCS / "demo" / "index.html").exists():
        _load("build_demo", ROOT / "scripts" / "build_demo.py").build(DOCS / "demo")
