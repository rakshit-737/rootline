#!/usr/bin/env python3
"""Check that the sources the sealed evaluation depends on match the pre-registered hashes.

    python scripts/verify_freeze.py                 # the working tree (exit 1 on any mismatch)
    python scripts/verify_freeze.py --ref 60e3561   # the commit that scored sealed (passes)
    python scripts/verify_freeze.py --ast 153eade   # which files differ in logic from the freeze?

Hashes are SHA-256 of the file with CRLF normalised to LF (so the check gives the
same answer on Windows checkouts). ``--ref`` hashes ``git show <ref>:<path>``
instead of the working tree, so anyone can confirm that the scored commit equals
the freeze. ``--ast BASE`` compares each file's syntax tree with docstrings removed
(comments never reach the tree) against the same file at BASE: files that differ
only in docstrings or comments report ``same logic``, and the exit code is 1 if
any selected file differs. CI asserts that the three rule files still have the
logic of the freeze (``--files`` restricts the check):

    python scripts/verify_freeze.py --ast 153eade --files src/rootline/rules_v03.py
        src/rootline/rules_linux.py src/rootline/detect.py

At HEAD the loaders, normaliser and graph differ in logic (post-scoring hardening),
so a full ``--ast 153eade`` reports 4 files and exits 1. See docs/protocol.md.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FREEZE = ROOT / "scripts" / "freeze_v03.json"


def lf_sha256(data: bytes) -> str:
    """SHA-256 of ``data`` with CRLF line endings normalised to LF."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def read(rel: str, ref: str | None) -> bytes:
    """A file's bytes from the working tree, or from commit ``ref`` via ``git show``."""
    if ref is None:
        return (ROOT / rel).read_bytes()
    out = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=ROOT, capture_output=True, check=False)
    if out.returncode:
        raise SystemExit(f"git show {ref}:{rel} failed: {out.stderr.decode(errors='replace').strip()} "
                         "(a shallow clone needs: git fetch --unshallow)")
    return out.stdout


def logic_dump(src: bytes) -> str:
    """The module's AST with every docstring removed, as a comparable string."""
    tree = ast.parse(src.decode("utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                node.body = node.body[1:] or [ast.Pass()]
    return ast.dump(tree)


def check_hashes(spec: dict, ref: str | None) -> int:
    """Print one line per frozen file and return the number of hash mismatches."""
    bad = 0
    for rel, want in spec["files"].items():
        got = lf_sha256(read(rel, ref))
        ok = got == want
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {rel} {got[:12]}")
    where = f"at {ref}" if ref else "in the working tree"
    print(f"freeze intact {where}" if not bad else f"{bad} file(s) changed since the freeze ({where})")
    return bad


def check_logic(spec: dict, base: str, ref: str | None) -> int:
    """Compare docstring-free ASTs with ``base``; return the number of files whose logic differs."""
    diff = 0
    for rel in spec["files"]:
        same = logic_dump(read(rel, ref)) == logic_dump(read(rel, base))
        diff += not same
        print(f"{'same logic   ' if same else 'LOGIC CHANGED'} {rel}")
    print(f"{diff} file(s) differ in logic from {base}")
    return diff


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ref", help="check the files as of this commit (git show) instead of the working tree")
    p.add_argument("--ast", metavar="BASE", help="report which files differ in logic (docstrings and comments "
                                                  "ignored) from commit BASE; exit 1 if any selected file does")
    p.add_argument("--files", nargs="+", metavar="PATH",
                   help="restrict the check to these frozen paths (default: every file in freeze_v03.json)")
    ns = p.parse_args(argv)
    spec = json.loads(FREEZE.read_text(encoding="utf-8"))
    if ns.files:
        unknown = set(ns.files) - set(spec["files"])
        if unknown:
            p.error(f"not in freeze_v03.json: {', '.join(sorted(unknown))}")
        spec = {**spec, "files": {k: v for k, v in spec["files"].items() if k in ns.files}}
    if ns.ast:
        return 1 if check_logic(spec, ns.ast, ns.ref) else 0
    return 1 if check_hashes(spec, ns.ref) else 0


if __name__ == "__main__":
    sys.exit(main())
