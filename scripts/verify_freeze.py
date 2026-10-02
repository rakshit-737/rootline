#!/usr/bin/env python3
"""Check that the sources the sealed evaluation depends on match the pre-registered hashes.

    python scripts/verify_freeze.py            # exit 1 on any mismatch

Hashes are SHA-256 of the file with CRLF normalised to LF (so the check gives the
same answer on Windows checkouts). See docs/protocol.md.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FREEZE = ROOT / "scripts" / "freeze_v03.json"


def lf_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def main() -> int:
    spec = json.loads(FREEZE.read_text(encoding="utf-8"))
    bad = 0
    for rel, want in spec["files"].items():
        got = lf_sha256(ROOT / rel)
        ok = got == want
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {rel} {got[:12]}")
    print("freeze intact" if not bad else f"{bad} file(s) changed since the freeze")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
