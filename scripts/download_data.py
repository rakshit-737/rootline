#!/usr/bin/env python3
"""Fetch the public datasets ROOTLINE is evaluated on, with SHA-256 checks.

Everything lands OUTSIDE the git repo (default ``../../datasets/rootline``
relative to the repo root, or ``$ROOTLINE_DATA``). Nothing here is executable
content: ATLAS ships pre-processed audit-log CSVs, OTRF and Splunk ship
Sysmon-for-Linux / auditd event logs.

    python scripts/download_data.py                 # required sets
    python scripts/download_data.py --all           # + optional (ATLAS M1-M6, ~62 MB)
    python scripts/download_data.py --source otrf   # one source only
    python scripts/download_data.py --list

Stdlib only. Resumable: files whose checksum already matches are skipped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "data_manifest.json"


def data_dir() -> Path:
    env = os.environ.get("ROOTLINE_DATA")
    if env:
        return Path(env)
    return (HERE.parent.parent.parent / "datasets" / "rootline").resolve()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract(dest: Path) -> None:
    """Unzip next to the archive once (marker file), refusing path traversal."""
    marker = dest.with_suffix(dest.suffix + ".extracted")
    if marker.exists():
        return
    with zipfile.ZipFile(dest) as z:
        base = dest.parent.resolve()
        for m in z.infolist():
            # data only: skip ATLAS' bundled model weights / resampling blobs
            if m.filename.endswith(".h5") or "/resampling/" in m.filename:
                continue
            target = (dest.parent / m.filename).resolve()
            if base not in target.parents and target != base:
                raise SystemExit(f"unsafe path in zip: {m.filename}")
            z.extract(m, dest.parent)
    marker.write_text("ok\n")


def fetch(item: dict, root: Path) -> str:
    dest = root / item["dest"]
    want = item.get("sha256")
    status = "cached"
    if not (dest.exists() and (want is None or sha256(dest) == want)):
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        for attempt in range(1, 6):
            try:
                req = urllib.request.Request(item["url"], headers={"User-Agent": "rootline-data/1"})
                with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as fh:
                    while chunk := r.read(1 << 16):
                        fh.write(chunk)
                break
            except OSError as e:  # URLError, timeouts, resets: flaky links are common
                if attempt == 5:
                    raise SystemExit(f"download failed for {item['url']}: {e}") from e
                time.sleep(2 * attempt)
        got = sha256(tmp)
        if want and got != want:
            tmp.unlink()
            raise SystemExit(f"checksum mismatch for {item['dest']}: {got} != {want}")
        tmp.replace(dest)
        status = "ok"
    if dest.suffix == ".zip":
        try:
            extract(dest)
        except zipfile.BadZipFile:
            dest.unlink()
            raise SystemExit(f"corrupt archive {dest} removed; re-run to download again") from None
    return status


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--all", action="store_true", help="include optional (large) files")
    p.add_argument("--source", choices=["atlas", "otrf", "splunk"])
    p.add_argument("--list", action="store_true")
    p.add_argument("--dest", type=Path, default=None)
    ns = p.parse_args(argv)
    items = json.loads(MANIFEST.read_text())["files"]
    items = [i for i in items if (ns.all or not i.get("optional")) and (not ns.source or i["source"] == ns.source)]
    root = ns.dest or data_dir()
    if ns.list:
        for i in items:
            print(f"{i['source']:7} {i.get('size', 0):>10}  {i['license']:10} {i['dest']}")
        print(f"{len(items)} files, {sum(i.get('size', 0) for i in items) / 1e6:.1f} MB -> {root}")
        return 0
    print(f"[data] {len(items)} files -> {root}")
    for n, i in enumerate(items, 1):
        status = fetch(i, root)
        print(f"  [{n}/{len(items)}] {status:8} {i['dest']}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
