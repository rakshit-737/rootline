"""Provenance block for generated result files.

Every benchmark script stamps the files it writes with the code state and the
environment that produced them, so a published number can be traced to a
commit and, when it ran in GitHub Actions, to a workflow run id.
"""
from __future__ import annotations

import datetime as _dt
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from . import __version__


def _git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=20, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip()


def provenance(script: str, root: str | Path | None = None) -> dict[str, Any]:
    """Describe the code and environment a result was generated from.

    Args:
        script: Path of the generating script, relative to the repository root.
        root: Repository root (defaults to two levels above this package).

    Returns:
        ``{script, rootline, commit, dirty, workflow, run_id, run_attempt,
        python, pythonhashseed, platform, generated_utc}``. ``commit`` is ``git rev-parse HEAD``
        (``None`` outside a git checkout); ``dirty`` is true when tracked files
        differ from that commit; ``workflow``/``run_id`` come from the GitHub
        Actions environment and are ``None`` for local runs.
    """
    root = Path(root) if root else Path(__file__).resolve().parents[2]
    status = _git(root, "status", "--porcelain", "--untracked-files=no")
    run_id = os.environ.get("GITHUB_RUN_ID")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
    return {
        "script": script,
        "rootline": __version__,
        "commit": _git(root, "rev-parse", "HEAD"),
        "dirty": None if status is None else bool(status),
        "workflow": os.environ.get("GITHUB_WORKFLOW"),
        "run_id": int(run_id) if run_id and run_id.isdigit() else None,
        "run_attempt": int(attempt) if attempt and attempt.isdigit() else None,
        "python": platform.python_version(),
        "pythonhashseed": os.environ.get("PYTHONHASHSEED"),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def describe(p: dict[str, Any] | None) -> str:
    """One-line human summary of a provenance block (for Markdown headers)."""
    if not p:
        return "no provenance recorded"
    where = (f"GitHub Actions `{p['workflow']}` run {p['run_id']}" if p.get("run_id")
             else f"a local run on {p.get('platform', '?')}")
    commit = (p.get("commit") or "?")[:12] + (" (dirty tree)" if p.get("dirty") else "")
    return f"`{p.get('script', '?')}` - rootline {p.get('rootline', '?')}, commit {commit}, {where}, " \
           f"Python {p.get('python', '?')}"
