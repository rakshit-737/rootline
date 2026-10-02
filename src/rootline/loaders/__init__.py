"""Real-data loaders: public provenance / host-telemetry formats -> raw records.

Every loader yields the same raw-record dicts the normalizer already accepts
(``{"ts", "kind", "pid", ...}``), so the graph, tagger and reconstructor are
format-agnostic.

| format | source | module |
|---|---|---|
| sysmon | Sysmon for Linux / Windows XML (OTRF, Splunk attack_data) | `sysmon` |
| auditd | raw `audit.log` or AUOMS syslog (OTRF Log4Shell) | `auditd` |
| atlas | ATLAS pre-processed, event-labelled audit logs | `atlas` |
| jsonl | ROOTLINE JSONL / bpftrace probe output (probe, synth) | `normalize` |
"""
from __future__ import annotations

from typing import Any

FORMATS = ("auto", "jsonl", "sysmon", "auditd")


def sniff(path: str) -> str:
    """Guess a capture's format from its first 8 KB: ``sysmon``, ``auditd`` or ``jsonl``."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(8192)
    if "Linux-Sysmon" in head or "Microsoft-Windows-Sysmon" in head or "<EventID>" in head:
        return "sysmon"
    if "msg=audit(" in head or "AUOMS_" in head:
        return "auditd"
    return "jsonl"


def merge_sources(*sources: list[dict[str, Any]], window: float = 1.0) -> list[dict[str, Any]]:
    """Fuse record streams from several sensors on the same host(s).

    Different sensors see different slices of the same activity (e.g. OTRF's
    Log4Shell capture: Sysmon has java's network connections, AUOMS has the
    ``execve`` whose parent is java). Merging them repairs broken lineage.
    Duplicate ``exec`` records (same host, pid and image within ``window``
    seconds) are kept once - the first source wins - so one exec never
    becomes two process vertices. Host names are compared case-insensitively.
    """
    seen: dict[tuple[str, int, str], list[float]] = {}
    out: list[dict[str, Any]] = []
    for src in sources:
        pending = []
        for r in src:
            r = {**r, "host": str(r.get("host", "")).lower()} if r.get("host") else dict(r)
            if r.get("kind") == "exec":
                key = (r.get("host", ""), int(r.get("pid", -1)), str(r.get("path", "")).rsplit("/", 1)[-1])
                if any(abs(t - float(r["ts"])) <= window for t in seen.get(key, [])):
                    continue
                pending.append((key, float(r["ts"])))
            out.append(r)
        for key, t in pending:
            seen.setdefault(key, []).append(t)
    out.sort(key=lambda r: float(r.get("ts", 0)))
    return out


def load_many(paths: list[str], fmt: str = "auto") -> list[dict[str, Any]]:
    """Load several captures (formats sniffed unless given) and fuse them with :func:`merge_sources`."""
    recs = [load_records(p, fmt) for p in paths]
    return recs[0] if len(recs) == 1 else merge_sources(*recs)


def load_records(path: str, fmt: str = "auto") -> list[dict[str, Any]]:
    """Load one capture as raw records in the given (or sniffed) format."""
    fmt = sniff(path) if fmt == "auto" else fmt
    if fmt == "sysmon":
        from .sysmon import load_sysmon
        return load_sysmon(path)
    if fmt == "auditd":
        from .auditd import load_audit
        return load_audit(path)
    if fmt == "jsonl":
        from ..normalize import read_jsonl
        return list(read_jsonl(path))
    raise ValueError(f"unknown format {fmt!r}; expected one of {FORMATS}")
