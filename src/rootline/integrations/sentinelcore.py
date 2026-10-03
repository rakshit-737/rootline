"""SentinelCore adapter (integration seam).

ROOTLINE is meant to sit on top of SentinelCore's eBPF/strace sensing core
("don't rebuild the sensor; build the graph brain"). SentinelCore's code is
not in this repo, so this module defines the *contract* ROOTLINE expects and
a best-guess field mapping. ``FIELD_MAP`` is an assumption until it is aligned
with SentinelCore's real event schema (listed under Limitations and on the roadmap).

Expected SentinelCore record (JSON per line), e.g.::

    {"timestamp_ns": 1700000000123456789, "syscall": "execve", "pid": 42,
     "ppid": 1, "uid": 1000, "process_name": "sh", "binary": "/bin/sh",
     "args": ["sh", "-c", "id"], "target": "/bin/sh"}
"""
from __future__ import annotations

from typing import Any, Iterable, Iterator, Protocol

FIELD_MAP = {
    "syscall": "kind", "process_name": "comm", "binary": "exe", "args": "argv",
    "target": "path", "remote_ip": "dst_ip", "remote_port": "dst_port",
    "child": "child_pid", "hostname": "host",
}


class EventSource(Protocol):
    """Anything yielding raw records ROOTLINE's normalizer accepts."""

    def __iter__(self) -> Iterator[dict[str, Any]]: ...


def adapt(record: dict[str, Any]) -> dict[str, Any]:
    """Map one SentinelCore record to a ROOTLINE raw record (``timestamp_ns`` becomes ``ts``)."""
    out: dict[str, Any] = {}
    for k, v in record.items():
        out[FIELD_MAP.get(k, k)] = v
    if "timestamp_ns" in record and "ts" not in out:
        out["ts"] = int(record["timestamp_ns"]) / 1e9
        out.pop("timestamp_ns", None)
    return out


def adapt_stream(records: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Lazily adapt a stream of SentinelCore records."""
    for r in records:
        yield adapt(r)
