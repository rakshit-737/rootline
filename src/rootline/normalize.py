"""Event normalizer: raw records (ROOTLINE JSONL, bpftrace lines,
SentinelCore stream) -> validated :class:`Event` objects.

Untrusted input: every field is type-checked and bounded; malformed records
are rejected (collected in ``errors``) rather than crashing ingestion.
"""
from __future__ import annotations

import ipaddress
import json
import posixpath
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from .models import Event, EventKind

MAX_STR = 4096
MAX_ARGV = 64

_KIND_ALIASES = {
    "clone": "fork", "vfork": "fork", "sched_process_fork": "fork",
    "execve": "exec", "sched_process_exec": "exec",
    "openat": "open", "open": "open",
    "unlinkat": "unlink", "connect": "connect", "accept4": "accept",
    "exit_group": "exit", "sched_process_exit": "exit",
}


class NormalizationError(ValueError):
    pass


def _s(v: Any, name: str, required: bool = False) -> str | None:
    if v is None:
        if required:
            raise NormalizationError(f"missing {name}")
        return None
    if not isinstance(v, (str, int, float)):
        raise NormalizationError(f"{name}: bad type")
    s = str(v).replace("\x00", "")
    return s[:MAX_STR]


def _i(v: Any, name: str, default: int | None = None) -> int | None:
    if v is None:
        return default
    if isinstance(v, bool):
        raise NormalizationError(f"{name}: bad type")
    try:
        i = int(v)
    except (TypeError, ValueError) as e:
        raise NormalizationError(f"{name}: not int") from e
    if i < 0 or i > 2**32:
        raise NormalizationError(f"{name}: out of range")
    return i


def _path(v: Any) -> str | None:
    s = _s(v, "path")
    if s is None or s == "":
        return None
    # collapse ../ and // so the same file maps to one vertex
    return posixpath.normpath(s) if s.startswith("/") else s


def normalize_record(rec: dict[str, Any], seq: int, default_host: str = "lab-host") -> Event:
    if not isinstance(rec, dict):
        raise NormalizationError("record is not an object")
    kind_raw = str(rec.get("kind") or rec.get("syscall") or rec.get("type") or "").lower()
    kind_raw = _KIND_ALIASES.get(kind_raw, kind_raw)
    try:
        kind = EventKind(kind_raw)
    except ValueError as e:
        raise NormalizationError(f"unknown kind {kind_raw!r}") from e
    try:
        ts = float(rec["ts"])
    except (KeyError, TypeError, ValueError) as e:
        raise NormalizationError("bad ts") from e
    if ts != ts or ts < 0:  # NaN / negative
        raise NormalizationError("bad ts")
    pid = _i(rec.get("pid"), "pid")
    if pid is None:
        raise NormalizationError("missing pid")
    # open with write flags becomes WRITE
    flags = rec.get("flags")
    if kind is EventKind.OPEN and isinstance(flags, str) and any(f in flags for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "w")):
        kind = EventKind.WRITE
    ip = _s(rec.get("dst_ip") or rec.get("daddr"), "dst_ip")
    if ip is not None:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError as e:
            raise NormalizationError("bad dst_ip") from e
    port = _i(rec.get("dst_port") or rec.get("dport"), "dst_port")
    if port is not None and port > 65535:
        raise NormalizationError("bad dst_port")
    argv = rec.get("argv") or ()
    if isinstance(argv, str):
        argv = argv.split()
    if not isinstance(argv, (list, tuple)):
        raise NormalizationError("bad argv")
    argv = tuple(str(a)[:MAX_STR] for a in argv[:MAX_ARGV])
    ev = Event(
        seq=seq, ts=ts, host=_s(rec.get("host"), "host") or default_host, kind=kind, pid=pid,
        ppid=_i(rec.get("ppid"), "ppid", 0) or 0, uid=_i(rec.get("uid"), "uid", 0) or 0,
        comm=_s(rec.get("comm"), "comm") or "", exe=_path(rec.get("exe")) or "",
        path=_path(rec.get("path") or rec.get("filename")),
        child_pid=_i(rec.get("child_pid"), "child_pid"),
        dst_ip=ip, dst_port=port, argv=argv,
        sha256=_s(rec.get("sha256"), "sha256"), domain=_s(rec.get("domain"), "domain"),
        label=_s(rec.get("label"), "label"),
    )
    if kind is EventKind.FORK and ev.child_pid is None:
        raise NormalizationError("fork without child_pid")
    if kind in (EventKind.OPEN, EventKind.READ, EventKind.WRITE, EventKind.UNLINK, EventKind.EXEC) and not ev.path:
        raise NormalizationError(f"{kind.value} without path")
    if kind is EventKind.DNS and (not ev.domain or ev.dst_ip is None):
        raise NormalizationError("dns without domain/ip")
    if kind in (EventKind.CONNECT, EventKind.ACCEPT) and (ev.dst_ip is None or ev.dst_port is None):
        raise NormalizationError(f"{kind.value} without endpoint")
    return ev


def parse_bpftrace_line(line: str) -> dict[str, Any]:
    """Parse the key=value line format emitted by ``probes/rootline.bt``.

    e.g. ``ts=12.5 kind=execve pid=10 ppid=1 uid=0 comm=sh path=/bin/sh``
    """
    rec: dict[str, Any] = {}
    for tok in line.strip().split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            rec[k] = v
    if "tsns" in rec:  # probe v1.1: explicit nanoseconds (monotonic clock, ~1e11 on a fresh boot)
        rec["ts"] = int(rec.pop("tsns")) / 1e9
    elif "ts" in rec:
        rec["ts"] = float(rec["ts"]) / (1e9 if float(rec["ts"]) > 1e12 else 1)
    return rec


@dataclass
class Normalizer:
    default_host: str = "lab-host"
    errors: list[tuple[int, str]] = field(default_factory=list)
    _seq: int = 0

    def normalize(self, records: Iterable[dict[str, Any]]) -> Iterator[Event]:
        for n, rec in enumerate(records):
            try:
                ev = normalize_record(rec, self._seq, self.default_host)
            except NormalizationError as e:
                self.errors.append((n, str(e)))
                continue
            self._seq += 1
            yield ev


def read_jsonl(path: str) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    yield {"_invalid": line[:80]}
            else:
                yield parse_bpftrace_line(line)


def load_events(path: str, normalizer: Normalizer | None = None) -> list[Event]:
    n = normalizer or Normalizer()
    return sorted(n.normalize(read_jsonl(path)), key=lambda e: (e.ts, e.seq))
