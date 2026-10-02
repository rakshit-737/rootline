"""Linux audit (auditd raw ``audit.log`` and Microsoft AUOMS) -> raw records.

Raw auditd splits one syscall across several lines that share an
``audit(<ts>:<serial>)`` id (SYSCALL, EXECVE, CWD, PATH, SOCKADDR, PROCTITLE).
We group by serial, then map the x86_64 syscall number:

* execve/execveat -> ``exec`` (path = first PATH item, argv from EXECVE)
* clone/fork/vfork/clone3 -> ``fork`` (child pid = ``exit``)
* open/openat/creat -> ``read`` or ``write`` from the O_ flags in a1/a2
* unlink/unlinkat/rename -> ``unlink`` of the DELETE-typed PATH
* connect/accept/accept4 -> ``connect``/``accept`` from SOCKADDR ``saddr``

Failed syscalls (``success=no``) are dropped - they moved no information.
AUOMS (Azure's audit multiplexer) emits one pre-joined line per syscall with
named syscalls and ``path_name=[...]``; it is handled by the same mapper.
"""
from __future__ import annotations

import json
import re
import socket
import struct
from typing import Any, Iterable, Iterator

SYSCALLS_X86_64 = {
    "59": "execve", "322": "execveat", "56": "clone", "57": "fork", "58": "vfork", "435": "clone3",
    "2": "open", "257": "openat", "85": "creat", "87": "unlink", "263": "unlinkat", "82": "rename",
    "316": "renameat2", "42": "connect", "43": "accept", "288": "accept4",
}
O_WRONLY, O_RDWR, O_CREAT, O_TRUNC = 0o1, 0o2, 0o100, 0o1000
_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\[[^\]]*\]|\S+)')
_HDR = re.compile(r"(?:type=(\w+)\s+)?(?:msg=)?audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)")


def kv(s: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in _KV.findall(s):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out.setdefault(k, v)
    return out


def _unhex(v: str) -> str:
    """auditd hex-encodes values containing spaces/specials."""
    if v and re.fullmatch(r"[0-9A-Fa-f]+", v) and len(v) % 2 == 0 and len(v) > 2:
        try:
            return bytes.fromhex(v).decode("utf-8", "replace").replace("\x00", " ").strip()
        except ValueError:
            return v
    return v


def decode_saddr(h: str) -> tuple[str, int] | None:
    try:
        b = bytes.fromhex(h)
    except ValueError:
        return None
    if len(b) < 8:
        return None
    fam = struct.unpack("<H", b[:2])[0]
    if fam == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, b[4:8]), struct.unpack(">H", b[2:4])[0]
    if fam == 10 and len(b) >= 24:  # AF_INET6 (10 on Linux, not the host's constant)
        return socket.inet_ntop(socket.AF_INET6, b[8:24]), struct.unpack(">H", b[2:4])[0]
    return None


def _open_kind(flags_hex: str | None) -> str:
    try:
        f = int(flags_hex or "0", 16)
    except ValueError:
        return "read"
    return "write" if f & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC) else "read"


def map_syscall(sc: dict[str, str], paths: list[dict[str, str]], execve: dict[str, str] | None,
                sockaddr: str | None, ts: float, host: str) -> list[dict[str, Any]]:
    if sc.get("success", "yes") != "yes":
        return []
    name = SYSCALLS_X86_64.get(sc.get("syscall", ""), sc.get("syscall", ""))
    try:
        pid, ppid = int(sc.get("pid", "-1")), int(sc.get("ppid", "0"))
    except ValueError:
        return []
    if pid < 0:
        return []
    uid = int(sc["uid"]) if sc.get("uid", "").isdigit() else 0
    comm = _unhex(sc.get("comm", ""))
    exe = _unhex(sc.get("exe", ""))
    base = {"ts": ts, "host": host, "pid": pid, "ppid": ppid, "uid": uid, "comm": comm, "exe": exe}
    named = [p for p in paths if p.get("name") and p.get("name") != "(null)"]

    def pth(p: dict[str, str]) -> str:
        n = _unhex(p["name"])
        cwd = sc.get("cwd", "")
        return n if n.startswith("/") or not cwd else f"{cwd.rstrip('/')}/{n}"

    if name in ("execve", "execveat"):
        target = pth(named[0]) if named else exe
        if not target:
            return []
        argv = []
        if execve:
            argc_s = execve.get("argc", "0") or "0"
            argc = int(argc_s) if argc_s.isdigit() else 0
            argv = [_unhex(execve.get(f"a{i}", "")) for i in range(min(argc, 64))]
        return [{**base, "kind": "exec", "path": target, "comm": target.rsplit("/", 1)[-1], "argv": argv}]
    if name in ("clone", "fork", "vfork", "clone3"):
        try:
            child = int(sc.get("exit", "0"))
        except ValueError:
            return []
        return [{**base, "kind": "fork", "child_pid": child}] if child > 0 else []
    if name in ("open", "openat", "creat"):
        flags = sc.get("a2") if name == "openat" else sc.get("a1")
        kind = "write" if name == "creat" else _open_kind(flags)
        want = [p for p in named if p.get("nametype") in ("NORMAL", "CREATE", None, "")] or named
        return [{**base, "kind": kind, "path": pth(want[-1])}] if want else []
    if name in ("unlink", "unlinkat", "rename", "renameat2"):
        dels = [p for p in named if p.get("nametype") == "DELETE"] or named[-1:]
        return [{**base, "kind": "unlink", "path": pth(p)} for p in dels]
    if name in ("connect", "accept", "accept4") and sockaddr:
        ep = decode_saddr(sockaddr)
        if ep is None or ep[0] in ("0.0.0.0", "::"):
            return []
        return [{**base, "kind": "connect" if name == "connect" else "accept", "dst_ip": ep[0], "dst_port": ep[1]}]
    return []


def read_raw_audit(lines: Iterable[str], host: str = "audit-host") -> Iterator[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for line in lines:
        m = _HDR.search(line)
        if not m:
            continue
        try:
            typ, ts, serial, rest = m.group(1) or "", float(m.group(2)), m.group(3), m.group(4)
        except ValueError:
            continue
        g = groups.get(serial)
        if g is None:
            g = groups[serial] = {"ts": ts, "sc": None, "paths": [], "execve": None, "sockaddr": None, "cwd": None}
            order.append(serial)
        fields = kv(rest)
        if typ == "SYSCALL":
            g["sc"] = fields
        elif typ == "PATH":
            g["paths"].append(fields)
        elif typ == "EXECVE":
            g["execve"] = fields
        elif typ == "SOCKADDR":
            g["sockaddr"] = fields.get("saddr")
        elif typ == "CWD":
            g["cwd"] = fields.get("cwd")
    for serial in order:
        g = groups[serial]
        if g["sc"] is None:
            continue
        sc = dict(g["sc"])
        if g["cwd"]:
            sc["cwd"] = _unhex(g["cwd"])
        paths = sorted(g["paths"], key=lambda p: int(p["item"]) if str(p.get("item", "")).isdigit() else 0)
        yield from map_syscall(sc, paths, g["execve"], g["sockaddr"], g["ts"], host)


def _auoms_list(v: str | None) -> list[str]:
    if not v or not v.startswith("["):
        return []
    return [x.strip().strip('"') for x in v[1:-1].split(",") if x.strip()]


def read_auoms(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """AUOMS lines (raw, or wrapped in Syslog JSON as in OTRF / Sentinel)."""
    for line in lines:
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if not isinstance(obj, dict):
                continue
            line = obj.get("SyslogMessage") or obj.get("EventData") or ""
            host = obj.get("Computer") or obj.get("HostName") or "auoms-host"
        else:
            host = "auoms-host"
        m = _HDR.search(line)
        if not m:
            continue
        f = kv(m.group(4))
        host = f.get("node", host)
        names, types = _auoms_list(f.get("path_name")), _auoms_list(f.get("path_nametype"))
        paths = [{"name": n, "nametype": t, "item": str(i)} for i, (n, t) in enumerate(zip(names, types + [""] * len(names), strict=False))]
        execve = None
        if f.get("syscall") in ("execve", "execveat"):
            pt = f.get("proctitle", "")
            # proctitle is the (possibly truncated) command line of the NEW image
            argv = pt.split()[:64]
            execve = {"argc": str(len(argv)), **{f"a{i}": a for i, a in enumerate(argv)}}
        try:
            ts = float(m.group(2))
        except ValueError:
            continue
        yield from map_syscall(f, paths, execve, f.get("saddr"), ts, host)


def load_audit(path: str, host: str = "audit-host") -> list[dict[str, Any]]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(4096)
        fh.seek(0)
        recs = list(read_auoms(fh) if "AUOMS" in head else read_raw_audit(fh, host))
    recs.sort(key=lambda r: r["ts"])
    return recs
