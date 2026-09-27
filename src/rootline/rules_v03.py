"""Command-line rules v0.3 (RL-019..RL-025).

Written in v1.1 against the ``dev`` and ``dev2`` Splunk captures (``dev2`` is
the v1.0 holdout, which was *burned* the moment its misses were published).
Each rule encodes an ATT&CK technique's generic Linux semantics rather than a
string seen in one capture. They were frozen before the ``sealed`` split was
downloaded (see docs/protocol.md), and ``sealed`` was scored exactly once.
"""
from __future__ import annotations

import re

from .graph import ProvenanceGraph
from .models import Alert, Edge, Relation, Severity
from .rules_linux import SHELLS, _alert, _argv, _exec_target, ancestors, comm

SUID_MODE = re.compile(r"(^|\s)([ugo]*\+[rwx]*s[rwx]*|[0-7]?[2467][0-7]{3})(\s|$)")
DANGEROUS_CAPS = re.compile(r"cap_(setuid|setgid|sys_admin|sys_ptrace|dac_override|dac_read_search|sys_module)",
                            re.I)
SUDOERS = re.compile(r"/etc/(sudoers(\.d/|\.tmp|$|\s)|doas\.conf)|NOPASSWD", re.I)
SSH_KEYS = re.compile(r"authorized_keys2?\b")
PRELOAD = re.compile(r"(^|\s)LD_PRELOAD=|/etc/ld\.so\.preload")
UNIT_DIRS = re.compile(r"(/etc/systemd/(system|user)|/(usr/)?lib/systemd/(system|user)|/run/systemd/(system|user)|"
                       r"\.config/systemd/user|\.local/share/systemd/user)(/|\s|$)")
PROFILE = re.compile(r"(/etc/profile(\.d)?(/|\s|$)|/etc/bash\.bashrc|/etc/zsh/|\.bash_profile|\.bashrc|\.zshrc|"
                     r"(^|\s|/)\.profile(\s|$))")
CRED_FILES = re.compile(r"(^|\s)/etc/(shadow|gshadow|security/opasswd)(\s|$)")
FILE_TOOLS = {"cp", "mv", "install", "ln", "tee", "touch", "echo", "printf", "sed", "cat", "dd", "rsync"}
EDITORS = {"vi", "vim", "nano", "ed", "emacs", "editor", "sensible-edito", "visudo", "vipw", "vigr"}
READERS = {"cat", "less", "more", "head", "tail", "cp", "base64", "xxd", "strings", "grep", "tar", "zip",
           "vi", "vim", "nano", "view"}
PKG = {"dpkg", "apt", "apt-get", "rpm", "dnf", "yum", "snap", "snapd", "unattended-upgr", "packagekitd"}


def _interactive(g: ProvenanceGraph, nid: str) -> bool:
    """Launched from a shell or sudo (a human or script), not by a package manager or init."""
    anc = [comm(g, a) for a in ancestors(g, nid, 6)]
    return not any(a in PKG for a in anc) and any(a in SHELLS or a in {"sudo", "doas", "su"} for a in anc)


def r_setuid_caps(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-019 (T1548.001): set the setuid/setgid bit or grant a dangerous file capability."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst)
    if c == "chmod" and SUID_MODE.search(argv):
        return _alert("RL-019", e.dst, e, Severity.HIGH, f"setuid/setgid bit set: {argv[:80]}", "T1548.001",
                      "privilege-escalation")
    if c == "setcap" and DANGEROUS_CAPS.search(argv):
        return _alert("RL-019", e.dst, e, Severity.HIGH, f"dangerous capability granted: {argv[:80]}", "T1548.001",
                      "privilege-escalation")
    return None


def r_kernel_module(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-020 (T1547.006): a kernel module loaded by hand (insmod, or modprobe from a shell/sudo)."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst)
    words = argv.split()
    if c == "insmod" or (c == "modprobe" and "-r" not in words and "--remove" not in words
                         and _interactive(g, e.dst)) or (c == "kmod" and "load" in words):
        return _alert("RL-020", e.dst, e, Severity.HIGH, f"kernel module loaded: {argv[:80]}", "T1547.006",
                      "persistence")
    return None


def r_sudo_abuse(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-021 (T1548.003): sudoers/doas policy edited or a NOPASSWD grant written,
    or sudo used to open a root shell (sudo su / sudo -i / sudo -s / sudo <shell>)."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst)
    words = argv.split()
    if c == "visudo" or ((c in FILE_TOOLS or c in EDITORS) and SUDOERS.search(argv)):
        return _alert("RL-021", e.dst, e, Severity.HIGH, f"sudo policy modified: {argv[:80]}", "T1548.003",
                      "privilege-escalation")
    if c in {"sudo", "doas"} and len(words) >= 2:
        rest = [w for w in words[1:] if not w.startswith("-")]
        flags = [w for w in words[1:] if w.startswith("-")]
        target = rest[0].rsplit("/", 1)[-1] if rest else ""
        if target == "su" or target in SHELLS or (not rest and any(f in ("-i", "-s", "--login", "--shell")
                                                                   for f in flags)):
            return _alert("RL-021", e.dst, e, Severity.MEDIUM, f"root shell via {c}: {argv[:80]}", "T1548.003",
                          "privilege-escalation", 0.6)
    return None


def r_preload_hijack(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-022 (T1574.006): LD_PRELOAD on a command line or /etc/ld.so.preload touched."""
    if _exec_target(g, e) and PRELOAD.search(_argv(g, e.dst)):
        return _alert("RL-022", e.dst, e, Severity.HIGH, f"dynamic linker hijack: {_argv(g, e.dst)[:80]}",
                      "T1574.006", "persistence")
    if e.rel is Relation.WROTE and g.nodes[e.dst].attrs.get("path") == "/etc/ld.so.preload":
        return _alert("RL-022", e.src, e, Severity.CRITICAL, f"{comm(g, e.src)} wrote /etc/ld.so.preload",
                      "T1574.006", "persistence")
    return None


def r_persistence_argv(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-023: a persistence location written or enabled from the command line (the argv view of RL-005):
    systemd units (T1543.002), shell profiles (T1546.004), ssh authorized_keys (T1098.004)."""
    if not _exec_target(g, e) or not _interactive(g, e.dst):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst)
    words = argv.split()
    if c == "systemctl" and any(w in ("enable", "link") for w in words):
        return _alert("RL-023", e.dst, e, Severity.MEDIUM, f"systemd unit enabled: {argv[:80]}", "T1543.002",
                      "persistence", 0.6)
    if c in FILE_TOOLS or c in EDITORS or c == "chmod":
        if UNIT_DIRS.search(argv):
            return _alert("RL-023", e.dst, e, Severity.HIGH, f"systemd unit planted: {argv[:80]}", "T1543.002",
                          "persistence")
        if PROFILE.search(argv):
            return _alert("RL-023", e.dst, e, Severity.HIGH, f"shell profile modified: {argv[:80]}", "T1546.004",
                          "persistence")
        if SSH_KEYS.search(argv):
            return _alert("RL-023", e.dst, e, Severity.HIGH, f"ssh authorized_keys modified: {argv[:80]}",
                          "T1098.004", "persistence")
    return None


def r_cred_dump_argv(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-024 (T1003.008): /etc/shadow (or gshadow/opasswd) read or copied from the command line."""
    if _exec_target(g, e) and comm(g, e.dst) in READERS and CRED_FILES.search(_argv(g, e.dst)):
        return _alert("RL-024", e.dst, e, Severity.HIGH, f"password hashes accessed: {_argv(g, e.dst)[:80]}",
                      "T1003.008", "credential-access")
    return None


RULES_V03_EXTRA = [r_setuid_caps, r_kernel_module, r_sudo_abuse, r_preload_hijack, r_persistence_argv,
                   r_cred_dump_argv]
