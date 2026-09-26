"""Command-line rules for real Linux telemetry (v0.2).

Sysmon-for-Linux and auditd captures mostly carry *exec + argv* evidence, not
the file/network syscalls the v0.1 rules were written for. These rules are
derived from MITRE ATT&CK technique semantics and the public GTFOBins
catalogue, and each fires on an EXECUTED edge (image -> new process vertex),
except RL-017 (file write) and RL-018 (an aggregate over a process subtree).
"""
from __future__ import annotations

import re

from .graph import ProvenanceGraph
from .models import Alert, Edge, NodeType, Relation, Severity

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "busybox"}
GTFOBINS = {"find", "awk", "gawk", "mawk", "nawk", "gdb", "vi", "vim", "less", "more", "man", "perl", "python",
            "python2", "python3", "ruby", "php", "node", "lua", "emacs", "tar", "zip", "git", "make", "env",
            "nmap", "apt", "apt-get", "docker", "mysql", "sqlite3", "openvpn", "octave-cli", "octave", "csvtool",
            "cpulimit", "composer", "gem", "puppet", "busybox", "gcc", "c89", "c99", "rpm", "ftp", "expect",
            "tclsh", "wish", "rlwrap", "script", "socat", "journalctl", "systemctl", "nice", "ionice",
            "taskset", "timeout", "stdbuf", "xargs", "flock", "watch", "strace", "ltrace", "ed", "nano"}
SHELL_IN_ARGV = re.compile(r"(/bin/(ba|da|z|k)?sh\b|\bsh -i\b|\bsystem\(|exec \"?/bin|\.shell\b|!sh\b|"
                           r"child_process|os\.execute|-exec /bin|-wrapper /bin|\bbusybox (ba)?sh\b)")
SECURITY_UNITS = re.compile(r"\b(sysmon|auditd?|falco|osqueryd?|apparmor|selinux|ufw|firewalld|"
                            r"rsyslog|syslog-ng|wazuh-agent|clamav|falcon-sensor|mdatp)\b")
CRITICAL_DIRS = re.compile(r"^/(boot|etc|usr|bin|sbin|lib\w*|var/lib|var/log|home|root)?/?\*?$")
TUNNELERS = {"ngrok", "chisel", "frpc", "frps", "gost", "iodine", "dns2tcp", "ligolo", "bore", "cloudflared"}
DISCOVERY = {"uname", "id", "whoami", "hostname", "hostnamectl", "ifconfig", "ip", "arp", "netstat", "ss",
             "ps", "lsmod", "kmod", "lscpu", "lsblk", "w", "who", "last", "lastlog", "groups", "route",
             "getent", "dmidecode", "lsb_release", "systemd-detect-virt", "df", "mount", "users"}
PKG_WRITERS = {"dpkg", "apt", "apt-get", "rpm", "dnf", "yum", "ldconfig", "unattended-upgr", "snapd", "pip", "pip3"}
USER_EXEC = re.compile(r"^/home/[^/]+/(Downloads|Desktop)/|^/(home/[^/]+|root)/\.[^/]+/")


def comm(g: ProvenanceGraph, nid: str) -> str:
    a = g.nodes[nid].attrs
    return a.get("comm") or (a.get("exe") or "").rsplit("/", 1)[-1]


def ancestors(g: ProvenanceGraph, nid: str, max_depth: int = 6) -> list[str]:
    out, cur = [], nid
    for _ in range(max_depth):
        parents = [e.src for e in g.in_edges.get(cur, []) if e.rel is Relation.FORKED]
        if not parents:
            break
        cur = parents[0]
        out.append(cur)
    return out


def _alert(rule, nid, e: Edge, sev, desc, tech, stage, score=1.0) -> Alert:
    return Alert(rule, nid, e.ts, sev, desc, tech, stage, score, [e.seq])


def _base(c: str) -> str:
    """Strip interpreter version suffixes: php7.2 -> php, ruby2.5 -> ruby, python3.6 -> python."""
    return re.sub(r"[\d.]+$", "", c) or c


def _argv(g: ProvenanceGraph, nid: str) -> str:
    return str(g.nodes[nid].attrs.get("argv") or "")


def _exec_target(g: ProvenanceGraph, e: Edge) -> bool:
    return e.rel is Relation.EXECUTED and g.nodes[e.dst].type is NodeType.PROCESS


def _under_sudo(g: ProvenanceGraph, nid: str) -> bool:
    return any(comm(g, a) in {"sudo", "doas", "pkexec"} for a in ancestors(g, nid))


def r_gtfobins_escape(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-008: a sudo-elevated non-shell binary carries a shell in its argv
    (GTFOBins pattern), or directly spawns a shell."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst)
    b = _base(c)
    if (c == "busybox" or c not in SHELLS) and (c in GTFOBINS or b in GTFOBINS) \
            and SHELL_IN_ARGV.search(argv) and _under_sudo(g, e.dst):
        return _alert("RL-008", e.dst, e, Severity.HIGH, f"sudo {c} used as a shell escape: {argv[:80]}",
                      "T1548.003", "privilege-escalation")
    parents = ancestors(g, e.dst, 3)
    if c in SHELLS and parents:
        # the exec's own predecessor vertex is the same pid pre-exec; look past it
        pc = next((comm(g, p) for p in parents if comm(g, p) != c), "")
        src = next((p for p in parents if comm(g, p) == pc), None)
        if (pc in GTFOBINS or _base(pc) in GTFOBINS) and pc not in SHELLS and src and _under_sudo(g, src):
            return _alert("RL-008", e.dst, e, Severity.HIGH, f"sudo {pc} spawned shell {c}",
                          "T1548.003", "privilege-escalation")
    return None


def r_decode_obfuscation(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-009: base64 decoding, or curl/wget with a percent-encoded URL."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst)
    if c == "base64" and re.search(r"(^|\s)(-d\w*|--decode)\b", argv):
        return _alert("RL-009", e.dst, e, Severity.MEDIUM, f"base64 decoding: {argv[:80]}", "T1140",
                      "defense-evasion", 0.6)
    if c in {"curl", "wget"} and len(re.findall(r"%[0-9A-Fa-f]{2}", argv)) >= 6:
        return _alert("RL-009", e.dst, e, Severity.MEDIUM, f"{c} with a percent-encoded URL", "T1027",
                      "defense-evasion", 0.6)
    return None


def r_ingress_argv(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-010: curl/wget saving a remote file or piping it to a shell."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst)
    if c in {"curl", "wget"} and re.search(r"https?://|ftp://", argv) and \
            re.search(r"(^|\s)(-\w*[oO]\w*|--output\S*|--remote-name|-P)(\s|$)|\|\s*(ba)?sh", argv):
        return _alert("RL-010", e.dst, e, Severity.MEDIUM, f"{c} fetched a remote file: {argv[:80]}",
                      "T1105", "delivery", 0.6)
    return None


def r_destruction(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-011: recursive rm of a critical directory, shred, or dd onto a device."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst).split()
    targets = [a for a in argv[1:] if not a.startswith("-")]
    if c == "shred" or (c == "rm" and any(a.startswith("-") and "r" in a.lower() for a in argv)
                        and any(CRITICAL_DIRS.match(a) for a in targets)):
        return _alert("RL-011", e.dst, e, Severity.CRITICAL, f"destructive command: {' '.join(argv)[:80]}",
                      "T1485", "impact")
    if c == "dd" and any(a.startswith("of=/dev/") and a != "of=/dev/null" for a in argv):
        return _alert("RL-011", e.dst, e, Severity.CRITICAL, "dd overwriting a block device", "T1561.001", "impact")
    return None


def r_impair_defenses(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-012: stopping/disabling a security or logging service."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst)
    words = argv.split()
    if c in {"systemctl", "service", "chkconfig", "update-rc.d"} and \
            re.search(r"\b(stop|disable|mask|kill)\b", argv) and SECURITY_UNITS.search(argv):
        return _alert("RL-012", e.dst, e, Severity.HIGH, f"security service stopped: {argv[:80]}",
                      "T1562.001", "defense-evasion")
    if (c == "setenforce" and "0" in words) or (c == "auditctl" and "-D" in words):
        return _alert("RL-012", e.dst, e, Severity.HIGH, f"security control disabled: {argv[:80]}",
                      "T1562.001", "defense-evasion")
    return None


def r_tunnel(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-013: known tunnelling tools, or ssh port forwarding."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst)
    if c in TUNNELERS or (c == "ssh" and re.search(r"(^|\s)-\w*[RDw](\s|$)", argv)):
        return _alert("RL-013", e.dst, e, Severity.HIGH, f"tunnelling tool {c}: {argv[:80]}", "T1572",
                      "command-and-control")
    return None


def r_ssh_batch(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-014: scripted (non-interactive) ssh to another host."""
    if _exec_target(g, e) and comm(g, e.dst) in {"ssh", "sshpass"} and \
            re.search(r"BatchMode=yes|StrictHostKeyChecking=no", _argv(g, e.dst)):
        return _alert("RL-014", e.dst, e, Severity.MEDIUM, "non-interactive ssh to a remote host",
                      "T1021.004", "lateral-movement", 0.6)
    return None


def r_clipboard(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-015: reading the X/Wayland clipboard."""
    if not _exec_target(g, e):
        return None
    c = comm(g, e.dst)
    if c == "wl-paste" or (c in {"xclip", "xsel"} and re.search(r"(^|\s)-(o|out|-output)(\s|$)", _argv(g, e.dst))):
        return _alert("RL-015", e.dst, e, Severity.LOW, "clipboard read", "T1115", "collection", 0.4)
    return None


def r_privesc_exploit(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-016: PwnKit-style pkexec, pre-authenticated root login, or execution
    of a binary from a user download / hidden directory."""
    if not _exec_target(g, e):
        return None
    c, argv = comm(g, e.dst), _argv(g, e.dst).split()
    if c == "pkexec" and len(argv) <= 1:
        return _alert("RL-016", e.dst, e, Severity.CRITICAL, "pkexec with empty argv (PwnKit, CVE-2021-4034)",
                      "T1068", "privilege-escalation")
    if c == "login" and "-f" in argv and "root" in argv:
        return _alert("RL-016", e.dst, e, Severity.CRITICAL, "pre-authenticated root login (login -f root)",
                      "T1548", "privilege-escalation")
    path = g.nodes[e.src].attrs.get("path", "")
    if USER_EXEC.search(path):
        return _alert("RL-016", e.dst, e, Severity.MEDIUM, f"execution from user download/hidden dir {path}",
                      "T1204.002", "execution", 0.6)
    return None


def r_lib_implant(g: ProvenanceGraph, e: Edge) -> Alert | None:
    """RL-017: a non-package-manager process writes a shared object or hidden
    file into a system library directory (userland rootkit staging)."""
    if e.rel is not Relation.WROTE or comm(g, e.src) in PKG_WRITERS:
        return None
    path = g.nodes[e.dst].attrs.get("path", "")
    if re.match(r"^/(usr/)?lib(64|32)?/", path) and (path.endswith(".so") or "/." in path or ".so." in path):
        return _alert("RL-017", e.src, e, Severity.HIGH, f"{comm(g, e.src)} planted {path} in a system lib dir",
                      "T1574.006", "persistence")
    return None


LINUX_RULES = [r_gtfobins_escape, r_decode_obfuscation, r_ingress_argv, r_destruction, r_impair_defenses,
               r_tunnel, r_ssh_batch, r_clipboard, r_privesc_exploit, r_lib_implant]


def discovery_bursts(g: ProvenanceGraph, window: float = 60.0, min_distinct: int = 4) -> list[Alert]:
    """RL-018: one ancestor spawns >= ``min_distinct`` different discovery tools
    within ``window`` seconds (T1082/T1033/T1016 recon sweep)."""
    by_parent: dict[str, list[tuple[float, str, Edge]]] = {}
    for e in g.edges:
        if _exec_target(g, e) and comm(g, e.dst) in DISCOVERY:
            pid = g.nodes[e.dst].attrs.get("pid")
            # nearest ancestor that is a different *process* (skip the pre-exec fork vertex)
            key = next((p for p in ancestors(g, e.dst, 4) if g.nodes[p].attrs.get("pid") != pid), None)
            if key:
                by_parent.setdefault(key, []).append((e.ts, comm(g, e.dst), e))
    out = []
    for parent, items in by_parent.items():
        items.sort(key=lambda x: x[0])
        lo = 0
        for hi in range(len(items)):
            while items[hi][0] - items[lo][0] > window:
                lo += 1
            tools = {t for _, t, _ in items[lo:hi + 1]}
            if len(tools) >= min_distinct:
                out.append(Alert("RL-018", parent, items[hi][0], Severity.MEDIUM,
                                 f"{comm(g, parent)} ran {len(tools)} discovery tools: {', '.join(sorted(tools))}",
                                 "T1082", "discovery", 0.5, [x[2].seq for x in items[lo:hi + 1]]))
                break
    return out
