"""Real-format loaders, exercised on small committed excerpts of public data
(see tests/fixtures/SOURCES.txt) plus hand-written edge cases."""
from pathlib import Path

from rootline.loaders import load_many, load_records, merge_sources, sniff
from rootline.loaders.atlas import discover, entity_matches, load_scenario, parse_lines
from rootline.loaders.auditd import decode_saddr, read_auoms, read_raw_audit
from rootline.loaders.sysmon import SysmonStats, parse_event_xml, read_sysmon
from rootline.pipeline import analyze

FX = Path(__file__).parent / "fixtures"


# ------------------------------------------------------------------ sniffing
def test_sniff_formats():
    assert sniff(str(FX / "sysmon_t1548_find.log")) == "sysmon"
    assert sniff(str(FX / "log4shell_sysmon.json")) == "sysmon"
    assert sniff(str(FX / "auditd_arp_cache.log")) == "auditd"
    assert sniff(str(FX / "log4shell_auoms.json")) == "auditd"


# -------------------------------------------------------------------- sysmon
def test_sysmon_process_create_becomes_fork_and_exec():
    recs = load_records(str(FX / "sysmon_t1548_find.log"))
    kinds = {r["kind"] for r in recs}
    assert {"fork", "exec"} <= kinds
    find = [r for r in recs if r["kind"] == "exec" and r["path"] == "/usr/bin/find"]
    assert find and find[0]["argv"][:3] == ["find", ".", "-exec"]
    assert [r["ts"] for r in recs] == sorted(r["ts"] for r in recs)


def test_sysmon_rejects_dtd_and_counts_bad_lines():
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]>'
            "<Event><System><EventID>1</EventID></System></Event>")
    assert parse_event_xml(bomb) is None
    st = SysmonStats()
    assert list(read_sysmon(["<Event><broken", "", "not xml"], stats=st)) == []
    assert st.bad == 1 and st.lines == 3


def test_sysmon_syslog_prefixed_lines():
    xml = ('<Event><System><EventID>11</EventID><Computer>h</Computer></System><EventData>'
           '<Data Name="UtcTime">2024-01-01 00:00:00.000</Data><Data Name="ProcessId">42</Data>'
           '<Data Name="Image">/usr/bin/curl</Data><Data Name="TargetFilename">/tmp/x</Data></EventData></Event>')
    recs = list(read_sysmon([f"May 13 13:42:08 host sysmon: {xml}"]))
    assert recs == [{"ts": 1704067200.0, "host": "h", "pid": 42, "comm": "curl", "exe": "/usr/bin/curl",
                     "kind": "write", "path": "/tmp/x"}]


# -------------------------------------------------------------------- auditd
def test_raw_auditd_groups_multiline_records():
    recs = load_records(str(FX / "auditd_arp_cache.log"))
    execs = [r for r in recs if r["kind"] == "exec"]
    assert {r["path"] for r in execs} >= {"/usr/sbin/arp"}
    arp = next(r for r in execs if r["path"] == "/usr/sbin/arp")
    assert arp["argv"] == ["arp", "-a"] and arp["ppid"] == 29002


def test_raw_auditd_open_connect_unlink():
    sa = "02001F90C0A80206" + "00" * 8  # AF_INET 192.168.2.6:8080
    lines = [
        'type=SYSCALL msg=audit(10.0:1): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=1 a2=241 '
        'ppid=1 pid=7 uid=0 comm="sh" exe="/bin/sh"',
        'type=CWD msg=audit(10.0:1): cwd="/root"',
        'type=PATH msg=audit(10.0:1): item=0 name="out.txt" nametype=CREATE',
        'type=SYSCALL msg=audit(11.0:2): arch=c000003e syscall=42 success=yes exit=0 ppid=1 pid=7 uid=0 comm="sh" exe="/bin/sh"',
        f'type=SOCKADDR msg=audit(11.0:2): saddr={sa}',
        'type=SYSCALL msg=audit(12.0:3): arch=c000003e syscall=87 success=yes exit=0 ppid=1 pid=7 uid=0 comm="rm" exe="/bin/rm"',
        'type=PATH msg=audit(12.0:3): item=0 name="/var/log/auth.log" nametype=DELETE',
        'type=SYSCALL msg=audit(13.0:4): arch=c000003e syscall=257 success=no exit=-2 a2=0 ppid=1 pid=7 comm="sh" exe="/bin/sh"',
    ]
    recs = list(read_raw_audit(lines, host="t"))
    assert [(r["kind"], r.get("path") or r.get("dst_ip")) for r in recs] == [
        ("write", "/root/out.txt"), ("connect", "192.168.2.6"), ("unlink", "/var/log/auth.log")]
    assert recs[1]["dst_port"] == 8080
    assert decode_saddr("zz") is None


def test_auoms_syslog_json():
    recs = load_records(str(FX / "log4shell_auoms.json"))
    bash = [r for r in recs if r["kind"] == "exec" and r["pid"] == 17790]
    assert bash and bash[0]["ppid"] == 1340 and bash[0]["path"] == "/bin/bash"
    assert list(read_auoms(["garbage", "{bad json"])) == []


# --------------------------------------------------------------------- fusion
def test_merge_sources_dedups_exec_and_repairs_lineage():
    fx = [str(FX / "log4shell_sysmon.json"), str(FX / "log4shell_auoms.json")]
    alone = analyze(load_records(fx[0]))
    fused = analyze(load_many(fx))
    # alone, the reverse shell's lineage stops before java; fused it reaches the JNDI callbacks
    assert "java[1340]" not in {alone.graph.nodes[n].label for n in alone.reconstruction.nodes}
    back = {fused.graph.nodes[n].label for n in fused.reconstruction.nodes}
    assert "java[1340]" in back
    assert {"192.168.2.6:1389", "192.168.2.6:8888"} <= {fused.graph.nodes[n].label
                                                         for n in fused.reconstruction.root_causes}
    a = [{"ts": 1.0, "host": "H", "kind": "exec", "pid": 5, "path": "/bin/sh"}]
    b = [{"ts": 1.2, "host": "h", "kind": "exec", "pid": 5, "path": "/bin/sh"},
         {"ts": 9.0, "host": "h", "kind": "exec", "pid": 5, "path": "/bin/sh"}]
    assert [r["ts"] for r in merge_sources(a, b)] == [1.0, 9.0]


# ---------------------------------------------------------------------- ATLAS
def test_atlas_parse_lines_mapping():
    lines = [
        "100,evil.com,10.0.0.9,,,,,,,,,,,,,,,,,-LD+",
        "101,,,4,1,/device/harddiskvolume1/users/u/payload.exe,,,,,,,,,,,,,,-LA+",
        "102,,,4,1,c:/users/u/payload.exe,10.0.0.5,49000,10.0.0.9,8080,,,,,,,,,,-LA+",
        "103,,,4,1,c:/users/u/payload.exe,,,,,,,,,,,,file_writedata_(or_addfile),c:/users/u/loot.txt,-LA+",
        "104,,,,,,,,,,request,x.com/a.png,,,,,,,,-LB-",
    ]
    recs, dropped = parse_lines(iter(lines), host_ip="10.0.0.5")
    kinds = [r["kind"] for r in recs]
    assert kinds == ["dns", "fork", "exec", "connect", "write"]
    assert recs[2]["path"] == "c:/users/u/payload.exe"
    assert recs[3]["dst_ip"] == "10.0.0.9" and all(r.get("label") == "attack" for r in recs)
    assert dropped["browser"] == 1


def test_atlas_scenario_fixture_and_entity_matching():
    [(d, s)] = discover(str(FX / "atlas_mini"))
    sc = load_scenario(d, s)
    assert sc.host_ip == "192.168.223.128" and "payload.exe" in sc.host_labels
    a = analyze(sc.records)
    ips = [n for n in a.graph.nodes.values() if n.attrs.get("ip") == "192.168.223.3"]
    assert ips and entity_matches(ips[0].label, ips[0].attrs, "192.168.223.3")
    assert any(entity_matches(ips[0].label, n.attrs, "0xalsaheel.com") for n in ips)
    procs = [n for n in a.graph.nodes.values() if n.attrs.get("exe", "").endswith("payload.exe")]
    assert procs and entity_matches(procs[0].label, procs[0].attrs, "payload.exe")
