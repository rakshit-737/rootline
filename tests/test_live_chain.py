"""The live-eBPF assertion logic, run on a committed capture (the CI job runs it on a live one)."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("assert_chain", ROOT / "scripts" / "live" / "assert_chain.py")
ac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ac)


@pytest.mark.parametrize("name", ["live_chain_synthetic.log", "live_chain_ci.log"])
def test_chain_recovered(name):
    lines = (ROOT / "tests" / "fixtures" / name).read_text().splitlines()
    res = ac.check_chain(lines)
    assert all(res["checks"].values()), res["checks"]
    assert res["story"]["download_socket_is_origin_of_script"]
    assert res["story"]["root_causes"] == ["/tmp/rootline-lab-stage.sh"]


def test_self_pid_check_catches_probe_lines():
    lines = (ROOT / "tests" / "fixtures" / "live_chain_synthetic.log").read_text().splitlines()
    lines.append("ts=1002600000000 kind=write pid=9 ppid=1 uid=0 comm=bpftrace path=/x fd=1")
    assert ac.check_chain(lines)["checks"]["self_pid"] is False


def test_ipv6_connect_normalizes():
    from rootline.normalize import normalize_record, parse_bpftrace_line
    ev = normalize_record(parse_bpftrace_line(
        "ts=5 kind=connect pid=3 ppid=1 uid=0 comm=curl dst_ip=::1 dst_port=4445"), 0)
    assert ev.dst_ip == "::1" and ev.dst_port == 4445


def test_v12_capture_from_ci():
    """Real probe v1.2 capture (CI run 36996901332, run 1): one query reaches the download socket."""
    lines = (ROOT / "tests" / "fixtures" / "live_chain_ci_v12.jsonl").read_text(encoding="utf-8").splitlines()
    res = ac.check_chain(lines, probe_pid=2862, lab_ip="198.51.100.7", decoy="/tmp/tmp.QzJZVbE5GZ/bpftrace")
    assert res["format"] == "v1.2-json"
    assert all(res["checks"].values()), res["checks"]
    assert "198.51.100.7:8081" in res["story"]["root_causes"]
    assert {"RL-002", "RL-004", "RL-005", "RL-006"} <= set(res["alerts"])
    # the self filter is by PID: a record forged with the probe's PID fails the check
    forged = lines + ['{"type": "printf", "data": "tsns=1 kind=exit pid=2862 ppid=1 uid=0 comm=x\\n"}']
    assert ac.check_chain(forged, probe_pid=2862, decoy="/tmp/tmp.QzJZVbE5GZ/bpftrace")["checks"]["self_pid"] is False
