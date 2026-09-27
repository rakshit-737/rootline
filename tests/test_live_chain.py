"""The live-eBPF assertion logic, run on a committed capture (the CI job runs it on a live one)."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("assert_chain", ROOT / "scripts" / "live" / "assert_chain.py")
ac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ac)


@pytest.mark.parametrize("name", ["live_chain_synthetic.log"])
def test_chain_recovered(name):
    lines = (ROOT / "tests" / "fixtures" / name).read_text().splitlines()
    res = ac.check_chain(lines)
    assert all(res["checks"].values()), res["checks"]
    assert res["story"]["download_socket_in_backward"]


def test_self_pid_check_catches_probe_lines():
    lines = (ROOT / "tests" / "fixtures" / "live_chain_synthetic.log").read_text().splitlines()
    lines.append("ts=1002600000000 kind=write pid=9 ppid=1 uid=0 comm=bpftrace path=/x fd=1")
    assert ac.check_chain(lines)["checks"]["self_pid"] is False


def test_ipv6_connect_normalizes():
    from rootline.normalize import normalize_record, parse_bpftrace_line
    ev = normalize_record(parse_bpftrace_line(
        "ts=5 kind=connect pid=3 ppid=1 uid=0 comm=curl dst_ip=::1 dst_port=4445"), 0)
    assert ev.dst_ip == "::1" and ev.dst_port == 4445
