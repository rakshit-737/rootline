import pytest

from rootline.integrations.sentinelcore import adapt
from rootline.models import EventKind
from rootline.normalize import NormalizationError, Normalizer, normalize_record, parse_bpftrace_line


def test_valid_exec():
    ev = normalize_record({"ts": 1.0, "kind": "execve", "pid": 5, "path": "/bin//sh", "argv": "sh -c id"}, 0)
    assert ev.kind is EventKind.EXEC
    assert ev.path == "/bin/sh"
    assert ev.argv == ("sh", "-c", "id")


def test_open_with_write_flags_becomes_write():
    ev = normalize_record({"ts": 1, "kind": "openat", "pid": 5, "path": "/tmp/a", "flags": "O_WRONLY|O_CREAT"}, 0)
    assert ev.kind is EventKind.WRITE


def test_path_traversal_collapsed():
    ev = normalize_record({"ts": 1, "kind": "open", "pid": 5, "path": "/home/a/../../etc/shadow"}, 0)
    assert ev.path == "/etc/shadow"


@pytest.mark.parametrize("bad", [
    {"ts": 1, "kind": "nope", "pid": 1},
    {"ts": "x", "kind": "exit", "pid": 1},
    {"ts": float("nan"), "kind": "exit", "pid": 1},
    {"ts": 1, "kind": "exit"},
    {"ts": 1, "kind": "exit", "pid": -3},
    {"ts": 1, "kind": "exit", "pid": True},
    {"ts": 1, "kind": "connect", "pid": 1, "dst_ip": "999.1.1.1", "dst_port": 80},
    {"ts": 1, "kind": "connect", "pid": 1, "dst_ip": "1.2.3.4", "dst_port": 70000},
    {"ts": 1, "kind": "open", "pid": 1},
    {"ts": 1, "kind": "fork", "pid": 1},
    {"ts": 1, "kind": "exec", "pid": 1, "path": "/x", "argv": {"a": 1}},
    "not a dict",
])
def test_rejects_malformed(bad):
    with pytest.raises(NormalizationError):
        normalize_record(bad, 0)  # type: ignore[arg-type]


def test_normalizer_collects_errors_and_continues():
    n = Normalizer()
    out = list(n.normalize([{"ts": 1, "kind": "exit", "pid": 1}, {"junk": 1}, {"ts": 2, "kind": "exit", "pid": 2}]))
    assert [e.seq for e in out] == [0, 1]
    assert len(n.errors) == 1 and n.errors[0][0] == 1


def test_long_strings_truncated_and_nul_stripped():
    ev = normalize_record({"ts": 1, "kind": "exit", "pid": 1, "comm": "a\x00" * 10000}, 0)
    assert "\x00" not in ev.comm and len(ev.comm) <= 4096


def test_bpftrace_line():
    r = parse_bpftrace_line("ts=1700000000123456789 kind=execve pid=10 ppid=1 uid=0 comm=sh path=/bin/sh")
    ev = normalize_record(r, 0)
    assert ev.kind is EventKind.EXEC and abs(ev.ts - 1700000000.123) < 0.01


def test_sentinelcore_adapter():
    r = adapt({"timestamp_ns": 2_000_000_000, "syscall": "connect", "pid": 3, "process_name": "nc",
               "remote_ip": "192.0.2.1", "remote_port": 4444})
    ev = normalize_record(r, 0)
    assert ev.kind is EventKind.CONNECT and ev.ts == 2.0 and ev.comm == "nc" and ev.dst_port == 4444
