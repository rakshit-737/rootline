"""Sysmon (for Linux, and Windows XML) -> ROOTLINE raw records.

Accepts any of the shapes public datasets ship:

* one ``<Event>...</Event>`` XML document per line (Splunk attack_data,
  ``sysmon_linux.log``);
* Azure/Sentinel Syslog JSON lines whose ``SyslogMessage`` holds the XML
  (OTRF Security-Datasets);
* Windows-style exports where the XML is wrapped in ``Message``/``xml``.

Mapping (Sysmon EventID -> ROOTLINE kind):

====  ======================  ====================================================
 1    ProcessCreate           ``fork`` (ParentProcessId -> ProcessId) + ``exec``
 3    NetworkConnect          ``connect`` (Initiated=true) / ``accept``
 5    ProcessTerminate        ``exit``
 9    RawAccessRead           ``read`` of the device
 11   FileCreate              ``write``
 23   FileDelete (archived)   ``unlink``
 26   FileDeleteDetected      ``unlink``
====  ======================  ====================================================

Input is untrusted: any document containing a ``<!`` declaration (DTD,
ENTITY) is rejected before it reaches the stdlib parser, so XXE and
entity-expansion bombs are impossible; malformed lines are skipped and
counted rather than raising.
"""
from __future__ import annotations

import json
import re
import shlex
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

_NS = re.compile(r"\sxmlns=['\"][^'\"]+['\"]")
_EVENT_START = re.compile(r"<Event[\s>]")
MAX_LINE = 1 << 20  # a single Sysmon event is a few KB; longer lines are skipped


def _find_event(s: str) -> str | None:
    """First ``<Event ...>...</Event>`` in ``s``, in linear time (no backtracking regex)."""
    m = _EVENT_START.search(s)
    if not m:
        return None
    end = s.find("</Event>", m.end())
    return s[m.start():end + 8] if end >= 0 else None
LOCAL_IPS = {"0.0.0.0", "::", "0:0:0:0:0:0:0:0", "127.0.0.1", "::1"}


def _ts(s: str | None) -> float | None:
    if not s:
        return None
    s = s.strip().rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s[:26], fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _argv(cmd: str | None) -> list[str]:
    if not cmd or cmd == "-":
        return []
    try:
        return shlex.split(cmd)[:64]
    except ValueError:
        return cmd.split()[:64]


def parse_event_xml(xml: str) -> dict[str, Any] | None:
    """Return ``{"EventID": int, "Computer": str, <Data Name>: value, ...}``."""
    if "<!" in xml:  # no DTD / ENTITY declarations: blocks XXE and entity-expansion bombs
        return None
    try:
        root = ET.fromstring(_NS.sub("", xml, count=1))
    except ET.ParseError:
        return None
    sysn = root.find("System")
    if sysn is None:
        return None
    try:
        eid = int((sysn.findtext("EventID") or "").strip())
    except ValueError:
        return None
    out: dict[str, Any] = {"EventID": eid, "Computer": sysn.findtext("Computer") or ""}
    tc = sysn.find("TimeCreated")
    if tc is not None:
        out["SystemTime"] = tc.get("SystemTime")
    ed = root.find("EventData")
    if ed is not None:
        for d in ed.findall("Data"):
            name = d.get("Name")
            if name:
                out[name] = (d.text or "").strip()
    return out


def _xml_from_line(line: str) -> str | None:
    line = line.strip()
    if not line or len(line) > MAX_LINE:
        return None
    if line.startswith("<"):
        return line
    if not line.startswith("{"):  # syslog-prefixed: "May 13 13:42:08 host sysmon: <Event>..."
        return _find_event(line)
    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            return None
        if not isinstance(obj, dict):
            return None
        for key in ("SyslogMessage", "Message", "xml", "_raw", "message"):
            v = obj.get(key)
            if isinstance(v, str) and "<Event" in v:
                return _find_event(v)
    return None


def to_records(ev: dict[str, Any], host: str | None = None) -> list[dict[str, Any]]:
    """Map one parsed Sysmon event to zero or more ROOTLINE raw records."""
    eid = ev["EventID"]
    ts = _ts(ev.get("UtcTime")) or _ts(ev.get("SystemTime"))
    if ts is None:
        return []
    h = host or ev.get("Computer") or "sysmon-host"
    try:
        pid = int(ev.get("ProcessId") or -1)
    except ValueError:
        return []
    if pid < 0:
        return []
    image = ev.get("Image") or ""
    comm = image.replace("\\", "/").rsplit("/", 1)[-1]
    base = {"ts": ts, "host": h, "pid": pid, "comm": comm, "exe": image if image.startswith("/") else ""}
    user = ev.get("User")
    if user and user.isdigit():
        base["uid"] = int(user)
    if eid == 1:
        try:
            ppid = int(ev.get("ParentProcessId") or 0)
        except ValueError:
            ppid = 0
        pimage = ev.get("ParentImage") or ""
        pcomm = pimage.replace("\\", "/").rsplit("/", 1)[-1]
        recs = []
        if ppid:
            recs.append({"ts": ts, "host": h, "kind": "fork", "pid": ppid, "comm": pcomm,
                         "exe": pimage if pimage.startswith("/") else "", "child_pid": pid,
                         "argv": _argv(ev.get("ParentCommandLine"))})
        if image:
            recs.append({**base, "kind": "exec", "ppid": ppid, "path": image,
                         "argv": _argv(ev.get("CommandLine"))})
        return recs
    if eid == 3:
        initiated = (ev.get("Initiated") or "").lower() == "true"
        rip, rport = (ev.get("DestinationIp"), ev.get("DestinationPort")) if initiated else \
                     (ev.get("SourceIp"), ev.get("DestinationPort"))
        if not rip or rip in LOCAL_IPS:
            return []
        try:
            port = int(rport or 0)
        except ValueError:
            port = 0
        return [{**base, "kind": "connect" if initiated else "accept", "dst_ip": rip, "dst_port": port}]
    if eid == 5:
        return [{**base, "kind": "exit"}]
    if eid == 11 and ev.get("TargetFilename"):
        return [{**base, "kind": "write", "path": ev["TargetFilename"]}]
    if eid in (23, 26) and ev.get("TargetFilename"):
        return [{**base, "kind": "unlink", "path": ev["TargetFilename"]}]
    if eid == 9 and ev.get("Device"):
        return [{**base, "kind": "read", "path": ev["Device"]}]
    return []


class SysmonStats:
    def __init__(self) -> None:
        self.lines = 0
        self.bad = 0
        self.by_id: dict[int, int] = {}


def read_sysmon(lines: Iterable[str], host: str | None = None,
                stats: SysmonStats | None = None) -> Iterator[dict[str, Any]]:
    st = stats or SysmonStats()
    for line in lines:
        st.lines += 1
        xml = _xml_from_line(line)
        if xml is None:
            continue
        ev = parse_event_xml(xml)
        if ev is None:
            st.bad += 1
            continue
        st.by_id[ev["EventID"]] = st.by_id.get(ev["EventID"], 0) + 1
        yield from to_records(ev, host)


def load_sysmon(path: str, host: str | None = None, stats: SysmonStats | None = None) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        recs = list(read_sysmon(fh, host, stats))
    recs.sort(key=lambda r: r["ts"])  # Sysmon record order != time order
    return recs
