"""The benchmark scripts refuse to overwrite results when data is missing, and stamp provenance."""
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FX = ROOT / "tests" / "fixtures"


def load_script(name: str, out: Path, data: Path):
    spec = importlib.util.spec_from_file_location(f"script_{name}", ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.OUT = out
    mod.data_dir = lambda: data
    return mod


@pytest.fixture
def dirs(tmp_path):
    out, data = tmp_path / "results", tmp_path / "data"
    out.mkdir()
    data.mkdir()
    return out, data


def test_atlas_without_scenarios_exits_nonzero_and_writes_nothing(dirs, capsys):
    out, data = dirs
    (out / "atlas.json").write_text('{"atlas": [{"keep": 1}]}')
    bench = load_script("bench", out, data)
    with pytest.raises(SystemExit) as e:
        bench.main(["--only", "atlas"])
    assert e.value.code == 2
    assert "no ATLAS scenarios" in capsys.readouterr().err
    assert json.loads((out / "atlas.json").read_text()) == {"atlas": [{"keep": 1}]}


def test_coverage_refuses_without_freeze_or_data(dirs, capsys):
    out, data = dirs
    bench = load_script("bench", out, data)
    bench.freeze_ok = lambda: False
    with pytest.raises(SystemExit) as e:
        bench.main(["--only", "coverage"])
    assert e.value.code == 2 and "freeze check failed" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:  # unfrozen path still needs every dev/dev2 capture
        bench.main(["--only", "coverage", "--allow-unfrozen"])
    assert e.value.code == 2 and "not downloaded" in capsys.readouterr().err
    assert not list(out.glob("coverage*.json"))


def test_log4shell_writes_provenance_and_reports_cached_parts(dirs, capsys):
    out, data = dirs
    (data / "otrf").mkdir()
    shutil.copy(FX / "log4shell_sysmon.json", data / "otrf" / "syslog_sysmon_log4shell_test.json")
    shutil.copy(FX / "log4shell_auoms.json", data / "otrf" / "syslog_auoms_auditd_log4shell_test.json")
    bench = load_script("bench", out, data)
    assert bench.main(["--only", "log4shell"]) == 0
    printed = capsys.readouterr().out
    assert "atlas: no cached result (not run)" in printed and "coverage: no cached result" in printed
    assert "log4shell done" in printed and "atlas done" not in printed
    res = json.loads((out / "log4shell.json").read_text())
    assert res["inputs"]["sysmon+auoms"]["reaches_java"] is True
    assert res["provenance"]["script"] == "scripts/bench.py --only log4shell"
    assert {"commit", "run_id", "python", "rootline"} <= set(res["provenance"])
    assert json.loads((out / "log4shell_story.json").read_text())["generated_by"]["script"].startswith("scripts/")
    assert "Source: `scripts/bench.py --only log4shell`" in (out / "RESULTS.md").read_text()


def test_ablation_without_scenarios_exits_nonzero(dirs, capsys):
    out, data = dirs
    ablation = load_script("ablation", out, data)
    assert ablation.main([]) == 2
    assert "no ATLAS scenarios" in capsys.readouterr().err
    assert not (out / "ablation.json").exists()


def test_verify_freeze_helpers():
    spec = importlib.util.spec_from_file_location("verify_freeze", ROOT / "scripts" / "verify_freeze.py")
    vf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vf)
    assert vf.lf_sha256(b"a\r\nb\n") == vf.lf_sha256(b"a\nb\n")
    a = b'"""Doc."""\ndef f(x):\n    """Old doc."""\n    return x + 1  # comment\n'
    b = b'"""New module doc."""\ndef f(x):\n    """New doc."""\n    return x + 1\n'
    c = b'def f(x):\n    return x + 2\n'
    assert vf.logic_dump(a) == vf.logic_dump(b) != vf.logic_dump(c)
    with pytest.raises(SystemExit):
        vf.main(["--help"])
