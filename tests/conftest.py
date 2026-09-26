import pytest

from rootline.pipeline import analyze
from rootline.synth import generate


@pytest.fixture(scope="session")
def attack_run():
    recs, truth = generate(200, attack=True, seed=7)
    base, _ = generate(200, attack=False, seed=1)
    return recs, truth, analyze(recs, base)


def rec(ts, kind, pid, **kw):
    return {"ts": ts, "kind": kind, "pid": pid, "host": "h", **kw}
