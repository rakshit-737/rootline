import math

import pytest

from rootline.stats import (
    cluster_bootstrap,
    fmt_p,
    paired_log_test,
    paired_t,
    sign_flip_test,
    sign_test,
    t_interval,
    t_ppf975,
    t_two_sided_p,
    wilson,
)


def test_wilson_from_counts_is_not_double_rounded():
    lo, hi = wilson(27, 45)
    assert round(lo, 2) == 0.45 and round(hi, 2) == 0.73  # 0.4545 -> 0.45, not 0.455 -> 0.46
    lo, hi = wilson(4, 64)
    assert round(lo, 2) == 0.02 and round(hi, 2) == 0.15
    assert wilson(0, 0) == (0.0, 0.0)


@pytest.mark.parametrize("df,crit", [(1, 12.706), (3, 3.182), (4, 2.776), (9, 2.262), (11, 2.201), (30, 2.042)])
def test_t_critical_values(df, crit):
    assert abs(t_ppf975(df) - crit) < 1e-3
    assert abs(t_two_sided_p(crit, df) - 0.05) < 1e-3


def test_t_interval_and_paired_t():
    m, lo, hi = t_interval([1.0, 2.0, 3.0])
    assert m == 2.0 and abs((hi - m) - 4.303 / math.sqrt(3)) < 1e-3
    assert t_interval([5.0]) == (5.0, 5.0, 5.0)
    r = paired_t([0.1, 0.2, 0.3, 0.4])
    assert r["df"] == 3 and r["t"] > 0 and 0 < r["p"] < 0.05
    assert paired_t([0.0, 0.0])["p"] == 1.0


def test_sign_test_keeps_tiny_p_values():
    r = sign_test([1.0] * 34)
    assert r["higher"] == 34 and r["lower"] == 0
    assert 0 < r["p"] < 1e-9  # exact 2 / 2**34, never stored as 0
    assert sign_test([1, 1, 1, -1])["p"] == 0.625
    assert sign_test([0, 0])["p"] == 1.0 and sign_test([0, 0])["tied"] == 2


def test_sign_flip_exact():
    assert sign_flip_test([0.1] * 12) == 2 / 2 ** 12
    assert sign_flip_test([1.0, -1.0]) == 1.0
    assert sign_flip_test([]) == 1.0
    with pytest.raises(ValueError):
        sign_flip_test([1.0] * 25)


def test_paired_log_test_and_bootstrap():
    r = paired_log_test({"a": 0.2, "b": 0.1, "c": 0.15, "d": 0.05})
    assert r["n"] == 4 and r["higher"] == 4 and r["sign_test_p"] == 0.125 and r["min_attainable_p"] == 0.125
    mean, lo, hi = cluster_bootstrap({"a": 0.2, "b": 0.1, "c": 0.15, "d": 0.05})
    assert lo <= mean <= hi and hi <= 0.2  # a percentile bootstrap cannot pass the largest cluster value


def test_fmt_p_never_prints_zero():
    assert fmt_p(1.2e-10) == "p < 1e-6"
    assert fmt_p(0.00048828125) == "p = 0.00049"
    assert fmt_p(0.039) == "p = 0.039"
    assert fmt_p(None) == "p n/a"
