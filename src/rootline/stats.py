"""Small, dependency-free statistics for the benchmarks.

Everything here is standard library only, so the result files can be
re-derived without NumPy or SciPy:

* :func:`wilson` - Wilson score interval for a binomial proportion.
* :func:`t_interval` / :func:`paired_t` - Student-t interval and paired t-test.
* :func:`cluster_bootstrap` - percentile bootstrap over clusters (logs).
* :func:`sign_test` / :func:`sign_flip_test` - exact paired tests that need no
  distributional assumption; with ``n`` clusters the smallest attainable
  two-sided p-value is ``2 / 2**n``.
* :func:`paired_log_test` - all of the above for one set of per-log paired
  differences, which is the unit the ablation and the anomaly tables test on.
* :func:`fmt_p` - print a p-value without ever printing ``p=0``.
"""
from __future__ import annotations

import math
import random
from collections.abc import Iterable, Mapping, Sequence
from itertools import product
from typing import Any


def mean(xs: Iterable[float]) -> float:
    """Arithmetic mean (exactly rounded ``math.fsum``, so it does not depend on the Python version); ``nan`` if empty."""
    xs = list(xs)
    return math.fsum(xs) / len(xs) if xs else float("nan")


def sig(x: float | None, digits: int = 4) -> float | None:
    """Round to ``digits`` significant digits (keeps tiny p-values non-zero, unlike fixed decimals)."""
    if x is None or x == 0 or math.isinf(x) or math.isnan(x):
        return x
    return float(f"{x:.{digits}g}")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for ``k`` successes in ``n`` trials (``(0, 0)`` when ``n == 0``)."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return max(0.0, c - h), min(1.0, c + h)


# ----------------------------------------------------------------- Student t
def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (modified Lentz)."""
    tiny, eps = 1e-300, 3e-16
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 400):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta function ``I_x(a, b)``."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbt = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log1p(-x)
    bt = math.exp(lbt)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def t_two_sided_p(t: float, df: int) -> float:
    """Two-sided p-value of Student's t statistic ``t`` with ``df`` degrees of freedom."""
    if math.isinf(t):
        return 0.0
    return betainc(df / 2.0, 0.5, df / (df + t * t))


def t_ppf975(df: int) -> float:
    """The 0.975 quantile of Student's t (two-sided 95 % critical value), by bisection."""
    lo, hi = 0.0, 1000.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if t_two_sided_p(mid, df) > 0.05:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def t_interval(xs: Sequence[float]) -> tuple[float, float, float]:
    """Mean and unclipped 95 % Student-t interval; the interval collapses to the mean for ``n < 2``."""
    n = len(xs)
    m = mean(xs)
    if n < 2:
        return m, m, m
    sd = math.sqrt(math.fsum((x - m) ** 2 for x in xs) / (n - 1))
    h = t_ppf975(n - 1) * sd / math.sqrt(n)
    return m, m - h, m + h


def paired_t(diffs: Sequence[float]) -> dict[str, Any]:
    """One-sample t-test of paired differences against zero: ``{t, df, p}`` (``p`` two-sided)."""
    n = len(diffs)
    if n < 2:
        return {"t": None, "df": max(0, n - 1), "p": None}
    m = mean(diffs)
    sd = math.sqrt(math.fsum((x - m) ** 2 for x in diffs) / (n - 1))
    if sd == 0:
        t = math.inf if m else 0.0
        return {"t": t if m >= 0 else -t, "df": n - 1, "p": 0.0 if m else 1.0}
    t = m / (sd / math.sqrt(n))
    return {"t": t, "df": n - 1, "p": t_two_sided_p(t, n - 1)}


# ---------------------------------------------------------------- resampling
def cluster_bootstrap(per_cluster: Mapping[str, float] | Sequence[float], b: int = 2000,
                      seed: int = 0) -> tuple[float, float, float]:
    """Mean of cluster means and a 95 % percentile interval, resampling whole clusters.

    With few clusters the percentile interval cannot extend past the largest or
    smallest cluster value, so it is too narrow for ``n`` of about 4; report the
    per-cluster values or :func:`t_interval` there instead.
    """
    vals = list(per_cluster.values()) if isinstance(per_cluster, Mapping) else list(per_cluster)
    if not vals:
        return float("nan"), float("nan"), float("nan")
    rng = random.Random(seed)
    boots = sorted(mean([rng.choice(vals) for _ in vals]) for _ in range(b))
    return mean(vals), boots[int(0.025 * b)], boots[int(0.975 * b) - 1]


# ------------------------------------------------------------- exact tests
def sign_test(diffs: Iterable[float]) -> dict[str, Any]:
    """Exact two-sided sign test of paired differences (ties dropped). ``p`` is not rounded."""
    diffs = list(diffs)
    higher = sum(1 for d in diffs if d > 0)
    lower = sum(1 for d in diffs if d < 0)
    n = higher + lower
    if n == 0:
        return {"higher": 0, "lower": 0, "tied": len(diffs), "p": 1.0}
    k = min(higher, lower)
    p = min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)
    return {"higher": higher, "lower": lower, "tied": len(diffs) - n, "p": p}


def sign_flip_test(diffs: Sequence[float], max_exact: int = 20) -> float:
    """Exact two-sided sign-flip (paired permutation) test of the mean difference.

    Counts the share of the ``2**n`` sign assignments whose absolute sum is at
    least the observed one. Zero differences do not change the sum and are
    dropped. Raises ``ValueError`` above ``max_exact`` non-zero differences.
    """
    xs = [d for d in diffs if d != 0]
    n = len(xs)
    if n == 0:
        return 1.0
    if n > max_exact:
        raise ValueError(f"exact sign-flip test limited to {max_exact} differences, got {n}")
    obs = abs(sum(xs)) - 1e-12
    hits = sum(1 for signs in product((1, -1), repeat=n) if abs(sum(s * x for s, x in zip(signs, xs, strict=True))) >= obs)
    return hits / 2 ** n


def paired_log_test(diffs: Mapping[str, float] | Sequence[float]) -> dict[str, Any]:
    """Test paired per-log differences: counts, exact sign and sign-flip tests, paired t and its 95 % CI."""
    xs = list(diffs.values()) if isinstance(diffs, Mapping) else list(diffs)
    st = sign_test(xs)
    m, lo, hi = t_interval(xs)
    pt = paired_t(xs)
    return {"n": len(xs), "mean": m, "higher": st["higher"], "lower": st["lower"], "tied": st["tied"],
            "sign_test_p": st["p"], "sign_flip_p": sign_flip_test(xs), "t": pt["t"], "df": pt["df"],
            "t_p": pt["p"], "t_ci95": [lo, hi], "min_attainable_p": 2 / 2 ** len(xs) if xs else 1.0}


def fmt_p(p: float | None, floor_exp: int = -6) -> str:
    """Format a p-value with two significant digits; values below ``10**floor_exp`` print as ``p < 1e-6``."""
    if p is None:
        return "p n/a"
    if p < 10.0 ** floor_exp:
        return f"p < 1e{floor_exp}"
    return f"p = {p:.2g}"
