import math
import random
from typing import Iterable, List, Sequence, Tuple


def mean(values: Iterable[float]) -> float:
    values = [float(v) for v in values]
    return sum(values) / len(values) if values else 0.0


def bootstrap_ci(
    values: Sequence[float],
    samples: int = 1000,
    confidence: float = 0.95,
    seed: int = 1337,
) -> Tuple[float, float]:
    data = [float(v) for v in values]
    if not data:
        raise ValueError("bootstrap_ci requires at least one value")
    rng = random.Random(seed)
    estimates = []
    for _ in range(max(1, samples)):
        draw = [data[rng.randrange(len(data))] for _ in data]
        estimates.append(mean(draw))
    estimates.sort()
    alpha = 1.0 - confidence
    low_idx = int((alpha / 2.0) * (len(estimates) - 1))
    high_idx = int((1.0 - alpha / 2.0) * (len(estimates) - 1))
    return round(estimates[low_idx], 6), round(estimates[high_idx], 6)


def paired_t_test(a: Sequence[float], b: Sequence[float]) -> dict:
    diffs = _paired_diffs(a, b)
    n = len(diffs)
    avg = mean(diffs)
    if n < 2:
        return {"n": n, "mean_diff": avg, "t": 0.0, "p_approx": 1.0,
                "note": "insufficient_samples"}
    variance = sum((d - avg) ** 2 for d in diffs) / (n - 1)
    stderr = math.sqrt(variance / n)
    if stderr == 0.0:
        # All differences are identical (zero variance). The t-statistic is
        # undefined, not zero. Report the degenerate case explicitly rather than
        # returning t=0/p=1 which looks like a valid non-significant result.
        return {"n": n, "mean_diff": round(avg, 6), "t": None, "p_approx": None,
                "note": "degenerate_zero_variance" if avg != 0.0 else "all_differences_zero"}
    t_stat = avg / stderr
    p_approx = 2.0 * (1.0 - _normal_cdf(abs(t_stat)))
    return {"n": n, "mean_diff": round(avg, 6), "t": round(t_stat, 6), "p_approx": round(max(0.0, p_approx), 6)}


def wilcoxon_signed_rank(a: Sequence[float], b: Sequence[float]) -> dict:
    diffs = [d for d in _paired_diffs(a, b) if d != 0]
    if not diffs:
        return {"n": 0, "w": 0.0, "z": 0.0, "p_approx": 1.0}
    ranked = sorted((abs(diff), 1 if diff > 0 else -1) for diff in diffs)
    ranks = []
    idx = 0
    while idx < len(ranked):
        end = idx + 1
        while end < len(ranked) and ranked[end][0] == ranked[idx][0]:
            end += 1
        avg_rank = (idx + 1 + end) / 2.0
        for _, sign in ranked[idx:end]:
            ranks.append((avg_rank, sign))
        idx = end
    w_plus = sum(rank for rank, sign in ranks if sign > 0)
    w_minus = sum(rank for rank, sign in ranks if sign < 0)
    w = min(w_plus, w_minus)
    n = len(ranks)
    expected = n * (n + 1) / 4.0
    variance = n * (n + 1) * (2 * n + 1) / 24.0
    z = (w - expected) / math.sqrt(variance) if variance else 0.0
    p_approx = 2.0 * (1.0 - _normal_cdf(abs(z)))
    return {"n": n, "w": round(w, 6), "z": round(z, 6), "p_approx": round(max(0.0, p_approx), 6)}


def mcnemar_test(baseline_correct: Sequence[bool], candidate_correct: Sequence[bool]) -> dict:
    if len(baseline_correct) != len(candidate_correct):
        raise ValueError("McNemar test requires equal-length correctness vectors")
    b01 = sum(1 for base, cand in zip(baseline_correct, candidate_correct) if base and not cand)
    b10 = sum(1 for base, cand in zip(baseline_correct, candidate_correct) if not base and cand)
    denom = b01 + b10
    if denom == 0:
        return {"b01": b01, "b10": b10, "chi2": 0.0, "p_approx": 1.0}
    chi2 = (abs(b01 - b10) - 1) ** 2 / denom
    p_approx = 1.0 - _chi_square_1_cdf(chi2)
    return {"b01": b01, "b10": b10, "chi2": round(chi2, 6), "p_approx": round(max(0.0, p_approx), 6)}


def _paired_diffs(a: Sequence[float], b: Sequence[float]) -> List[float]:
    if len(a) != len(b):
        raise ValueError("paired tests require equal-length inputs")
    return [float(x) - float(y) for x, y in zip(a, b)]


def _normal_cdf(value: float) -> float:
    return 0.5 * (1.0 + math.erf(value / math.sqrt(2.0)))


def _chi_square_1_cdf(value: float) -> float:
    return math.erf(math.sqrt(max(value, 0.0) / 2.0))
