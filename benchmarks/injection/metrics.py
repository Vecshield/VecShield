"""Scoring for the injection benchmark.

Every rate is reported with a 95% Wilson interval, and a rate over fewer than
``MIN_OBSERVATIONS`` rows is not reported at all, the convention
``vecshield_platform/benchmark.py`` already uses.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

MIN_OBSERVATIONS = 5


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (0.0, 1.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def rate(successes: int, total: int) -> dict[str, Any]:
    if total < MIN_OBSERVATIONS:
        return {"n": total, "k": successes, "measured": False}
    low, high = wilson(successes, total)
    return {"n": total, "k": successes, "measured": True,
            "value": round(successes / total, 4), "interval": [round(low, 4), round(high, 4)]}


def group_rates(rows: Iterable[dict], key) -> dict[str, dict]:
    """Share of rows flagged, per group. Recall for attacks, FPR for benign."""
    flagged: dict[str, int] = defaultdict(int)
    total: dict[str, int] = defaultdict(int)
    for row in rows:
        group = key(row)
        if group is None:
            continue
        total[group] += 1
        flagged[group] += bool(row["flagged"])
    return {g: rate(flagged[g], total[g]) for g in sorted(total)}


def _counts_at_thresholds(positives, negatives):
    """Distinct thresholds, descending, with attacks and benign rows at or above each."""
    import numpy as np

    pos = np.sort(np.asarray(positives, dtype=float))
    neg = np.sort(np.asarray(negatives, dtype=float))
    thresholds = np.unique(np.concatenate([pos, neg]))[::-1]
    true = len(pos) - np.searchsorted(pos, thresholds, side="left")
    false = len(neg) - np.searchsorted(neg, thresholds, side="left")
    return thresholds, true, false


def recall_at_fpr(positives: list[float], negatives: list[float], target: float) -> dict:
    """Recall at the lowest score threshold whose FPR does not exceed ``target``.

    The threshold is chosen on the same rows it is scored on, so this is the
    detector's best case at that false-positive rate, not a deployable setting.
    """
    if not positives or not negatives:
        return {"measured": False}
    thresholds, true, false = _counts_at_thresholds(positives, negatives)
    ok = false <= int(target * len(negatives))
    if not ok.any():
        return {"measured": True, "threshold": None, "recall": 0.0, "fpr": 0.0}
    index = int(ok.nonzero()[0][-1])          # lowest threshold still within the target
    return {"measured": True, "threshold": round(float(thresholds[index]), 6),
            "recall": round(float(true[index]) / len(positives), 4),
            "fpr": round(float(false[index]) / len(negatives), 5),
            "positives": len(positives), "negatives": len(negatives)}


# --------------------------------------------------------------------------- #
# threshold-free measures                                                     #
# --------------------------------------------------------------------------- #

def _ranks(values):
    """Average ranks (1-based), ties sharing the mean of their positions."""
    import numpy as np

    values = np.asarray(values, dtype=float)
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values), dtype=float)
    sorted_values = values[order]
    boundaries = np.flatnonzero(np.diff(sorted_values)) + 1
    starts = np.concatenate(([0], boundaries))
    ends = np.concatenate((boundaries, [len(values)]))
    for start, end in zip(starts, ends):
        ranks[order[start:end]] = (start + end + 1) / 2.0
    return ranks


def roc_auc(positives: list[float], negatives: list[float]) -> float | None:
    """Probability that an attack row scores above a benign row, ties counting half."""
    if not positives or not negatives:
        return None
    ranks = _ranks(list(positives) + list(negatives))
    n_pos, n_neg = len(positives), len(negatives)
    return float((ranks[:n_pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def average_precision(positives: list[float], negatives: list[float]) -> float | None:
    """Area under the precision-recall curve, stepping once per distinct score.

    Depends on the share of attack rows, which here is the benchmark's and far
    higher than a store's. Read it as a comparison between detectors on the
    same rows, not as the precision to expect.
    """
    import numpy as np

    if not positives or not negatives:
        return None
    scores = np.concatenate([np.asarray(positives, float), np.asarray(negatives, float)])
    labels = np.concatenate([np.ones(len(positives)), np.zeros(len(negatives))])
    order = np.argsort(-scores, kind="mergesort")
    scores, labels = scores[order], labels[order]
    last = np.concatenate((np.flatnonzero(np.diff(scores)), [len(scores) - 1]))
    true = np.cumsum(labels)[last]
    precision = true / (last + 1)
    recall = true / len(positives)
    previous = np.concatenate(([0.0], recall[:-1]))
    return float(np.sum((recall - previous) * precision))


def bootstrap_interval(fn, positives: list[float], negatives: list[float], *,
                       resamples: int = 200, seed: int = 20261118) -> list[float] | None:
    """95% percentile interval of ``fn`` under resampling of rows within each class."""
    import numpy as np

    if not positives or not negatives:
        return None
    rng = np.random.default_rng(seed)
    pos, neg = np.asarray(positives, float), np.asarray(negatives, float)
    values = []
    for _ in range(resamples):
        values.append(fn(list(rng.choice(pos, len(pos))), list(rng.choice(neg, len(neg)))))
    low, high = np.percentile(values, [2.5, 97.5])
    return [round(float(low), 4), round(float(high), 4)]


def f1_at(positives: list[float], negatives: list[float], threshold: float) -> dict:
    tp = sum(score >= threshold for score in positives)
    fp = sum(score >= threshold for score in negatives)
    fn = len(positives) - tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(positives) if positives else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"threshold": round(float(threshold), 6), "f1": round(f1, 4),
            "precision": round(precision, 4), "recall": round(recall, 4),
            "false_positive_rate": round(fp / len(negatives), 5) if negatives else None,
            "tp": tp, "fp": fp, "fn": fn}


def best_f1_threshold(positives: list[float], negatives: list[float]) -> float:
    """The score threshold with the highest F1 on these rows (zero is not a threshold)."""
    import numpy as np

    thresholds, true, false = _counts_at_thresholds(positives, negatives)
    keep = thresholds > 0
    if not keep.any():
        return 1.01
    thresholds, true, false = thresholds[keep], true[keep], false[keep]
    f1 = 2 * true / np.maximum(2 * true + false + (len(positives) - true), 1)
    return float(thresholds[int(np.argmax(f1))])


def threshold_for_fpr(negatives: list[float], target: float) -> float:
    """The lowest threshold whose false-positive rate on ``negatives`` is within ``target``."""
    thresholds, _, false = _counts_at_thresholds([], negatives)
    ok = false <= int(target * len(negatives))
    return float(thresholds[int(ok.nonzero()[0][-1])]) if ok.any() else 1.01
