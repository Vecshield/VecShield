"""Run detectors over the built dataset and write the results.

    python benchmarks/injection/run.py --detectors legacy vecshield
    python benchmarks/injection/run.py --detectors protectai_v2 \\
        --model-dir /path/to/protectai-v2 --sample 4000

Per-row predictions go to ``results/<detector>.rows.jsonl`` (git-ignored,
because they sit beside third-party text ids). The summary goes to
``results/<detector>.summary.json``; ``report.py`` turns summaries into the
tables in ``docs/library/benchmarks/injection.md``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from benchmarks.injection import detectors  # noqa: E402
from benchmarks.injection.metrics import (  # noqa: E402
    average_precision,
    best_f1_threshold,
    bootstrap_interval,
    f1_at,
    group_rates,
    rate,
    recall_at_fpr,
    roc_auc,
    threshold_for_fpr,
)

#: Families outside what the detector is for. They are scored and reported in
#: their own table, and left out of the headline figures. Decided before any
#: second-round result was seen.
OUT_OF_SCOPE = frozenset({"jailbreak_prompt"})

BUILT = HERE / ".cache" / "_built"
RESULTS = HERE / "results"


def _git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(HERE), *args], capture_output=True,
                          text=True).stdout.strip()


def load_rows(sample: int | None, all_negatives: bool = False) -> list[dict]:
    rows = [json.loads(line) for line in (BUILT / "dataset.jsonl").open(encoding="utf-8")]
    if sample:
        # A fixed subset per (split, label, family, source): the first ``sample``
        # ids in hash order.
        # With ``all_negatives`` every benign row is kept, because a
        # false-positive rate of one in a thousand cannot be read off a few
        # hundred rows.
        keep: dict[tuple, list] = {}
        for row in sorted(rows, key=lambda r: hashlib.sha256(r["id"].encode()).hexdigest()):
            keep.setdefault((row["split"], row["label"], row["family"], row["source"]),
                            []).append(row)
        rows = [r for (_, label, _, _), group in keep.items()
                for r in (group if all_negatives and label == 0 else group[:sample])]
    return rows


def _scores(rows: list[dict], split: str) -> tuple[list[float], list[float]]:
    part = [r for r in rows if r["split"] == split and r["family"] not in OUT_OF_SCOPE]
    return ([r["score"] for r in part if r["label"] == 1],
            [r["score"] for r in part if r["label"] == 0])


def summarise(rows: list[dict], default_threshold: float = 0.5) -> dict:
    out: dict = {}
    # Thresholds are chosen on the dev split and then applied, unchanged, to
    # the others: the only honest way to report an F1 at a tuned threshold.
    dev_pos, dev_neg = _scores(rows, "dev")
    tuned = {}
    if dev_pos and dev_neg:
        tuned = {"best_f1_on_dev": best_f1_threshold(dev_pos, dev_neg),
                 "fpr_0.01_on_dev": threshold_for_fpr(dev_neg, 0.01),
                 "fpr_0.001_on_dev": threshold_for_fpr(dev_neg, 0.001)}
    for split in ("dev", "test", "heldout"):
        part = [r for r in rows if r["split"] == split]
        if not part:
            continue
        scoped = [r for r in part if r["family"] not in OUT_OF_SCOPE]
        pos = [r for r in scoped if r["label"] == 1]
        neg = [r for r in scoped if r["label"] == 0]
        scores_pos = [r["score"] for r in pos]
        scores_neg = [r["score"] for r in neg]
        tp = sum(r["flagged"] for r in pos)
        fp = sum(r["flagged"] for r in neg)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / len(pos) if pos else 0.0
        entry = {
            "recall": rate(tp, len(pos)),
            "false_positive_rate": rate(fp, len(neg)),
            "precision": round(precision, 4),
            "f1": round(2 * precision * recall / (precision + recall), 4)
            if precision + recall else 0.0,
            "roc_auc": roc_auc(scores_pos, scores_neg),
            "roc_auc_interval": bootstrap_interval(roc_auc, scores_pos, scores_neg),
            "average_precision": average_precision(scores_pos, scores_neg),
            "average_precision_interval": bootstrap_interval(
                average_precision, scores_pos, scores_neg),
            "at_thresholds_chosen_on_dev": {
                name: f1_at(scores_pos, scores_neg, threshold)
                for name, threshold in tuned.items()},
            "recall_by_family": group_rates(pos, lambda r: r["family"]),
            "recall_by_family_source": group_rates(
                pos, lambda r: f"{r['family']}/{r['source']}"),
            "roc_auc_by_family_source": {
                group: round(roc_auc([r["score"] for r in pos
                                      if f"{r['family']}/{r['source']}" == group],
                                     scores_neg), 4)
                for group in sorted({f"{r['family']}/{r['source']}" for r in pos})},
            "fpr_by_family": group_rates(neg, lambda r: r["family"]),
            "fpr_by_source": group_rates(neg, lambda r: r["source"]),
            "out_of_scope_recall": group_rates(
                (r for r in part if r["family"] in OUT_OF_SCOPE and r["label"] == 1),
                lambda r: f"{r['family']}/{r['source']}"),
            "recall_by_obfuscation": group_rates(
                pos, lambda r: r["meta"].get("obfuscation")
                if r["family"] in ("evasion", "stacked_evasion") else None),
            "recall_by_container": group_rates(
                pos, lambda r: r["meta"].get("container")
                if r["family"] == "container_payload" else None),
            "recall_by_position": group_rates(
                pos, lambda r: r["meta"].get("position")
                if r["family"] == "embedded_payload" else None),
            "recall_by_carrier_length": group_rates(
                pos, lambda r: str(r["meta"].get("carrier_length"))
                if r["family"] == "embedded_payload" else None),
            "recall_by_language": group_rates(
                pos, lambda r: r["meta"].get("language")
                if r["family"] in ("direct_prompt", "labelled_prompt") else None),
            "recall_by_bipia_marker": group_rates(
                pos, lambda r: r["meta"].get("marker")
                if r["family"].startswith("bipia") else None),
            "recall_by_spml_degree": group_rates(
                pos, lambda r: r["meta"].get("degree") if r["source"] == "spml" else None),
            "fpr_by_notinject_level": group_rates(
                neg, lambda r: r["meta"].get("trigger_words")
                if r["family"] == "notinject" else None),
        }
        plain = {r["meta"]["payload_id"] for r in pos if r["family"] == "evasion"
                 and r["meta"].get("obfuscation") == "none" and r["flagged"]}
        entry["evasion_retention"] = group_rates(
            (r for r in pos if r["family"] in ("evasion", "stacked_evasion")
             and r["meta"].get("obfuscation") != "none"
             and r["meta"].get("payload_id") in plain),
            lambda r: r["meta"]["obfuscation"])
        entry["discussed_share_of_false_positives"] = rate(
            sum(r.get("verdict") == "suspicious" for r in neg if r["flagged"]),
            sum(r["flagged"] for r in neg))
        entry["recall_at_fpr"] = {"0.001": recall_at_fpr(scores_pos, scores_neg, 0.001),
                                  "0.01": recall_at_fpr(scores_pos, scores_neg, 0.01)}
        out[split] = entry
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--detectors", nargs="+", default=["legacy", "vecshield"])
    parser.add_argument("--model-dir", help="local directory holding a classifier's files")
    parser.add_argument("--canonical-input", action="store_true",
                        help="give a classifier the scanner's normalised reading of the text")
    parser.add_argument("--sample", type=int,
                        help="score at most this many rows per (split, label, family)")
    parser.add_argument("--all-negatives", action="store_true",
                        help="with --sample, still score every benign row")
    parser.add_argument("--tag", default="", help="suffix for the output file names")
    parser.add_argument("--splits", nargs="+", default=["dev", "test", "heldout"],
                        help="splits to score")
    args = parser.parse_args()

    manifest = json.loads((BUILT / "manifest.json").read_text())
    rows = [r for r in load_rows(args.sample, args.all_negatives)
            if r["split"] in args.splits]
    RESULTS.mkdir(exist_ok=True)
    for name in args.detectors:
        if name in detectors.CLASSIFIERS:
            detect = detectors.onnx_classifier(name, args.model_dir,
                                               canonical=args.canonical_input)
        else:
            detect = getattr(detectors, name)()
        scored, chars, started = [], 0, time.perf_counter()
        slowest = (0.0, "")
        for row in rows:
            t0 = time.perf_counter()
            flagged, score, *extra = detect(row["text"])
            elapsed = time.perf_counter() - t0
            if elapsed > slowest[0]:
                slowest = (elapsed, row["id"])
            chars += len(row["text"])
            scored.append({**{k: row[k] for k in ("id", "split", "label", "family", "source",
                                                  "meta")},
                           "flagged": flagged, "score": score, **(extra[0] if extra else {})})
        wall = time.perf_counter() - started
        summary = {
            "detector": name,
            "dataset_sha256": manifest["sha256"],
            "dataset_rows": manifest["rows"],
            "rows_scored": len(rows),
            "sample_per_group": args.sample,
            "all_negatives": args.all_negatives,
            "sample_key": "split,label,family,source",
            "splits_scored": args.splits,
            "code_commit": _git("rev-parse", "--short", "HEAD"),
            "working_tree_dirty": bool(_git("status", "--porcelain", "--", "../../vecshield",
                                            "../../vecshield_platform")),
            "legacy_commit": detectors.LEGACY_COMMIT if name == "legacy" else None,
            "python": platform.python_version(),
            "machine": f"{platform.system()} {platform.machine()}",
            "timing": {"wall_seconds": round(wall, 2), "characters": chars,
                       "ms_per_1000_chars": round(1000 * wall / max(chars, 1) * 1000, 4),
                       "slowest_row_ms": round(slowest[0] * 1000, 1),
                       "slowest_row_id": slowest[1]},
            "splits": summarise(scored),
        }
        tag = f".{args.tag}" if args.tag else ""
        (RESULTS / f"{name}{tag}.summary.json").write_text(json.dumps(summary, indent=1) + "\n")
        with (RESULTS / f"{name}{tag}.rows.jsonl").open("w", encoding="utf-8") as handle:
            for item in scored:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        for split, entry in summary["splits"].items():
            print(f"{name:14s} {split:8s} recall={entry['recall'].get('value')} "
                  f"fpr={entry['false_positive_rate'].get('value')} "
                  f"n+={entry['recall']['n']} n-={entry['false_positive_rate']['n']}")
        print(f"{name:14s} {summary['timing']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
