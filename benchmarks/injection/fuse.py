"""Score the scanner with a classifier beside it, from each one's per-row output.

    python benchmarks/injection/fuse.py --classifier horizon_small \\
        --scanner-tag final --classifier-tag final

The library combines the two layers with one rule: the fused score is the
higher of the rules' score and the classifier's probability mapped so that its
threshold lands on 0.5 (``vecshield.injection.scanner.classifier_score``). That
rule is applied here to the stored scores, so the expensive model pass is made
once per model and every threshold can be examined without repeating it. A
test checks this arithmetic against the library's own ``scan_text``.

The classifier's threshold is taken from the dev split and nothing else: the
lowest probability at which it flags no more than ``--target-fpr`` of the dev
split's benign rows. ``--threshold`` fixes it instead.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from benchmarks.injection.metrics import threshold_for_fpr  # noqa: E402
from benchmarks.injection.run import RESULTS, summarise  # noqa: E402
from vecshield.injection.scanner import THRESHOLD, classifier_score  # noqa: E402


def _rows(name: str, tag: str) -> dict[str, dict]:
    path = RESULTS / f"{name}.{tag}.rows.jsonl"
    return {row["id"]: row for row in map(json.loads, path.open(encoding="utf-8"))}


def dev_threshold(classifier_rows: dict[str, dict], target_fpr: float) -> float:
    negatives = [r["score"] for r in classifier_rows.values()
                 if r["split"] == "dev" and r["label"] == 0]
    if not negatives:
        raise SystemExit("the classifier was not scored on dev benign rows; "
                         "pass --threshold or score the dev split first")
    return threshold_for_fpr(negatives, target_fpr)


def fuse(scanner_rows: dict[str, dict], classifier_rows: dict[str, dict],
         threshold: float) -> tuple[list[dict], list[dict], list[dict]]:
    """Rows scored by both: ``(fused, scanner alone, classifier at this threshold)``."""
    fused, alone, model = [], [], []
    for row_id, clf in classifier_rows.items():
        sig = scanner_rows.get(row_id)
        if sig is None:
            continue
        mapped = classifier_score(clf["score"], threshold)
        score = max(sig["score"], mapped)
        base = {k: sig[k] for k in ("id", "split", "label", "family", "source", "meta")}
        fused.append({**base, "score": score, "flagged": score >= THRESHOLD,
                      "verdict": sig.get("verdict") if sig["score"] >= THRESHOLD else None,
                      "signature_score": sig["score"], "probability": clf["score"]})
        alone.append(sig)
        model.append({**base, "score": mapped, "flagged": mapped >= THRESHOLD})
    return fused, alone, model


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--classifier", required=True)
    parser.add_argument("--scanner-tag", required=True)
    parser.add_argument("--classifier-tag", required=True)
    parser.add_argument("--threshold-tag",
                        help="tag of the classifier run that holds the dev benign rows, "
                             "if it is not --classifier-tag")
    parser.add_argument("--target-fpr", type=float, default=0.001)
    parser.add_argument("--threshold", type=float)
    parser.add_argument("--out-tag", default="")
    args = parser.parse_args()

    scanner = _rows("vecshield", args.scanner_tag)
    classifier = _rows(args.classifier, args.classifier_tag)
    threshold = args.threshold
    if threshold is None:
        source = (_rows(args.classifier, args.threshold_tag) if args.threshold_tag
                  else classifier)
        threshold = dev_threshold(source, args.target_fpr)
    fused, alone, model = fuse(scanner, classifier, threshold)
    tag = f".{args.out_tag}" if args.out_tag else ""
    for name, rows in ((f"fused_{args.classifier}", fused), ("vecshield_same_rows", alone),
                       (f"{args.classifier}_at_threshold", model)):
        summary = {"detector": name, "classifier": args.classifier,
                   "classifier_threshold": threshold, "target_fpr_on_dev": args.target_fpr,
                   "rows_scored": len(rows), "splits": summarise(rows)}
        (RESULTS / f"{name}{tag}.summary.json").write_text(json.dumps(summary, indent=1) + "\n")
        with (RESULTS / f"{name}{tag}.rows.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        for split, entry in summary["splits"].items():
            if split == "dev" or args.out_tag.startswith("final"):
                print(f"{name:34s} {split:8s} F1={entry['f1']:.3f} "
                      f"recall={entry['recall'].get('value')} "
                      f"fpr={entry['false_positive_rate'].get('value')} "
                      f"auc={entry['roc_auc']:.3f}")
    print(f"classifier threshold {threshold:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
