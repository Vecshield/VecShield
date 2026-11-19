"""Turn run summaries into the tables published in docs/library/benchmarks/injection.md.

    python benchmarks/injection/report.py \\
        --detectors "Scanner before=legacy.before" "Pack 2026.11.1=vecshield.before" \\
                    "Pack 2026.11.2=vecshield.final" \\
        --splits test heldout --record 2026-11-18-round2

Each ``LABEL=NAME`` names a summary in ``results/NAME.summary.json``.
``--record`` copies those summaries (numbers only, no third-party text) into
``recorded/`` with that prefix, so every figure in the write-up can be traced
to a file in the repository.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from benchmarks.injection.metrics import rate  # noqa: E402

RESULTS = HERE / "results"
RECORDED = HERE / "recorded"

GROUP_TABLES = (
    ("Recall by attack family and source", "recall_by_family_source", "Family / source"),
    ("ROC-AUC of each attack family against the split's benign rows",
     "roc_auc_by_family_source", "Family / source"),
    ("False-positive rate by benign family", "fpr_by_family", "Family"),
    ("False-positive rate by benign source", "fpr_by_source", "Source"),
    ("Out of scope: recall on jailbreak prompts", "out_of_scope_recall", "Family / source"),
    ("Recall under each obfuscation", "recall_by_obfuscation", "Obfuscation"),
    ("Of payloads found in plain form, share still found", "evasion_retention", "Obfuscation"),
    ("Recall by container", "recall_by_container", "Container"),
    ("Recall by position of the payload in the document", "recall_by_position", "Position"),
    ("Recall by document length (characters)", "recall_by_carrier_length", "Length"),
    ("Recall by language (heuristic bucket)", "recall_by_language", "Language"),
    ("BIPIA: recall by whether the string names the answer", "recall_by_bipia_marker",
     "Marker"),
    ("SPML: recall by the dataset's own degree of attack", "recall_by_spml_degree", "Degree"),
    ("NotInject: false-positive rate by number of trigger words", "fpr_by_notinject_level",
     "Trigger words"),
)


def _cell(entry) -> str:
    if entry is None:
        return "not run"
    if isinstance(entry, (int, float)):
        return f"{entry:.3f}"
    if not entry.get("measured"):
        return f"n<5 ({entry.get('k', 0)}/{entry.get('n', 0)})"
    low, high = entry["interval"]
    return f"{entry['value']:.3f} [{low:.3f}, {high:.3f}] ({entry['k']}/{entry['n']})"


def _with_interval(value, interval) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}" + (f" [{interval[0]:.3f}, {interval[1]:.3f}]" if interval else "")


def headline(summaries: dict[str, dict], split: str) -> list[str]:
    lines = ["| Detector | F1 | Precision | Recall | False-positive rate | ROC-AUC | PR-AUC |",
             "|---|---|---|---|---|---|---|"]
    for label, summary in summaries.items():
        entry = summary["splits"].get(split)
        if not entry:
            lines.append(f"| {label} | not run | | | | | |")
            continue
        lines.append(
            f"| {label} | {entry['f1']:.3f} | {entry['precision']:.3f} | "
            f"{_cell(entry['recall'])} | {_cell(entry['false_positive_rate'])} | "
            f"{_with_interval(entry['roc_auc'], entry.get('roc_auc_interval'))} | "
            f"{_with_interval(entry['average_precision'], entry.get('average_precision_interval'))} |")
    return lines + [""]


def fixed_fpr(summaries: dict[str, dict], split: str) -> list[str]:
    lines = ["| Detector | Threshold from dev for FPR ≤ 1% | Recall | FPR here | F1 | "
             "Threshold from dev for FPR ≤ 0.1% | Recall | FPR here | F1 |",
             "|---|---|---|---|---|---|---|---|---|"]
    for label, summary in summaries.items():
        entry = (summary["splits"].get(split) or {}).get("at_thresholds_chosen_on_dev") or {}
        cells = []
        for key in ("fpr_0.01_on_dev", "fpr_0.001_on_dev"):
            at = entry.get(key)
            cells += ([f"{at['threshold']:.4f}", f"{at['recall']:.3f}",
                       f"{at['false_positive_rate']:.4f}", f"{at['f1']:.3f}"]
                      if at else ["n/a"] * 4)
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    return lines + [""]


def group_table(title: str, summaries: dict[str, dict], split: str, key: str,
                label: str) -> list[str]:
    groups: list[str] = []
    for summary in summaries.values():
        for group in (summary["splits"].get(split) or {}).get(key, {}) or {}:
            if group not in groups:
                groups.append(group)
    if not groups:
        return []
    lines = [f"#### {title}", "", f"| {label} | " + " | ".join(summaries) + " |",
             "|---|" + "---|" * len(summaries)]
    for group in sorted(groups):
        cells = [_cell(((summary["splits"].get(split) or {}).get(key) or {}).get(group))
                 for summary in summaries.values()]
        lines.append(f"| `{group}` | " + " | ".join(cells) + " |")
    return lines + [""]


def per_rule(rows_name: str, split_names: tuple[str, ...]) -> list[dict]:
    """How each rule that can flag behaved on the rows it fired on."""
    path = RESULTS / f"{rows_name}.rows.jsonl"
    if not path.exists():
        return []
    fired_attack: dict[str, int] = defaultdict(int)
    fired_benign: dict[str, int] = defaultdict(int)
    benign_rows = 0
    for line in path.open(encoding="utf-8"):
        row = json.loads(line)
        if row["split"] not in split_names:
            continue
        benign_rows += row["label"] == 0
        for rule in set(row.get("primary") or []):
            if row["label"] == 1:
                fired_attack[rule] += 1
            else:
                fired_benign[rule] += 1
    out = []
    for rule in sorted(set(fired_attack) | set(fired_benign)):
        total = fired_attack[rule] + fired_benign[rule]
        out.append({"rule": rule, "fired_on_attacks": fired_attack[rule],
                    "fired_on_benign": fired_benign[rule],
                    "precision_on_this_mix": rate(fired_attack[rule], total),
                    "benign_fire_rate": rate(fired_benign[rule], benign_rows)})
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--detectors", nargs="+", required=True, metavar="LABEL=NAME")
    parser.add_argument("--splits", nargs="+", default=["test", "heldout"])
    parser.add_argument("--per-rule", metavar="NAME",
                        help="also print the per-rule table from results/NAME.rows.jsonl")
    parser.add_argument("--record", metavar="PREFIX")
    args = parser.parse_args()

    names = dict(item.split("=", 1) for item in args.detectors)
    summaries = {label: json.loads((RESULTS / f"{name}.summary.json").read_text())
                 for label, name in names.items()}
    lines: list[str] = []
    for split in args.splits:
        lines += [f"### Split: {split}", ""] + headline(summaries, split)
        lines += ["Thresholds chosen on the dev split, applied here unchanged:", ""]
        lines += fixed_fpr(summaries, split)
        for title, key, label in GROUP_TABLES:
            lines += group_table(title, summaries, split, key, label)
    rules = per_rule(args.per_rule, tuple(args.splits)) if args.per_rule else []
    if rules:
        lines += ["### Per-rule behaviour", "",
                  "| Rule | Fired on attacks | Fired on benign | Precision on this mix | "
                  "Benign fire rate |", "|---|---|---|---|---|"]
        for item in sorted(rules, key=lambda r: -r["fired_on_attacks"]):
            lines.append(f"| `{item['rule']}` | {item['fired_on_attacks']} | "
                         f"{item['fired_on_benign']} | {_cell(item['precision_on_this_mix'])} | "
                         f"{_cell(item['benign_fire_rate'])} |")
        lines.append("")
    print("\n".join(lines))
    if args.record:
        RECORDED.mkdir(exist_ok=True)
        for name in names.values():
            shutil.copy(RESULTS / f"{name}.summary.json",
                        RECORDED / f"{args.record}-{name}.summary.json")
        if rules:
            (RECORDED / f"{args.record}-per-rule.json").write_text(
                json.dumps(rules, indent=1) + "\n")
        manifest = HERE / ".cache" / "_built" / "manifest.json"
        if manifest.exists():
            shutil.copy(manifest, RECORDED / f"{args.record}-dataset-manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
