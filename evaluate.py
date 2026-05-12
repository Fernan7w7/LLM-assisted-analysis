# evaluate.py
import argparse
import csv
import json
import os
from collections import defaultdict
from pathlib import Path

from pipeline.runner import analyze_file
from data.taxonomy import ACTIVE_IDS, FUTURE_IDS, TAXONOMY

# ---------------------------------------------------------------------------
# DATASET DISCOVERY
# ---------------------------------------------------------------------------

DEFAULT_DATASET = Path(__file__).resolve().parent.parent / "evm-trace-dataset"


def _vuln_id_from_dir(dir_name: str) -> str:
    """'1.1_reentrancy' → '1.1'"""
    return dir_name.split("_")[0]


def build_cases(dataset_root: Path) -> list[dict]:
    """
    Build the full case list from the dataset root.
    Positive cases: from labels.json (with metadata) + any positive/*.sol files
    not covered by labels.json (synthetic categories).
    Negative cases: enumerated from negative/ subdirectories; taxonomy_id inferred
    from the parent directory name.
    """
    labels_path = dataset_root / "labels.json"
    labels: dict = {}
    if labels_path.exists():
        with open(labels_path, encoding="utf-8") as f:
            labels = json.load(f)

    contracts_root = dataset_root / "contracts"
    cases = []
    seen_paths: set[str] = set()

    for cat_dir in sorted(contracts_root.iterdir()):
        if not cat_dir.is_dir():
            continue
        vuln_id = _vuln_id_from_dir(cat_dir.name)

        for split in ("positive", "negative"):
            split_dir = cat_dir / split
            if not split_dir.exists():
                continue
            vulnerable = split == "positive"

            for sol_file in sorted(split_dir.glob("*.sol")):
                abs_path = str(sol_file)
                if abs_path in seen_paths:
                    continue
                seen_paths.add(abs_path)

                rel_key = f"contracts/{cat_dir.name}/{split}/{sol_file.name}"
                label_meta = labels.get(rel_key, {})

                cases.append({
                    "path": abs_path,
                    "taxonomy_id": label_meta.get("taxonomy_id", vuln_id),
                    "vulnerable": vulnerable,
                    "source": label_meta.get("source", ""),
                    "notes": label_meta.get("notes", ""),
                    "fuzzer_confirmed": label_meta.get("fuzzer_confirmed", False),
                })

    return cases


# ---------------------------------------------------------------------------
# PREDICTION HELPERS
# ---------------------------------------------------------------------------

def get_prediction(results: list[dict], expected_id: str) -> tuple[bool, dict | None]:
    """
    Returns (predicted_flag, matched_result) for the expected taxonomy ID.
    Considers any positive finding for the expected ID a hit.
    """
    matches = [r for r in results if r.get("vulnerability_id") == expected_id]
    positives = [r for r in matches if r.get("final_vulnerable") is True]
    if positives:
        return True, positives[0]
    return False, matches[0] if matches else None


def safe_get(dct, key, default=None):
    return dct.get(key, default) if isinstance(dct, dict) else default


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate TRACE pipeline against the evm-trace-dataset."
    )
    parser.add_argument(
        "--dataset", default=str(DEFAULT_DATASET),
        help="Path to the evm-trace-dataset root (default: ../evm-trace-dataset)"
    )
    parser.add_argument(
        "--ids", nargs="+", metavar="ID",
        help="Restrict evaluation to specific taxonomy IDs (e.g. 1.1 2.1)"
    )
    parser.add_argument(
        "--include-future", action="store_true",
        help="Also evaluate future-work IDs (default: skip them)"
    )
    args = parser.parse_args()

    dataset_root = Path(args.dataset)
    if not dataset_root.exists():
        print(f"[ERROR] Dataset not found: {dataset_root}")
        return

    cases = build_cases(dataset_root)

    # Filter to requested IDs
    id_filter = set(args.ids) if args.ids else None
    skip_ids = set(FUTURE_IDS) if not args.include_future else set()

    rows = []
    all_raw = []
    per_id_counts: dict[str, dict] = defaultdict(lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0})
    tp = fp = tn = fn = skipped = 0

    for case in cases:
        tid = case["taxonomy_id"]

        if tid in skip_ids:
            skipped += 1
            continue
        if id_filter and tid not in id_filter:
            continue
        if not os.path.exists(case["path"]):
            print(f"[WARN] Missing file: {case['path']}")
            continue

        print(f"\nRunning [{tid}] {'positive' if case['vulnerable'] else 'negative'}: "
              f"{os.path.basename(case['path'])}")

        results = analyze_file(case["path"])
        all_raw.append({
            "path": case["path"],
            "taxonomy_id": tid,
            "vulnerable": case["vulnerable"],
            "results": results,
        })

        predicted_flag, matched = get_prediction(results, tid)
        should_flag = case["vulnerable"]

        if should_flag and predicted_flag:
            outcome = "TP"; tp += 1; per_id_counts[tid]["TP"] += 1
        elif not should_flag and predicted_flag:
            outcome = "FP"; fp += 1; per_id_counts[tid]["FP"] += 1
        elif not should_flag and not predicted_flag:
            outcome = "TN"; tn += 1; per_id_counts[tid]["TN"] += 1
        else:
            outcome = "FN"; fn += 1; per_id_counts[tid]["FN"] += 1

        rows.append({
            "file": case["path"],
            "taxonomy_id": tid,
            "vuln_name": TAXONOMY.get(tid, {}).get("name", ""),
            "should_flag": should_flag,
            "predicted_flag": predicted_flag,
            "outcome": outcome,
            "source": case.get("source", ""),
            "notes": case.get("notes", ""),
            "function_name": safe_get(matched, "function_name"),
            "scenario_match": safe_get(matched, "scenario_match"),
            "property_match": safe_get(matched, "property_match"),
            "final_vulnerable": safe_get(matched, "final_vulnerable"),
            "scenario_reason": safe_get(matched, "scenario_reason"),
            "property_reason": safe_get(matched, "property_reason"),
            "static_check_passed": safe_get(safe_get(matched, "static_check", {}), "passed"),
            "provider": safe_get(matched, "provider"),
        })

    # ---------------------------------------------------------------------------
    # METRICS
    # ---------------------------------------------------------------------------
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    per_id_metrics = {}
    for tid, counts in sorted(per_id_counts.items()):
        t, f_, tn_, fn_ = counts["TP"], counts["FP"], counts["TN"], counts["FN"]
        p = t / (t + f_) if (t + f_) else 0.0
        r = t / (t + fn_) if (t + fn_) else 0.0
        f = (2 * p * r / (p + r)) if (p + r) else 0.0
        per_id_metrics[tid] = {
            "name": TAXONOMY.get(tid, {}).get("name", tid),
            **counts,
            "Precision": round(p, 4),
            "Recall": round(r, 4),
            "F1": round(f, 4),
        }

    overall_metrics = {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Precision": round(precision, 4),
        "Recall": round(recall, 4),
        "F1": round(f1, 4),
        "Accuracy": round(accuracy, 4),
        "Total": total,
        "Skipped (future work)": skipped,
        "per_id": per_id_metrics,
    }

    # ---------------------------------------------------------------------------
    # OUTPUT
    # ---------------------------------------------------------------------------
    output_dir = Path("evaluation_outputs")
    output_dir.mkdir(exist_ok=True)

    csv_path = output_dir / "evaluation_summary.csv"
    if rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    json_path = output_dir / "evaluation_raw.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_raw, f, indent=2)

    metrics_path = output_dir / "evaluation_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(overall_metrics, f, indent=2)

    print("\n" + "=" * 60)
    print("TRACE — EVALUATION SUMMARY")
    print("=" * 60)
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}  (skipped={skipped})")
    print(f"Precision={precision:.4f}  Recall={recall:.4f}  F1={f1:.4f}  Acc={accuracy:.4f}")
    print("\nPer-ID breakdown:")
    for tid, m in per_id_metrics.items():
        print(f"  [{tid}] {m['name']:<35} "
              f"TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']}  "
              f"F1={m['F1']:.4f}")
    print(f"\nSaved: {csv_path}, {json_path}, {metrics_path}")


if __name__ == "__main__":
    main()
