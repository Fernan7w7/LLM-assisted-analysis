# evaluate.py
import os
import csv
import json
from pathlib import Path

from pipeline.runner import analyze_file

# -----------------------------
# CONFIG
# -----------------------------
CASES = [
    # DOS
    {"path": "./datasets/positive/dos_01_real_auction.sol", "expected": "DOS_EXTERNAL", "should_flag": True},
    {"path": "./datasets/negative/dos_03_pull_payment_safe.sol", "expected": "DOS_EXTERNAL", "should_flag": False},

    # Reentrancy
    {"path": "./datasets/positive/reentrancy_01.sol", "expected": "REENTRANCY", "should_flag": True},
    {"path": "./datasets/negative/reentrancy_02.sol", "expected": "REENTRANCY", "should_flag": False},

    # Access Control
    {"path": "./datasets/positive/access_01.sol", "expected": "ACCESS_CONTROL", "should_flag": True},
    {"path": "./datasets/negative/access_02.sol", "expected": "ACCESS_CONTROL", "should_flag": False},

    # Delegatecall Misuse
    {"path": "./datasets/positive/delegatecall_01.sol", "expected": "DELEGATECALL_MISUSE", "should_flag": True},
    {"path": "./datasets/negative/delegatecall_02.sol", "expected": "DELEGATECALL_MISUSE", "should_flag": False},

    # Logic / Validation
    {"path": "./datasets/positive/logic_01.sol", "expected": "LOGIC_VALIDATION", "should_flag": True},
    {"path": "./datasets/negative/logic_02.sol", "expected": "LOGIC_VALIDATION", "should_flag": False},
    {"path": "./datasets/positive/logic_03.sol", "expected": "LOGIC_VALIDATION", "should_flag": True},
    {"path": "./datasets/negative/logic_04.sol", "expected": "LOGIC_VALIDATION", "should_flag": False},
]

OUTPUT_DIR = Path("evaluation_outputs")
OUTPUT_DIR.mkdir(exist_ok=True)

# -----------------------------
# HELPERS
# -----------------------------
def get_case_prediction(results, expected_vuln_id):
    """
    Returns:
      predicted_flag: bool
      matched_result: dict | None
    """
    matched = [
        r for r in results
        if r.get("vulnerability_id") == expected_vuln_id
    ]

    final_matches = [r for r in matched if r.get("final_vulnerable") is True]

    if final_matches:
        return True, final_matches[0]

    return False, matched[0] if matched else None


def safe_get(dct, key, default=None):
    return dct.get(key, default) if isinstance(dct, dict) else default


# -----------------------------
# MAIN
# -----------------------------
def main():
    rows = []
    all_raw = []

    tp = fp = tn = fn = 0

    for case in CASES:
        path = case["path"]
        expected = case["expected"]
        should_flag = case["should_flag"]

        if not os.path.exists(path):
            print(f"[WARN] Missing file: {path}")
            continue

        print(f"\nRunning: {path}")
        results = analyze_file(path)
        all_raw.append({
            "path": path,
            "expected": expected,
            "should_flag": should_flag,
            "results": results
        })

        predicted_flag, matched_result = get_case_prediction(results, expected)

        if should_flag and predicted_flag:
            outcome = "TP"
            tp += 1
        elif not should_flag and predicted_flag:
            outcome = "FP"
            fp += 1
        elif not should_flag and not predicted_flag:
            outcome = "TN"
            tn += 1
        else:
            outcome = "FN"
            fn += 1

        row = {
            "file": path,
            "expected_vulnerability": expected,
            "should_flag": should_flag,
            "predicted_flag": predicted_flag,
            "outcome": outcome,
            "predicted_vulnerability": safe_get(matched_result, "vulnerability_id"),
            "function_name": safe_get(matched_result, "function_name"),
            "scenario_match": safe_get(matched_result, "scenario_match"),
            "property_match": safe_get(matched_result, "property_match"),
            "final_vulnerable": safe_get(matched_result, "final_vulnerable"),
            "scenario_reason": safe_get(matched_result, "scenario_reason"),
            "property_reason": safe_get(matched_result, "property_reason"),
            "static_check_passed": safe_get(safe_get(matched_result, "static_check", {}), "passed"),
            "static_check_details": safe_get(safe_get(matched_result, "static_check", {}), "details"),
            "provider": safe_get(matched_result, "provider"),
        }
        rows.append(row)

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    metrics = {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": round(precision, 4),
        "Recall": round(recall, 4),
        "F1": round(f1, 4),
        "Accuracy": round(accuracy, 4),
        "Total": total,
    }

    # Save CSV
    csv_path = OUTPUT_DIR / "evaluation_summary.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [
            "file", "expected_vulnerability", "should_flag", "predicted_flag", "outcome"
        ])
        writer.writeheader()
        writer.writerows(rows)

    # Save JSON
    json_path = OUTPUT_DIR / "evaluation_raw.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_raw, f, indent=2)

    metrics_path = OUTPUT_DIR / "evaluation_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\n==============================")
    print("EVALUATION SUMMARY")
    print("==============================")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"Precision={precision:.4f}")
    print(f"Recall={recall:.4f}")
    print(f"F1={f1:.4f}")
    print(f"Accuracy={accuracy:.4f}")
    print(f"\nSaved CSV: {csv_path}")
    print(f"Saved raw JSON: {json_path}")
    print(f"Saved metrics JSON: {metrics_path}")


if __name__ == "__main__":
    main()