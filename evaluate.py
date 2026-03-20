import json
from pathlib import Path
from collections import defaultdict

LABELS_PATH = Path("datasets/labels.json")
REPORTS_DIR = Path("reports")


def normalize_label_path(p: str) -> str:
    p = p.strip().replace("\\", "/")
    if p.startswith("datasets/"):
        p = p[len("datasets/"):]
    return p


def normalize_report_path(p: str) -> str:
    p = p.strip().replace("\\", "/")
    if p.startswith("datasets/"):
        p = p[len("datasets/"):]
    return p


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def f1_score(precision: float, recall: float) -> float:
    return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0


def load_labels():
    with LABELS_PATH.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    labels = {}
    for item in raw:
        key = (normalize_label_path(item["file"]), item["vulnerability_id"])
        labels[key] = {
            "expected": bool(item["expected"]),
            "affected_functions": item.get("affected_functions"),
            "notes": item.get("notes", ""),
            "category": item.get("category"),
            "split": item.get("split"),
        }
    return labels


def load_reports():
    grouped = defaultdict(list)

    for report_file in REPORTS_DIR.glob("*.json"):
        with report_file.open("r", encoding="utf-8") as f:
            rows = json.load(f)

        for row in rows:
            file_key = normalize_report_path(row["file"])
            vuln_key = row["vulnerability_id"]
            grouped[(file_key, vuln_key)].append(row)

    return grouped


def reduce_provider_predictions(rows):
    provider_preds = {}
    for row in rows:
        provider = row["provider"]
        provider_preds[provider] = bool(row.get("final_vulnerable", False))
    return provider_preds


def reduce_final_prediction(rows):
    return any(bool(r.get("final_vulnerable", False)) for r in rows)


def compute_metrics(records, actor_name):
    tp = fp = tn = fn = 0

    for rec in records:
        expected = rec["expected"]
        predicted = rec["predicted"]

        if predicted and expected:
            tp += 1
        elif predicted and not expected:
            fp += 1
        elif not predicted and not expected:
            tn += 1
        else:
            fn += 1

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = f1_score(precision, recall)
    accuracy = safe_div(tp + tn, tp + tn + fp + fn)

    print(f"\n=== {actor_name} ===")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"Precision={precision:.3f}")
    print(f"Recall={recall:.3f}")
    print(f"F1={f1:.3f}")
    print(f"Accuracy={accuracy:.3f}")

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def main():
    labels = load_labels()
    reports = load_reports()

    provider_records = defaultdict(list)
    final_records = []

    missing = []

    for key, label_info in labels.items():
        rows = reports.get(key, [])
        expected = label_info["expected"]

        if not rows:
            missing.append(key)
            continue

        provider_preds = reduce_provider_predictions(rows)
        final_pred = reduce_final_prediction(rows)

        final_records.append({
            "key": key,
            "expected": expected,
            "predicted": final_pred,
        })

        for provider in ["gpt", "claude", "gemini"]:
            pred = provider_preds.get(provider, False)
            provider_records[provider].append({
                "key": key,
                "expected": expected,
                "predicted": pred,
            })

    if missing:
        print("Missing report entries for:")
        for file_path, vuln_id in missing:
            print(f"  - {file_path} :: {vuln_id}")

    print(f"\nEvaluated {len(final_records)} labeled cases.")

    results = {}
    for provider in ["gpt", "claude", "gemini"]:
        results[provider] = compute_metrics(provider_records[provider], provider.upper())

    results["final"] = compute_metrics(final_records, "FINAL HYBRID")

    print("\n=== Per-case summary ===")
    for rec in final_records:
        file_path, vuln_id = rec["key"]
        print(f"{file_path} :: {vuln_id} | expected={rec['expected']} final={rec['predicted']}")

    return results


if __name__ == "__main__":
    main()