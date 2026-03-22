import json
from pathlib import Path
from collections import defaultdict

LABELS_PATH = Path("datasets/labels.json")
REPORTS_DIR = Path("reports")
PROVIDERS = ["gpt", "claude", "gemini"]
LAYERS = {
    "scenario": "scenario_match",
    "property": "property_match",
    "llm": "llm_vulnerable",
    "final": "final_vulnerable",
}


def normalize_path(p: str) -> str:
    p = p.strip().replace("\\", "/")
    if p.startswith("datasets/"):
        p = p[len("datasets/"):]
    return p


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def f1_score(precision: float, recall: float) -> float:
    return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0


def compute_metrics(records):
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


def print_metric_block(title: str, metrics: dict):
    print(f"\n=== {title} ===")
    print(f"TP={metrics['tp']} FP={metrics['fp']} TN={metrics['tn']} FN={metrics['fn']}")
    print(f"Precision={metrics['precision']:.3f}")
    print(f"Recall={metrics['recall']:.3f}")
    print(f"F1={metrics['f1']:.3f}")
    print(f"Accuracy={metrics['accuracy']:.3f}")


def load_labels():
    with LABELS_PATH.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    labels = {}
    for item in raw:
        key = (normalize_path(item["file"]), item["vulnerability_id"])
        labels[key] = {
            "expected": bool(item["expected"]),
            "affected_functions": item.get("affected_functions"),
            "notes": item.get("notes", ""),
            "category": item.get("category"),
            "split": item.get("split"),
            "vulnerability_id": item["vulnerability_id"],
        }
    return labels


def load_report_rows():
    grouped = defaultdict(list)

    for report_file in REPORTS_DIR.glob("*.json"):
        with report_file.open("r", encoding="utf-8") as f:
            rows = json.load(f)

        for row in rows:
            key = (normalize_path(row["file"]), row["vulnerability_id"])
            grouped[key].append(row)

    return grouped


def reduce_rows_by_provider(rows):
    by_provider = {}
    for row in rows:
        by_provider[row["provider"]] = row
    return by_provider


def bool_field(row: dict | None, field: str) -> bool:
    if row is None:
        return False
    return bool(row.get(field, False))


def build_layer_records(labels, grouped_rows, field_name: str):
    provider_records = defaultdict(list)
    aggregated_records = []
    missing = []

    for key, label in labels.items():
        rows = grouped_rows.get(key, [])
        expected = bool(label["expected"])

        if not rows:
            missing.append(key)
            continue

        by_provider = reduce_rows_by_provider(rows)

        aggregated_pred = any(bool_field(r, field_name) for r in rows)
        aggregated_records.append({
            "key": key,
            "expected": expected,
            "predicted": aggregated_pred,
            "vulnerability_id": label["vulnerability_id"],
            "split": label.get("split"),
            "category": label.get("category"),
        })

        for provider in PROVIDERS:
            row = by_provider.get(provider)
            pred = bool_field(row, field_name)
            provider_records[provider].append({
                "key": key,
                "expected": expected,
                "predicted": pred,
                "vulnerability_id": label["vulnerability_id"],
                "split": label.get("split"),
                "category": label.get("category"),
            })

    return provider_records, aggregated_records, missing


def group_records(records, field_name: str):
    grouped = defaultdict(list)
    for rec in records:
        grouped[rec.get(field_name)].append(rec)
    return grouped


def print_summary_table(results_by_layer):
    print("\n=== SUMMARY TABLE ===")
    print(f"{'Layer':<12} {'Actor':<12} {'Precision':<10} {'Recall':<10} {'F1':<10} {'Accuracy':<10}")
    print("-" * 66)

    for layer, actors in results_by_layer.items():
        for actor, metrics in actors.items():
            print(
                f"{layer:<12} {actor:<12} "
                f"{metrics['precision']:<10.3f} "
                f"{metrics['recall']:<10.3f} "
                f"{metrics['f1']:<10.3f} "
                f"{metrics['accuracy']:<10.3f}"
            )


def print_per_vulnerability_breakdown(layer_name, actor_name, records):
    print(f"\n--- {actor_name} / {layer_name} / by vulnerability ---")
    grouped = group_records(records, "vulnerability_id")
    for vuln_id, vuln_records in grouped.items():
        metrics = compute_metrics(vuln_records)
        print(
            f"{vuln_id:<24} "
            f"P={metrics['precision']:.3f} "
            f"R={metrics['recall']:.3f} "
            f"F1={metrics['f1']:.3f} "
            f"Acc={metrics['accuracy']:.3f}"
        )


def print_per_split_breakdown(layer_name, actor_name, records):
    print(f"\n--- {actor_name} / {layer_name} / by split ---")
    grouped = group_records(records, "split")
    for split, split_records in grouped.items():
        metrics = compute_metrics(split_records)
        print(
            f"{str(split):<12} "
            f"P={metrics['precision']:.3f} "
            f"R={metrics['recall']:.3f} "
            f"F1={metrics['f1']:.3f} "
            f"Acc={metrics['accuracy']:.3f}"
        )


def print_correction_stats(labels, grouped_rows):
    print("\n=== CORRECTION STATS (LLM -> FINAL) ===")

    provider_stats = {
        provider: {"fp_removed": 0, "fn_fixed": 0}
        for provider in PROVIDERS
    }
    aggregated_stats = {"fp_removed": 0, "fn_fixed": 0}

    for key in labels.keys():
        rows = grouped_rows.get(key, [])
        if not rows:
            continue

        by_provider = reduce_rows_by_provider(rows)

        for provider in PROVIDERS:
            row = by_provider.get(provider)
            if row is None:
                continue

            llm_pred = bool_field(row, "llm_vulnerable")
            final_pred = bool_field(row, "final_vulnerable")

            if llm_pred and not final_pred:
                provider_stats[provider]["fp_removed"] += 1
            if not llm_pred and final_pred:
                provider_stats[provider]["fn_fixed"] += 1

        llm_agg = any(bool_field(r, "llm_vulnerable") for r in rows)
        final_agg = any(bool_field(r, "final_vulnerable") for r in rows)

        if llm_agg and not final_agg:
            aggregated_stats["fp_removed"] += 1
        if not llm_agg and final_agg:
            aggregated_stats["fn_fixed"] += 1

    for provider in PROVIDERS:
        stats = provider_stats[provider]
        print(
            f"{provider.upper():<10} "
            f"False positives removed={stats['fp_removed']}, "
            f"False negatives fixed={stats['fn_fixed']}"
        )

    print(
        f"{'AGGREGATED':<10} "
        f"False positives removed={aggregated_stats['fp_removed']}, "
        f"False negatives fixed={aggregated_stats['fn_fixed']}"
    )


def main():
    labels = load_labels()
    grouped_rows = load_report_rows()

    print(f"Loaded {len(labels)} labeled cases.")

    all_results = {}

    for layer_name, field_name in LAYERS.items():
        provider_records, aggregated_records, missing = build_layer_records(labels, grouped_rows, field_name)

        print("\n" + "#" * 32)
        print(f"# LAYER: {layer_name.upper()} ({field_name})")
        print("#" * 32)

        if missing:
            print("\nMissing report entries for:")
            for file_path, vuln_id in missing:
                print(f"  - {file_path} :: {vuln_id}")

        layer_results = {}

        for provider in PROVIDERS:
            metrics = compute_metrics(provider_records[provider])
            print_metric_block(f"{provider.upper()} [{layer_name}]", metrics)
            print_per_vulnerability_breakdown(layer_name, provider.upper(), provider_records[provider])
            print_per_split_breakdown(layer_name, provider.upper(), provider_records[provider])
            layer_results[provider] = metrics

        aggregated_metrics = compute_metrics(aggregated_records)
        print_metric_block(f"AGGREGATED [{layer_name}]", aggregated_metrics)
        print_per_vulnerability_breakdown(layer_name, "AGGREGATED", aggregated_records)
        print_per_split_breakdown(layer_name, "AGGREGATED", aggregated_records)
        layer_results["aggregated"] = aggregated_metrics

        all_results[layer_name] = layer_results

    print_summary_table(all_results)
    print_correction_stats(labels, grouped_rows)

    print("\n=== Per-case FINAL layer summary ===")
    _, final_records, _ = build_layer_records(labels, grouped_rows, "final_vulnerable")
    for rec in final_records:
        file_path, vuln_id = rec["key"]
        print(f"{file_path} :: {vuln_id} | expected={rec['expected']} final={rec['predicted']}")


if __name__ == "__main__":
    main()