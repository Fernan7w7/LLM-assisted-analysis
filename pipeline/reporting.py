import json
import os


def save_json(results: list[dict], output_path: str):
    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def print_summary(results: list[dict]):
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)

    print(f"Total stored results: {len(results)}")

    vulnerable = [r for r in results if r.get("final_vulnerable")]
    print(f"Final vulnerable results: {len(vulnerable)}")

    grouped = {}
    for result in vulnerable:
        provider = result["provider"]
        grouped.setdefault(provider, []).append(result)

    for provider, items in grouped.items():
        print(f"\n{provider.upper()} ({len(items)} findings)")
        for item in items:
            print(f"  - {item['function_name']} -> {item['vulnerability_name']}")
            print(f"    Reason: {item.get('property_reason')}")
            if item.get("recommendation"):
                print(f"    Fix: {item['recommendation']}")