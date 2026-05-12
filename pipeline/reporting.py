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
    print("TRACE — FINAL SUMMARY")
    print("=" * 60)

    print(f"Total stored results: {len(results)}")

    vulnerable = [r for r in results if r.get("final_vulnerable")]
    print(f"Final vulnerable results: {len(vulnerable)}")

    primary_findings = [r for r in vulnerable if r.get("triage_label") == "primary"]
    secondary_findings = [r for r in vulnerable if r.get("triage_label") == "secondary"]

    print(f"Primary findings: {len(primary_findings)}")
    print(f"Secondary findings: {len(secondary_findings)}")

    grouped = {}
    for result in primary_findings:
        provider = result["provider"]
        grouped.setdefault(provider, []).append(result)

    for provider, items in grouped.items():
        print(f"\n{provider.upper()} ({len(items)} primary findings)")
        for item in items:
            vuln_id = item.get("vulnerability_id", "?")
            vuln_name = item.get("vulnerability_name", "?")
            vuln_class = item.get("vulnerability_class") or _infer_class(vuln_id)
            print(f"  [{vuln_id}] {vuln_name}  (Class {vuln_class})")
            print(f"    Function: {item['function_name']}")
            print(f"    Reason:   {item.get('property_reason')}")
            if item.get("recommendation"):
                print(f"    Fix:      {item['recommendation']}")

            related = [
                r for r in secondary_findings
                if r.get("provider") == item.get("provider")
                and r.get("file") == item.get("file")
                and r.get("contract_name") == item.get("contract_name")
                and r.get("function_name") == item.get("function_name")
            ]

            if related:
                print("    Also detected (secondary):")
                for rel in related:
                    rel_id = rel.get("vulnerability_id", "?")
                    rel_name = rel.get("vulnerability_name", "?")
                    print(f"      - [{rel_id}] {rel_name}")


def _infer_class(vuln_id: str) -> str:
    try:
        return vuln_id.split(".")[0]
    except Exception:
        return "?"
