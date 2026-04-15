# pipeline/triage.py

CATEGORY_PRIORITY = {
    "NUANCED_ACCESS_CONTROL": 100,
    "ASSET_LOCKING": 95,
    "DELEGATECALL_MISUSE": 90,
    "REENTRANCY": 85,
    "ACCESS_CONTROL": 70,
    "DOS_EXTERNAL": 65,
    "LOGIC_VALIDATION": 40,
}

OVERLAP_RULES = {
    "NUANCED_ACCESS_CONTROL": {"ACCESS_CONTROL", "LOGIC_VALIDATION"},
    "DELEGATECALL_MISUSE": {"ACCESS_CONTROL", "LOGIC_VALIDATION"},
    "REENTRANCY": {"LOGIC_VALIDATION"},
    "ASSET_LOCKING": {"LOGIC_VALIDATION"},
    "ACCESS_CONTROL": {"LOGIC_VALIDATION"},
    "DOS_EXTERNAL": {"LOGIC_VALIDATION"},
}


def _is_positive(result: dict) -> bool:
    return result.get("final_vulnerable") is True


def triage_results(results: list[dict]) -> list[dict]:
    grouped = {}

    for r in results:
        key = (
            r.get("file"),
            r.get("contract_name"),
            r.get("function_name"),
            r.get("provider"),
        )
        grouped.setdefault(key, []).append(r)

    triaged = []

    for _, group in grouped.items():
        positives = [r for r in group if _is_positive(r)]

        if not positives:
            for r in group:
                r["finding_role"] = None
                triaged.append(r)
            continue

        primary = max(
            positives,
            key=lambda r: (
                CATEGORY_PRIORITY.get(r.get("vulnerability_id"), 0),
                float(r.get("final_confidence", 0) or 0),
            )
        )

        primary_label = primary.get("vulnerability_id")
        overlap_labels = OVERLAP_RULES.get(primary_label, set())

        for r in group:
            if not _is_positive(r):
                r["finding_role"] = None
            elif r is primary:
                r["finding_role"] = "primary"
            elif r.get("vulnerability_id") in overlap_labels:
                r["finding_role"] = "overlap"
            else:
                r["finding_role"] = "secondary"

            triaged.append(r)

    return triaged