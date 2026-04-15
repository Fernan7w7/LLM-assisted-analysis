from collections import defaultdict

STRUCTURAL_PRIORITY = {
    "REENTRANCY": 100,
    "DELEGATECALL_MISUSE": 95,
    "DOS_EXTERNAL": 90,
}

CONTEXTUAL_PRIORITY = {
    "NUANCED_ACCESS_CONTROL": 70,
    "ASSET_LOCKING": 75,
    "LOGIC_VALIDATION": 60,
    "ACCESS_CONTROL": 50,
}

DEMOTE_IF_STRUCTURAL_PRESENT = {
    "ACCESS_CONTROL",
    "LOGIC_VALIDATION",
    "NUANCED_ACCESS_CONTROL",
}

OVERLAP_IF_STRUCTURAL_PRESENT = {
    "DOS_EXTERNAL",
}

def _base_priority(result: dict) -> int:
    vuln_id = result.get("vulnerability_id")
    if vuln_id in STRUCTURAL_PRIORITY:
        return STRUCTURAL_PRIORITY[vuln_id]
    if vuln_id in CONTEXTUAL_PRIORITY:
        return CONTEXTUAL_PRIORITY[vuln_id]
    return 40

def _confidence_score(result: dict) -> float:
    try:
        return float(result.get("final_confidence", 0) or 0)
    except Exception:
        return 0.0

def _same_function_key(result: dict):
    return (
        result.get("provider"),
        result.get("file"),
        result.get("contract_name"),
        result.get("function_name"),
    )

def triage_results(results: list[dict]) -> list[dict]:
    positive_results = [r for r in results if r.get("final_vulnerable", False)]
    negative_results = [r for r in results if not r.get("final_vulnerable", False)]

    grouped = defaultdict(list)
    for result in positive_results:
        grouped[_same_function_key(result)].append(result)

    triaged = []

    for _, function_results in grouped.items():
        structural_present = any(
            r.get("vulnerability_id") in STRUCTURAL_PRIORITY
            for r in function_results
        )

        for r in function_results:
            r["_triage_score"] = _base_priority(r) + _confidence_score(r)

        function_results.sort(
            key=lambda r: r["_triage_score"],
            reverse=True
        )

        primary = function_results[0]
        primary["triage_label"] = "primary"
        triaged.append(primary)

        for r in function_results[1:]:
            vuln_id = r.get("vulnerability_id")

            if structural_present and vuln_id in DEMOTE_IF_STRUCTURAL_PRESENT:
                r["triage_label"] = "secondary"
            elif structural_present and vuln_id in OVERLAP_IF_STRUCTURAL_PRESENT:
                r["triage_label"] = "overlap"
            else:
                r["triage_label"] = "secondary"

            triaged.append(r)

    for r in negative_results:
        r["triage_label"] = None
        triaged.append(r)

    for r in triaged:
        r.pop("_triage_score", None)

    return triaged