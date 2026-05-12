from collections import defaultdict

# Within-class priority: higher = wins triage when multiple IDs fire on same function.
# Class 1 always beats Class 2 (base scores are separated by 100).
ID_PRIORITY = {
    # Class 1 — Operation Ordering Violations (200-range)
    "1.1": 210,  # Reentrancy
    "1.2": 205,  # Reentrancy (state-only)
    "1.3": 200,  # Delegatecall state corruption
    "1.4": 190,  # DoS via external call
    "1.5": 180,  # Silent termination (future)
    # Class 2 — Guard Absence Violations (100-range)
    "2.1": 120,  # Access control bypass
    "2.2": 115,  # Unprotected delegatecall
    "2.3": 100,  # Missing input validation
    "2.4": 90,   # Unprotected selfdestruct (future)
    "2.5": 80,   # Unguarded state deletion (future)
    # Class 3 — State Visibility Violations (future, 0-range)
    "3.1": 30,
    "3.2": 25,
    "3.3": 20,
    "3.4": 10,
}

# Class 2 IDs that should be demoted to secondary when a Class 1 finding is also present
DEMOTE_IF_CLASS1_PRESENT = {"2.1", "2.2", "2.3", "2.4", "2.5"}


def _base_priority(result: dict) -> int:
    return ID_PRIORITY.get(result.get("vulnerability_id", ""), 0)


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


def _vuln_class(result: dict) -> int:
    vid = result.get("vulnerability_id", "")
    try:
        return int(vid.split(".")[0])
    except (ValueError, IndexError):
        return 99


def triage_results(results: list[dict]) -> list[dict]:
    positive_results = [r for r in results if r.get("final_vulnerable", False)]
    negative_results = [r for r in results if not r.get("final_vulnerable", False)]

    grouped = defaultdict(list)
    for result in positive_results:
        grouped[_same_function_key(result)].append(result)

    triaged = []

    for _, function_results in grouped.items():
        class1_present = any(_vuln_class(r) == 1 for r in function_results)

        for r in function_results:
            r["_triage_score"] = _base_priority(r) + _confidence_score(r)

        function_results.sort(key=lambda r: r["_triage_score"], reverse=True)

        primary = function_results[0]
        primary["triage_label"] = "primary"
        triaged.append(primary)

        for r in function_results[1:]:
            vuln_id = r.get("vulnerability_id", "")
            if class1_present and vuln_id in DEMOTE_IF_CLASS1_PRESENT:
                r["triage_label"] = "secondary"
            else:
                r["triage_label"] = "secondary"
            triaged.append(r)

    for r in negative_results:
        r["triage_label"] = None
        triaged.append(r)

    for r in triaged:
        r.pop("_triage_score", None)

    return triaged
