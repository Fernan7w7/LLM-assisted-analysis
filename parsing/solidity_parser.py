import re

def load_contract(filepath: str) -> str:
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def _line_number_from_index(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def extract_contract_names(contract_code: str) -> list[dict]:
    pattern = re.compile(r'\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)')
    results = []
    for match in pattern.finditer(contract_code):
        results.append({
            "type": match.group(1),
            "name": match.group(2),
            "start": match.start(),
            "line": _line_number_from_index(contract_code, match.start())
        })
    return results


def _find_enclosing_contract(contracts: list[dict], function_start: int):
    current = None
    for c in contracts:
        if c["start"] <= function_start:
            current = c
        else:
            break
    return current["name"] if current else None


def load_contract(filepath: str) -> str:
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def _line_number_from_index(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def extract_contract_names(contract_code: str) -> list[dict]:
    pattern = re.compile(r'\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)')
    results = []
    for match in pattern.finditer(contract_code):
        results.append({
            "type": match.group(1),
            "name": match.group(2),
            "start": match.start(),
            "line": _line_number_from_index(contract_code, match.start())
        })
    return results


def _find_enclosing_contract(contracts: list[dict], function_start: int):
    current = None
    for c in contracts:
        if c["start"] <= function_start:
            current = c
        else:
            break
    return current["name"] if current else None


def _extract_body(contract_code: str, match_end: int):
    """Find the matching closing brace for a function body. Returns (body_start, end)."""
    body_start = contract_code.find("{", match_end - 1)
    if body_start == -1:
        return None, None

    depth = 0
    end = body_start
    while end < len(contract_code):
        ch = contract_code[end]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end += 1
                break
        end += 1

    return body_start, end


def extract_functions(contract_code: str) -> list[dict]:
    contracts = extract_contract_names(contract_code)
    functions = []
    seen_starts = set()

    # Named functions
    named_pattern = re.compile(
        r'function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*[^{;]*\{',
        re.MULTILINE
    )
    for match in named_pattern.finditer(contract_code):
        fn_name = match.group(1)
        start = match.start()
        body_start, end = _extract_body(contract_code, match.end())
        if body_start is None:
            continue
        seen_starts.add(start)
        functions.append({
            "contract_name": _find_enclosing_contract(contracts, start),
            "function_name": fn_name,
            "signature": contract_code[start:body_start].strip(),
            "code": contract_code[start:end],
            "start_line": _line_number_from_index(contract_code, start),
            "end_line": _line_number_from_index(contract_code, end),
        })

    # Fallback / receive functions:
    #   Old-style anonymous fallback: function() { ... }
    #   Modern: fallback() external { ... } / receive() external payable { ... }
    special_pattern = re.compile(
        r'(?:'
        r'(function)\s*\(\s*\)'          # old-style anonymous fallback
        r'|'
        r'(fallback|receive)\s*\(\s*\)'  # modern fallback / receive
        r')\s*[^{;]*\{',
        re.MULTILINE
    )
    for match in special_pattern.finditer(contract_code):
        start = match.start()
        if start in seen_starts:
            continue
        keyword = match.group(2) if match.group(2) else "fallback"
        fn_name = keyword  # "fallback" or "receive"
        body_start, end = _extract_body(contract_code, match.end())
        if body_start is None:
            continue
        seen_starts.add(start)
        functions.append({
            "contract_name": _find_enclosing_contract(contracts, start),
            "function_name": fn_name,
            "signature": contract_code[start:body_start].strip(),
            "code": contract_code[start:end],
            "start_line": _line_number_from_index(contract_code, start),
            "end_line": _line_number_from_index(contract_code, end),
        })

    functions.sort(key=lambda f: f["start_line"])
    return functions