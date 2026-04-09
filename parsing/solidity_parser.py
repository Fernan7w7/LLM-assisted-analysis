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


def extract_functions(contract_code: str) -> list[dict]:
    contracts = extract_contract_names(contract_code)

    pattern = re.compile(
        r'function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*[^{;]*\{',
        re.MULTILINE
    )

    functions = []

    for match in pattern.finditer(contract_code):
        fn_name = match.group(1)
        start = match.start()
        body_start = contract_code.find("{", match.end() - 1)
        if body_start == -1:
            continue

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

        fn_code = contract_code[start:end]
        signature = contract_code[start:body_start].strip()

        functions.append({
            "contract_name": _find_enclosing_contract(contracts, start),
            "function_name": fn_name,
            "signature": signature,
            "code": fn_code,
            "start_line": _line_number_from_index(contract_code, start),
            "end_line": _line_number_from_index(contract_code, end)
        })

    return functions