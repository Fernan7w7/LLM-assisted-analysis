import re

def extract_behavior(function_code: str) -> dict:
    lines = [ln.strip() for ln in function_code.splitlines() if ln.strip()]
    ops = []

    for line in lines:
        if "require(" in line:
            ops.append({"type": "CHECK", "detail": line})

        if re.match(r"^(if|else if|else|for|while)\b", line):
            continue

        if "delegatecall" in line:
            ops.append({"type": "DELEGATECALL", "detail": line})
        elif (
            ".call(" in line
            or ".call{" in line
            or ".call.value(" in line
            or ".send(" in line
            or ".transfer(" in line
        ):
            ops.append({"type": "CALL", "detail": line})
        elif (
            "=" in line
            and "==" not in line
            and "!=" not in line
            and ">=" not in line
            and "<=" not in line
        ):
            if line.startswith(("uint ", "int ", "bool ", "address ", "bytes ", "string ")):
                continue
            ops.append({"type": "WRITE", "detail": line})

    has_external_call = any(op["type"] == "CALL" for op in ops)
    has_delegatecall = any(op["type"] == "DELEGATECALL" for op in ops)
    has_auth_check = (
        "onlyowner" in function_code.lower()
        or "msg.sender == owner" in function_code.lower()
        or "require(msg.sender==" in function_code.replace(" ", "").lower()
    )
    has_require = "require(" in function_code

    call_idx = next((i for i, op in enumerate(ops) if op["type"] in {"CALL", "DELEGATECALL"}), None)
    write_after_call = False
    if call_idx is not None:
        write_after_call = any(op["type"] == "WRITE" for op in ops[call_idx + 1:])

    return {
        "operation_sequence": ops,
        "signals": {
            "has_external_call": has_external_call,
            "has_delegatecall": has_delegatecall,
            "has_auth_check": has_auth_check,
            "has_require": has_require,
            "writes_after_call": write_after_call,
        }
    }