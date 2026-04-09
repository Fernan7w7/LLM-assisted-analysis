import re

def extract_behavior(function_code: str) -> dict:
    lines = [ln.strip() for ln in function_code.splitlines() if ln.strip()]
    ops = []

    for line in lines:
        if "require(" in line:
            ops.append({"type": "CHECK", "detail": line})

        if re.match(r"^(if|else if|else|for|while)\b", line):
            continue

        if ".delegatecall(" in line:
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
            if line.startswith((
                "uint ", "uint8 ", "uint16 ", "uint32 ", "uint64 ", "uint128 ", "uint256 ",
                "int ", "int8 ", "int16 ", "int32 ", "int64 ", "int128 ", "int256 ",
                "bool ", "address ", "bytes ", "bytes32 ", "string "
            )):
                continue
            ops.append({"type": "WRITE", "detail": line})

    lowered = function_code.lower()
    compact = function_code.replace(" ", "").lower()

    has_external_call = any(op["type"] == "CALL" for op in ops)
    has_delegatecall = any(op["type"] == "DELEGATECALL" for op in ops)
    has_auth_check = (
        "onlyowner" in lowered
        or "msg.sender == owner" in lowered
        or "require(msg.sender==" in compact
    )
    has_require = "require(" in function_code

    call_idx = next((i for i, op in enumerate(ops) if op["type"] in {"CALL", "DELEGATECALL"}), None)
    write_after_call = False
    if call_idx is not None:
        write_after_call = any(op["type"] == "WRITE" for op in ops[call_idx + 1:])

    delegatecall_uses_msg_data = "delegatecall(msg.data)" in compact or ".delegatecall(msg.data)" in compact
    delegatecall_uses_variable_target = False
    if has_delegatecall:
        variable_target_terms = ["target.delegatecall", "implementation.delegatecall", "logic.delegatecall", "_impl.delegatecall", "impl.delegatecall"]
        delegatecall_uses_variable_target = any(term in compact for term in variable_target_terms)

    return {
        "operation_sequence": ops,
        "signals": {
            "has_external_call": has_external_call,
            "has_delegatecall": has_delegatecall,
            "has_auth_check": has_auth_check,
            "has_require": has_require,
            "writes_after_call": write_after_call,
            "delegatecall_uses_msg_data": delegatecall_uses_msg_data,
            "delegatecall_uses_variable_target": delegatecall_uses_variable_target,
        }
    }