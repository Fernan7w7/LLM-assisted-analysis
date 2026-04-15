import re

def extract_behavior(function_code: str) -> dict:
    lines = [ln.strip() for ln in function_code.splitlines() if ln.strip()]
    ops = []

    for line in lines:
        lowered = line.lower()
        compact = line.replace(" ", "").lower()

        # checks
        if "require(" in lowered or re.match(r"^if\s*\(", lowered):
            ops.append({"type": "CHECK", "detail": line})

        # detect delegatecall before skipping control-flow lines
        if ".delegatecall(" in compact:
            ops.append({"type": "DELEGATECALL", "detail": line})

        # detect external calls, including old-style call.value(...) and calls inside if(...)
        elif (
            ".call(" in compact
            or ".call{" in compact
            or ".call.value(" in compact
            or ".send(" in compact
            or ".transfer(" in compact
        ):
            ops.append({"type": "CALL", "detail": line})

        # skip control-flow lines for WRITE classification only
        if re.match(r"^(if|else\s+if|else|for|while)\b", lowered):
            continue

        # writes
        if (
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

    lowered_code = function_code.lower()
    compact_code = function_code.replace(" ", "").lower()

    has_external_call = any(op["type"] == "CALL" for op in ops)
    has_delegatecall = any(op["type"] == "DELEGATECALL" for op in ops)
    has_auth_check = (
        "onlyowner" in lowered_code
        or "msg.sender == owner" in lowered_code
        or "require(msg.sender==" in compact_code
    )
    has_require = "require(" in lowered_code or "if(" in compact_code

    call_idx = next((i for i, op in enumerate(ops) if op["type"] in {"CALL", "DELEGATECALL"}), None)
    write_after_call = False
    if call_idx is not None:
        write_after_call = any(op["type"] == "WRITE" for op in ops[call_idx + 1:])

    delegatecall_uses_msg_data = (
        "delegatecall(msg.data)" in compact_code
        or ".delegatecall(msg.data)" in compact_code
    )

    delegatecall_uses_variable_target = False
    if has_delegatecall:
        variable_target_terms = [
            "target.delegatecall",
            "implementation.delegatecall",
            "logic.delegatecall",
            "_impl.delegatecall",
            "impl.delegatecall"
        ]
        delegatecall_uses_variable_target = any(term in compact_code for term in variable_target_terms)

    has_zero_address_check = (
        "address(0)" in compact_code
        and ("require(" in compact_code or "if(" in compact_code)
    )

    has_amount_check = any(pattern in compact_code for pattern in [
        "require(amount>0",
        "require(amount!=0",
        "require(_am>0",
        "require(_am!=0",
        "require(value>0",
        "require(value!=0",
        "require(msg.value>0",
        "require(msg.value!=0"
    ])

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
            "has_zero_address_check": has_zero_address_check,
            "has_amount_check": has_amount_check,
        }
    }