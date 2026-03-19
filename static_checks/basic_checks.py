import re

def confirm_order_issue(function_code: str, early_terms: list[str], late_terms: list[str]) -> dict:
    lower = function_code.lower()

    early_positions = [lower.find(term.lower()) for term in early_terms if lower.find(term.lower()) != -1]
    late_positions = [lower.find(term.lower()) for term in late_terms if lower.find(term.lower()) != -1]

    if not early_positions or not late_positions:
        return {
            "applied": True,
            "passed": False,
            "details": "Could not locate both statement groups."
        }

    early_pos = min(early_positions)
    late_pos = min(late_positions)

    return {
        "applied": True,
        "passed": early_pos > late_pos,
        "details": f"checkpoint_position={early_pos}, balance_or_reward_position={late_pos}"
    }


def confirm_external_call_dos(function_code: str) -> dict:
    lower = function_code.lower()

    external_call_patterns = [
        r"\.call\s*\(",
        r"\.call\s*\.value\s*\(",
        r"\.call\s*\{",
        r"\.delegatecall\s*\(",
        r"\.delegatecall\s*\{",
        r"\.staticcall\s*\(",
        r"\.staticcall\s*\{",
        r"\.transfer\s*\(",
        r"\.send\s*\("
    ]

    has_external = any(re.search(p, lower) for p in external_call_patterns)

    if not has_external:
        return {
            "applied": True,
            "passed": False,
            "details": "No obvious external call found."
        }

    is_withdraw_function = "function withdraw" in lower
    sends_to_msg_sender = (
        re.search(r"payable\s*\(\s*msg\.sender\s*\)\s*\.transfer\s*\(", lower) is not None
        or re.search(r"msg\.sender\s*\s*\.transfer\s*\(", lower) is not None
        or re.search(r"payable\s*\(\s*msg\.sender\s*\)\s*\.call\s*\{", lower) is not None
    )
    reads_pending_withdrawal = (
        "pendingwithdrawals[msg.sender]" in lower
        or "pending[msg.sender]" in lower
        or "withdrawals[msg.sender]" in lower
    )
    clears_user_balance_before_call = any(term in lower for term in [
        "pendingwithdrawals[msg.sender] = 0",
        "pending[msg.sender] = 0",
        "withdrawals[msg.sender] = 0"
    ])

    self_withdraw_pattern = (
        is_withdraw_function
        and sends_to_msg_sender
        and reads_pending_withdrawal
        and clears_user_balance_before_call
    )

    if self_withdraw_pattern:
        return {
            "applied": True,
            "passed": False,
            "details": "Self-withdraw pull-payment pattern detected; failure affects only the caller, not shared protocol progress."
        }

    direct_blocking_call = (
        re.search(r"require\s*\([^;{}]*\.call", lower) is not None
        or re.search(r"require\s*\([^;{}]*\.transfer", lower) is not None
        or re.search(r"require\s*\([^;{}]*\.send", lower) is not None
    )

    checked_success_flag = (
        re.search(r"\(\s*bool\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*,", lower) is not None
        and re.search(r"require\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)", lower) is not None
    )

    revert_on_failed_success = (
        re.search(r"if\s*\(\s*!\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*\{\s*revert", lower) is not None
        or re.search(r"if\s*\(\s*!\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)\s*revert", lower) is not None
    )

    if direct_blocking_call or checked_success_flag or revert_on_failed_success:
        return {
            "applied": True,
            "passed": True,
            "details": "External call found together with blocking logic tied to the call result."
        }

    return {
        "applied": True,
        "passed": False,
        "details": "External call present, but its failure is not tied to blocking logic."
    }


def confirm_authorization_check(function_code: str) -> dict:
    lower = function_code.lower()

    transfer_from_like = (
        ".transferfrom(" in lower
        or "transferfrom(" in lower
    )

    auth_indicators = [
        "allowance(",
        ".allowance(",
        "approve(",
        "approved",
        "onlyowner",
        "ownerof(",
        "isapprovedforall",
        "msg.sender == owner",
        "require(msg.sender == owner"
    ]

    has_auth_signal = any(term in lower for term in auth_indicators)

    if not transfer_from_like:
        return {
            "applied": True,
            "passed": False,
            "details": "No transferFrom-like token pattern found."
        }

    if has_auth_signal:
        return {
            "applied": True,
            "passed": False,
            "details": "Authorization-related indicators found around token movement."
        }

    return {
        "applied": True,
        "passed": True,
        "details": "transferFrom-like token movement found without obvious authorization checks."
    }

def confirm_slippage_check(function_code: str) -> dict:
    lower = function_code.lower()
    compact = " ".join(lower.split())

    swap_patterns = [
        r"swapexactethfortokens",
        r"swapexacttokensfortokens",
        r"swapexacttokensforeth",
        r"swapethforexacttokens",
        r"swaptokensforexacttokens",
        r"swaptokensforexacteth"
    ]

    quote_only_patterns = [
        r"getamountsout",
        r"getamountsin"
    ]

    has_swap = any(re.search(p, compact) for p in swap_patterns)
    is_quote_only = any(re.search(p, compact) for p in quote_only_patterns) and not has_swap

    if is_quote_only:
        return {
            "applied": True,
            "passed": False,
            "details": "Read-only price query detected; no swap execution."
        }

    if not has_swap:
        return {
            "applied": True,
            "passed": False,
            "details": "No obvious swap execution found."
        }

    zero_min_patterns = [
        r"swapexactethfortokens\s*\{[^}]*\}\s*\(\s*0\s*,",
        r"swapexactethfortokens\s*\(\s*0\s*,",
        r"swapexacttokensfortokens\s*\(\s*[^,]+\s*,\s*0\s*,",
        r"swapexacttokensforeth\s*\(\s*[^,]+\s*,\s*0\s*,"
    ]

    has_zero_min = any(re.search(p, compact) for p in zero_min_patterns)

    named_min_patterns = [
        r"amountoutmin",
        r"\bminout\b",
        r"\bminimum\b",
        r"\bmin_out\b"
    ]

    has_named_min = any(re.search(p, compact) for p in named_min_patterns)

    manual_output_check = (
        "require(" in compact and
        (
            ">= minout" in compact or
            ">= amountoutmin" in compact or
            "slippage too high" in compact or
            "amounts[amounts.length - 1] >=" in compact or
            "amounts[amounts.length-1] >=" in compact
        )
    )

    if has_zero_min and not manual_output_check:
        return {
            "applied": True,
            "passed": True,
            "details": "Swap found with amountOutMin set to 0 and no manual minimum-output check."
        }

    if has_named_min or manual_output_check:
        return {
            "applied": True,
            "passed": False,
            "details": "Swap found with explicit slippage protection or manual minimum-output validation."
        }

    return {
        "applied": True,
        "passed": False,
        "details": "Swap found, but missing zero-min confirmation for a strong slippage finding."
    }