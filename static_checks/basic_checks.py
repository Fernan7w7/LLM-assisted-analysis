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

    external_patterns = [
        ".call(",
        ".call.value(",
        ".delegatecall(",
        ".staticcall(",
        ".transfer(",
        ".send(",
        ".balanceof(",
        ".totalsupply(",
        ".transferfrom(",
        ".approve("
    ]

    has_external = any(pattern in lower for pattern in external_patterns)
    has_blocking_logic = "require(" in lower or "revert(" in lower

    if not has_external:
        return {
            "applied": True,
            "passed": False,
            "details": "No obvious external call found."
        }

    if has_external and has_blocking_logic:
        return {
            "applied": True,
            "passed": True,
            "details": "External call found together with critical require/revert logic."
        }

    return {
        "applied": True,
        "passed": False,
        "details": "External call present, but critical blocking logic not obvious."
    }


def confirm_authorization_check(function_code: str) -> dict:
    lower = function_code.lower()

    transfer_from_like = (
        ".transferfrom(" in lower
        or "transferfrom(" in lower
    )

    authorization_terms = [
        "allowance",
        "approve",
        "approved",
        "onlyowner",
        "ownerof",
        "isapprovedforall",
        "msg.sender"
    ]

    has_auth_signal = any(term in lower for term in authorization_terms)

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
            "details": "Authorization-related indicators found."
        }

    return {
        "applied": True,
        "passed": True,
        "details": "transferFrom-like token pattern found without obvious authorization indicators."
    }

def confirm_slippage_check(function_code: str) -> dict:
    lower = function_code.lower()

    swap_like = any(term in lower for term in [
        "swap",
        "router",
        "liquidity",
        "amountout",
        "buy",
        "sell"
    ])

    slippage_protection = any(term in lower for term in [
        "amountoutmin",
        "minout",
        "minimum",
        "slippage"
    ])

    if not swap_like:
        return {
            "applied": True,
            "passed": False,
            "details": "No obvious swap or liquidity operation found."
        }

    if slippage_protection:
        return {
            "applied": True,
            "passed": False,
            "details": "Potential slippage protection indicators found."
        }

    return {
        "applied": True,
        "passed": True,
        "details": "Swap-like behavior found without obvious minimum output protection."
    }