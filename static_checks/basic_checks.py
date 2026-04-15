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

def confirm_reentrancy_pattern(function_data: dict) -> dict:
    behavior = function_data.get("behavior", {})
    signals = behavior.get("signals", {})

    has_external_call = signals.get("has_external_call", False)
    writes_after_call = signals.get("writes_after_call", False)

    if not has_external_call:
        return {
            "applied": True,
            "passed": False,
            "details": "No external call detected."
        }

    if writes_after_call:
        return {
            "applied": True,
            "passed": True,
            "details": "External call occurs before a later state write, matching a reentrancy risk pattern."
        }

    return {
        "applied": True,
        "passed": False,
        "details": "External call detected, but no state write appears after the call."
    }

def confirm_access_control(function_data: dict) -> dict:
    behavior = function_data.get("behavior", {})
    signals = behavior.get("signals", {})
    code = function_data.get("code", "").lower()
    fn_name = function_data.get("function_name", "").lower()

    sensitive_name = any(term in fn_name for term in [
        "withdraw", "sweep", "set", "mint", "burn", "pause",
        "upgrade", "initialize", "admin", "owner"
    ])

    sensitive_action = (
        signals.get("has_external_call", False)
        or "selfdestruct" in code
        or "delegatecall" in code
        or "owner =" in code
        or "admin =" in code
        or "pause =" in code
    )

    if not (sensitive_name or sensitive_action):
        return {
            "applied": True,
            "passed": False,
            "details": "No clearly sensitive action detected."
        }

    if signals.get("has_auth_check", False):
        return {
            "applied": True,
            "passed": False,
            "details": "Sensitive action detected, but an authorization check is present."
        }

    return {
        "applied": True,
        "passed": True,
        "details": "Sensitive action detected with no authorization check."
    }

def confirm_delegatecall_misuse(function_data: dict) -> dict:
    behavior = function_data.get("behavior", {})
    signals = behavior.get("signals", {})
    code = function_data.get("code", "").lower()
    signature = function_data.get("signature", "").lower()

    if not signals.get("has_delegatecall", False):
        return {
            "applied": True,
            "passed": False,
            "details": "No delegatecall detected."
        }

    risky_target = signals.get("delegatecall_uses_variable_target", False)
    risky_data = signals.get("delegatecall_uses_msg_data", False)
    no_auth = not signals.get("has_auth_check", False)

    if risky_target and risky_data and no_auth:
        return {
            "applied": True,
            "passed": True,
            "details": "Delegatecall uses a variable target and forwarded calldata without authorization."
        }

    if risky_target and no_auth:
        return {
            "applied": True,
            "passed": True,
            "details": "Delegatecall uses a variable target without authorization."
        }

    if risky_data and no_auth:
        return {
            "applied": True,
            "passed": True,
            "details": "Delegatecall forwards msg.data without authorization."
        }

    return {
        "applied": True,
        "passed": False,
        "details": "Delegatecall detected, but no strong misuse pattern was confirmed."
    }

def confirm_logic_validation(function_data: dict) -> dict:
    behavior = function_data.get("behavior", {})
    signals = behavior.get("signals", {})
    code = function_data.get("code", "").lower()
    signature = function_data.get("signature", "").lower()

    missing_zero_address_check = False
    missing_amount_check = False
    matched_subpatterns = []

    address_input_like = (
        "address " in signature
        or "address payable" in signature
        or " recipient" in code
        or " to" in code
    )

    amount_input_like = (
        "uint" in signature
        or "amount" in code
        or "value" in code
        or "msg.value" in code
    )

    if address_input_like and not signals.get("has_zero_address_check", False):
        missing_zero_address_check = True
        matched_subpatterns.append("missing_zero_address_check")

    if amount_input_like and not signals.get("has_amount_check", False):
        missing_amount_check = True
        matched_subpatterns.append("missing_amount_check")

    if matched_subpatterns:
        return {
            "applied": True,
            "passed": True,
            "details": f"Missing validation patterns detected: {', '.join(matched_subpatterns)}."
        }

    return {
        "applied": True,
        "passed": False,
        "details": "No missing zero-address or amount/value validation pattern confirmed."
    }

#========================================== LLM SPECIFIC CHECKS ==========================================
def confirm_nuanced_access_control(function_data: dict) -> dict:
    behavior = function_data.get("behavior", {})
    signals = behavior.get("signals", {})
    code = function_data.get("code", "").lower()
    fn_name = function_data.get("function_name", "").lower()

    privileged_name = any(term in fn_name for term in [
        "initialize", "init", "setup", "setowner", "newowner", "deleteowner",
        "changeowner", "setadmin", "addadmin", "removeadmin", "upgrade",
        "migrate", "close", "settle", "execute", "finalize", "configure"
    ])

    privileged_action = (
        "owner =" in code
        or "owners[" in code
        or "admin =" in code
        or "admins[" in code
        or "initialized =" in code
    )

    if not (privileged_name or privileged_action):
        return {
            "applied": True,
            "passed": False,
            "details": "No clearly privileged action detected."
        }

    if signals.get("has_auth_check", False):
        return {
            "applied": True,
            "passed": False,
            "details": "Privileged action detected, but an authorization check is present."
        }

    return {
        "applied": True,
        "passed": True,
        "details": "Privileged action detected with no authorization check."
    }


def confirm_asset_locking(function_data: dict) -> dict:
    code = function_data.get("code", "").lower()
    fn_name = function_data.get("function_name", "").lower()

    looks_like_deposit = (
        "deposit" in fn_name
        or "balances[" in code
        or "msg.value" in code
    )

    suspicious_gate = (
        "withdrawalsenabled" in code
        or "locked" in code
        or "unlock" in code
    )

    if not looks_like_deposit:
        return {
            "applied": True,
            "passed": False,
            "details": "No clear asset-holding behavior detected."
        }

    if suspicious_gate and "require(withdrawalsenabled" in code:
        return {
            "applied": True,
            "passed": True,
            "details": "Asset movement depends on a gating condition that may leave funds unrecoverable."
        }

    return {
        "applied": True,
        "passed": False,
        "details": "No clear asset-locking pattern confirmed."
    }