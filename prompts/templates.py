import json


def _format_behavior(function_data: dict) -> str:
    behavior = function_data.get("behavior", {})
    try:
        return json.dumps(behavior, indent=2, ensure_ascii=False)
    except Exception:
        return str(behavior)


def build_scenario_prompt(function_data: dict, vulnerability: dict) -> str:
    behavior_text = _format_behavior(function_data)

    extra_rules = ""
    if vulnerability.get("id") == "REENTRANCY":
        extra_rules = """
Reentrancy-specific rules:
- Do NOT mark reentrancy only because an external call exists.
- If the relevant balance or sensitive state is updated before the external call, treat that as evidence against reentrancy.
- If the behavior summary shows writes_before_call = true and cei_safe_order = true, that is strong evidence against reentrancy.
- A reentrancy scenario should require that the external call happens before the critical state update, or that stale state can still be exploited during re-entry.
- Checks-Effects-Interactions means performing critical state updates before the external interaction, not after it.
"""
    elif vulnerability.get("id") == "DELEGATECALL_MISUSE":
        extra_rules = """
Delegatecall-specific rules:
- Do NOT mark delegatecall misuse only because delegatecall exists.
- Treat delegatecall as risky when the target, calldata, or execution surface is externally controllable, insufficiently restricted, or can unexpectedly alter caller storage.
- If the delegatecall target is fixed/trusted and the function is protected by a strong authorization check, that is evidence against delegatecall misuse.
- Be careful not to confuse delegatecall misuse with generic validation or access-control issues.
"""
    elif vulnerability.get("id") == "ASSET_LOCKING":
        extra_rules = """
Asset Locking-specific rules:
- A key pattern is irreversible state mutation before an external transfer: if tokens are burned, balances cleared, or records deleted before the transfer executes, a failed transfer permanently traps the user's assets with no recovery path.
- Also covers: permanently gated withdrawal logic, conditions that can never be satisfied, or missing recovery mechanisms.
- Do NOT conflate with DoS (which blocks shared protocol progress for multiple users). Asset locking affects an individual user's own assets.
- Do NOT dismiss a scenario merely because it involves an external call — the order of operations is the key signal: irreversible state changes before the transfer create a one-way trap.
- Do NOT flag a correctly phase-gated or condition-gated settlement/finalization function (e.g. settle() only callable after endAuction()) merely because it transfers ETH/tokens. If the conditions are reachable through normal protocol operation, this is NOT asset locking.
- Do NOT flag CEI-compliant functions (state updated before external call + nonReentrant) as asset locking — if the transfer fails, the full transaction reverts and state is restored.
- A protocol with a working alternative recovery path does not match this scenario.
"""
    elif vulnerability.get("id") == "NUANCED_ACCESS_CONTROL":
        extra_rules = """
Nuanced Access Control-specific rules:
- Do NOT mark a function merely because it is public or externally callable.
- Do NOT mark a clearly role-guarded admin function (onlyOwner, onlyAdmin, onlyRole) as a scenario match unless the guard itself is flawed, bypassable, or incorrectly scoped.
- The scenario must involve a specific authorization flaw: a missing check on one execution path while another is guarded, an incorrect actor assumption, an initialization window where ownership can be hijacked, or a governance bypass.
- Distinguish between 'this function is privileged' (not a vulnerability by itself) and 'this function's authorization logic is specifically broken or incomplete'.
- Do not flag functions where the authorization structure is sound but simply involves multiple roles or modifiers.
- IMPORTANT sub-pattern — wrong guard on two-step transfer: if a function named acceptOwnership (or similar) uses the CURRENT owner's guard (onlyOwner) instead of checking msg.sender == pendingOwner, this is a critical flaw. The pending owner can never accept, defeating the purpose of the two-step pattern. HOWEVER, if the function correctly uses require(msg.sender == pendingOwner), that IS the right guard — do NOT flag it.
- IMPORTANT sub-pattern — missing initialization guard: if an initialize() function has no caller restriction (only a one-time flag like require(!initialized)), any attacker who frontruns the deployment can set themselves as owner. A constructor-based initialization does NOT have this problem.
"""

    return f"""
You are analyzing a Solidity smart contract function for a possible vulnerability scenario.
  

Your job in this stage is NOT to decide final vulnerability.
Your only job is to decide whether the function matches the general behavioral scenario of the vulnerability.

Vulnerability information:
- ID: {vulnerability.get("id")}
- Name: {vulnerability.get("name")}
- Severity: {vulnerability.get("severity")}
- Scenario: {vulnerability.get("scenario")}

Function information:
- Contract: {function_data.get("contract_name")}
- Function: {function_data.get("function_name")}
- Signature: {function_data.get("signature")}
- Start line: {function_data.get("start_line")}
- End line: {function_data.get("end_line")}

Execution summary:
{behavior_text}

Raw Solidity:
[BEGIN SOLIDITY]
{function_data.get("code", "")}
[END SOLIDITY]

Instructions:
- Use the execution summary as the primary reasoning aid.
- Use the raw Solidity code to confirm details or recover missing context.
- Focus only on whether the behavioral scenario is present.
- Do NOT assume a vulnerability exists unless the function behavior clearly matches the scenario.
- Be conservative and avoid overclaiming.
{extra_rules}

Return JSON only in exactly this format:
{{
  "scenario_match": true,
  "confidence": 0.0,
  "reason": "short explanation"
}}

Rules:
- scenario_match must be true or false
- confidence must be a number between 0 and 1
- reason must be short and specific
- return JSON only, no markdown, no extra text
""".strip()


def build_property_prompt(function_data: dict, vulnerability: dict) -> str:
    behavior_text = _format_behavior(function_data)

    extra_rules = ""
    if vulnerability.get("id") == "REENTRANCY":
        extra_rules = """
Reentrancy-specific rules:
- Distinguish unsafe order from CEI-safe order.
- Unsafe order: external call before the critical state update.
- Safe order: critical state update before the external call.
- If the behavior summary shows writes_before_call = true and cei_safe_order = true, property_match should normally be false.
- Do NOT claim reentrancy if the user balance or other critical state is already fully updated before the external call, unless there is clear evidence that another important state remains stale across re-entry.
- Checks-Effects-Interactions means performing critical state updates before the external interaction, not after it.
"""
    elif vulnerability.get("id") == "DELEGATECALL_MISUSE":
        extra_rules = """
Delegatecall-specific rules:
- Do NOT mark delegatecall misuse only because delegatecall exists.
- Treat delegatecall as risky when the target, calldata, or execution surface is externally controllable, insufficiently restricted, or can unexpectedly alter caller storage.
- If the delegatecall target is fixed/trusted and the function is protected by a strong authorization check, that is evidence against delegatecall misuse.
- Be careful not to confuse delegatecall misuse with generic validation or access-control issues.
"""
    elif vulnerability.get("id") == "ASSET_LOCKING":
        extra_rules = """
Asset Locking-specific rules:
- A key pattern is irreversible state mutation before an external transfer: if tokens are burned, balances cleared, or records deleted before the transfer executes, a failed transfer permanently traps the user's assets with no recovery path.
- Also covers: permanently gated withdrawal logic, conditions that can never be satisfied, or missing recovery mechanisms.
- Do NOT conflate with DoS (which blocks shared protocol progress for multiple users). Asset locking affects an individual user's own assets.
- Do NOT dismiss this property merely because it involves an external call — the order of operations is the key signal: irreversible state changes before the transfer create a one-way trap.
- Do NOT confirm for a correctly phase-gated or condition-gated settlement function (e.g. settle() requiring Phase.Ended) that simply pays a winner. If conditions are reachable through normal protocol operation, asset locking is not present.
- Do NOT confirm for CEI-compliant functions (state decremented before external transfer, with nonReentrant) — a failed transfer reverts the entire transaction and restores all state. There is no permanent lock.
- A protocol with a working alternative recovery path does not satisfy this property.
"""
    elif vulnerability.get("id") == "NUANCED_ACCESS_CONTROL":
        extra_rules = """
Nuanced Access Control-specific rules:
- Do NOT confirm this property merely because the function is public or externally callable.
- Do NOT confirm for a clearly role-guarded admin function (onlyOwner, onlyAdmin, onlyRole) unless the guard itself is flawed, bypassable, or incorrectly scoped.
- The property is present when a specific authorization flaw exists: a missing check on one execution path while another is guarded, an incorrect actor assumption, an initialization window where ownership can be hijacked, or a governance bypass.
- The presence of multiple roles or modifiers is not itself a flaw — confirm only when the logic is specifically broken or incomplete.
- Do not flag functions where the authorization structure is sound but simply involves multiple roles.
- CRITICAL: acceptOwnership() wrong-guard test — read the function carefully. If the function uses onlyOwner (or any check that resolves to msg.sender == owner), the guard is WRONG for this function. The PENDING owner should be calling acceptOwnership, not the current owner. This is always a bug: property_match = true. Only property_match = false if the function explicitly checks msg.sender == pendingOwner (or newOwner).
- IMPORTANT: if initialize() has no caller restriction and only a one-time flag, confirm the property — a frontrunner can set themselves as owner before the legitimate deployer. A constructor-based initialization does NOT have this flaw.
"""

    return f"""
You are analyzing a Solidity smart contract function for a specific vulnerability property.

This is the second stage.
Assume the function already matched the general scenario.
Your job now is to decide whether the risky property is actually present in a meaningful way.

Vulnerability information:
- ID: {vulnerability.get("id")}
- Name: {vulnerability.get("name")}
- Severity: {vulnerability.get("severity")}
- Property: {vulnerability.get("property")}

Function information:
- Contract: {function_data.get("contract_name")}
- Function: {function_data.get("function_name")}
- Signature: {function_data.get("signature")}
- Start line: {function_data.get("start_line")}
- End line: {function_data.get("end_line")}

Execution summary:
{behavior_text}

Raw Solidity:
[BEGIN SOLIDITY]
{function_data.get("code", "")}
[END SOLIDITY]

Instructions:
- Use the execution summary as the primary reasoning aid.
- Use the raw Solidity code to confirm details or recover missing context.
- Decide whether the risky property is actually present, not just superficially similar.
- Look for operation order, state changes, external calls, authorization checks, and validation logic.
- Be conservative and avoid overclaiming.
{extra_rules}

Return JSON only in exactly this format:
{{
  "property_match": true,
  "confidence": 0.0,
  "reason": "short explanation",
  "evidence": ["evidence 1", "evidence 2"],
  "recommendation": "short fix"
}}

Rules:
- property_match must be true or false
- confidence must be a number between 0 and 1
- reason must be short and specific
- evidence must be a short list of concrete observations from the function
- recommendation must be short and practical
- return JSON only, no markdown, no extra text
""".strip()