import json


def _format_behavior(function_data: dict) -> str:
    behavior = function_data.get("behavior", {})
    try:
        return json.dumps(behavior, indent=2, ensure_ascii=False)
    except Exception:
        return str(behavior)


# Per-ID extra rules injected into both scenario and property prompts.
# Keys are taxonomy IDs; values are (scenario_rules, property_rules) tuples.
_EXTRA_RULES = {
    "1.1": (
        """
Reentrancy (1.1) — scenario rules:
- Do NOT match only because an external call exists.
- The match requires that the external call happens BEFORE the critical state update (e.g. balance
  zeroed, withdrawal flag set, share burned). CEI order means writes come first, not last.
- If cei_safe_order = true and writes_before_call = true, that is strong evidence against reentrancy.
- Owner-only admin withdrawals that send only to the owner address are not reentrancy candidates.
""",
        """
Reentrancy (1.1) — property rules:
- Confirm only when re-entry can exploit stale ETH/token accounting: stale balances, stale withdrawal
  flags, or a reusable allowance that has not been decremented before the call.
- If the critical state is fully updated before the call, property_match = false unless another
  important stale state variable remains exploitable during re-entry.
- CEI compliance (writes before call, cei_safe_order = true) is strong evidence against this property.
""",
    ),

    "1.2": (
        """
Reentrancy state-only (1.2) — scenario rules:
- This variant involves callbacks (ERC-777 tokensReceived, ERC-721 onERC721Received, flash-loan
  callbacks, or arbitrary hooks) rather than plain ETH transfers.
- Match when the callback is invoked BEFORE a non-ETH state update: vote tallies, token snapshots,
  reward accumulators, or mint/burn balances.
- The "value" being stolen is corrupted on-chain state, not necessarily ETH.
- Do NOT match only because a transfer() or send() exists — look for callback hook patterns.
""",
        """
Reentrancy state-only (1.2) — property rules:
- Confirm when re-entry through a callback exploits stale non-ETH state: vote counts, snapshot
  indices, reward amounts, or token balances that have not been updated before the hook fires.
- The attacker does not need to extract ETH — corrupting state (inflating votes, double-minting)
  is sufficient for a positive property match.
- If the state update happens before the callback, property_match = false.
""",
    ),

    "1.3": (
        """
Delegatecall state corruption (1.3) — scenario rules:
- This is an ORDERING violation: a protective state WRITE happens AFTER the delegatecall instead
  of before it.
- Because delegatecall runs in the caller's storage context, the callee can overwrite the caller's
  storage slots before the guard write executes.
- Do NOT match only because delegatecall exists. Match when a critical state write (lock, flag,
  accounting update) comes after the delegatecall in the operation sequence.
- Distinguish from 2.2 (unprotected delegatecall): 1.3 is about WRITE order, 2.2 is about missing
  caller auth check.
""",
        """
Delegatecall state corruption (1.3) — property rules:
- Confirm when: (a) the delegatecall target or calldata is externally controllable, AND (b) a
  critical state write occurs after the delegatecall, meaning the callee executes before the
  protective write completes.
- The attacker's contract (the delegatecall target) can stomp the write slot or corrupt adjacent
  storage before the guard write lands.
- If all critical writes precede the delegatecall, property_match = false.
""",
    ),

    "1.4": (
        """
DoS via external call (1.4) — scenario rules:
- Match when an external call sits inside a SHARED settlement path — an auction finalization,
  a distribution loop, or a shared-state progression — where a reverting callee blocks the
  workflow for ALL other participants, not just the caller.
- Do NOT match a normal user withdrawal that only affects the caller's own payout.
- Look for patterns: iterating over a list of recipients, forcing payment to a current winner or
  leader, or requiring a call to succeed before state advances for others.
""",
        """
DoS via external call (1.4) — property rules:
- Confirm when the external call can permanently revert and there is NO safe fallback: no
  try/catch, no pull-payment alternative, no skip-on-failure logic.
- The blocking must affect other users or shared protocol state, not just the caller.
- A pull-payment pattern (where each user withdraws independently) is NOT a DoS vulnerability.
- If the callee reverting only causes the caller's own transaction to fail, property_match = false.
""",
    ),

    "2.1": (
        """
Access control bypass (2.1) — scenario rules:
- Match when a privileged action (ownership transfer, role grant, upgrade, pause, mint, sweep) is
  either missing an authorization guard entirely, OR has a guard that is flawed, bypassable, or
  incorrectly scoped.
- Key sub-patterns to catch:
  * No guard at all on a sensitive function.
  * acceptOwnership() checking msg.sender == owner (current owner) instead of msg.sender ==
    pendingOwner — the pending owner can never call this, defeating the two-step pattern.
  * initialize() with only a one-time flag (require(!initialized)) and no caller restriction —
    any frontrunner can call it first and set themselves as owner.
- Do NOT match a plainly role-guarded admin function (onlyOwner, onlyAdmin) unless the guard
  itself is broken.
""",
        """
Access control bypass (2.1) — property rules:
- Confirm when an unauthorized caller CAN reach and execute the privileged action through the
  flawed, missing, or incorrectly scoped guard.
- acceptOwnership() wrong-guard: if the function uses onlyOwner (or msg.sender == owner), the
  property IS present — the pending owner can never call it. Only false if it correctly checks
  msg.sender == pendingOwner.
- Unguarded initialize(): if any caller can front-run deployment and set themselves as owner,
  property_match = true.
- A correctly scoped onlyOwner or role guard with no initialization or transition surface is NOT
  a confirmed property.
""",
    ),

    "2.2": (
        """
Unprotected delegatecall (2.2) — scenario rules:
- Match when a delegatecall is reachable without an adequate guard on WHO can trigger it or WHAT
  target can be specified.
- This is a GUARD ABSENCE violation: no CHECK(msg.sender) or CHECK(target) before the delegatecall.
- Distinguish from 1.3 (delegatecall state corruption): 2.2 is about the missing caller/target
  guard, not the write-ordering violation.
- A delegatecall to a fixed trusted address guarded by onlyOwner is NOT a scenario match here.
""",
        """
Unprotected delegatecall (2.2) — property rules:
- Confirm when an unauthorized caller can invoke the delegatecall with an arbitrary target,
  executing attacker code in the calling contract's storage context.
- If the target is hardcoded and trusted (not user-supplied), or the function is guarded by a
  correct onlyOwner modifier, property_match = false.
- The risk is storage slot corruption or complete ownership takeover via a malicious implementation
  address chosen by the attacker.
""",
    ),

    "2.3": (
        """
Missing input validation (2.3) — scenario rules:
- Match when a sensitive state-changing function is missing guards that should be there: no
  zero-address check on an address parameter that becomes an owner or recipient, no amount > 0
  check on a mint/transfer amount, no phase check on a state-advancing function, or no
  initialization guard that allows re-initialization.
- Do NOT match read-only getters, pure helpers, or view functions.
- Do NOT match role-guarded admin functions (onlyOwner, initializer modifier) unless the guard
  itself is incomplete.
- The missing check must create a meaningful exploit path, not just be theoretically imperfect.
""",
        """
Missing input validation (2.3) — property rules:
- Confirm when the missing check enables a concrete exploit: setting address(0) as owner/recipient,
  minting zero or unbounded tokens, skipping a phase requirement, or allowing re-initialization
  that overwrites the legitimate owner.
- Do NOT confirm merely because a function has parameters without checks — the absent validation
  must make a harmful state transition reachable.
- If the contract has compensating guards elsewhere (e.g. the function is only callable via a
  checked router), property_match = false.
""",
    ),
}


def build_scenario_prompt(function_data: dict, vulnerability: dict) -> str:
    behavior_text = _format_behavior(function_data)
    vuln_id = vulnerability.get("id", "")
    scenario_rules, _ = _EXTRA_RULES.get(vuln_id, ("", ""))

    return f"""
You are analyzing a Solidity smart contract function for a possible vulnerability scenario.

Your job in this stage is NOT to decide final vulnerability.
Your only job is to decide whether the function matches the general behavioral scenario of the vulnerability.

Vulnerability information:
- Taxonomy ID: {vuln_id}
- Name: {vulnerability.get("name")}
- Class: {vulnerability.get("class")} — {vulnerability.get("class_name")}
- Severity: {vulnerability.get("severity")}
- Precondition: {vulnerability.get("precondition")}
- Scenario: {vulnerability.get("scenario")}

Function information:
- Contract: {function_data.get("contract_name")}
- Function: {function_data.get("function_name")}
- Signature: {function_data.get("signature")}
- Start line: {function_data.get("start_line")}
- End line: {function_data.get("end_line")}

Execution summary (IR):
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
{scenario_rules}
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
    vuln_id = vulnerability.get("id", "")
    _, property_rules = _EXTRA_RULES.get(vuln_id, ("", ""))

    return f"""
You are analyzing a Solidity smart contract function for a specific vulnerability property.

This is the second stage.
Assume the function already matched the general scenario.
Your job now is to decide whether the risky property is actually present in a meaningful way.

Vulnerability information:
- Taxonomy ID: {vuln_id}
- Name: {vulnerability.get("name")}
- Class: {vulnerability.get("class")} — {vulnerability.get("class_name")}
- Severity: {vulnerability.get("severity")}
- Precondition: {vulnerability.get("precondition")}
- Property: {vulnerability.get("property")}

Function information:
- Contract: {function_data.get("contract_name")}
- Function: {function_data.get("function_name")}
- Signature: {function_data.get("signature")}
- Start line: {function_data.get("start_line")}
- End line: {function_data.get("end_line")}

Execution summary (IR):
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
{property_rules}
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
