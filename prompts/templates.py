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
This vulnerability has TWO structural variants — match either one.

VARIANT A — Write-ordering violation:
- A protective state WRITE happens AFTER the delegatecall instead of before it.
- Because delegatecall runs in the caller's storage context, the callee can overwrite the caller's
  storage slots before the guard write executes.
- Match when a critical state write (lock, flag, accounting update) comes AFTER the delegatecall.

VARIANT B — Proxy storage corruption (no writes in the delegating function):
- A proxy contract delegates ALL external calls to an implementation/logic contract via a
  fallback (or receive) function that contains NO state writes — it simply performs delegatecall.
- Corruption occurs because of one of two structural conditions:
  (B1) SLOT COLLISION: the implementation's storage layout overlaps with the proxy's own privileged
       slots. When the logic writes its own variables through delegatecall, it silently overwrites
       the proxy's admin state (owner, totalFunds, etc.).
  (B2) UNINITIALIZED PROXY: the proxy never calls initialize() in its constructor, leaving an
       owner/admin slot at address(0). Anyone can call initialize() through the fallback to seize
       ownership of the proxy's storage.
- Do NOT require a state write in the fallback — the collision is structural, not ordering-based.

- Distinguish from 2.2 (unprotected delegatecall): 1.3 is about STORAGE CORRUPTION via slot
  overlap or uninitialized privileged state; 2.2 is about missing caller auth on the delegatecall.
""",
        """
Delegatecall state corruption (1.3) — property rules:
VARIANT A — Write-ordering:
- Confirm when: (a) the delegatecall target or calldata is externally controllable, AND (b) a
  critical state write occurs AFTER the delegatecall, meaning the callee executes before the
  protective write completes.
- The attacker's contract can stomp the write slot or corrupt adjacent storage before the guard
  write lands.
- If all critical writes precede the delegatecall, property_match = false.

VARIANT B — Proxy storage corruption:
- Confirm when: (a) a proxy's fallback delegates ALL calls to an implementation with no state
  writes in the fallback itself, AND either:
  (b1) the proxy and implementation share overlapping storage slots used for semantically different
       variables, so implementation writes silently corrupt proxy admin state (owner, funds, logic
       address). The implementation's own variables begin at slot 0 or 1, the same as the proxy's
       privileged variables. OR
  (b2) the proxy never initializes its own owner/admin slot, leaving it as address(0), and the
       implementation exposes an initialize() or similar function callable by anyone through the
       proxy's fallback.
- property_match = true for either (b1) or (b2) when (a) holds.
- property_match = false if: the implementation's variables start at a higher slot offset (e.g.,
  slot 4+) to avoid collision with proxy variables, OR the proxy called initialize() in its
  constructor so the owner slot is already set and the initialized flag is true.
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
- Match when a sensitive state-changing function is missing guards that should be there:
  (A) No zero-address check on an address parameter that becomes an owner or recipient.
  (B) No amount > 0 check on a mint/transfer amount.
  (C) No phase check on a state-advancing function.
  (D) No initialization guard that allows re-initialization.
  (E) No return-value check on a low-level send/call: the function calls `.send()` or
      `.call{value:...}()` / `.call.value(...)()` but does NOT check whether the call
      succeeded (no `require(success, ...)` or `if (!success) revert()`). A silent failure
      means funds are silently lost.
- Do NOT match read-only getters, pure helpers, or view functions.
- An authorization check (onlyOwner, require(msg.sender == owner)) does NOT substitute for
  the missing guard — if the function still lacks pattern A/B/C/D/E, it is vulnerable.
- The missing check must create a meaningful exploit path, not just be theoretically imperfect.
""",
        """
Missing input validation (2.3) — property rules:
- Confirm when the missing check enables a concrete exploit:
  (A) Zero-address: setting address(0) as owner/recipient bricks the function or locks funds.
  (B) Amount: minting zero or unbounded tokens causes economic damage.
  (C) Phase: skipping a phase requirement allows premature state advancement.
  (D) Re-initialization: overwriting the legitimate owner with an attacker-supplied address.
  (E) Unchecked send/call: `.send()` or low-level `.call{value:...}()` returns false on failure
      but the function does not check the boolean result — funds sent to a failing recipient
      are silently lost, and execution continues incorrectly.
- Do NOT confirm merely because a function has parameters without checks — the absent validation
  must make a harmful state transition reachable.
- Do NOT reject just because the function has an authorization check (onlyOwner, require(msg.sender
  == owner)). Authorization alone does not substitute for return-value or input validation.
- A balance check (require(deposits[msg.sender] >= amount)) IS a valid amount guard — it prevents
  over-withdrawal. Do NOT flag for missing amount > 0 if an effective balance or supply check is
  already present; withdrawing zero is harmless and not a meaningful exploit path.
- If the contract has compensating guards elsewhere (e.g. the function is only callable via a
  checked router), property_match = false.
""",
    ),

    "1.5": (
        """
Silent termination (1.5) — scenario rules:
- Match when a function calls selfdestruct (or its 0.4.x alias suicide()) WITHOUT emitting
  any event BEFORE the selfdestruct executes.
- Because selfdestruct is final and irreversible, off-chain monitors and dependent contracts
  that watch for event logs receive no signal that the contract was terminated.
- An emit that appears AFTER the selfdestruct in the code is unreachable and does NOT count
  as a preceding notification.
- Do NOT match if a relevant event (e.g. ContractDestroyed, EmergencyShutdown, or any
  shutdown-related event) is emitted BEFORE the selfdestruct call in the same function.
""",
        """
Silent termination (1.5) — property rules:
- Confirm when selfdestruct fires without any preceding emit in the same function body.
  The consequence: off-chain systems (front-ends, indexers, monitoring bots) that rely on
  event logs to detect contract termination receive no signal and may remain in an
  inconsistent state.
- property_match = false if a shutdown/destruction event is emitted before the selfdestruct
  — the emit ORDER matters: emit must precede selfdestruct, not follow it.
- Do NOT reject just because the function is owner-restricted (onlyOwner). Authorization
  does not substitute for pre-termination notification. A protected but silent selfdestruct
  is still a 1.5 vulnerability.
""",
    ),

    "2.4": (
        """
Unprotected selfdestruct (2.4) — scenario rules:
- Match when selfdestruct (or its 0.4.x alias suicide()) is called inside a function that
  has NO authorization check — any external caller can invoke it.
- An authorization check means: onlyOwner modifier, require(msg.sender == owner), or any
  equivalent role guard that restricts the caller.
- Do NOT match if the function has a clear, effective access control guard before the
  selfdestruct call. The guard must be present in THIS function (modifier or require in body).
""",
        """
Unprotected selfdestruct (2.4) — property rules:
- Confirm when an unauthorized caller (any address, not just the owner) can reach the
  selfdestruct call. The consequence is permanent contract destruction and loss of all
  deposited ETH for every user.
- property_match = false if an onlyOwner modifier or equivalent require check gates the
  function — even if the function name looks dangerous (kill, destroy, terminate).
""",
    ),

    "2.5": (
        """
Unguarded state deletion (2.5) — scenario rules:
- Match when a function deletes critical storage (a mapping entry, struct, or array element)
  without verifying that the caller is authorized to perform that deletion.
- Critical storage includes: balance mappings, ownership records, access control entries,
  session or staking records — anything that, if erased, causes economic damage or privilege
  loss for the affected address.
- Do NOT match delete operations on the caller's OWN data (e.g., delete balances[msg.sender])
  — a user wiping their own record is not a vulnerability.
- Do NOT match if a clear authorization check (onlyOwner or require(msg.sender == target))
  gates the function before the delete.
""",
        """
Unguarded state deletion (2.5) — property rules:
- Confirm when any external caller can delete another user's record without restriction.
  The exploit: attacker calls the function with victim's address, zeroing their balance,
  stake, or membership record.
- property_match = false if: the function only deletes msg.sender's own data, OR a sufficient
  authorization check (owner check, role check, or require(msg.sender == target)) is present.
""",
    ),

    "3.1": (
        """
Block/timestamp dependency (3.1) — scenario rules:
- Match when a function uses block.timestamp, block.number, or blockhash as a source of
  randomness OR as the sole timing guard for a critical state transition.
- RANDOMNESS pattern: block attributes fed into a hash function (keccak256, sha3) to
  produce a "random" outcome for a lottery, card game, or selection — predictable/manipulable
  by the block proposer.
- TIMING pattern: block.timestamp used as the only condition to gate a phase transition,
  auction end, or lock period — miner/validator can shift timestamp within accepted drift
  (±15 seconds) to influence the outcome.
- Do NOT match if block attributes are used ONLY for informational logging (emit, off-chain
  data) without affecting any state-changing decision or payout.
""",
        """
Block/timestamp dependency (3.1) — property rules:
- Confirm when the block attribute directly determines a financial outcome or controls
  access to a privileged state transition:
  (A) Randomness: keccak256(block.timestamp, ...) or similar used to pick a winner,
      determine a card, or select an outcome — the block proposer can try multiple values.
  (B) Timing gate: block.timestamp >= deadline used as the sole check to open/close a
      phase — a validator can adjust the timestamp within the allowed drift window to
      self-include or exclude a transaction.
- property_match = false if: the block attribute is only logged in an event (no state
  change), or if additional independent randomness sources (VRF, commit-reveal) are also
  used alongside the block attribute.
""",
    ),

    "3.3": (
        """
Price oracle manipulation (3.3) — scenario rules:
This vulnerability has TWO structural sub-patterns — match either one.

SUB-PATTERN A — Spot/AMM price (flash-loan manipulable):
- The function reads a price or exchange rate directly from an AMM's current reserves
  (e.g. Uniswap getReserves(), balanceOf() ratio, or getAmountsOut()) and uses that
  spot price to drive a collateral valuation, borrowing limit, or mint amount.
- Because the spot price reflects the current pool state, an attacker can flash-loan
  a large amount, swap it to move the reserves in the same transaction, then call this
  function — the inflated or deflated price makes an otherwise undercollateralized
  borrow appear safe.
- A TWAP (time-weighted average price computed over multiple blocks) is NOT manipulable
  in a single transaction. If the function uses a TWAP, do NOT match A.

SUB-PATTERN B — Stale oracle (no freshness check):
- The function reads from a Chainlink-style price feed (latestRoundData, latestAnswer)
  but does NOT check the `updatedAt` timestamp to verify the price is recent.
- If the oracle stops updating (network outage, deprecated feed, sequencer downtime),
  the protocol continues using the last known price indefinitely.
- Do NOT match if the function explicitly checks `block.timestamp - updatedAt <= MAX_STALENESS`
  or equivalent before using the price.

ALSO MATCH: attacker-side exploit contracts that demonstrate oracle manipulation —
functions that combine flash loans (flashLoan callback, pancakeCall, uniswapV2Call)
with swaps to manipulate a pool's spot price before calling a victim protocol.
""",
        """
Price oracle manipulation (3.3) — property rules:
SUB-PATTERN A — Spot price:
- Confirm when: (a) the price is read from current AMM reserves (getReserves, balanceOf ratio),
  AND (b) no TWAP or time-delay mechanism guards the read. The attacker can move reserves
  within a single transaction to inflate/deflate the apparent price.
- property_match = false if: a TWAP price is used (accumulated over multiple blocks), OR
  a staleness/circuit-breaker check prevents single-block manipulation.

SUB-PATTERN B — Stale oracle:
- Confirm when: (a) a Chainlink-style feed is read (latestRoundData / latestAnswer), AND
  (b) the `updatedAt` field is returned but never compared against `block.timestamp` to
  enforce a maximum staleness window.
- property_match = false if: there is a `require(block.timestamp - updatedAt <= MAX_STALENESS)`
  or equivalent check before the price is used.

EXPLOIT CONTRACTS:
- If the function is an attacker-side flash loan callback that swaps to inflate a pool's
  spot price then calls a victim lending/borrowing function in the same transaction,
  property_match = true — the pattern directly demonstrates the oracle manipulation attack.
""",
    ),

    "3.4": (
        """
Stale state read (3.4) — scenario rules:
- Match when a function reads a state variable (or struct field) into a local variable
  BEFORE making an external call, and then uses that cached local value AFTER the call
  returns to drive a critical calculation or decision.
- Because the external call may change the underlying storage (directly or via a callback),
  the local variable is stale by the time it is used — the computation is based on
  pre-call data, not post-call data.
- Also match when a struct field (e.g., snapshotPrice recorded at open time) is never
  refreshed before being used in a calculation that depends on current values.
- Do NOT match if the state variable is read AFTER the external call returns, or if the
  function re-reads storage after the call instead of using the cached value.
""",
        """
Stale state read (3.4) — property rules:
- Confirm when the stale value drives a financial or access-control decision:
  (A) Cached balance: user's balance/stake is read before an external call, and the payout
      or accounting uses the pre-call value even if the balance changed during the call.
  (B) Price snapshot: a price or rate recorded at a prior point in time (e.g., at loan
      open) is used without refreshing from the current oracle value — the discrepancy
      is exploitable if the price has moved significantly.
- property_match = false if:
  (a) The function re-reads the state variable AFTER the external call, so no stale cache
      is used, OR
  (b) The underlying storage is deleted or fully reset BEFORE the external call — the cached
      value is simply the amount to transfer/return and cannot be made stale by the call, OR
  (c) The external call cannot plausibly change the cached storage variable (no callback
      path exists that would modify it), OR
  (d) The cached value does not affect any financial calculation or access-control decision.
""",
    ),

    "3.2": (
        """
tx.origin misuse (3.2) — scenario rules:
- Match when tx.origin is used as the authorization check instead of msg.sender.
- tx.origin always equals the original EOA that initiated the transaction, regardless of
  how many contracts were called in between. Any intermediate contract in the call chain
  can exploit this: if the victim (the tx.origin) is tricked into calling a malicious
  contract, that malicious contract can call the vulnerable contract and pass the tx.origin
  check — even though msg.sender would be the attacker contract, not the owner.
- Do NOT match if tx.origin is used only for informational logging (emit, off-chain data),
  not for an authorization check.
""",
        """
tx.origin misuse (3.2) — property rules:
- Confirm when tx.origin is the sole authorization check for a privileged action (transfer,
  ownership change, withdraw). An attacker contract, called by the legitimate owner, passes
  the tx.origin == owner check and can perform the privileged action on the owner's behalf
  without their specific intent.
- property_match = false if msg.sender is also checked alongside tx.origin, or if tx.origin
  is only used for non-authorization purposes (e.g., event data, informational tracking).
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
