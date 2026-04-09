VULNERABILITY_SCENARIOS = [
        {
        "id": "DOS_EXTERNAL",
        "name": "DoS by External Contract",
        "scenario": "The function makes an external call inside critical control flow.",
        "property": "If that external call reverts or is controlled by a malicious contract, the core function can become blocked with no recovery path.",
        "severity": "High",
        "confirmation_type": "external_call_criticality",
        "filters": {
            "function_keywords": ["bid", "participate", "claim", "redeem", "borrow", "withdraw"],
            "content_keywords": [
                ".call(",
                ".call{",
                ".call.value(",
                "bool success",
                "require(success)",
                "if (!success)",
                "revert(",
                "currentLeader",
                "lastUser",
                "pendingWithdrawals"
            ]
        }
    },
    {
        "id": "SLIPPAGE",
        "name": "Slippage",
        "scenario": "The function performs a swap, liquidity operation, or asset exchange.",
        "property": "The function does not enforce a minimum output amount or equivalent slippage protection, allowing adverse execution or sandwich-style loss.",
        "severity": "High",
        "confirmation_type": "slippage_check",
        "filters": {
            "function_keywords": ["swap", "buy", "sell", "addliquidity", "removeliquidity"],
            "content_keywords": [
                "swapexactethfortokens",
                "swapexacttokensfortokens",
                "swapexacttokensforeth",
                "amountoutmin",
                "minout",
                "minimum",
                "getamountsout",
                "router"
            ]
        }
    },
    {
        "id": "UNAUTHORIZED_TRANSFER",
        "name": "Unauthorized Transfer",
        "scenario": "The function moves tokens or assets to another address, especially from an address that may differ from msg.sender, or performs a transfer operation that may require authorization.",
        "property": "There is no proper authorization check such as allowance validation, approval validation, ownership validation, or equivalent access control before the transfer occurs.",
        "severity": "High",
        "confirmation_type": "authorization_check",
        "filters": {
            "function_keywords": ["transfer", "transferfrom", "move", "sweep", "spend", "pay", "payout"],
            "content_keywords": [
                "transferfrom",
                ".transferfrom(",
                ".transfer(",
                "allowance(",
                ".allowance(",
                "approve(",
                "approved",
                "ownerof(",
                "isapprovedforall",
                "onlyowner",
                "msg.sender == owner",
                "require(msg.sender == owner",
                "to.transfer("
            ]
        }
    },
    {
        "id": "REENTRANCY",
        "name": "Reentrancy",
        "scenario": "The function makes an external call before finishing critical state updates.",
        "property": "A malicious callee can re-enter before the contract updates its internal state, allowing repeated execution against stale state.",
        "severity": "High",
        "confirmation_type": "reentrancy_pattern",
        "filters": {
            "function_keywords": ["withdraw", "claim", "redeem", "borrow", "unstake", "exit"],
            "content_keywords": [
                ".call(",
                ".call{",
                ".call.value(",
                ".send(",
                ".transfer(",
                "balances[",
                "msg.sender",
                "bool success",
                "require(success)"
            ]
        }
    },
    {
        "id": "DELEGATECALL_MISUSE",
        "name": "Delegatecall Misuse",
        "scenario": "The function performs a delegatecall or exposes delegatecall-based execution to external input.",
        "property": "The delegatecall target or calldata is externally controllable, insufficiently restricted, or used in a way that can alter the caller contract's storage unexpectedly.",
        "severity": "High",
        "confirmation_type": "delegatecall_check",
        "filters": {
            "function_keywords": [
                "execute", "delegate", "proxy", "upgrade", "forward", "multicall"
            ],
            "content_keywords": [
                ".delegatecall(",
                "target.delegatecall(",
                "implementation.delegatecall(",
                "logic.delegatecall(",
                "delegatecall(data)",
                "delegatecall(msg.data)"
            ]
        }
    }
]