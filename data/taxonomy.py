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
        "id": "ACCESS_CONTROL",
        "name": "Access Control",
        "scenario": "The function performs a privileged or sensitive action such as changing critical state, moving funds, or changing configuration.",
        "property": "The function lacks an appropriate authorization check such as onlyOwner, role validation, or an explicit msg.sender permission check.",
        "severity": "High",
        "confirmation_type": "access_control_check",
        "filters": {
            "function_keywords": [
                "withdraw", "sweep", "setowner", "setadmin", "pause", "unpause",
                "mint", "burn", "upgrade", "set", "configure", "initialize"
            ],
            "content_keywords": [
                "onlyowner",
                "msg.sender == owner",
                "require(msg.sender == owner",
                "owner =",
                "admin =",
                "transfer(",
                ".call{",
                ".call(",
                "selfdestruct",
                "delegatecall",
                "pause =",
                "mint("
            ]
        }
    }
]