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
                "pendingwithdrawals"
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
                "mint", "burn", "upgrade", "set", "configure", "initialize", "execute"
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
    },
    {
        "id": "LOGIC_VALIDATION",
        "name": "Logic / Validation Bug",
        "scenario": "The function performs a sensitive action that depends on input validation or sanity checks.",
        "property": "A required validation is missing, allowing unsafe or unintended execution.",
        "severity": "Medium",
        "confirmation_type": "logic_validation_check",
        "filters": {
            "function_keywords": [
                "set", "update", "mint", "burn", "deposit", "initialize", "configure"
            ],
            "content_keywords": [
                "address ",
                "amount",
                "recipient",
                "msg.value",
                "mint(",
                "burn("
            ]
        }
    }
]