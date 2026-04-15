VULNERABILITY_SCENARIOS = [
    {
        "id": "DOS_EXTERNAL",
        "name": "DoS by External Contract",
        "scenario": "The function makes an external call inside critical control flow where a failing or malicious callee can block an intended workflow, settlement path, auction progression, distribution, or protocol action for other users or the protocol itself.",
        "property": "The vulnerability exists when an external call can revert or fail in a way that blocks a broader intended process with no safe recovery path. A normal user-facing withdrawal that only affects the caller's own payout is not, by itself, a denial-of-service vulnerability unless it can block other users, shared state progression, or protocol-level execution.",
        "severity": "High",
        "confirmation_type": "external_call_criticality",
        "filters": {
            "function_keywords": ["bid", "participate", "claim", "redeem", "borrow", "withdraw", "settle", "finalize", "distribute"],
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
                "highestBidder",
                "winner",
                "pendingwithdrawals",
                "refund",
                "settle"
            ]
        }
    },
    {
        "id": "ACCESS_CONTROL",
        "name": "Access Control",
        "scenario": "The function performs a privileged or administrator-restricted action such as sweeping shared funds, changing ownership, changing configuration, upgrading logic, pausing protocol behavior, minting, burning, or executing privileged calls.",
        "property": "The vulnerability exists when a truly privileged action lacks an appropriate authorization check such as onlyOwner, role validation, or explicit caller restriction. A normal user-facing function that lets a user withdraw or manage only their own funds is not, by itself, an access-control vulnerability.",
        "severity": "High",
        "confirmation_type": "access_control_check",
        "filters": {
            "function_keywords": [
                "sweep", "setowner", "setadmin", "pause", "unpause",
                "mint", "burn", "upgrade", "set", "configure",
                "initialize", "execute", "transferownership",
                "acceptownership", "grantrole", "revokerole"
            ],
            "content_keywords": [
                "onlyowner",
                "msg.sender == owner",
                "require(msg.sender == owner",
                "owner =",
                "admin =",
                "selfdestruct",
                "delegatecall",
                "pause =",
                "mint(",
                "grantrole",
                "revokerole",
                "transferownership"
            ]
        }
    },
    {
        "id": "REENTRANCY",
        "name": "Reentrancy",
        "scenario": "The function makes an external call before completing a critical state update in a way that may let a malicious callee re-enter and exploit stale accounting or repeat a value-extracting action.",
        "property": "The vulnerability exists when re-entry can exploit stale balances, stale withdrawal state, stale claim state, or another reusable authorization/accounting condition to obtain repeated execution or repeated asset extraction. A function is not reentrant merely because it performs an external call before a later state write; there must be a meaningful re-entry path that benefits from stale state.",
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
    },
    {
        "id": "NUANCED_ACCESS_CONTROL",
        "name": "Nuanced Access Control",
        "scenario": "A function or workflow performs a privileged, governance-sensitive, initialization-sensitive, or role-sensitive action where authorization logic exists or is implied, but is inconsistent, incomplete, bypassable, or incorrectly scoped.",
        "property": "The issue is not merely that a function is public or externally callable. The vulnerability exists when a sensitive action that should be restricted to a specific actor, role, phase, or governance path can be performed through flawed authorization logic, missing path-specific checks, inconsistent caller assumptions, or incorrect initialization / ownership transitions.",
        "severity": "High",
        "confirmation_type": "nuanced_access_control_check",
        "filters": {
            "function_keywords": [
                "initialize", "init", "setup", "setowner", "transferownership",
                "acceptownership", "renounceownership", "changeowner", "setadmin",
                "addadmin", "removeadmin", "upgrade", "migrate", "finalize",
                "configure", "execute", "setrole", "grantrole", "revokerole"
            ],
            "content_keywords": [
                "owner",
                "admin",
                "governance",
                "initializer",
                "onlyowner",
                "onlyadmin",
                "onlyrole",
                "msg.sender == owner",
                "require(msg.sender ==",
                "pendingowner",
                "newowner",
                "transferownership",
                "acceptownership",
                "grantrole",
                "revokerole"
            ]
        }
    },
    {
        "id": "ASSET_LOCKING",
        "name": "Asset Locking / Frozen Funds",
        "scenario": "A function or workflow can place Ether, tokens, or balances into a state where users or the protocol may be unable to withdraw, recover, migrate, redeem, or settle assets through the intended valid path.",
        "property": "The vulnerability exists when contract logic can trap assets because withdrawal, recovery, migration, redemption, or settlement depends on broken, unreachable, contradictory, permanently failing, or missing conditions. A normal deposit or withdrawal function is not, by itself, an asset-locking vulnerability unless the logic can actually prevent valid asset recovery.",
        "severity": "High",
        "confirmation_type": "asset_locking_check",
        "filters": {
            "function_keywords": [
                "claim", "redeem", "settle", "close",
                "refund", "migrate", "recover", "release", "unlock"
            ],
            "content_keywords": [
                "locked",
                "unlock",
                "pending",
                "claim",
                "redeem",
                "settle",
                "migrate",
                "refund",
                "recover",
                "release",
                "unclaimed",
                "expired",
                "timelock",
                "vesting"
            ]
        }
    }
]