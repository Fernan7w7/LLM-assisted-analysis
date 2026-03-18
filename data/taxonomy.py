VULNERABILITY_SCENARIOS = [
    {
        "id": "DOS_EXTERNAL",
        "name": "DoS by External Contract",
        "scenario": "The function makes an external call inside critical control flow.",
        "property": "If that external call reverts or is controlled by a malicious contract, the core function can become blocked with no recovery path.",
        "severity": "High",
        "confirmation_type": "external_call_criticality",
        "filters": {
            "function_keywords": ["withdraw", "claim", "redeem", "unstake", "borrow"],
            "content_keywords": [".call(", ".transfer(", ".send(", "require(", "if ("]
        }
    },
    {
        "id": "WRONG_CHECKPOINT_ORDER",
        "name": "Wrong Checkpoint Order",
        "scenario": "The function invokes a checkpoint and also updates balances, shares, stakes, or rewards.",
        "property": "The checkpoint is executed after the balance or reward update instead of before it, which can lead to incorrect reward accounting or manipulation.",
        "severity": "High",
        "confirmation_type": "order_check",
        "filters": {
            "function_keywords": ["deposit", "withdraw", "stake", "claim"],
            "content_keywords": ["checkpoint", "reward", "balance", "share", "stake"]
        }
    },
    {
        "id": "SLIPPAGE",
        "name": "Slippage",
        "scenario": "The function performs a swap, liquidity operation, or asset exchange.",
        "property": "The function does not enforce a minimum output amount or equivalent slippage protection, allowing adverse price execution or sandwich attacks.",
        "severity": "High",
        "confirmation_type": "slippage_check",
        "filters": {
            "function_keywords": ["swap", "buy", "sell", "mint", "addliquidity", "removeliquidity"],
            "content_keywords": ["swap", "router", "amountoutmin", "minout", "liquidity"]
        }
    },
    {
        "id": "UNAUTHORIZED_TRANSFER",
        "name": "Unauthorized Transfer",
        "scenario": "The function invokes token transferFrom or equivalent token movement from a from address that may differ from msg.sender.",
        "property": "There is no proper authorization check such as allowance validation, approval validation, ownership validation, or equivalent access control before the token transfer occurs.",
        "severity": "High",
        "confirmation_type": "authorization_check",
        "filters": {
            "function_keywords": ["transfer", "transferfrom", "spend"],
            "content_keywords": ["transferfrom", "allowance", "approve", "from", "erc20"]
        }
    }
]