import os
import sys
import re

from analyzers.gpt import analyze_prompt as analyze_with_gpt
from analyzers.claude import analyze_prompt as analyze_with_claude
from analyzers.gemini import analyze_prompt as analyze_with_gemini
from data.taxonomy import VULNERABILITY_SCENARIOS
from parsing.solidity_parser import load_contract, extract_functions
from pipeline.reporting import print_summary, save_json
from prompts.templates import build_property_prompt, build_scenario_prompt
from parsing.behavior_extractor import extract_behavior
from pipeline.triage import triage_results
from static_checks.basic_checks import (
    confirm_authorization_check,
    confirm_external_call_dos,
    confirm_order_issue,
    confirm_reentrancy_pattern,
    confirm_access_control,
    confirm_delegatecall_misuse,
    confirm_logic_validation,
    confirm_nuanced_access_control,
    confirm_asset_locking,
)


PROVIDERS = {
    "gpt": analyze_with_gpt,
    #claude": analyze_with_claude,
    #"gemini": analyze_with_gemini,
}

DEBUG_BEHAVIOR_ONLY = False

def function_matches_filter(function_data: dict, vulnerability: dict) -> bool:
    filters = vulnerability.get("filters", {})
    function_keywords = [k.lower() for k in filters.get("function_keywords", [])]
    content_keywords = [k.lower() for k in filters.get("content_keywords", [])]
    behavior = function_data.get("behavior", {})
    signals = behavior.get("signals", {})

    fn_name = function_data["function_name"].lower()
    code = function_data["code"].lower()
    code_compact = " ".join(code.split())

    # --- IR-FIRST SPECIAL CASES ---
    if vulnerability["id"] == "REENTRANCY":
        if not signals.get("has_external_call", False):
            return False

        fn_name = function_data["function_name"].lower()
        code = function_data["code"].lower()

        reentrancy_name_hints = ["withdraw", "claim", "redeem", "borrow", "unstake", "exit"]
        has_name_hint = any(hint in fn_name for hint in reentrancy_name_hints)

        reusable_accounting_hints = (
            "balances[" in code
            or "balanceof[" in code
            or "credits[" in code
            or "shares[" in code
            or "claimable[" in code
            or "pending[" in code
            or "allowance[" in code
        )

        state_reset_hints = (
            "= 0;" in code
            or "=0;" in code
            or "-=" in code
        )

        return has_name_hint or (reusable_accounting_hints and state_reset_hints)

    if vulnerability["id"] == "DELEGATECALL_MISUSE":
        return signals.get("has_delegatecall", False)

    if vulnerability["id"] == "LOGIC_VALIDATION":
        signature = function_data.get("signature", "").lower()

        address_input_like = (
            "address " in signature
            or "address payable" in signature
        )

        amount_input_like = (
            "uint" in signature
            and (
                " amount" in signature
                or "(uint" in signature
                or "msg.value" in code
            )
        )

        return address_input_like or amount_input_like

    # --- GENERIC KEYWORD/CONTENT FILTERS ---
    name_match = any(keyword in fn_name for keyword in function_keywords) if function_keywords else True
    content_match = any(
        keyword in code or keyword in code_compact
        for keyword in content_keywords
    ) if content_keywords else True

    basic_match = name_match or content_match

    if not basic_match:
        return False

    # --- CATEGORY-SPECIFIC REFINEMENTS ---
    if vulnerability["id"] == "DOS_EXTERNAL":
        if not signals.get("has_external_call", False):
            return False

        owner_payout_pattern = (
            ("onlyowner" in code_compact or "msg.sender == owner" in code_compact)
            and (".transfer(" in code_compact or ".call{" in code_compact or ".call.value(" in code_compact)
            and "transferfrom" not in code_compact
        )

        # Normal self-withdraw pattern: user withdraws own balance and only their own call can fail.
        self_withdraw_pattern = (
            function_data["function_name"].lower() == "withdraw"
            and (
                "balances[msg.sender]" in code_compact
                or "balanceof[msg.sender]" in code_compact
                or "pendingwithdrawals[msg.sender]" in code_compact
                or "pending[msg.sender]" in code_compact
                or "credits[msg.sender]" in code_compact
            )
            and ("=0;" in code_compact or "= 0;" in code.lower())
            and (
                "msg.sender.call{" in code_compact
                or "msg.sender.call.value(" in code_compact
                or "msg.sender.transfer(" in code_compact
                or "msg.sender.send(" in code_compact
                or "payable(msg.sender).transfer(" in code_compact
                or "payable(msg.sender).send(" in code_compact
            )
        )

        if owner_payout_pattern or self_withdraw_pattern:
            return False

    return True

def apply_static_check(function_data: dict, vulnerability: dict) -> dict:
    confirmation_type = vulnerability.get("confirmation_type")
    code = function_data["code"]

    if confirmation_type == "reentrancy_pattern":
        return confirm_reentrancy_pattern(function_data)

    if confirmation_type == "access_control_check":
        return confirm_access_control(function_data)

    if confirmation_type == "delegatecall_check":
        return confirm_delegatecall_misuse(function_data)

    if confirmation_type == "logic_validation_check":
        return confirm_logic_validation(function_data)

    if confirmation_type == "nuanced_access_control_check":
        return confirm_nuanced_access_control(function_data)

    if confirmation_type == "asset_locking_check":
        return confirm_asset_locking(function_data)

    if confirmation_type == "order_check":
        return confirm_order_issue(
            code,
            early_terms=["checkpoint"],
            late_terms=["balance", "reward", "share", "stake"]
        )

    if confirmation_type == "external_call_criticality":
        return confirm_external_call_dos(code)

    if confirmation_type == "authorization_check":
        return confirm_authorization_check(code)

    return {
        "applied": False,
        "passed": False,
        "details": "No static check configured."
    }

def analyze_function_with_provider(provider_name: str, provider_fn, filepath: str, function_data: dict, vulnerability: dict) -> dict | None:
    scenario_prompt = build_scenario_prompt(function_data, vulnerability)
    scenario_resp = provider_fn(scenario_prompt)

    if not scenario_resp["ok"]:
        return {
            "provider": provider_name,
            "file": filepath,
            "contract_name": function_data.get("contract_name"),
            "function_name": function_data["function_name"],
            "start_line": function_data.get("start_line"),
            "end_line": function_data.get("end_line"),
            "vulnerability_id": vulnerability["id"],
            "vulnerability_name": vulnerability["name"],
            "error": scenario_resp["error"],
            "raw": {
                "scenario_raw": scenario_resp.get("raw"),
                "property_raw": None,
                "scenario_full_response": scenario_resp.get("full_response")
            },
            "llm_vulnerable": False,
            "final_vulnerable": False
        }

    scenario_data = scenario_resp["parsed"]

    if not scenario_data.get("scenario_match", False):
        return {
            "provider": provider_name,
            "file": filepath,
            "contract_name": function_data.get("contract_name"),
            "function_name": function_data["function_name"],
            "signature": function_data.get("signature"),
            "start_line": function_data.get("start_line"),
            "end_line": function_data.get("end_line"),
            "vulnerability_id": vulnerability["id"],
            "vulnerability_name": vulnerability["name"],
            "severity": vulnerability["severity"],
            "scenario_match": False,
            "scenario_confidence": scenario_data.get("confidence"),
            "scenario_reason": scenario_data.get("reason"),
            "property_match": False,
            "property_confidence": None,
            "property_reason": None,
            "evidence": [],
            "recommendation": None,
            "static_check": {
                "applied": False,
                "passed": False,
                "details": "Property stage not reached because scenario did not match."
            },
            "llm_vulnerable": False,
            "final_vulnerable": False,
            "final_confidence": float(scenario_data.get("confidence", 0) or 0),
            "raw": {
                "scenario_raw": scenario_resp["raw"],
                "property_raw": None
            },
            "error": None
        }

    property_prompt = build_property_prompt(function_data, vulnerability)
    property_resp = provider_fn(property_prompt)

    if not property_resp["ok"]:
        return {
            "provider": provider_name,
            "file": filepath,
            "contract_name": function_data.get("contract_name"),
            "function_name": function_data["function_name"],
            "start_line": function_data.get("start_line"),
            "end_line": function_data.get("end_line"),
            "vulnerability_id": vulnerability["id"],
            "vulnerability_name": vulnerability["name"],
            "error": property_resp["error"],
            "raw": {
                "scenario_raw": scenario_resp.get("raw"),
                "property_raw": None,
                "scenario_full_response": scenario_resp.get("full_response")
            },
            "llm_vulnerable": False,
            "final_vulnerable": False
        }

    property_data = property_resp["parsed"]
    static_result = apply_static_check(function_data, vulnerability)

    llm_vulnerable = (
        scenario_data.get("scenario_match", False)
        and property_data.get("property_match", False)
    )

    STRUCTURAL_CATEGORIES = {
        "REENTRANCY",
        "DELEGATECALL_MISUSE",
        "DOS_EXTERNAL",
        "ACCESS_CONTROL",
    }

    CONTEXTUAL_CATEGORIES = {
        "NUANCED_ACCESS_CONTROL",
        "ASSET_LOCKING",
        "LOGIC_VALIDATION",
    }

    static_corroborated = static_result.get("passed", False)

    final_confidence = 0.0
    try:
        s_conf = float(scenario_data.get("confidence", 0))
        p_conf = float(property_data.get("confidence", 0))
        final_confidence = round((s_conf + p_conf) / 2, 4)
    except Exception:
        final_confidence = 0.0

    if llm_vulnerable:
        if vulnerability["id"] in CONTEXTUAL_CATEGORIES:
            verdict = "llm_positive_contextual"
            decision_basis = "llm_decision_behavior_aware_contextual"
        else:
            verdict = "llm_positive_structural"
            decision_basis = "llm_decision_behavior_aware_structural"
    else:
        verdict = "rejected"
        decision_basis = "llm_negative"

    final_vulnerable = llm_vulnerable

    return {
        "provider": provider_name,
        "file": filepath,
        "contract_name": function_data.get("contract_name"),
        "function_name": function_data["function_name"],
        "signature": function_data.get("signature"),
        "start_line": function_data.get("start_line"),
        "end_line": function_data.get("end_line"),
        "vulnerability_id": vulnerability["id"],
        "vulnerability_name": vulnerability["name"],
        "severity": vulnerability["severity"],
        "scenario_match": scenario_data.get("scenario_match"),
        "scenario_confidence": scenario_data.get("confidence"),
        "scenario_reason": scenario_data.get("reason"),
        "property_match": property_data.get("property_match"),
        "property_confidence": property_data.get("confidence"),
        "property_reason": property_data.get("reason"),
        "evidence": property_data.get("evidence", []),
        "recommendation": property_data.get("recommendation"),
        "static_check": static_result,
        "static_corroborated": static_corroborated,
        "llm_vulnerable": llm_vulnerable,
        "final_vulnerable": final_vulnerable,
        "verdict": verdict,
        "decision_basis": decision_basis,
        "final_confidence": final_confidence,
        "raw": {
            "scenario_raw": scenario_resp["raw"],
            "property_raw": property_resp["raw"]
        },
        "error": None
    }


def analyze_file(filepath: str) -> list[dict]:
    contract_code = load_contract(filepath)
    functions = extract_functions(contract_code)
    results = []

    for function_data in functions:
        function_data["behavior"] = extract_behavior(function_data["code"])
        #print("\n=== FUNCTION ===")
        #print(function_data["function_name"])
        #print(function_data["behavior"])

        if DEBUG_BEHAVIOR_ONLY:
            continue

        for vulnerability in VULNERABILITY_SCENARIOS:
            #========================DEBUG================================
            #if function_data["function_name"] == "Collect":
            #    print("\n=== COLLECT BEHAVIOR ===")
            #    print(function_data["behavior"])
            #    print("TRYING:", vulnerability["id"])
            #==============================================================
            
            matched = function_matches_filter(function_data, vulnerability)
            
            #==========================DEBUG===============================
            #if function_data["function_name"] == "Collect":
            #    print("MATCHED:", vulnerability["id"], matched)
            #==============================================================

            if not matched:
                continue

            for provider_name, provider_fn in PROVIDERS.items():
                result = analyze_function_with_provider(
                    provider_name,
                    provider_fn,
                    filepath,
                    function_data,
                    vulnerability
                )
                if result is not None:
                    results.append(result)

    return triage_results(results)


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m pipeline.runner <contract.sol>")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        sys.exit(1)

    results = analyze_file(filepath)
    print_summary(results)

    output_name = f"llm_analysis_{os.path.basename(filepath)}.json"
    output_path = os.path.join("reports", output_name)
    save_json(results, output_path)

    print(f"\nSaved report to: {output_path}")


if __name__ == "__main__":
    main()