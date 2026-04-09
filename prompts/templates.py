import json


def _format_behavior(function_data: dict) -> str:
    behavior = function_data.get("behavior", {})
    try:
        return json.dumps(behavior, indent=2, ensure_ascii=False)
    except Exception:
        return str(behavior)


def build_scenario_prompt(function_data: dict, vulnerability: dict) -> str:
    behavior_text = _format_behavior(function_data)

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