def build_scenario_prompt(function_data: dict, vulnerability: dict) -> str:
    return f"""
      You are a smart contract security auditor.

      Decide whether the Solidity function below matches this vulnerability scenario.

      Vulnerability: {vulnerability['name']}
      Scenario: {vulnerability['scenario']}

      Return ONLY valid JSON:
      {{
        "scenario_match": true,
        "confidence": 0.0,
        "reason": "short reason"
      }}

      or

      {{
        "scenario_match": false,
        "confidence": 0.0,
        "reason": "short reason"
      }}

      Rules:
      - confidence must be a number between 0 and 1
      - use only the given function
      - do not include markdown
      - do not include extra keys

      Contract: {function_data.get('contract_name')}
      Function: {function_data['function_name']}
      Signature: {function_data['signature']}

      Code:
      {function_data['code']}
      """.strip()


def build_property_prompt(function_data: dict, vulnerability: dict) -> str:
    return f"""
You are a smart contract security auditor.

Assume the function already matches the vulnerability scenario.
Now decide whether it also satisfies the risky property below.

Vulnerability: {vulnerability['name']}
Property: {vulnerability['property']}

Return ONLY valid JSON:
{{
  "property_match": true,
  "confidence": 0.0,
  "reason": "short reason",
  "evidence": ["specific code evidence"],
  "recommendation": "one sentence fix"
}}

or

{{
  "property_match": false,
  "confidence": 0.0,
  "reason": "short reason",
  "evidence": [],
  "recommendation": null
}}

Rules:
- confidence must be a number between 0 and 1
- evidence must contain short code-grounded phrases
- use only the given function
- do not include markdown
- do not include extra keys

Contract: {function_data.get('contract_name')}
Function: {function_data['function_name']}
Signature: {function_data['signature']}

Code:
{function_data['code']}
""".strip()