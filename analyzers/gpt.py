import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()
GPT_API_KEY = os.getenv("GPT_API_KEY")


def parse_json_response(raw: str) -> dict:
    raw = raw.strip()

    if "```" in raw:
        parts = raw.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("{"):
                raw = part
                break

    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start != -1 and end > start:
        raw = raw[start:end]

    return json.loads(raw)


def analyze_prompt(prompt: str) -> dict:
    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GPT_API_KEY}"
            },
            json={
                "model": "gpt-4o-mini",
                "temperature": 0,
                "max_tokens": 300,
                "response_format": {"type": "json_object"},
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a smart contract auditor. Respond only with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            },
            timeout=60
        )

        if response.status_code != 200:
            return {
                "ok": False,
                "parsed": None,
                "raw": response.text,
                "error": f"HTTP {response.status_code}"
            }

        data = response.json()

        if "error" in data:
            return {
                "ok": False,
                "parsed": None,
                "raw": json.dumps(data),
                "error": data["error"].get("message", "Unknown API error")
            }

        raw = data["choices"][0]["message"]["content"]
        parsed = parse_json_response(raw)

        return {
            "ok": True,
            "parsed": parsed,
            "raw": raw,
            "error": None
        }

    except Exception as e:
        return {
            "ok": False,
            "parsed": None,
            "raw": None,
            "error": str(e)
        }