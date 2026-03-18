import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


def parse_json_response(raw: str) -> dict:
    if raw is None:
        raise ValueError("Raw response is None")

    raw = raw.strip()

    if not raw:
        raise ValueError("Raw response is empty")

    if "```" in raw:
        parts = raw.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if "{" in part and "}" in part:
                raw = part
                break

    start = raw.find("{")
    end = raw.rfind("}") + 1

    if start == -1 or end <= start:
        raise ValueError(f"No JSON object found in raw response: {raw!r}")

    return json.loads(raw[start:end])


def extract_all_text(obj):
    texts = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "text" and isinstance(value, str):
                texts.append(value)
            else:
                texts.extend(extract_all_text(value))
    elif isinstance(obj, list):
        for item in obj:
            texts.extend(extract_all_text(item))

    return texts


def analyze_prompt(prompt: str) -> dict:
    model_id = "gemini-2.5-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={GEMINI_API_KEY}"

    try:
        response = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            json={
                "system_instruction": {
                    "parts": [
                        {
                            "text": "Return exactly one complete JSON object. Do not use markdown fences. Do not add any extra words. Do not split the JSON across multiple blocks."
                        }
                    ]
                },
                "contents": [
                    {
                        "parts": [
                            {"text": prompt}
                        ]
                    }
                ],
                "generationConfig": {
                    "thinkingConfig": {
                        "thinkingBudget": 0
                    },
                    "temperature": 0,
                    "maxOutputTokens": 500,
                    "response_mime_type": "application/json"
                }
            },
            timeout=60
        )

        if response.status_code != 200:
            return {
                "ok": False,
                "parsed": None,
                "raw": response.text,
                "full_response": None,
                "error": f"HTTP {response.status_code}"
            }

        data = response.json()

        if "error" in data:
            return {
                "ok": False,
                "parsed": None,
                "raw": json.dumps(data),
                "full_response": data,
                "error": data["error"].get("message", "Unknown API error")
            }

        texts = extract_all_text(data)
        raw = "\n".join(t for t in texts if t).strip()

        if not raw:
            return {
                "ok": False,
                "parsed": None,
                "raw": json.dumps(data),
                "full_response": data,
                "error": "No text found anywhere in Gemini response"
            }

        try:
            parsed = parse_json_response(raw)
        except Exception as e:
            return {
                "ok": False,
                "parsed": None,
                "raw": raw,
                "full_response": data,
                "error": f"JSON parse error: {e}"
            }

        return {
            "ok": True,
            "parsed": parsed,
            "raw": raw,
            "full_response": data,
            "error": None
        }

    except Exception as e:
        return {
            "ok": False,
            "parsed": None,
            "raw": None,
            "full_response": None,
            "error": str(e)
        }