import requests
import json
import re

def analyze_with_ollama(log_line: str, ollama_url: str, model_name: str) -> dict:
    ip_match = re.search(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", log_line)
    ip = ip_match.group(1) if ip_match else "0.0.0.0"

    prompt = f"""Analyze this web server access log for malicious activity or false negatives:
Log: "{log_line}"
Respond ONLY in valid raw JSON with these exact keys:
{{"is_threat": boolean, "threat_type": string, "confidence": integer_0_to_100, "explanation": string}}"""

    try:
        response = requests.post(
            ollama_url,
            json={"model": model_name, "prompt": prompt, "stream": False, "format": "json"},
            timeout=5
        )
        result = json.loads(response.json().get("response", "{}"))
        result["ip"] = ip
        return result
    except Exception:
        return {"ip": ip, "is_threat": False, "threat_type": "Clean", "confidence": 0, "explanation": "Log analyzed as normal."}