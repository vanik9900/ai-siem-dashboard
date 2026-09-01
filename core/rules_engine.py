import re

SQLI_PATTERN = r"(?i)(SELECT|UNION|INSERT|DROP|--|OR\s+1=1|' OR ')"
XSS_PATTERN = r"(?i)(<script>|javascript:|onload=)"
CMD_PATTERN = r"(?i)(;|\||`|\$\(|/etc/passwd|/bin/sh)"

def check_heuristics(log_line: str) -> dict | None:
    ip_match = re.search(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", log_line)
    ip = ip_match.group(1) if ip_match else "0.0.0.0"

    if re.search(SQLI_PATTERN, log_line):
        return {"ip":ip, "is_threat":True, "threat_type":"SQL Injection", "confidence":95, "explanation": "Matched SQL injection heuristic pattern."}
    elif re.search(XSS_PATTERN, log_line):
        return {"ip": ip, "is_threat": True, "threat_type": "Cross-Site Scripting (XSS)", "confidence": 90, "explanation": "Matched XSS script tag pattern."}
    elif re.search(CMD_PATTERN, log_line):
        return {"ip": ip, "is_threat": True, "threat_type": "Command Injection", "confidence": 98, "explanation": "Matched system command execution attempt."}

    return None

