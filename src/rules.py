import re

# Definicíón modular de reglas asociadas a técnicas concretas de MITRE ATT&CK
DETECTION_RULES = [
    {
        "id": "RULE-001",
        "name": "Network Tool Execution",
        "pattern": r"\b(nc|netcat|ncat|socat)\b",
        "risk_level": "HIGH",
        "mitre_technique": "T1059.004 (Command and Scripting Interpreter: Unix Shell)"
    },
    {
        "id": "RULE-002",
        "name": "Credential Access Attempt",
        "pattern": r"(/etc/shadow|unshadow)",
        "risk_level": "CRITICAL",
        "mitre_technique": "T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow)"
    },
    {
        "id": "RULE-003",
        "name": "Defense Evasion - History Cleared",
        "pattern": r"\b(history\s+-c|rm\s+.*\.bash_history|shred)\b",
        "risk_level": "HIGH",
        "mitre_technique": "T1070.003 (Indicator Removal: Clear Linux History)"
    },
    {
        "id": "RULE-004",
        "name": "Persistence - Cron Modification",
        "pattern": r"(/etc/cron|crontab\s+-e)",
        "risk_level": "MEDIUM",
        "mitre_technique": "T1053.003 (Scheduled Task/Job: Cron)"
    },
    {
        "id": "RULE-005",
        "name": "Privilege Escalation - SUID Manipulation",
        "pattern": r"\bchmod\s+(\+s|4[0-7]{3})\b",
        "risk_level": "HIGH",
        "mitre_technique": "T1548.001 (Abuse Elevation Control: Setuid and Setgid)"
    },
    {
        "id": "RULE-006",
        "name": "System Reconnaissance",
        "pattern": r"\b(linpeas|linenum|checksec)\b",
        "risk_level": "MEDIUM",
        "mitre_technique": "T1082 (System Information Discovery)"
    }
]

def evaluate_event(pid: int, comm: str, filename: str) -> dict:
    
    for rule in DETECTION_RULES:
        if re.search(rule["pattern"], filename):
            return {
                "pid": pid,
                "process": comm,
                "path": filename,
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "risk_level": rule["risk_level"],
                "mitre_technique": rule["mitre_technique"]
            }

    return {
        "pid": pid,
        "process": comm,
        "path": filename,
        "rule_id": None,
        "rule_name": None,
        "risk_level": "INFO",
        "mitre_technique": None
    }