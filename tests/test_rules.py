import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from rules import evaluate_event

def test_detects_reverse_shell():
    result = evaluate_event(pid=1001, comm="zsh", filename="/usr/bin/nc -e /bin/bash")
    assert result["risk_level"] == "HIGH"
    assert "T1059.004" in result["mitre_technique"]

def test_detects_credential_dumping():
    result = evaluate_event(pid=1002, comm="cat", filename="/bin/cat /etc/shadow")
    assert result["risk_level"] == "CRITICAL"
    assert "T1003.008" in result["mitre_technique"]

def test_detects_defense_evasion():
    result = evaluate_event(pid=1003, comm="bash", filename="history -c")
    assert result["risk_level"] == "HIGH"
    assert "T1070.003" in result["mitre_technique"]

def test_detects_cron_persistence():
    result = evaluate_event(pid=1004, comm="crontab", filename="crontab -e")
    assert result["risk_level"] == "MEDIUM"
    assert "T1053.003" in result["mitre_technique"]

def test_ignores_benign_commands():
    result = evaluate_event(pid=1005, comm="bash", filename="/usr/bin/ls -la")
    assert result["risk_level"] == "INFO"
    assert result["mitre_technique"] is None
