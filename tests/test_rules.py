import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from rules import evaluate_event


def test_detects_network_tool():
    result = evaluate_event(
        pid=1001,
        comm="zsh",
        filename="/usr/bin/nc -e /bin/bash",
    )
    assert result["risk_level"] == "HIGH"
    assert result["rule_id"] == "RULE-001"


def test_detects_credential_dumping():
    result = evaluate_event(
        pid=1002,
        comm="cat",
        filename="/bin/cat /etc/shadow",
    )
    assert result["risk_level"] == "CRITICAL"
    assert result["rule_id"] == "RULE-002"


def test_detects_defense_evasion():
    result = evaluate_event(
        pid=1003,
        comm="bash",
        filename="history -c",
    )
    assert result["risk_level"] == "HIGH"
    assert result["rule_id"] == "RULE-003"


def test_detects_cron_persistence():
    result = evaluate_event(
        pid=1004,
        comm="crontab",
        filename="crontab -e",
    )
    assert result["risk_level"] == "MEDIUM"
    assert result["rule_id"] == "RULE-004"


def test_detects_suid_symbolic():
    result = evaluate_event(
        pid=1005,
        comm="chmod",
        filename="chmod +s /tmp/test",
    )
    assert result["risk_level"] == "HIGH"
    assert result["rule_id"] == "RULE-005"


def test_detects_suid_numeric():
    result = evaluate_event(
        pid=1006,
        comm="chmod",
        filename="chmod 4755 /tmp/test",
    )
    assert result["risk_level"] == "HIGH"
    assert result["rule_id"] == "RULE-005"


def test_detects_system_reconnaissance():
    result = evaluate_event(
        pid=1007,
        comm="bash",
        filename="/tmp/linpeas",
    )
    assert result["risk_level"] == "MEDIUM"
    assert result["rule_id"] == "RULE-006"


def test_ignores_benign_commands():
    result = evaluate_event(
        pid=1008,
        comm="bash",
        filename="/usr/bin/ls -la",
    )
    assert result["risk_level"] == "INFO"
    assert result["rule_id"] is None


def test_ignores_similar_benign_command():
    result = evaluate_event(
        pid=1009,
        comm="bash",
        filename="/usr/bin/ncatting",
    )
    assert result["risk_level"] == "INFO"
    assert result["rule_id"] is None