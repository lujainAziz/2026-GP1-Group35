"""alert_text.py must match the reviewed table in
docs/sprint-2/threat-alert-titles.md row for row (team decision 4)."""
import os

import alert_text

DOC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "docs", "sprint-2", "threat-alert-titles.md")


def _doc_rows():
    rows, fallback = {}, None
    with open(DOC, encoding="utf-8") as f:
        for line in f:
            cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
            if len(cells) != 5:
                continue
            num, classtype, _rules, title, explanation = cells
            if num.isdigit():
                rows[classtype] = (title, explanation)
            elif num == "-":
                fallback = (title, explanation)
    return rows, fallback


def test_table_matches_reviewed_doc():
    rows, fallback = _doc_rows()
    assert len(rows) == 39
    assert alert_text.CLASSTYPE_TEXT == rows
    assert alert_text.FALLBACK_TEXT == fallback


def test_alert_text_lookup_and_fallback():
    assert alert_text.alert_text("trojan-activity") == alert_text.CLASSTYPE_TEXT["trojan-activity"]
    assert alert_text.alert_text(" network-scan ")[0] == "Network scan"
    for missing in (None, "", "tcp-connection", 5):
        title, explanation = alert_text.alert_text(missing, "ASSAS TEST High", 1000001)
        assert title == "Network activity detected"
        assert '("ASSAS TEST High", rule ID 1000001)' in explanation
        assert "{rule}" not in explanation


def test_fallback_rule_info_parts():
    assert alert_text.rule_info("ET X", 7) == '"ET X", rule ID 7'
    assert alert_text.rule_info("  ", 7) == "rule ID 7"
    assert alert_text.rule_info("ET X", None) == '"ET X"'
    assert alert_text.rule_info(None, None) == "no rule details available"


def test_policy_violation_title_does_not_deny_an_attack():
    # Team decision 3: the title must not contradict its High badge (priority 1).
    assert alert_text.CLASSTYPE_TEXT["policy-violation"][0] == "Unsafe activity"
