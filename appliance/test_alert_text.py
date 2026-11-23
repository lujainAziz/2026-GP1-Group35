"""alert_text.py must match the reviewed tables in
docs/sprint-2/threat-alert-titles.md row for row (team decision 4)."""
import os
import re

import alert_text

DOC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "docs", "sprint-2", "threat-alert-titles.md")


def _cells(line):
    return [c.strip() for c in line.strip().strip("|").split(" | ")]


def _doc_rows():
    rows, fallback = {}, None
    with open(DOC, encoding="utf-8") as f:
        for line in f:
            cells = _cells(line)
            if len(cells) != 5:
                continue
            num, classtype, _rules, title, explanation = cells
            if num.isdigit():
                rows[classtype] = (title, explanation)
            elif num == "-":
                fallback = (title, explanation)
    return rows, fallback


def _doc_rule_groups():
    """Rows of the 'Rule-specific messages' table: (sids, (title, explanation))."""
    groups, in_section = [], False
    with open(DOC, encoding="utf-8") as f:
        for line in f:
            if line.startswith("## "):
                in_section = line.startswith("## Rule-specific messages")
                continue
            cells = _cells(line)
            if in_section and len(cells) == 3 and re.fullmatch(r"\d+(, \d+)*", cells[0]):
                sids = tuple(int(s) for s in cells[0].split(", "))
                groups.append((sids, (cells[1], cells[2])))
    return tuple(groups)


def test_table_matches_reviewed_doc():
    rows, fallback = _doc_rows()
    assert len(rows) == 39
    assert alert_text.CLASSTYPE_TEXT == rows
    assert alert_text.FALLBACK_TEXT == fallback


def test_rule_table_matches_reviewed_doc():
    groups = _doc_rule_groups()
    assert len(groups) == 6
    assert alert_text.RULE_GROUPS == groups
    sids = [s for g, _ in groups for s in g]
    assert len(sids) == len(set(sids)) == len(alert_text.RULE_TEXT) == 20


def test_alert_text_lookup_and_fallback():
    assert alert_text.alert_text("trojan-activity") == alert_text.CLASSTYPE_TEXT["trojan-activity"]
    assert alert_text.alert_text(" network-scan ")[0] == "Network scan"
    for missing in (None, "", "tcp-connection", 5):
        title, explanation = alert_text.alert_text(missing, "ASSAS TEST High")
        assert title == "Network activity detected"
        assert explanation == (
            'Assas noticed traffic that matched one of its security rules ("ASSAS TEST High"). '
            "The full rule details are below.")


def test_rule_text_overrides_classtype():
    override = alert_text.RULE_TEXT[2010937]
    assert override[0] == "Attempt to reach a device's database feature"
    # The SID wins over the classtype, and over the fallback for an unknown one.
    assert alert_text.alert_text("network-scan", "ET SCAN X", 2010937) == override
    assert alert_text.alert_text(None, "ET SCAN X", 2010937) == override
    assert alert_text.alert_text("network-scan", "ET SCAN X", "2010937") == override
    # Unlisted or unusable rule IDs use the classtype text.
    for rule_id in (None, 8, "", "abc", True, 2010937.0):
        assert (alert_text.alert_text("network-scan", "ET SCAN X", rule_id)
                == alert_text.CLASSTYPE_TEXT["network-scan"])
    # The rule ID is never shown to the user.
    for sid, (title, explanation) in alert_text.RULE_TEXT.items():
        assert str(sid) not in title + explanation


def test_fallback_rule_info_is_the_name_only():
    # Team decision: the rule ID is never shown to the user.
    assert alert_text.rule_info("ET X") == '"ET X"'
    assert alert_text.rule_info("  ") == "no rule details available"
    assert alert_text.rule_info(None) == "no rule details available"


def test_policy_violation_text_does_not_deny_an_attack():
    # Team decision 3: the text must not contradict its High badge (priority 1).
    title, explanation = alert_text.CLASSTYPE_TEXT["policy-violation"]
    assert title == "Risky or restricted activity"
    assert "It is not an attack" not in explanation
    assert "This is not always an attack, but it can put privacy or security at risk." in explanation
