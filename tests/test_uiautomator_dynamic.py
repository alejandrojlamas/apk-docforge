from __future__ import annotations

from apk_docforge.tools.uiautomator import (
    classify_blocked_flows,
    parse_bounds,
    parse_uiautomator_dump,
    safe_tap_candidates,
)


def test_uiautomator_parser_safe_and_blocked_nodes() -> None:
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<hierarchy>
  <node index="0" text="Continue" resource-id="app:id/continue" class="android.widget.Button" clickable="true" enabled="true" password="false" bounds="[10,20][110,120]" />
  <node index="1" text="Pay now" resource-id="app:id/pay" class="android.widget.Button" clickable="true" enabled="true" password="false" bounds="[10,140][110,240]" />
  <node index="2" text="" resource-id="app:id/password" class="android.widget.EditText" clickable="true" enabled="true" password="true" bounds="[10,260][210,320]" />
</hierarchy>"""
    nodes = parse_uiautomator_dump(xml)
    assert len(nodes) == 3
    assert parse_bounds("[1,2][3,4]") == (1, 2, 3, 4)
    safe = safe_tap_candidates(nodes)
    assert len(safe) == 1
    assert safe[0].text == "Continue"
    blocked = classify_blocked_flows(nodes)
    assert {item["type"] for item in blocked} == {
        "destructive_or_transactional_action",
        "login_or_sensitive_input",
    }
