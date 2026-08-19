from __future__ import annotations

from typing import Any


def navigation_graph(screens: list[dict[str, Any]], ui_elements: list[dict[str, Any]]) -> str:
    if not screens:
        return "graph TD\n  Unknown[Unknown]\n"
    lines = ["graph TD"]
    for screen in screens:
        node = _node_id(screen.get("name", "Unknown"))
        label = _escape_label(screen.get("name", "Unknown"))
        lines.append(f"  {node}[{label}]")
    if len(screens) == 1:
        return "\n".join(lines) + "\n"
    first = _node_id(screens[0].get("name", "Unknown"))
    for screen in screens[1:]:
        target = _node_id(screen.get("name", "Unknown"))
        lines.append(f"  {first} -. inferred .-> {target}")
    for element in ui_elements[:20]:
        hint = element.get("screen_hint")
        action = element.get("action_guess") or element.get("visible_text") or element.get("element_type")
        if not hint or not action:
            continue
        node = _node_id(hint)
        lines.append(f"  {node} -- {_escape_label(str(action))} --> {node}")
    return "\n".join(lines) + "\n"


def _node_id(value: str) -> str:
    cleaned = "".join(ch for ch in value if ch.isalnum())
    return cleaned or "Unknown"


def _escape_label(value: str) -> str:
    return value.replace("[", "(").replace("]", ")").replace('"', "'")
