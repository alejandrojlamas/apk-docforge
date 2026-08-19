from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any


BOUNDS_RE = re.compile(r"\[(\d+),(\d+)]\[(\d+),(\d+)]")
SAFE_ACTION_WORDS = {
    "ok",
    "continue",
    "next",
    "allow",
    "start",
    "skip",
    "close",
    "got it",
    "accept",
    "aceptar",
    "continuar",
    "siguiente",
    "omitir",
    "permitir",
    "cerrar",
    "entendido",
}
DESTRUCTIVE_WORDS = {
    "delete",
    "remove",
    "buy",
    "purchase",
    "pay",
    "subscribe",
    "send",
    "post",
    "share",
    "logout",
    "sign out",
    "borrar",
    "eliminar",
    "comprar",
    "pagar",
    "suscribir",
    "enviar",
    "publicar",
    "compartir",
    "cerrar sesión",
}
LOGIN_WORDS = {"login", "log in", "sign in", "ingresar", "entrar", "iniciar sesión"}


@dataclass(frozen=True)
class UINode:
    node_id: str
    class_name: str | None
    text: str | None
    resource_id: str | None
    content_desc: str | None
    clickable: bool
    enabled: bool
    password: bool
    bounds: tuple[int, int, int, int] | None

    @property
    def center(self) -> tuple[int, int] | None:
        if not self.bounds:
            return None
        x1, y1, x2, y2 = self.bounds
        return ((x1 + x2) // 2, (y1 + y2) // 2)

    @property
    def label(self) -> str:
        return self.text or self.content_desc or self.resource_id or self.class_name or self.node_id

    def to_json(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "class_name": self.class_name,
            "text": self.text,
            "resource_id": self.resource_id,
            "content_desc": self.content_desc,
            "clickable": self.clickable,
            "enabled": self.enabled,
            "password": self.password,
            "bounds": list(self.bounds) if self.bounds else None,
            "center": list(self.center) if self.center else None,
        }


def parse_uiautomator_dump(xml_text: str) -> list[UINode]:
    cleaned = _clean_dump(xml_text)
    if not cleaned:
        return []
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return []
    nodes: list[UINode] = []
    for index, element in enumerate(root.iter("node")):
        nodes.append(
            UINode(
                node_id=str(index),
                class_name=_attr(element, "class"),
                text=_none_empty(_attr(element, "text")),
                resource_id=_none_empty(_attr(element, "resource-id")),
                content_desc=_none_empty(_attr(element, "content-desc")),
                clickable=_bool_attr(element, "clickable"),
                enabled=_bool_attr(element, "enabled", default=True),
                password=_bool_attr(element, "password"),
                bounds=parse_bounds(_attr(element, "bounds")),
            )
        )
    return nodes


def safe_tap_candidates(nodes: list[UINode], limit: int = 5) -> list[UINode]:
    candidates = []
    for node in nodes:
        if not node.clickable or not node.enabled or not node.center:
            continue
        label = node.label.lower()
        if any(word in label for word in DESTRUCTIVE_WORDS | LOGIN_WORDS):
            continue
        if any(word in label for word in SAFE_ACTION_WORDS):
            candidates.append(node)
            continue
        if node.content_desc and any(word in node.content_desc.lower() for word in SAFE_ACTION_WORDS):
            candidates.append(node)
    return candidates[:limit]


def classify_blocked_flows(nodes: list[UINode]) -> list[dict[str, Any]]:
    blocked = []
    for node in nodes:
        label = node.label.lower()
        if any(word in label for word in LOGIN_WORDS) or node.password:
            blocked.append(
                {
                    "type": "login_or_sensitive_input",
                    "label": node.label,
                    "uiautomator_node_id": node.node_id,
                    "reason": "Login or password-gated flow detected; dynamic runner does not enter real credentials.",
                    "confidence": 0.8,
                }
            )
        if any(word in label for word in DESTRUCTIVE_WORDS):
            blocked.append(
                {
                    "type": "destructive_or_transactional_action",
                    "label": node.label,
                    "uiautomator_node_id": node.node_id,
                    "reason": "Destructive, publishing, sending, purchase, payment, or subscription action is not tapped.",
                    "confidence": 0.8,
                }
            )
    return blocked


def parse_bounds(value: str | None) -> tuple[int, int, int, int] | None:
    if not value:
        return None
    match = BOUNDS_RE.fullmatch(value.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _clean_dump(xml_text: str) -> str:
    start = xml_text.find("<?xml")
    if start == -1:
        start = xml_text.find("<hierarchy")
    if start == -1:
        return ""
    end = xml_text.rfind("</hierarchy>")
    if end != -1:
        return xml_text[start : end + len("</hierarchy>")]
    return xml_text[start:]


def _attr(element: ET.Element, name: str) -> str | None:
    return element.attrib.get(name)


def _bool_attr(element: ET.Element, name: str, default: bool = False) -> bool:
    value = element.attrib.get(name)
    if value is None:
        return default
    return value.lower() == "true"


def _none_empty(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return value
