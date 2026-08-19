from __future__ import annotations

import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from apk_docforge.agents.base import AgentContext, BaseAgent


ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID = f"{{{ANDROID_NS}}}"

UI_TAGS = {
    "Button": "button",
    "ImageButton": "button",
    "TextView": "text",
    "EditText": "input",
    "CheckBox": "checkbox",
    "Switch": "switch",
    "SwitchCompat": "switch",
    "RadioButton": "radio",
    "Spinner": "select",
    "AutoCompleteTextView": "input",
    "SearchView": "input",
    "Toolbar": "toolbar",
    "BottomNavigationView": "bottom_nav",
    "NavigationView": "drawer",
    "item": "menu_item",
}


class UIStaticMapperAgent(BaseAgent):
    name = "UIStaticMapperAgent"
    output_files = ("static_screens.json", "ui_elements_static.json", "string_catalog.json")

    def run(self) -> AgentContext:
        apk_path = Path(self.context.data["primary_apk_path"])
        apktool_dir = Path(self.context.data["apktool_dir"]) if self.context.data.get("apktool_dir") else None
        xml_files = self._xml_files(apk_path, apktool_dir)
        string_catalog = self._string_catalog(xml_files)
        ui_elements = self._ui_elements(xml_files, string_catalog)
        screens = self._screens(ui_elements)

        self.write_json(
            "string_catalog.json",
            {"schema_version": "1.0", "strings": sorted(string_catalog.values(), key=lambda x: x["name"])},
        )
        self.write_json("ui_elements_static.json", {"schema_version": "1.0", "ui_elements": ui_elements})
        self.write_json("static_screens.json", {"schema_version": "1.0", "screens": screens})

        self.context.data["string_catalog"] = string_catalog
        self.context.data["ui_elements_static"] = ui_elements
        self.context.data["static_screens"] = screens
        return self.context

    def _xml_files(self, apk_path: Path, apktool_dir: Path | None) -> list[dict[str, str]]:
        files: list[dict[str, str]] = []
        if zipfile.is_zipfile(apk_path):
            with zipfile.ZipFile(apk_path) as archive:
                for info in archive.infolist():
                    if info.is_dir() or not info.filename.startswith("res/") or not info.filename.endswith(".xml"):
                        continue
                    if info.file_size > 1_000_000:
                        continue
                    raw = archive.read(info)
                    text = raw.decode("utf-8", errors="replace")
                    if "<" in text[:200]:
                        files.append({"path": info.filename, "text": text, "source": "apk_zip"})
        if apktool_dir and apktool_dir.exists():
            for file_path in apktool_dir.glob("res/**/*.xml"):
                if file_path.stat().st_size > 1_000_000:
                    continue
                files.append(
                    {
                        "path": str(file_path),
                        "text": file_path.read_text(encoding="utf-8", errors="replace"),
                        "source": "apktool",
                    }
                )
        return files

    def _string_catalog(self, xml_files: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
        catalog: dict[str, dict[str, Any]] = {}
        for file in xml_files:
            if "/values" not in file["path"] and not file["path"].startswith("res/values"):
                continue
            try:
                root = ET.fromstring(file["text"])
            except ET.ParseError:
                continue
            for node in root.findall("string"):
                name = node.attrib.get("name")
                if not name:
                    continue
                text = "".join(node.itertext()).strip()
                catalog[name] = {
                    "name": name,
                    "value": text,
                    "status": "observed",
                    "confidence": 0.95,
                    "evidence_refs": [
                        {
                            "path": file["path"],
                            "kind": "resource",
                            "description": f"String resource `{name}`.",
                        }
                    ],
                }
        return catalog

    def _ui_elements(
        self, xml_files: list[dict[str, str]], string_catalog: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        elements: list[dict[str, Any]] = []
        for file in xml_files:
            path = file["path"]
            if not self._is_ui_xml(path):
                continue
            try:
                root = ET.fromstring(file["text"])
            except ET.ParseError:
                continue
            for node in root.iter():
                tag = _strip_ns(node.tag).split(".")[-1]
                element_type = UI_TAGS.get(tag)
                if not element_type:
                    continue
                resource_id = self._resource_id(_attr(node, "id"))
                visible_text = self._resolve_text(
                    _attr(node, "text") or _attr(node, "title") or _attr(node, "hint"),
                    string_catalog,
                )
                action_guess = self._action_guess(tag, visible_text, resource_id)
                elements.append(
                    {
                        "screen_hint": self._screen_hint(path),
                        "element_type": element_type,
                        "tag": tag,
                        "visible_text": visible_text,
                        "resource_id": resource_id,
                        "action_guess": action_guess,
                        "status": "observed",
                        "confidence": 0.8,
                        "source_path": path,
                        "evidence_refs": [
                            {
                                "path": path,
                                "kind": "layout",
                                "description": f"UI element `{tag}` in static XML resource.",
                            }
                        ],
                    }
                )
        return elements

    def _screens(self, ui_elements: list[dict[str, Any]]) -> list[dict[str, Any]]:
        screens_by_name: dict[str, dict[str, Any]] = {}
        manifest_components = self.context.data.get("components", {}).get("activities", [])
        for activity in manifest_components:
            name = activity.get("name") or "UnknownActivity"
            simple = name.rsplit(".", 1)[-1]
            screens_by_name[simple] = {
                "name": simple,
                "activity_or_fragment": name,
                "source": "manifest",
                "description": "Activity declared in AndroidManifest.xml; static screen mapping inferred.",
                "status": "observed",
                "confidence": 0.75,
                "ui_element_count": 0,
                "related_layouts": [],
                "evidence_refs": activity.get("evidence_refs", []),
            }

        for element in ui_elements:
            hint = element["screen_hint"]
            screen = screens_by_name.setdefault(
                hint,
                {
                    "name": hint,
                    "activity_or_fragment": None,
                    "source": "layout",
                    "description": "Screen inferred from static layout/menu/navigation resource.",
                    "status": "inferred",
                    "confidence": 0.65,
                    "ui_element_count": 0,
                    "related_layouts": [],
                    "evidence_refs": [],
                },
            )
            screen["ui_element_count"] += 1
            if element["source_path"] not in screen["related_layouts"]:
                screen["related_layouts"].append(element["source_path"])
            screen["evidence_refs"].extend(element.get("evidence_refs", [])[:1])

        return sorted(screens_by_name.values(), key=lambda row: row["name"])

    def _is_ui_xml(self, path: str) -> bool:
        normalized = path.replace("\\", "/")
        return any(part in normalized for part in ["/layout", "/menu", "/navigation"]) or normalized.startswith(
            ("res/layout", "res/menu", "res/navigation")
        )

    def _screen_hint(self, path: str) -> str:
        name = Path(path).stem
        cleaned = re.sub(r"^(activity|fragment|screen|view)_", "", name)
        return "".join(part.capitalize() for part in cleaned.split("_")) or name

    def _resource_id(self, value: str | None) -> str | None:
        if not value:
            return None
        return value.replace("@+id/", "").replace("@id/", "")

    def _resolve_text(self, value: str | None, string_catalog: dict[str, dict[str, Any]]) -> str | None:
        if not value:
            return None
        if value.startswith("@string/"):
            key = value.split("/", 1)[1]
            return string_catalog.get(key, {}).get("value") or value
        return value

    def _action_guess(self, tag: str, visible_text: str | None, resource_id: str | None) -> str | None:
        text = " ".join(item for item in [visible_text, resource_id] if item).lower()
        if tag in {"Button", "ImageButton", "item"}:
            if any(token in text for token in ["login", "sign_in", "ingresar", "entrar"]):
                return "login_or_authenticate"
            if any(token in text for token in ["register", "signup", "crear", "cuenta"]):
                return "register_account"
            if any(token in text for token in ["pay", "pagar", "purchase", "subscribe"]):
                return "payment_or_subscription"
            if any(token in text for token in ["search", "buscar"]):
                return "search"
            return "tap"
        if tag in {"EditText", "SearchView", "AutoCompleteTextView"}:
            return "enter_text"
        if tag in {"Switch", "SwitchCompat", "CheckBox"}:
            return "toggle"
        return None


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _attr(node: ET.Element, name: str) -> str | None:
    return node.attrib.get(f"{ANDROID}{name}") or node.attrib.get(f"android:{name}") or node.attrib.get(name)
