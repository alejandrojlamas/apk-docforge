from __future__ import annotations

import io
import json
import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID = f"{{{ANDROID_NS}}}"


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


class BinaryAndroidXmlParser:
    """Small AXML reader sufficient for AndroidManifest metadata extraction."""

    RES_STRING_POOL_TYPE = 0x0001
    RES_XML_START_ELEMENT_TYPE = 0x0102
    RES_XML_END_ELEMENT_TYPE = 0x0103
    UTF8_FLAG = 0x00000100
    NO_INDEX = 0xFFFFFFFF

    TYPE_STRING = 0x03
    TYPE_INT_DEC = 0x10
    TYPE_INT_HEX = 0x11
    TYPE_INT_BOOLEAN = 0x12

    def __init__(self, data: bytes):
        self.data = data
        self.strings: list[str] = []

    def parse_to_xml(self) -> str:
        self._read_string_pool()
        out = io.StringIO()
        out.write('<manifest xmlns:android="http://schemas.android.com/apk/res/android">')
        stack: list[str] = ["manifest"]
        offset = 8
        first_start = True
        while offset + 8 <= len(self.data):
            chunk_type = _read_u16(self.data, offset)
            chunk_size = _read_u32(self.data, offset + 4)
            if chunk_size <= 0:
                break
            if chunk_type == self.RES_XML_START_ELEMENT_TYPE:
                name, attrs = self._read_start_element(offset)
                if first_start and name == "manifest":
                    out.seek(0)
                    out.truncate(0)
                    attr_text = self._attrs_to_text(attrs)
                    out.write(
                        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
                        f"{attr_text}>"
                    )
                    first_start = False
                else:
                    out.write(f"<{name}{self._attrs_to_text(attrs)}>")
                    stack.append(name)
            elif chunk_type == self.RES_XML_END_ELEMENT_TYPE:
                name = self._string_at(_read_u32(self.data, offset + 20))
                if stack and stack[-1] == name:
                    stack.pop()
                if not (first_start and name == "manifest"):
                    out.write(f"</{name}>")
            offset += chunk_size
        while stack:
            name = stack.pop()
            out.write(f"</{name}>")
        return out.getvalue()

    def _read_string_pool(self) -> None:
        offset = 8
        while offset + 28 <= len(self.data):
            chunk_type = _read_u16(self.data, offset)
            chunk_size = _read_u32(self.data, offset + 4)
            if chunk_type == self.RES_STRING_POOL_TYPE:
                string_count = _read_u32(self.data, offset + 8)
                flags = _read_u32(self.data, offset + 16)
                strings_start = _read_u32(self.data, offset + 20)
                offsets_start = offset + 28
                is_utf8 = bool(flags & self.UTF8_FLAG)
                for index in range(string_count):
                    string_offset = _read_u32(self.data, offsets_start + index * 4)
                    self.strings.append(
                        self._read_string(offset + strings_start + string_offset, is_utf8)
                    )
                return
            if chunk_size <= 0:
                break
            offset += chunk_size

    def _read_string(self, offset: int, is_utf8: bool) -> str:
        if is_utf8:
            _, offset = self._read_length8(offset)
            byte_length, offset = self._read_length8(offset)
            raw = self.data[offset : offset + byte_length]
            return raw.decode("utf-8", errors="replace")
        char_length, offset = self._read_length16(offset)
        raw = self.data[offset : offset + char_length * 2]
        return raw.decode("utf-16le", errors="replace")

    def _read_length8(self, offset: int) -> tuple[int, int]:
        value = self.data[offset]
        if value & 0x80:
            return ((value & 0x7F) << 8) | self.data[offset + 1], offset + 2
        return value, offset + 1

    def _read_length16(self, offset: int) -> tuple[int, int]:
        value = _read_u16(self.data, offset)
        if value & 0x8000:
            return ((value & 0x7FFF) << 16) | _read_u16(self.data, offset + 2), offset + 4
        return value, offset + 2

    def _read_start_element(self, offset: int) -> tuple[str, list[tuple[str, str, str | None]]]:
        name = self._string_at(_read_u32(self.data, offset + 20))
        attr_start = _read_u16(self.data, offset + 24)
        attr_size = _read_u16(self.data, offset + 26)
        attr_count = _read_u16(self.data, offset + 28)
        attrs: list[tuple[str, str, str | None]] = []
        base = offset + 16 + attr_start
        for index in range(attr_count):
            item = base + index * attr_size
            namespace = self._string_at(_read_u32(self.data, item))
            attr_name = self._string_at(_read_u32(self.data, item + 4))
            raw_value_index = _read_u32(self.data, item + 8)
            data_type = self.data[item + 15]
            data_value = _read_u32(self.data, item + 16)
            value = self._coerce_value(raw_value_index, data_type, data_value)
            attrs.append((attr_name, value, namespace))
        return name, attrs

    def _coerce_value(self, raw_value_index: int, data_type: int, data_value: int) -> str:
        if raw_value_index != self.NO_INDEX:
            return self._string_at(raw_value_index)
        if data_type == self.TYPE_STRING:
            return self._string_at(data_value)
        if data_type == self.TYPE_INT_BOOLEAN:
            return "true" if data_value else "false"
        if data_type == self.TYPE_INT_DEC:
            return str(data_value)
        if data_type == self.TYPE_INT_HEX:
            return hex(data_value)
        return str(data_value)

    def _attrs_to_text(self, attrs: list[tuple[str, str, str | None]]) -> str:
        parts: list[str] = []
        for name, value, namespace in attrs:
            prefix = "android:" if namespace == ANDROID_NS else ""
            parts.append(f' {prefix}{name}="{_xml_escape(value)}"')
        return "".join(parts)

    def _string_at(self, index: int) -> str:
        if index == self.NO_INDEX or index >= len(self.strings):
            return ""
        return self.strings[index]


@dataclass(frozen=True)
class ParsedManifest:
    xml_text: str | None
    manifest: dict[str, Any]
    parser: str
    error: str | None = None


def parse_manifest_bytes(data: bytes) -> ParsedManifest:
    if not data:
        return ParsedManifest(None, unknown_manifest(), "none", "AndroidManifest.xml is empty")
    try:
        stripped = data.lstrip()
        if stripped.startswith(b"<"):
            text = data.decode("utf-8", errors="replace")
            return ParsedManifest(text, manifest_xml_to_json(text), "xml")
        text = BinaryAndroidXmlParser(data).parse_to_xml()
        return ParsedManifest(text, manifest_xml_to_json(text), "binary_axml")
    except Exception as exc:
        return ParsedManifest(None, unknown_manifest(), "failed", str(exc))


def unknown_manifest() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "status": "unknown",
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "application": {},
        "components": {"activities": [], "services": [], "receivers": [], "providers": []},
        "deep_links": [],
        "intent_filters": [],
    }


def manifest_xml_to_json(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    data = unknown_manifest()
    data["status"] = "observed"
    data["package_name"] = root.attrib.get("package")
    data["version_name"] = _attr(root, "versionName")
    data["version_code"] = _attr(root, "versionCode")
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        data["min_sdk"] = _attr(uses_sdk, "minSdkVersion")
        data["target_sdk"] = _attr(uses_sdk, "targetSdkVersion")
    data["permissions"] = [
        {
            "name": _attr(node, "name") or node.attrib.get("name"),
            "source": "manifest",
            "status": "observed",
        }
        for node in root.findall("uses-permission")
        if _attr(node, "name") or node.attrib.get("name")
    ]
    app = root.find("application")
    if app is not None:
        data["application"] = {
            "label": _attr(app, "label"),
            "debuggable": _attr(app, "debuggable"),
            "allow_backup": _attr(app, "allowBackup"),
            "uses_cleartext_traffic": _attr(app, "usesCleartextTraffic"),
            "network_security_config": _attr(app, "networkSecurityConfig"),
        }
        components: dict[str, list[dict[str, Any]]] = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        for xml_name, key in [
            ("activity", "activities"),
            ("activity-alias", "activities"),
            ("service", "services"),
            ("receiver", "receivers"),
            ("provider", "providers"),
        ]:
            for node in app.findall(xml_name):
                component = _component_to_json(node, xml_name)
                components[key].append(component)
                data["intent_filters"].extend(component["intent_filters"])
                data["deep_links"].extend(component["deep_links"])
        data["components"] = components
    return data


def _attr(node: ET.Element, name: str) -> str | None:
    return node.attrib.get(f"{ANDROID}{name}") or node.attrib.get(f"android:{name}") or node.attrib.get(name)


def _component_to_json(node: ET.Element, component_type: str) -> dict[str, Any]:
    filters = [_intent_filter_to_json(child) for child in node.findall("intent-filter")]
    deep_links = [link for item in filters for link in item.get("data", [])]
    return {
        "type": component_type,
        "name": _attr(node, "name"),
        "exported": _attr(node, "exported"),
        "enabled": _attr(node, "enabled"),
        "permission": _attr(node, "permission"),
        "intent_filters": filters,
        "deep_links": deep_links,
        "status": "observed",
    }


def _intent_filter_to_json(node: ET.Element) -> dict[str, Any]:
    actions = [_attr(child, "name") for child in node.findall("action")]
    categories = [_attr(child, "name") for child in node.findall("category")]
    data_nodes = []
    for child in node.findall("data"):
        data_nodes.append(
            {
                "scheme": _attr(child, "scheme"),
                "host": _attr(child, "host"),
                "path": _attr(child, "path"),
                "path_prefix": _attr(child, "pathPrefix"),
                "mime_type": _attr(child, "mimeType"),
            }
        )
    return {
        "actions": [value for value in actions if value],
        "categories": [value for value in categories if value],
        "data": data_nodes,
    }


def write_manifest_files(parsed: ParsedManifest, output_dir: Path) -> None:
    if parsed.xml_text:
        (output_dir / "manifest_text.xml").write_text(parsed.xml_text, encoding="utf-8")
    (output_dir / "manifest.json").write_text(
        json.dumps(parsed.manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def extract_manifest_package_from_text(text: str) -> str | None:
    match = re.search(r'<manifest[^>]+package=["\']([^"\']+)["\']', text)
    return match.group(1) if match else None
