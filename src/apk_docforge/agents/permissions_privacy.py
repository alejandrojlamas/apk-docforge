from __future__ import annotations

from typing import Any

from apk_docforge.agents.base import AgentContext, BaseAgent


DANGEROUS_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION": "location",
    "android.permission.ACCESS_COARSE_LOCATION": "location",
    "android.permission.CAMERA": "camera",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.WRITE_CONTACTS": "contacts",
    "android.permission.READ_CALENDAR": "calendar",
    "android.permission.WRITE_CALENDAR": "calendar",
    "android.permission.READ_PHONE_STATE": "phone",
    "android.permission.CALL_PHONE": "phone",
    "android.permission.READ_SMS": "sms",
    "android.permission.SEND_SMS": "sms",
    "android.permission.READ_EXTERNAL_STORAGE": "storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "storage",
    "android.permission.READ_MEDIA_IMAGES": "media",
    "android.permission.READ_MEDIA_VIDEO": "media",
    "android.permission.READ_MEDIA_AUDIO": "media",
    "android.permission.POST_NOTIFICATIONS": "notifications",
    "android.permission.BLUETOOTH_CONNECT": "bluetooth",
    "android.permission.NFC": "nfc",
    "android.permission.USE_BIOMETRIC": "biometric",
    "android.permission.USE_FINGERPRINT": "biometric",
}

NORMAL_PRIVACY_PERMISSIONS = {
    "android.permission.INTERNET": "network",
    "android.permission.ACCESS_NETWORK_STATE": "network",
    "android.permission.WAKE_LOCK": "background",
    "android.permission.RECEIVE_BOOT_COMPLETED": "background",
    "android.permission.FOREGROUND_SERVICE": "background",
}


class PermissionPrivacyAgent(BaseAgent):
    name = "PermissionPrivacyAgent"
    output_files = ("permissions.json", "components.json", "deep_links.json", "privacy_findings.json")

    def run(self) -> AgentContext:
        manifest = self.context.data.get("manifest", {})
        permissions = self._permissions(manifest)
        components = self._components(manifest)
        deep_links = self._deep_links(manifest, components)
        privacy_findings = self._privacy_findings(permissions, components, manifest)

        self.write_json("permissions.json", {"schema_version": "1.0", "permissions": permissions})
        self.write_json("components.json", {"schema_version": "1.0", "components": components})
        self.write_json("deep_links.json", {"schema_version": "1.0", "deep_links": deep_links})
        self.write_json(
            "privacy_findings.json",
            {"schema_version": "1.0", "privacy_findings": privacy_findings},
        )

        self.context.data["permissions"] = permissions
        self.context.data["components"] = components
        self.context.data["deep_links"] = deep_links
        self.context.data["privacy_findings"] = privacy_findings
        return self.context

    def _permissions(self, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        rows = []
        for permission in manifest.get("permissions", []):
            name = permission.get("name")
            if not name:
                continue
            category = DANGEROUS_PERMISSIONS.get(name) or NORMAL_PRIVACY_PERMISSIONS.get(name) or "other"
            risk = "high" if name in DANGEROUS_PERMISSIONS else "medium" if category != "other" else "low"
            rows.append(
                {
                    "name": name,
                    "category": category,
                    "risk": risk,
                    "status": "observed",
                    "justification_probable": self._permission_justification(name, category),
                    "confidence": 0.9,
                    "evidence_refs": [
                        self.evidence(
                            path="manifest.json",
                            manifest_path="manifest_raw.xml",
                            kind="manifest",
                            description=f"Permission `{name}` declared in AndroidManifest.xml.",
                        )
                    ],
                }
            )
        return rows

    def _components(self, manifest: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        normalized: dict[str, list[dict[str, Any]]] = {}
        for key, rows in manifest.get("components", {}).items():
            normalized[key] = []
            for row in rows:
                exported = row.get("exported")
                has_intent_filter = bool(row.get("intent_filters"))
                inferred_exported = exported
                if exported is None and has_intent_filter:
                    inferred_exported = "unknown_pre_android_12"
                normalized[key].append(
                    {
                        **row,
                        "risk": self._component_risk(row, inferred_exported, has_intent_filter),
                        "exported_effective": inferred_exported,
                        "confidence": 0.85,
                        "evidence_refs": [
                            self.evidence(
                                path="manifest.json",
                                manifest_path="manifest_raw.xml",
                                kind="manifest",
                                description=f"Component `{row.get('name')}` declared in AndroidManifest.xml.",
                            )
                        ],
                    }
                )
        return normalized

    def _deep_links(
        self, manifest: dict[str, Any], components: dict[str, list[dict[str, Any]]]
    ) -> list[dict[str, Any]]:
        links = []
        for component_type, rows in components.items():
            for row in rows:
                for link in row.get("deep_links", []):
                    if not any(link.values()):
                        continue
                    links.append(
                        {
                            **link,
                            "component_type": component_type,
                            "component_name": row.get("name"),
                            "status": "observed",
                            "confidence": 0.9,
                            "evidence_refs": [
                                self.evidence(
                                    path="manifest.json",
                                    manifest_path="manifest_raw.xml",
                                    kind="manifest",
                                    description="Deep link data element declared in intent-filter.",
                                )
                            ],
                        }
                    )
        if not links:
            for link in manifest.get("deep_links", []):
                if any(link.values()):
                    links.append({**link, "status": "observed", "confidence": 0.75})
        return links

    def _privacy_findings(
        self,
        permissions: list[dict[str, Any]],
        components: dict[str, list[dict[str, Any]]],
        manifest: dict[str, Any],
    ) -> list[dict[str, Any]]:
        findings = []
        for permission in permissions:
            if permission["risk"] in {"high", "medium"}:
                findings.append(
                    {
                        "category": "privacy_permission",
                        "severity": "medium" if permission["risk"] == "high" else "low",
                        "title": f"Sensitive permission declared: {permission['name']}",
                        "description": "The app declares a permission that may expose sensitive user data or device capability.",
                        "status": "observed",
                        "confidence": permission["confidence"],
                        "evidence_refs": permission["evidence_refs"],
                    }
                )
        for rows in components.values():
            for component in rows:
                if component.get("risk") in {"medium", "high"}:
                    findings.append(
                        {
                            "category": "android_component",
                            "severity": component["risk"],
                            "title": f"Exported component review needed: {component.get('name')}",
                            "description": "Exported Android components increase externally reachable surface and should be intentionally protected.",
                            "status": "observed",
                            "confidence": 0.8,
                            "evidence_refs": component["evidence_refs"],
                        }
                    )
        app = manifest.get("application", {})
        if app.get("allow_backup") == "true":
            findings.append(
                {
                    "category": "privacy_storage",
                    "severity": "low",
                    "title": "Application backup is allowed",
                    "description": "allowBackup=true can expose app data through device backup flows unless data is excluded or encrypted.",
                    "status": "observed",
                    "confidence": 0.9,
                    "evidence_refs": [
                        self.evidence(
                            path="manifest.json",
                            manifest_path="manifest_raw.xml",
                            kind="manifest",
                            description="Application allowBackup flag.",
                        )
                    ],
                }
            )
        return findings

    def _permission_justification(self, name: str, category: str) -> str:
        if category == "network":
            return "Network communication or SDK connectivity."
        if category == "location":
            return "Location-based features, maps, nearby content, or analytics."
        if category == "camera":
            return "Camera capture, scanning, or media upload."
        if category == "notifications":
            return "Push notifications or local notification delivery."
        if category == "background":
            return "Background jobs, foreground services, or wakeful work."
        return f"Probable {category} feature; verify against UI/code evidence."

    def _component_risk(
        self, component: dict[str, Any], exported: str | None, has_intent_filter: bool
    ) -> str:
        if exported == "true" and not component.get("permission"):
            return "high" if component.get("type") in {"service", "receiver", "provider"} else "medium"
        if exported == "unknown_pre_android_12" and has_intent_filter:
            return "medium"
        return "low"
