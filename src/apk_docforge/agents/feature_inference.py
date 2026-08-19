from __future__ import annotations

from typing import Any, Iterable

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.tools.static_extractors import ignored_signal_source


class FeatureInferenceAgent(BaseAgent):
    name = "FeatureInferenceAgent"
    output_files = ("features.json", "feature_evidence_map.json", "confidence_report.json")

    def run(self) -> AgentContext:
        features: list[dict[str, Any]] = []
        self._infer_from_permissions(features)
        self._infer_from_ui(features)
        self._infer_from_dynamic_ui(features)
        self._infer_from_network_and_sdks(features)
        self._infer_from_strings(features)
        self._infer_from_components(features)

        deduped = self._dedupe(features)
        evidence_map = {
            feature["name"]: feature.get("evidence_refs", []) for feature in deduped if feature.get("evidence_refs")
        }
        confidence_report = self._confidence_report(deduped)

        self.write_json("features.json", {"schema_version": "1.0", "features": deduped})
        self.write_json(
            "feature_evidence_map.json",
            {"schema_version": "1.0", "feature_evidence_map": evidence_map},
        )
        self.write_json("confidence_report.json", confidence_report)
        self.context.data["features"] = deduped
        self.context.data["feature_evidence_map"] = evidence_map
        self.context.data["confidence_report"] = confidence_report
        return self.context

    def _infer_from_permissions(self, features: list[dict[str, Any]]) -> None:
        by_category: dict[str, list[dict[str, Any]]] = {}
        for permission in self.context.data.get("permissions", []):
            by_category.setdefault(permission.get("category", "other"), []).append(permission)
        permission_features = {
            "location": ("maps/location", "maps_location", "Location permission indicates location or map-related capability."),
            "camera": ("camera", "camera", "Camera permission indicates image capture, scanning, or media feature."),
            "microphone": ("audio/microphone", "media", "Microphone permission indicates audio capture or voice feature."),
            "notifications": ("push notifications", "notifications", "Notification permission indicates notification delivery."),
            "bluetooth": ("bluetooth/NFC", "device_connectivity", "Bluetooth permission indicates device connectivity."),
            "nfc": ("bluetooth/NFC", "device_connectivity", "NFC permission indicates device connectivity."),
            "biometric": ("biometrics", "auth", "Biometric permission indicates biometric authentication support."),
            "background": ("background workers", "background", "Background-related permission indicates background work."),
            "storage": ("file upload/management", "files", "Storage permission indicates file access or upload/download flows."),
            "media": ("file upload/management", "files", "Media permission indicates media access or upload/download flows."),
        }
        for category, (name, feature_category, description) in permission_features.items():
            if category not in by_category:
                continue
            evidence = [ref for item in by_category[category] for ref in item.get("evidence_refs", [])]
            features.append(
                self._feature(name, feature_category, description, 0.72, evidence[:5], ["permissions"])
            )

    def _infer_from_ui(self, features: list[dict[str, Any]]) -> None:
        elements = self.context.data.get("ui_elements_static", [])
        ui_map = {
            "login_or_authenticate": ("login/auth", "auth", "Login/authentication action is visible in static UI."),
            "register_account": ("registration", "auth", "Registration action is visible in static UI."),
            "payment_or_subscription": ("payments/subscriptions", "commerce", "Payment or subscription action is visible in static UI."),
            "search": ("search", "navigation", "Search action is visible in static UI."),
        }
        for action, (name, category, description) in ui_map.items():
            matched = [item for item in elements if item.get("action_guess") == action]
            if matched:
                evidence = [ref for item in matched for ref in item.get("evidence_refs", [])]
                features.append(self._feature(name, category, description, 0.75, evidence[:5], ["ui_static"]))

    def _infer_from_dynamic_ui(self, features: list[dict[str, Any]]) -> None:
        elements = self.context.data.get("ui_elements_dynamic", [])
        rules = [
            ("login/auth", "auth", ["login", "sign in", "ingresar", "entrar"], "Login/auth UI observed dynamically."),
            ("registration", "auth", ["register", "signup", "crear cuenta", "registr"], "Registration UI observed dynamically."),
            ("payments/subscriptions", "commerce", ["pay", "buy", "subscribe", "pagar", "comprar"], "Payment/subscription UI observed dynamically."),
            ("search", "navigation", ["search", "buscar"], "Search UI observed dynamically."),
        ]
        for name, category, needles, description in rules:
            evidence = []
            for item in elements:
                haystack = " ".join(
                    str(value)
                    for value in [item.get("visible_text"), item.get("resource_id"), item.get("action_guess")]
                    if value
                ).lower()
                if any(needle in haystack for needle in needles):
                    evidence.extend(item.get("evidence_refs", []))
            if evidence:
                features.append(self._feature(name, category, description, 0.82, evidence[:5], ["ui_dynamic"]))

    def _infer_from_network_and_sdks(self, features: list[dict[str, Any]]) -> None:
        sdk_names = {
            item["name"]: item
            for item in self.context.data.get("sdk_detection", [])
            if item.get("status") == "observed"
        }
        sdk_features = {
            "Firebase": ("backend Firebase", "backend_sdk", "Firebase SDK marker detected."),
            "Firebase Crashlytics": (
                "crash reporting",
                "observability",
                "Crashlytics SDK marker detected.",
            ),
            "Sentry": ("crash reporting", "observability", "Sentry SDK marker detected."),
            "Google Analytics": ("analytics", "analytics", "Analytics SDK marker detected."),
            "AdMob": ("ads", "ads", "Ad SDK marker detected."),
            "Stripe": ("payments", "commerce", "Payment SDK marker detected."),
            "Braintree": ("payments", "commerce", "Payment SDK marker detected."),
            "PayPal": ("payments", "commerce", "Payment SDK marker detected."),
            "Supabase": ("backend Supabase", "backend_sdk", "Supabase marker detected."),
        }
        for sdk, (name, category, description) in sdk_features.items():
            if sdk in sdk_names:
                features.append(
                    self._feature(
                        name,
                        category,
                        description,
                        0.82,
                        sdk_names[sdk].get("evidence_refs", []),
                        ["sdk_detection"],
                    )
                )

        endpoint_types = {item.get("type") for item in self.context.data.get("network_endpoints", [])}
        if "websocket" in endpoint_types:
            evidence = self._first_endpoint_evidence("websocket")
            features.append(
                self._feature("real-time/WebSocket", "network", "WebSocket endpoint detected.", 0.78, evidence, ["network"])
            )
        if "graphql" in endpoint_types:
            evidence = self._first_endpoint_evidence("graphql")
            features.append(
                self._feature("GraphQL API", "network", "GraphQL endpoint or marker detected.", 0.78, evidence, ["network"])
            )

    def _infer_from_strings(self, features: list[dict[str, Any]]) -> None:
        rules = [
            ("chat", "communication", ["chat", "message", "conversation", "mensaje"], "Messaging/chat strings detected."),
            ("profile", "account", ["profile", "perfil", "account", "cuenta"], "Profile/account strings detected."),
            ("WebView", "webview", ["webview", "android.webkit"], "WebView class or string marker detected."),
            (
                "local database",
                "local_storage",
                ["roomdatabase", "sqlite", "sharedpreferences", "datastore"],
                "Local storage/database marker detected.",
            ),
            (
                "QR/barcode scanning",
                "scanner",
                ["barcode", "qrcode", "qr_code", "zxing", "mlkit.vision.barcode"],
                "QR/barcode scanner marker detected.",
            ),
            (
                "content sharing",
                "sharing",
                ["intent.action_send", "action_send", "sharecompat", "compartir"],
                "Content sharing marker detected.",
            ),
            (
                "offline/cache",
                "local_storage",
                ["cache", "offline", "workmanager", "okhttp cache"],
                "Cache/offline marker detected.",
            ),
        ]
        strings = self.context.data.get("static_strings", [])
        for name, category, needles, description in rules:
            evidence = self._string_evidence(strings, needles)
            if evidence:
                features.append(self._feature(name, category, description, 0.62, evidence[:5], ["static_strings"]))

    def _infer_from_components(self, features: list[dict[str, Any]]) -> None:
        if self.context.data.get("deep_links"):
            evidence = [ref for item in self.context.data["deep_links"] for ref in item.get("evidence_refs", [])]
            features.append(
                self._feature("deep links", "navigation", "Deep links declared in manifest.", 0.9, evidence[:5], ["manifest"])
            )

    def _feature(
        self,
        name: str,
        category: str,
        description: str,
        confidence: float,
        evidence_refs: list[dict[str, Any]],
        evidence_sources: list[str],
    ) -> dict[str, Any]:
        return {
            "name": name,
            "category": category,
            "description": description,
            "status": "inferred",
            "confidence": min(max(confidence, 0.0), 1.0),
            "confidence_score": min(max(confidence, 0.0), 1.0),
            "evidence_sources": evidence_sources,
            "evidence_refs": evidence_refs,
            "related_screens": self._related_screens(evidence_refs),
            "related_endpoints": self._related_endpoints(evidence_refs),
            "risks_or_notes": [],
        }

    def _dedupe(self, features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_name: dict[str, dict[str, Any]] = {}
        for feature in features:
            if not feature.get("evidence_refs"):
                continue
            existing = by_name.get(feature["name"])
            if not existing:
                by_name[feature["name"]] = feature
                continue
            existing["confidence"] = max(existing["confidence"], feature["confidence"])
            existing["confidence_score"] = existing["confidence"]
            existing["evidence_refs"].extend(feature.get("evidence_refs", []))
            existing["evidence_sources"] = sorted(
                set(existing.get("evidence_sources", [])) | set(feature.get("evidence_sources", []))
            )
        return sorted(by_name.values(), key=lambda item: (item["category"], item["name"]))

    def _confidence_report(self, features: list[dict[str, Any]]) -> dict[str, Any]:
        without_evidence = [item["name"] for item in features if not item.get("evidence_refs")]
        return {
            "schema_version": "1.0",
            "feature_count": len(features),
            "features_without_evidence": without_evidence,
            "average_confidence": (
                sum(item.get("confidence", 0.0) for item in features) / len(features) if features else 0.0
            ),
            "status": "completed" if not without_evidence else "needs_review",
        }

    def _string_evidence(
        self, strings: Iterable[dict[str, Any]], needles: list[str]
    ) -> list[dict[str, Any]]:
        evidence = []
        lowered_needles = [needle.lower() for needle in needles]
        for item in strings:
            if ignored_signal_source(str(item.get("path", ""))):
                continue
            value = item.get("value", "")
            if any(needle in value.lower() for needle in lowered_needles):
                evidence.append(
                    {
                        "path": item.get("path"),
                        "line_number": item.get("line_number"),
                        "kind": "string",
                        "description": f"Feature marker detected in string: {value[:80]}",
                    }
                )
            if len(evidence) >= 5:
                break
        return evidence

    def _first_endpoint_evidence(self, endpoint_type: str) -> list[dict[str, Any]]:
        for endpoint in self.context.data.get("network_endpoints", []):
            if endpoint.get("type") == endpoint_type:
                return endpoint.get("evidence_refs", [])
        return []

    def _related_screens(self, evidence_refs: list[dict[str, Any]]) -> list[str]:
        screens = []
        paths = {ref.get("path") for ref in evidence_refs}
        for screen in self.context.data.get("static_screens", []):
            if paths & {ref.get("path") for ref in screen.get("evidence_refs", [])}:
                screens.append(screen["name"])
        return sorted(set(screens))

    def _related_endpoints(self, evidence_refs: list[dict[str, Any]]) -> list[str]:
        paths = {ref.get("path") for ref in evidence_refs}
        endpoints = []
        for endpoint in self.context.data.get("network_endpoints", []):
            endpoint_paths = {ref.get("path") for ref in endpoint.get("evidence_refs", [])}
            if paths & endpoint_paths:
                endpoints.append(endpoint.get("url") or endpoint.get("domain"))
        return sorted({str(item) for item in endpoints if item})
