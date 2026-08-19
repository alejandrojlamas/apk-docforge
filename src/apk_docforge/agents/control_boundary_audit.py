from __future__ import annotations

from typing import Any

from apk_docforge.agents.base import AgentContext, BaseAgent


CONTROL_PATTERNS = {
    "certificate_pinning": {
        "category": "network_security_control",
        "severity": "medium",
        "markers": [
            "certificatepinner",
            "pinning",
            "checkservertrusted",
            "trustmanager",
            "x509trustmanager",
            "hostnameverifier",
            "network_security_config",
        ],
        "description": "Certificate pinning or TLS trust customization marker detected.",
        "recommendation": "Document expected TLS behavior and validate with owned test builds or authorized debug configuration. Do not bypass pinning.",
    },
    "authentication_gate": {
        "category": "authorization_boundary",
        "severity": "info",
        "markers": [
            "login",
            "sign in",
            "signin",
            "oauth",
            "openid",
            "jwt",
            "password",
            "session",
            "auth_token",
            "access_token",
            "refresh_token",
        ],
        "description": "Authentication or session boundary marker detected.",
        "recommendation": "Use test credentials and authorized test tenants for dynamic validation. Do not bypass login or session checks.",
    },
    "payment_or_subscription_gate": {
        "category": "commerce_boundary",
        "severity": "high",
        "markers": [
            "billingclient",
            "com.android.billingclient",
            "inapp",
            "subs",
            "subscription",
            "stripe",
            "paypal",
            "braintree",
            "purchase",
            "skuDetails",
        ],
        "description": "Payment, billing, purchase, or subscription marker detected.",
        "recommendation": "Use sandbox billing/test accounts only. Do not bypass purchases, subscriptions, receipts, or entitlement checks.",
    },
    "license_or_drm_gate": {
        "category": "license_drm_boundary",
        "severity": "high",
        "markers": [
            "com.android.vending.licensing",
            "licensechecker",
            "licensevalidator",
            "widevine",
            "mediadrm",
            "drm",
            "playintegrity",
            "integritymanager",
            "safetynet",
        ],
        "description": "License, DRM, Play Integrity, or entitlement marker detected.",
        "recommendation": "Record the control and validate only through official test channels. Do not bypass DRM, license, or integrity checks.",
    },
    "anti_tamper_or_root_detection": {
        "category": "runtime_integrity_control",
        "severity": "medium",
        "markers": [
            "isdebuggerconnected",
            "debugger",
            "ptrace",
            "rootbeer",
            "magisk",
            "/system/xbin/su",
            "/system/bin/su",
            "frida",
            "xposed",
            "tamper",
            "emulator",
        ],
        "description": "Anti-tamper, root, emulator, debugger, or instrumentation marker detected.",
        "recommendation": "Document test-device requirements and validate with authorized builds. Do not bypass anti-tamper or runtime integrity controls.",
    },
}

PROHIBITED_ACTIONS = [
    "certificate_pinning_bypass",
    "authentication_bypass",
    "payment_or_subscription_bypass",
    "drm_or_license_bypass",
    "anti_tamper_bypass",
    "root_or_debugger_evasion",
    "credential_entry_without_test_account",
]


class ControlBoundaryAuditAgent(BaseAgent):
    name = "ControlBoundaryAuditAgent"
    output_files = (
        "control_boundary_assessment.json",
        "protection_controls.json",
        "authorization_boundaries.json",
    )

    def run(self) -> AgentContext:
        controls = self._detect_controls()
        dynamic_blocked = self.context.data.get("blocked_flows_dynamic", [])
        boundaries = self._boundaries(controls, dynamic_blocked)
        assessment = {
            "schema_version": "1.0",
            "agent": self.name,
            "status": "completed",
            "mode": "safe_detection_only",
            "policy": {
                "bypass_implemented": False,
                "bypass_attempted": False,
                "reason": "Audit mode documents protection boundaries and blocks bypass behavior by design.",
                "prohibited_actions": PROHIBITED_ACTIONS,
            },
            "controls_detected_count": len(controls),
            "controls": controls,
            "authorization_boundaries": boundaries,
            "blocked_flows_dynamic": dynamic_blocked,
        }
        self.write_json("control_boundary_assessment.json", assessment)
        self.write_json(
            "protection_controls.json",
            {
                "schema_version": "1.0",
                "status": "completed",
                "controls": controls,
                "policy": assessment["policy"],
            },
        )
        self.write_json(
            "authorization_boundaries.json",
            {
                "schema_version": "1.0",
                "status": "completed",
                "boundaries": boundaries,
                "blocked_flows_dynamic": dynamic_blocked,
                "policy": assessment["policy"],
            },
        )
        self.context.data["control_boundary_assessment"] = assessment
        self.context.data["protection_controls"] = controls
        self.context.data["authorization_boundaries"] = boundaries
        self.context.data["bypass_policy"] = assessment["policy"]
        return self.context

    def _detect_controls(self) -> list[dict[str, Any]]:
        strings = self.context.data.get("static_strings", [])
        controls: list[dict[str, Any]] = []
        for control_name, spec in CONTROL_PATTERNS.items():
            evidence = self._marker_evidence(strings, spec["markers"])
            if not evidence:
                controls.append(
                    {
                        "name": control_name,
                        "category": spec["category"],
                        "status": "unknown",
                        "severity": spec["severity"],
                        "description": spec["description"],
                        "recommendation": spec["recommendation"],
                        "bypass_allowed": False,
                        "bypass_status": "prohibited_by_policy",
                        "confidence": 0.0,
                        "confidence_score": 0.0,
                        "evidence_refs": [],
                    }
                )
                continue
            confidence = 0.85 if len(evidence) > 1 else 0.68
            controls.append(
                {
                    "name": control_name,
                    "category": spec["category"],
                    "status": "observed" if confidence >= 0.75 else "inferred",
                    "severity": spec["severity"],
                    "description": spec["description"],
                    "recommendation": spec["recommendation"],
                    "bypass_allowed": False,
                    "bypass_status": "prohibited_by_policy",
                    "confidence": confidence,
                    "confidence_score": confidence,
                    "evidence_refs": evidence,
                }
            )
        return controls

    def _marker_evidence(self, strings: list[dict[str, Any]], markers: list[str]) -> list[dict[str, Any]]:
        evidence: list[dict[str, Any]] = []
        marker_set = [marker.lower() for marker in markers]
        for item in strings:
            value = str(item.get("value") or "")
            lowered = value.lower()
            matched = next((marker for marker in marker_set if marker in lowered), None)
            if not matched:
                continue
            evidence.append(
                {
                    "path": item.get("path"),
                    "line_number": item.get("line_number"),
                    "kind": "string",
                    "description": f"Protection boundary marker `{matched}` detected.",
                }
            )
            if len(evidence) >= 8:
                break
        return evidence

    def _boundaries(
        self,
        controls: list[dict[str, Any]],
        dynamic_blocked: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        boundaries = []
        for control in controls:
            if control.get("status") == "unknown":
                continue
            boundaries.append(
                {
                    "name": control["name"],
                    "category": control["category"],
                    "status": control["status"],
                    "allowed_audit_action": "document_and_validate_with_authorized_test_configuration",
                    "blocked_action": control["bypass_status"],
                    "confidence": control["confidence"],
                    "confidence_score": control["confidence_score"],
                    "evidence_refs": control.get("evidence_refs", []),
                }
            )
        for item in dynamic_blocked:
            boundaries.append(
                {
                    "name": item.get("type") or "dynamic_blocked_flow",
                    "category": "dynamic_navigation_boundary",
                    "status": "observed",
                    "allowed_audit_action": "record_screen_and_stop_before_sensitive_or_irreversible_action",
                    "blocked_action": "non_destructive_runner_policy",
                    "confidence": item.get("confidence", 0.8),
                    "confidence_score": item.get("confidence", 0.8),
                    "evidence_refs": item.get("evidence_refs", []),
                }
            )
        return boundaries
