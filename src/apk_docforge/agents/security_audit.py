from __future__ import annotations

import re
from typing import Any

from apk_docforge.agents.base import AgentContext, BaseAgent


SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|secret|token|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b"),
    re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
]


class SecurityAuditAgent(BaseAgent):
    name = "SecurityAuditAgent"
    output_files = ("security_findings.json", "privacy_risks.json", "compliance_notes.json")

    def run(self) -> AgentContext:
        findings: list[dict[str, Any]] = []
        findings.extend(self._manifest_findings())
        findings.extend(self._component_findings())
        findings.extend(self._network_findings())
        findings.extend(self._string_findings())
        findings.extend(self._tracker_findings())

        privacy_risks = self._privacy_risks(findings)
        compliance_notes = self._compliance_notes(findings)
        self.write_json("security_findings.json", {"schema_version": "1.0", "findings": findings})
        self.write_json("privacy_risks.json", {"schema_version": "1.0", "privacy_risks": privacy_risks})
        self.write_json(
            "compliance_notes.json",
            {"schema_version": "1.0", "compliance_notes": compliance_notes},
        )
        self.context.data["security_findings"] = findings
        self.context.data["privacy_risks"] = privacy_risks
        self.context.data["compliance_notes"] = compliance_notes
        return self.context

    def _manifest_findings(self) -> list[dict[str, Any]]:
        manifest = self.context.data.get("manifest", {})
        app = manifest.get("application", {})
        findings = []
        if app.get("debuggable") == "true":
            findings.append(
                self._finding(
                    "MASVS-CODE",
                    "high",
                    "Application is debuggable",
                    "android:debuggable=true is set in the manifest.",
                    "Debuggable production builds can expose runtime inspection and sensitive state.",
                    "Disable debuggable for release builds.",
                    0.95,
                    [self._manifest_evidence("Application debuggable flag.")],
                )
            )
        if app.get("allow_backup") == "true":
            findings.append(
                self._finding(
                    "MASVS-STORAGE",
                    "low",
                    "Application backup is allowed",
                    "android:allowBackup=true is set or inferred from manifest data.",
                    "App data may be included in backup flows unless excluded or encrypted.",
                    "Disable backup for sensitive apps or configure backup exclusion rules.",
                    0.9,
                    [self._manifest_evidence("Application allowBackup flag.")],
                )
            )
        if app.get("uses_cleartext_traffic") == "true":
            findings.append(
                self._finding(
                    "MASVS-NETWORK",
                    "medium",
                    "Cleartext traffic is allowed",
                    "android:usesCleartextTraffic=true is declared.",
                    "HTTP traffic can expose sensitive data on the network.",
                    "Prefer HTTPS and restrict cleartext through network security config.",
                    0.9,
                    [self._manifest_evidence("Application cleartext traffic flag.")],
                )
            )
        if not app.get("network_security_config"):
            findings.append(
                self._finding(
                    "MASVS-NETWORK",
                    "info",
                    "Network security config not detected",
                    "No networkSecurityConfig attribute was observed in the manifest.",
                    "Absence is not a vulnerability by itself, but explicit network policy is easier to audit.",
                    "Document the intended network security posture.",
                    0.45,
                    [self._manifest_evidence("Application network security config attribute absent.")],
                )
            )
        return findings

    def _component_findings(self) -> list[dict[str, Any]]:
        findings = []
        for rows in self.context.data.get("components", {}).values():
            for component in rows:
                if component.get("risk") not in {"medium", "high"}:
                    continue
                findings.append(
                    self._finding(
                        "MASVS-PLATFORM",
                        component["risk"],
                        f"Review exported component: {component.get('name')}",
                        "An exported component without a clear permission guard was detected or inferred.",
                        "Externally reachable components may expand the attack surface.",
                        "Verify exported intent, add permissions when needed, and keep components private by default.",
                        0.8,
                        component.get("evidence_refs", []),
                    )
                )
        return findings

    def _network_findings(self) -> list[dict[str, Any]]:
        findings = []
        for endpoint in self.context.data.get("network_endpoints", []):
            if endpoint.get("scheme") != "http":
                continue
            findings.append(
                self._finding(
                    "MASVS-NETWORK",
                    "medium",
                    f"Cleartext HTTP endpoint detected: {endpoint.get('domain')}",
                    "A static string contains an HTTP URL.",
                    "Cleartext endpoints can leak traffic if used at runtime.",
                    "Use HTTPS and verify whether this string is active, dead code, or test configuration.",
                    float(endpoint.get("confidence", 0.7)),
                    endpoint.get("evidence_refs", []),
                )
            )
        return findings

    def _string_findings(self) -> list[dict[str, Any]]:
        findings = []
        strings = self.context.data.get("static_strings", [])
        for item in strings:
            value = item.get("value", "")
            for pattern in SECRET_PATTERNS:
                if pattern.search(value):
                    findings.append(
                        self._finding(
                            "MASVS-CRYPTO",
                            "high",
                            "Potential hardcoded secret",
                            "A string matching a secret/API-key pattern was found. Value is redacted in reports.",
                            "Hardcoded secrets can be extracted from APKs and abused outside the app.",
                            "Move secrets server-side or rotate and scope exposed public keys appropriately.",
                            0.72,
                            [
                                {
                                    "path": item.get("path"),
                                    "line_number": item.get("line_number"),
                                    "kind": "string",
                                    "description": "Potential secret pattern; value redacted.",
                                }
                            ],
                        )
                    )
                    break
            lowered = value.lower()
            if "setjavascriptenabled(true)" in lowered or "addjavascriptinterface" in lowered:
                findings.append(
                    self._finding(
                        "MASVS-PLATFORM",
                        "medium",
                        "Potentially risky WebView setting",
                        "A WebView API marker such as JavaScript enablement or JS bridge was found.",
                        "Risk depends on trusted content boundaries and bridge exposure.",
                        "Audit WebView content origins and JavaScript interfaces.",
                        0.6,
                        [
                            {
                                "path": item.get("path"),
                                "line_number": item.get("line_number"),
                                "kind": "string",
                                "description": "WebView security-relevant marker.",
                            }
                        ],
                    )
                )
            if "log." in lowered and any(token in lowered for token in ["password", "token", "secret"]):
                findings.append(
                    self._finding(
                        "MASVS-PRIVACY",
                        "medium",
                        "Potential sensitive logging",
                        "Logging marker appears near sensitive-field terminology.",
                        "Sensitive values in logs may leak through logcat or crash reports.",
                        "Review logging statements and redact sensitive values.",
                        0.55,
                        [
                            {
                                "path": item.get("path"),
                                "line_number": item.get("line_number"),
                                "kind": "string",
                                "description": "Sensitive logging marker.",
                            }
                        ],
                    )
                )
        return self._dedupe_findings(findings)

    def _tracker_findings(self) -> list[dict[str, Any]]:
        findings = []
        tracker_names = {"Google Analytics", "Firebase Crashlytics", "Sentry", "AdMob", "Facebook SDK"}
        for sdk in self.context.data.get("sdk_detection", []):
            if sdk.get("name") not in tracker_names or sdk.get("status") != "observed":
                continue
            findings.append(
                self._finding(
                    "MASVS-PRIVACY",
                    "info",
                    f"Third-party telemetry SDK detected: {sdk.get('name')}",
                    "A telemetry, crash reporting, ads, or analytics SDK marker was detected.",
                    "Telemetry may affect privacy disclosures and consent requirements.",
                    "Verify data collection, consent, retention, and privacy policy coverage.",
                    0.78,
                    sdk.get("evidence_refs", []),
                )
            )
        return findings

    def _privacy_risks(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        privacy_categories = {"MASVS-PRIVACY", "MASVS-STORAGE"}
        inherited = [
            item
            for item in findings
            if item.get("category") in privacy_categories or "privacy" in item.get("category", "").lower()
        ]
        inherited.extend(self.context.data.get("privacy_findings", []))
        return inherited

    def _compliance_notes(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        categories = sorted({item.get("category", "UNKNOWN") for item in findings})
        return [
            {
                "taxonomy": "OWASP MASVS/MASTG",
                "category": category,
                "status": "mapped",
                "finding_count": sum(1 for item in findings if item.get("category") == category),
                "note": "Static MVP signal only; validate manually and with authorized dynamic testing where appropriate.",
            }
            for category in categories
        ]

    def _finding(
        self,
        category: str,
        severity: str,
        title: str,
        description: str,
        impact: str,
        recommendation: str,
        confidence: float,
        evidence_refs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "impact": impact,
            "recommendation": recommendation,
            "status": "observed" if confidence >= 0.75 else "inferred",
            "confidence": min(max(confidence, 0.0), 1.0),
            "confidence_score": min(max(confidence, 0.0), 1.0),
            "evidence_refs": evidence_refs,
        }

    def _manifest_evidence(self, description: str) -> dict[str, Any]:
        return self.evidence(
            path="manifest.json",
            manifest_path="manifest_raw.xml",
            kind="manifest",
            description=description,
        )

    def _dedupe_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        deduped = []
        for finding in findings:
            key = (finding["title"], tuple((ref.get("path"), ref.get("line_number")) for ref in finding["evidence_refs"]))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped
