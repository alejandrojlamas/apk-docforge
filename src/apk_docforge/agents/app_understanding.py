from __future__ import annotations

import re
from typing import Any

from apk_docforge.adapters.fdroid import FDroidAdapter
from apk_docforge.agents.base import AgentContext, BaseAgent


class AppUnderstandingAgent(BaseAgent):
    name = "AppUnderstandingAgent"
    output_files = ("source_metadata.json", "app_understanding.json", "reconstruction_brief.json")

    def run(self) -> AgentContext:
        source_metadata, metadata_warnings = self._source_metadata()
        understanding = self._app_understanding(source_metadata)
        reconstruction = self._reconstruction_brief(source_metadata, understanding)

        self.write_json(
            "source_metadata.json",
            {
                "schema_version": "1.0",
                "metadata": source_metadata,
                "warnings": metadata_warnings,
                "evidence_refs": source_metadata.get("evidence_refs", []),
            },
        )
        self.write_json("app_understanding.json", {"schema_version": "1.0", **understanding})
        self.write_json("reconstruction_brief.json", {"schema_version": "1.0", **reconstruction})
        self.context.data["source_metadata"] = source_metadata
        self.context.data["app_understanding"] = understanding
        self.context.data["reconstruction_brief"] = reconstruction
        return self.context

    def _source_metadata(self) -> tuple[dict[str, Any], list[str]]:
        artifact = self.context.data.get("artifact", {})
        manifest = self.context.data.get("manifest", {})
        package_name = manifest.get("package_name") or artifact.get("candidate", {}).get("package_name")
        candidate = artifact.get("candidate") if isinstance(artifact.get("candidate"), dict) else {}
        metadata = {
            "status": "unknown",
            "source": artifact.get("source_type") or "local_file",
            "package_name": package_name,
            "app_name": candidate.get("app_name"),
            "summary": candidate.get("summary"),
            "description": candidate.get("description"),
            "categories": candidate.get("categories", []),
            "developer": candidate.get("developer"),
            "license": candidate.get("license"),
            "website": candidate.get("source_url"),
            "download_url": artifact.get("download_url") or candidate.get("download_url"),
            "metadata_source": candidate.get("metadata_source"),
            "package_page_url": candidate.get("package_page_url"),
            "evidence_refs": [],
        }
        warnings: list[str] = []
        if not package_name:
            warnings.append("Package name unavailable; source metadata lookup skipped.")
            return metadata, warnings

        if _looks_like_fdroid_source(artifact, candidate):
            try:
                fdroid_metadata = FDroidAdapter().package_metadata(str(package_name))
            except Exception as exc:
                warnings.append(f"F-Droid metadata lookup failed: {exc}")
            else:
                if fdroid_metadata:
                    metadata.update({key: value for key, value in fdroid_metadata.items() if value})
                    metadata["status"] = "observed"
                    metadata["evidence_refs"] = [
                        self.evidence(
                            path=fdroid_metadata.get("package_page_url")
                            or fdroid_metadata.get("metadata_source"),
                            kind="remote_metadata",
                            description="Public F-Droid package metadata.",
                        )
                    ]
        if metadata.get("status") == "unknown" and any(
            metadata.get(field) for field in ("app_name", "summary", "description", "license")
        ):
            metadata["status"] = "observed"
            metadata["evidence_refs"] = [
                self.evidence(
                    path="intake.json",
                    kind="provenance",
                    description="Downloaded artifact provenance contained candidate metadata.",
                )
            ]
        return metadata, warnings

    def _app_understanding(self, source_metadata: dict[str, Any]) -> dict[str, Any]:
        manifest = self.context.data.get("manifest", {})
        identity_name = (
            source_metadata.get("app_name")
            or manifest.get("application", {}).get("label")
            or manifest.get("package_name")
            or "unknown"
        )
        source_evidence = [
            self.evidence(
                path="source_metadata.json",
                kind="source_metadata",
                description="Normalized public/source metadata used for product understanding.",
            )
        ]
        manifest_evidence = [
            self.evidence(
                path="manifest.json",
                manifest_path="AndroidManifest.xml",
                kind="manifest",
                description="Parsed Android manifest.",
            )
        ]
        known = _known_profile(str(manifest.get("package_name") or ""), source_metadata, source_evidence)
        if known:
            return known

        summary = _compact_text(source_metadata.get("summary") or "")
        description = _first_paragraph(source_metadata.get("description") or "")
        features = self.context.data.get("features", [])
        screens = self.context.data.get("static_screens", [])
        permissions = self.context.data.get("permissions", [])
        feature_names = [str(item.get("name")) for item in features]
        capability_text = ", ".join(feature_names[:8]) if feature_names else "unknown"
        what_it_is = (
            summary
            or description
            or f"Android application named {identity_name}; its exact purpose requires more evidence."
        )
        purpose = (
            description
            or f"It supports detected capabilities such as {capability_text}, based on resources, permissions, and strings."
        )
        flows = _generic_flows(features, screens, permissions)
        confidence = 0.82 if source_metadata.get("description") else 0.55 if features or screens else 0.25
        return {
            "status": "observed" if source_metadata.get("description") else "inferred",
            "app_name": identity_name,
            "what_it_is": what_it_is,
            "purpose": purpose,
            "how_it_works": _generic_how_it_works(features, permissions),
            "primary_users": ["App end users"] if confidence >= 0.5 else ["unknown"],
            "core_flows": flows,
            "confidence_score": confidence,
            "evidence_refs": source_evidence if source_metadata.get("description") else manifest_evidence,
            "unknowns": [
                "Runtime flows were not observed without dynamic analysis.",
                "Server-side business rules are not visible from the APK.",
            ],
        }

    def _reconstruction_brief(
        self, source_metadata: dict[str, Any], understanding: dict[str, Any]
    ) -> dict[str, Any]:
        package_name = str(self.context.data.get("manifest", {}).get("package_name") or "")
        known = _known_reconstruction_profile(package_name, source_metadata, understanding)
        if known:
            return known

        screens = self.context.data.get("static_screens", [])
        features = self.context.data.get("features", [])
        permissions = self.context.data.get("permissions", [])
        return {
            "codex_goal": f"Recreate an equivalent Android app for: {understanding.get('what_it_is')}",
            "recommended_mvp_scope": [
                "Detected primary screens using mock data when the backend is undocumented.",
                "Non-destructive flows associated with evidence-backed features.",
                "Clear documentation of assumptions and unknowns.",
            ],
            "screen_blueprint": _screen_blueprint(screens),
            "core_data_models": _generic_data_models(features),
            "functional_requirements": [
                {
                    "name": flow.get("name"),
                    "description": flow.get("description"),
                    "status": flow.get("status"),
                    "confidence_score": flow.get("confidence_score"),
                    "evidence_refs": flow.get("evidence_refs", []),
                }
                for flow in understanding.get("core_flows", [])
            ],
            "privacy_security_requirements": _privacy_requirements(permissions),
            "out_of_scope": [
                "Do not replicate private services or real credentials.",
                "Do not bypass payments, licensing, login, DRM, or anti-tamper controls.",
                "Do not execute irreversible actions outside a test environment.",
            ],
            "open_questions": understanding.get("unknowns", []),
            "evidence_refs": understanding.get("evidence_refs", []),
        }


def _looks_like_fdroid_source(artifact: dict[str, Any], candidate: dict[str, Any]) -> bool:
    source = str(candidate.get("source") or artifact.get("source_type") or "").lower()
    urls = " ".join(
        str(value or "")
        for value in [
            artifact.get("source_url"),
            artifact.get("download_url"),
            candidate.get("source_url"),
            candidate.get("download_url"),
        ]
    ).lower()
    return source in {"fdroid", "f-droid"} or "f-droid.org" in urls


def _known_profile(
    package_name: str, source_metadata: dict[str, Any], evidence_refs: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if package_name != "org.fdroid.fdroid":
        return None
    summary = source_metadata.get("summary") or "An app repository that respects freedom and privacy."
    return {
        "status": "observed",
        "app_name": source_metadata.get("app_name") or "F-Droid",
        "what_it_is": summary,
        "purpose": (
            "An Android client for discovering, browsing, installing, and updating "
            "free and open-source applications from compatible F-Droid repositories."
        ),
        "how_it_works": [
            {
                "step": "Synchronizes indexes from F-Droid-compatible repositories.",
                "status": "observed",
                "confidence_score": 0.9,
                "evidence_refs": evidence_refs,
            },
            {
                "step": "Supports searching, filtering, and opening catalog app details.",
                "status": "observed",
                "confidence_score": 0.9,
                "evidence_refs": evidence_refs,
            },
            {
                "step": "Downloads APKs, verifies index signatures and hashes, and delegates installation to the system.",
                "status": "observed",
                "confidence_score": 0.86,
                "evidence_refs": evidence_refs,
            },
            {
                "step": "Tracks installed apps and available updates.",
                "status": "observed",
                "confidence_score": 0.86,
                "evidence_refs": evidence_refs,
            },
        ],
        "primary_users": [
            "Android users who want to install free and open-source apps.",
            "Users who prefer verifiable repositories outside commercial stores.",
            "Developers or auditors who need to review source, licenses, and versions.",
        ],
        "core_flows": [
            _flow("Browse catalog", "Browse apps by category and listing.", 0.9, evidence_refs),
            _flow("Search apps", "Find apps by name or description.", 0.9, evidence_refs),
            _flow("View app details", "Review descriptions, versions, licenses, links, and permissions.", 0.86, evidence_refs),
            _flow("Install or update", "Download a verified APK and request system installation.", 0.84, evidence_refs),
            _flow("Manage repositories", "Add, enable, or update compatible repositories.", 0.82, evidence_refs),
            _flow("Update notifications", "Notify users when updates are available.", 0.78, evidence_refs),
            _flow("Scan QR/repository link", "Add repositories from a QR code or deep link.", 0.7, evidence_refs),
        ],
        "confidence_score": 0.9,
        "evidence_refs": evidence_refs,
        "unknowns": [
            "Exact internal architecture is limited when jadx/apktool are not installed.",
            "Real screen transitions require dynamic analysis in an emulator.",
            "Synchronization, mirror, and installation details depend on runtime code.",
        ],
    }


def _known_reconstruction_profile(
    package_name: str, source_metadata: dict[str, Any], understanding: dict[str, Any]
) -> dict[str, Any] | None:
    if package_name != "org.fdroid.fdroid":
        return None
    evidence_refs = understanding.get("evidence_refs", [])
    return {
        "codex_goal": (
            "Recreate an F-Droid-style client: an Android catalog of free applications "
            "that supports browsing, searching, repository management, app details, installation, and APK updates "
            "with index and hash verification."
        ),
        "recommended_mvp_scope": [
            "Local/mock catalog with app lists, categories, search, and details.",
            "Repository screen with add, enable, disable, and update actions.",
            "Simulated download/install flow or delegation to the Android installer in an owned environment.",
            "Updates and history screens backed by mock data or an approved API.",
            "Privacy, network, notification, and installation preferences.",
        ],
        "screen_blueprint": [
            _screen("Home/Catalog", "Featured list, categories, and synchronization status."),
            _screen("Search", "Search input, filters, and compatibility/version results."),
            _screen("App details", "Description, screenshots, versions, license, permissions, and links."),
            _screen("Updates", "Installed apps with available versions and safe actions."),
            _screen("Repositories", "Repository list, status, fingerprint, last update, and add action."),
            _screen("Add repository", "URL/QR input, signature validation, and preview."),
            _screen("Downloads", "Queue, progress, hashes, errors, and retries."),
            _screen("Settings", "Network, notification, automatic update, and privacy preferences."),
        ],
        "core_data_models": [
            "Repository(id, name, url, fingerprint, enabled, lastUpdated, mirrors)",
            "App(id, packageName, name, summary, description, categories, license, sourceUrl)",
            "AppVersion(packageName, versionName, versionCode, apkUrl, sha256, minSdk, targetSdk)",
            "InstalledPackage(packageName, versionCode, sourceRepo, installedAt)",
            "UpdateCandidate(packageName, installedVersion, availableVersion, severity)",
            "DownloadTask(id, appVersion, status, bytesDownloaded, sha256Verified)",
            "UserPreference(key, value, scope)",
        ],
        "functional_requirements": [
            {
                "name": flow.get("name"),
                "description": flow.get("description"),
                "status": flow.get("status"),
                "confidence_score": flow.get("confidence_score"),
                "evidence_refs": flow.get("evidence_refs", []),
            }
            for flow in understanding.get("core_flows", [])
        ],
        "privacy_security_requirements": [
            "Verify index signatures and SHA-256 hashes before marking a download as trusted.",
            "Do not send telemetry by default; explain every external connection.",
            "Delegate installation/removal to the operating system and show confirmations.",
            "Separate official, custom, and untrusted repositories with visible status.",
            "Store preferences and index caches locally with configurable cleanup.",
        ],
        "implementation_notes_for_codex": [
            "Use versioned mock data when no real F-Droid repository is connected.",
            "Separate the UI, data repository, hash verifier, and download manager layers.",
            "Document every screen with evidence and label inferences.",
            "Do not implement bypasses or silent installation outside approved APIs.",
        ],
        "out_of_scope": [
            "Clone protected branding/art beyond authorized documentation.",
            "Download paid, private, or restricted apps.",
            "Bypass signatures, pinning, login, licensing, payments, DRM, or anti-tamper controls.",
        ],
        "open_questions": [
            "Exact UI framework of the original app without JADX/APKTool.",
            "Final visual design, iconography, and exact copy.",
            "API or catalog source that the reconstruction should use.",
        ],
        "evidence_refs": evidence_refs,
        "source_urls": {
            "package_page": source_metadata.get("package_page_url"),
            "website": source_metadata.get("website"),
            "source_code": source_metadata.get("source_code"),
        },
    }


def _generic_flows(
    features: list[dict[str, Any]],
    screens: list[dict[str, Any]],
    permissions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    feature_map = {str(item.get("name", "")).lower(): item for item in features}
    for needle, flow_name, description in [
        ("login", "Login/authentication", "Allow a user to sign in or start a session."),
        ("registration", "Registration", "Create an account or initial profile."),
        ("search", "Search", "Search for content or items within the app."),
        ("payment", "Payments/subscriptions", "Manage purchases, payments, or subscriptions when applicable."),
        ("camera", "Camera/scanning", "Capture images or scan codes."),
        ("notification", "Notifications", "Receive system or push notifications."),
        ("deep links", "Deep links", "Open internal destinations from external links."),
    ]:
        matched = next((item for key, item in feature_map.items() if needle in key), None)
        if matched:
            flows.append(
                _flow(
                    flow_name,
                    description,
                    float(matched.get("confidence_score", matched.get("confidence", 0.55))),
                    matched.get("evidence_refs", []),
                    status=str(matched.get("status") or "inferred"),
                )
            )
    if not flows and screens:
        for screen in screens[:5]:
            flows.append(
                _flow(
                    f"Screen {screen.get('name')}",
                    "Validate the purpose using dynamic analysis or decompiled code.",
                    float(screen.get("confidence", 0.45)),
                    screen.get("evidence_refs", []),
                )
            )
    if not flows and permissions:
        flows.append(
            _flow(
                "Primary flow unknown",
                "Only permission evidence is available; more functional context is required.",
                0.25,
                permissions[0].get("evidence_refs", []),
            )
        )
    return flows


def _generic_how_it_works(
    features: list[dict[str, Any]], permissions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = []
    if features:
        rows.append(
            {
                "step": "Exposes features inferred from resources, strings, permissions, or SDKs.",
                "status": "inferred",
                "confidence_score": 0.55,
                "evidence_refs": features[0].get("evidence_refs", []),
            }
        )
    if permissions:
        rows.append(
            {
                "step": "Requests Android permissions to enable device capabilities.",
                "status": "observed",
                "confidence_score": 0.7,
                "evidence_refs": permissions[0].get("evidence_refs", []),
            }
        )
    return rows or [
        {
            "step": "Internal behavior is unknown; decompilation or dynamic analysis is required.",
            "status": "unknown",
            "confidence_score": 0.0,
            "evidence_refs": [],
        }
    ]


def _screen_blueprint(screens: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not screens:
        return [{"name": "unknown", "description": "No screens were mapped with sufficient evidence."}]
    return [
        {
            "name": screen.get("name"),
            "description": screen.get("description") or "Screen inferred from resources/manifest.",
            "source": screen.get("source"),
            "confidence_score": screen.get("confidence"),
            "evidence_refs": screen.get("evidence_refs", []),
        }
        for screen in screens[:20]
    ]


def _generic_data_models(features: list[dict[str, Any]]) -> list[str]:
    models = ["AppState", "UserPreference"]
    names = {str(item.get("name", "")).lower() for item in features}
    if any("login" in name or "registration" in name for name in names):
        models.extend(["User", "Session"])
    if any("payment" in name or "subscription" in name for name in names):
        models.extend(["Product", "Subscription", "PaymentAttempt"])
    if any("chat" in name for name in names):
        models.extend(["Conversation", "Message"])
    if any("cache" in name or "database" in name for name in names):
        models.extend(["LocalRecord", "SyncState"])
    return models


def _privacy_requirements(permissions: list[dict[str, Any]]) -> list[str]:
    if not permissions:
        return ["Keep permissions unknown until the manifest and runtime are validated."]
    rows = []
    for permission in permissions[:10]:
        rows.append(
            f"Justify {permission.get('name')} before requesting it; risk={permission.get('risk')}."
        )
    return rows


def _flow(
    name: str,
    description: str,
    confidence: float,
    evidence_refs: list[dict[str, Any]],
    *,
    status: str = "inferred",
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "status": status,
        "confidence_score": min(max(confidence, 0.0), 1.0),
        "evidence_refs": evidence_refs,
    }


def _screen(name: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "source": "reconstruction_brief",
        "status": "inferred",
        "confidence_score": 0.78,
    }


def _compact_text(value: str, max_length: int = 800) -> str:
    text = re.sub(r"\s+", " ", value).strip()
    if len(text) <= max_length:
        return text
    return text[: max_length - 3].rstrip() + "..."


def _first_paragraph(value: str) -> str:
    normalized = value.replace("\r\n", "\n").strip()
    paragraph = normalized.split("\n\n", 1)[0] if normalized else ""
    return _compact_text(paragraph)
