from __future__ import annotations

from typing import Any

from apk_docforge.renderers.markdown import evidence_label, md_table
from apk_docforge.renderers.mermaid import navigation_graph


def render_codex_prompt(data: dict[str, Any]) -> str:
    identity = data.get("identity", {})
    features = data.get("features", [])
    screens = data.get("screens", [])
    screens_dynamic = data.get("screens_dynamic", [])
    ui_elements = data.get("ui_elements", [])
    ui_elements_dynamic = data.get("ui_elements_dynamic", [])
    endpoints = data.get("endpoints", [])
    permissions = data.get("permissions", [])
    components = data.get("components", {})
    findings = data.get("findings", [])
    protection_controls = data.get("protection_controls", [])
    authorization_boundaries = data.get("authorization_boundaries", [])
    bypass_policy = data.get("bypass_policy", {})
    app_understanding = data.get("app_understanding", {})
    reconstruction_brief = data.get("reconstruction_brief", {})
    storage = _storage(features)
    lines = [
        "# Master prompt for documenting Android reverse engineering",
        "",
        "## Role",
        (
            "Act as a technical writer for authorized reverse engineering. Your task is to "
            "turn the JSON files and artifacts produced by `apk-docforge` into a clear natural-language "
            "record of what the app is, what it does, how it works, which screens it has, which "
            "connections and permissions it uses, which risks appear, and which details remain unknown."
        ),
        "",
        "## Objective",
        (
            "Create human-readable reverse-engineering documentation for the analyzed application. "
            "Do not implement an app, generate reconstruction code, or design bypasses unless the user "
            "explicitly requests a permitted follow-up task. This prompt records knowledge; it is not "
            "intended to clone the app or evade controls."
        ),
        "",
        "## Documentation rules",
        "1. Treat the attached JSON files as the source of truth.",
        "2. Do not invent features, screens, endpoints, or flows without evidence.",
        "3. Always distinguish `observed`, `inferred`, and `unknown`.",
        "4. Every important claim must include evidence or be identified as an inference.",
        "5. Preserve `confidence_score` when present and lower confidence for indirect evidence.",
        "6. Do not propose bypasses for licensing, payment, DRM, authentication, certificate pinning, or anti-tamper controls.",
        "7. Do not assume runtime behavior when the analysis was static.",
        "8. Record contradictions or weak data as limitations or open questions.",
        "",
        "## Expected output format",
        "Generate a natural-language document with this structure:",
        "- Executive summary.",
        "- Identity and chain of custody.",
        "- What the app is and what it does.",
        "- How it works at a functional level.",
        "- Screens, navigation, buttons, and actions.",
        "- Evidence-backed detected features.",
        "- Connections, endpoints, repositories, SDKs, and HTTP clients.",
        "- Permissions, privacy, and data likely processed.",
        "- Android components and exposed surface.",
        "- Local storage and offline/cache state.",
        "- Security findings and observed protection controls.",
        "- Limitations, unknowns, and open questions.",
        "- Evidence appendix with relevant paths and JSON files.",
        "",
        "## Reference artifacts",
        "- `app_understanding.json`: normalized functional summary.",
        "- `source_metadata.json`: public or provenance metadata.",
        "- `manifest.json`, `components.json`, `permissions.json`, `deep_links.json`: Android foundation.",
        "- `features.json`, `feature_evidence_map.json`, `confidence_report.json`: features.",
        "- `static_screens.json`, `ui_elements_static.json`: static screens and elements.",
        "- `network_endpoints.json`, `sdk_detection.json`, `api_clients.json`: network and SDKs.",
        "- `security_findings.json`, `privacy_risks.json`, `control_boundary_assessment.json`: audit artifacts.",
        "- `reconstruction_brief.json`: optional context only if a reconstruction plan is requested later.",
        "",
        "## Evidence package for this app",
        "",
        "### Identity",
        f"- Name: {identity.get('app_name') or 'unknown'}",
        f"- Package name: {identity.get('package_name') or 'unknown'}",
        f"- Version name: {identity.get('version_name') or 'unknown'}",
        f"- Version code: {identity.get('version_code') or 'unknown'}",
        f"- Min SDK: {identity.get('min_sdk') or 'unknown'}",
        f"- Target SDK: {identity.get('target_sdk') or 'unknown'}",
        f"- Signature/certificate: {identity.get('certificate') or 'unknown'}",
        f"- Source: {identity.get('source') or 'local_file'}",
        f"- SHA256: {identity.get('sha256') or 'unknown'}",
        f"- Analysis date: {identity.get('analysis_date') or 'unknown'}",
        f"- Analysis mode: {identity.get('mode') or 'static'}",
        "",
        "### Functional understanding",
        f"- What it is: {app_understanding.get('what_it_is') or 'unknown'}",
        f"- Purpose: {app_understanding.get('purpose') or 'unknown'}",
        f"- Confidence: {app_understanding.get('confidence_score', 'unknown')}",
        f"- Evidence: {evidence_label(app_understanding.get('evidence_refs', []))}",
        "- Directly observed: review sources/metadata, screens, permissions, and endpoints marked `observed`.",
        "- Inferred from names/code/resources: features and flows marked `inferred` with a confidence score.",
        "- Unknown: runtime flows, real login, server responses, and unexecuted dynamic actions.",
        "",
        "### How the app works",
        _how_it_works_section(app_understanding),
        "",
        "### Recorded core flows",
        md_table(
            ["Flow", "Description", "Status", "Confidence", "Evidence"],
            [
                [
                    item.get("name"),
                    item.get("description"),
                    item.get("status"),
                    item.get("confidence_score"),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in app_understanding.get("core_flows", [])
            ],
        ),
        "### Data models inferred for documentation",
        _data_models_section(reconstruction_brief),
        "",
        "### Detected features",
        md_table(
            [
                "Feature",
                "Category",
                "Evidence",
                "Confidence",
                "Related screens",
                "Related endpoints/SDKs",
                "Risks/notes",
            ],
            [
                [
                    item.get("name"),
                    item.get("category"),
                    evidence_label(item.get("evidence_refs", [])),
                    item.get("confidence_score", item.get("confidence")),
                    ", ".join(item.get("related_screens", [])) or "unknown",
                    ", ".join(item.get("related_endpoints", [])) or "unknown",
                    ", ".join(item.get("risks_or_notes", [])) or "unknown",
                ]
                for item in features
            ],
        ),
        "### Screens",
        _screens_section(screens, ui_elements),
        "### Dynamic screens",
        _dynamic_screens_section(screens_dynamic, ui_elements_dynamic),
        "### Navigation map",
        "```mermaid",
        navigation_graph(screens, ui_elements).rstrip(),
        "```",
        "",
        _blocked_flows_section(data.get("blocked_flows", [])),
        "",
        "### Connections",
        md_table(
            ["Domains/Endpoints", "Method", "Client/Type", "SDKs", "Related classes", "Likely sensitive data"],
            [
                [
                    item.get("url") or item.get("domain"),
                    item.get("method_hint") or "unknown",
                    item.get("type") or "unknown",
                    ", ".join(data.get("observed_sdks", [])) or "unknown",
                    evidence_label(item.get("evidence_refs", [])),
                    "unknown",
                ]
                for item in endpoints
            ],
        ),
        "### Permissions and privacy",
        md_table(
            ["Permission", "Likely justification", "Evidence", "Risk", "Recommendation"],
            [
                [
                    item.get("name"),
                    item.get("justification_probable"),
                    evidence_label(item.get("evidence_refs", [])),
                    item.get("risk"),
                    "Verify necessity and associated consent.",
                ]
                for item in permissions
            ],
        ),
        "### Android components",
        _components_section(components),
        "### Local storage",
        storage,
        "### Security findings",
        md_table(
            ["Severity", "Title", "Evidence", "Impact", "Recommendation", "Limitations"],
            [
                [
                    item.get("severity"),
                    item.get("title"),
                    evidence_label(item.get("evidence_refs", [])),
                    item.get("impact"),
                    item.get("recommendation"),
                    "Static signal; validate manually.",
                ]
                for item in findings
            ],
        ),
        "### Protection controls and boundaries",
        _protection_boundaries_section(protection_controls, authorization_boundaries, bypass_policy),
        "### Suggested test matrix for validating the documentation",
        md_table(
            ["Flow", "Precondition", "Steps", "Expected result", "Test data", "Priority"],
            _test_matrix(features, screens),
        ),
        "### Limitations",
        "- Obfuscation: see `obfuscation_report.json`.",
        "- Code that cannot be decompiled: depends on installed jadx/apktool tools.",
        "- Flows behind login: unknown in static-only mode.",
        "- Missing test credentials: no real login was executed.",
        "- Dynamic analysis not executed: this run was exclusively static.",
        "- Certificate pinning or traffic not visible without authorization: no bypass is attempted.",
        "",
        "## Final instructions for Codex",
        "Using this context:",
        "1. Write the reverse-engineering record in natural language.",
        "2. Begin with a human-readable explanation, then move into technical detail.",
        "3. Do not invent features without evidence.",
        "4. Do not turn this into a specification for cloning the app unless the user requests that later.",
        "5. Preserve evidence, confidence, and observed/inferred/unknown status.",
        "6. Use `unknown` whenever evidence is missing.",
        "7. Do not propose bypasses for licensing, payment, DRM, authentication, or security controls.",
        "",
    ]
    return "\n".join(lines).replace("\n\n\n", "\n\n")


def _screens_section(screens: list[dict[str, Any]], elements: list[dict[str, Any]]) -> str:
    if not screens:
        return "_No observed screens._\n"
    lines = []
    for screen in screens:
        related = [item for item in elements if item.get("screen_hint") == screen.get("name")]
        buttons = [item for item in related if item.get("element_type") in {"button", "menu_item"}]
        inputs = [item for item in related if item.get("element_type") == "input"]
        lines.extend(
            [
                f"### {screen.get('name')}",
                f"- Likely name: {screen.get('name')}",
                f"- Related Activity/Fragment/Composable/layout: {screen.get('activity_or_fragment') or ', '.join(screen.get('related_layouts', [])) or 'unknown'}",
                f"- UI elements: {len(related)}",
                f"- Buttons: {', '.join(_element_label(item) for item in buttons) or 'unknown'}",
                f"- Inputs: {', '.join(_element_label(item) for item in inputs) or 'unknown'}",
                "- Menus: see `ui_elements_static.json`.",
                "- Expected actions: inferred from text/resources when available.",
                "- Observed actions: unknown in static-only mode.",
                f"- Evidence: {evidence_label(screen.get('evidence_refs', []))}",
                "",
            ]
        )
    return "\n".join(lines)


def _components_section(components: dict[str, list[dict[str, Any]]]) -> str:
    lines = []
    for title, rows in [
        ("Activities", components.get("activities", [])),
        ("Services", components.get("services", [])),
        ("Receivers", components.get("receivers", [])),
        ("Providers", components.get("providers", [])),
    ]:
        lines.append(f"### {title}")
        lines.append(
            md_table(
                ["Name", "Exported", "Risk", "Intent filters / Deep links"],
                [
                    [
                        item.get("name"),
                        item.get("exported_effective", item.get("exported", "unknown")),
                        item.get("risk", "unknown"),
                        len(item.get("intent_filters", [])) + len(item.get("deep_links", [])),
                    ]
                    for item in rows
                ],
            )
        )
    return "\n".join(lines)


def _dynamic_screens_section(screens: list[dict[str, Any]], elements: list[dict[str, Any]]) -> str:
    if not screens:
        return "_No observed dynamic screens._\n"
    lines = []
    for screen in screens:
        related = [item for item in elements if item.get("screen_id") == screen.get("id")]
        buttons = [item for item in related if item.get("element_type") in {"button", "clickable"}]
        lines.extend(
            [
                f"### {screen.get('name')}",
                "- Source: dynamic UIAutomator capture",
                f"- Screenshot: {screen.get('screenshot') or 'unknown'}",
                f"- UI dump: {screen.get('uiautomator_dump') or 'unknown'}",
                f"- Elements: {len(related)}",
                f"- Observed actions: {', '.join(_element_label(item) for item in buttons[:8]) or 'unknown'}",
                f"- Evidence: {evidence_label(screen.get('evidence_refs', []))}",
                "",
            ]
        )
    return "\n".join(lines)


def _reconstruction_goal_section(
    understanding: dict[str, Any],
    brief: dict[str, Any],
    source_metadata: dict[str, Any],
) -> str:
    lines = [
        f"- Primary goal: {brief.get('codex_goal') or understanding.get('what_it_is') or 'unknown'}",
        f"- Public/approved source: {source_metadata.get('package_page_url') or source_metadata.get('metadata_source') or source_metadata.get('source') or 'unknown'}",
        f"- Base app: {understanding.get('app_name') or source_metadata.get('app_name') or 'unknown'}",
        f"- Users: {', '.join(understanding.get('primary_users', [])) or 'unknown'}",
        f"- Evidence refs: {evidence_label(brief.get('evidence_refs') or understanding.get('evidence_refs', []))}",
        "",
        "### Baseline screens to recreate",
    ]
    screens = brief.get("screen_blueprint", [])
    if not screens:
        lines.append("- unknown")
    else:
        lines.extend(f"- {item.get('name')}: {item.get('description')}" for item in screens)
    return "\n".join(lines)


def _how_it_works_section(understanding: dict[str, Any]) -> str:
    rows = understanding.get("how_it_works", [])
    if not rows:
        return "- unknown\n"
    return "\n".join(
        f"- {item.get('step')}: status={item.get('status')}, confidence={item.get('confidence_score')}, "
        f"evidence={evidence_label(item.get('evidence_refs', []))}"
        for item in rows
    )


def _mvp_scope_section(brief: dict[str, Any]) -> str:
    items = brief.get("recommended_mvp_scope", [])
    if not items:
        return "- unknown\n"
    return "\n".join(f"- {item}" for item in items) + "\n"


def _data_models_section(brief: dict[str, Any]) -> str:
    items = brief.get("core_data_models", [])
    if not items:
        return "- unknown\n"
    return "\n".join(f"- {item}" for item in items) + "\n"


def _reconstruction_backlog(brief: dict[str, Any]) -> str:
    items = brief.get("recommended_mvp_scope", [])
    if not items:
        return ""
    rows = ["- Reconstruction epics:"]
    rows.extend(f"  - {item}" for item in items[:8])
    return "\n".join(rows)


def _blocked_flows_section(blocked_flows: list[dict[str, Any]]) -> str:
    if not blocked_flows:
        return "- Blocked flows: unknown or not observed."
    rows = [
        f"- Blocked flows: {item.get('type')} / {item.get('label')} / {item.get('reason')}"
        for item in blocked_flows
    ]
    return "\n".join(rows)


def _storage(features: list[dict[str, Any]]) -> str:
    markers = [item for item in features if item.get("category") == "local_storage"]
    status = "inferred" if markers else "unknown"
    return "\n".join(
        [
            f"- SharedPreferences: {status}",
            f"- SQLite/Room: {status}",
            "- Files/cache: unknown",
            "- Encrypted storage when detected: unknown",
            "- Risks: review storage findings and evidence before asserting that sensitive data is present.",
            "",
        ]
    )


def _protection_boundaries_section(
    controls: list[dict[str, Any]],
    boundaries: list[dict[str, Any]],
    policy: dict[str, Any],
) -> str:
    observed = [item for item in controls if item.get("status") != "unknown"]
    lines = [
        f"- Bypass implemented: {str(policy.get('bypass_implemented', False)).lower()}",
        f"- Bypass attempted: {str(policy.get('bypass_attempted', False)).lower()}",
        f"- Policy: {policy.get('reason') or 'Controls are documented without evasion.'}",
        "",
        "### Detected controls",
        md_table(
            ["Control", "Category", "Status", "Bypass", "Confidence", "Evidence"],
            [
                [
                    item.get("name"),
                    item.get("category"),
                    item.get("status"),
                    item.get("bypass_status") or "prohibited_by_policy",
                    item.get("confidence_score", item.get("confidence")),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in observed
            ],
        ),
        "### Authorization boundaries",
        md_table(
            ["Boundary", "Category", "Allowed action", "Blocked action", "Confidence", "Evidence"],
            [
                [
                    item.get("name"),
                    item.get("category"),
                    item.get("allowed_audit_action"),
                    item.get("blocked_action"),
                    item.get("confidence_score", item.get("confidence")),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in boundaries
            ],
        ),
    ]
    return "\n".join(lines)


def _test_matrix(features: list[dict[str, Any]], screens: list[dict[str, Any]]) -> list[list[str]]:
    rows: list[list[str]] = []
    for screen in screens[:8]:
        rows.append(
            [
                f"Screen {screen.get('name')}",
                "APK installed in an authorized test emulator",
                "Open the app, navigate to the screen, and record visible elements",
                "The screen shows expected elements without errors",
                "Non-sensitive test data",
                "Medium",
            ]
        )
    for feature in features[:8]:
        rows.append(
            [
                str(feature.get("name")),
                "Static evidence reviewed",
                "Validate the flow in a test environment without irreversible actions",
                "Behavior matches the documented evidence",
                "Test account or data when applicable",
                "High" if feature.get("category") in {"auth", "commerce"} else "Medium",
            ]
        )
    return rows


def _element_label(item: dict[str, Any]) -> str:
    return str(item.get("visible_text") or item.get("resource_id") or item.get("tag") or "unknown")
