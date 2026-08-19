from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apk_docforge.renderers.mermaid import navigation_graph


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_No hay datos observados._\n"
    header = "| " + " | ".join(headers) + " |"
    separator = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(_cell(cell) for cell in row) + " |" for row in rows]
    return "\n".join([header, separator, *body]) + "\n"


def render_report(data: dict[str, Any]) -> str:
    identity = data.get("identity", {})
    features = data.get("features", [])
    screens = data.get("screens", [])
    screens_dynamic = data.get("screens_dynamic", [])
    endpoints = data.get("endpoints", [])
    permissions = data.get("permissions", [])
    findings = data.get("findings", [])
    protection_controls = data.get("protection_controls", [])
    ui_elements = data.get("ui_elements", [])
    app_understanding = data.get("app_understanding", {})
    source_metadata = data.get("source_metadata", {})
    reconstruction_brief = data.get("reconstruction_brief", {})
    lines = [
        "# apk-docforge static analysis report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Identity",
        "",
        md_table(
            ["Field", "Value"],
            [
                ["Name", identity.get("app_name") or "unknown"],
                ["Package name", identity.get("package_name") or "unknown"],
                ["Version name", identity.get("version_name") or "unknown"],
                ["Version code", identity.get("version_code") or "unknown"],
                ["SHA256", identity.get("sha256") or "unknown"],
                ["Mode", identity.get("mode") or "unknown"],
            ],
        ),
        "## Que Es Y Como Funciona",
        "",
        _app_understanding_section(app_understanding, source_metadata),
        "",
        "## Brief Para Rehacer En Codex",
        "",
        _reconstruction_brief_section(reconstruction_brief),
        "",
        "## Functional Summary",
        "",
        _functional_summary(features, screens),
        "",
        "## Features",
        "",
        md_table(
            ["Feature", "Category", "Status", "Confidence", "Evidence"],
            [
                [
                    item.get("name"),
                    item.get("category"),
                    item.get("status"),
                    item.get("confidence_score", item.get("confidence")),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in features
            ],
        ),
        "## Screens And Buttons",
        "",
        md_table(
            ["Screen", "Source", "Elements", "Confidence", "Evidence"],
            [
                [
                    item.get("name"),
                    item.get("source"),
                    item.get("ui_element_count", 0),
                    item.get("confidence"),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in screens
            ],
        ),
        "## Dynamic Screens",
        "",
        md_table(
            ["Screen", "Elements", "Screenshot", "Confidence", "Evidence"],
            [
                [
                    item.get("name"),
                    item.get("ui_element_count", 0),
                    item.get("screenshot") or "unknown",
                    item.get("confidence"),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in screens_dynamic
            ],
        ),
        "## Navigation Map",
        "",
        "```mermaid",
        navigation_graph(screens, ui_elements).rstrip(),
        "```",
        "",
        "## Connections And SDKs",
        "",
        md_table(
            ["Domain/URL", "Type", "Method hint", "Confidence", "Evidence"],
            [
                [
                    item.get("url") or item.get("domain"),
                    item.get("type"),
                    item.get("method_hint") or "unknown",
                    item.get("confidence"),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in endpoints
            ],
        ),
        "## Permissions And Privacy",
        "",
        md_table(
            ["Permission", "Category", "Risk", "Justification", "Evidence"],
            [
                [
                    item.get("name"),
                    item.get("category"),
                    item.get("risk"),
                    item.get("justification_probable"),
                    evidence_label(item.get("evidence_refs", [])),
                ]
                for item in permissions
            ],
        ),
        "## Security Findings",
        "",
        md_table(
            ["Severity", "Title", "Category", "Confidence", "Recommendation"],
            [
                [
                    item.get("severity"),
                    item.get("title"),
                    item.get("category"),
                    item.get("confidence_score", item.get("confidence")),
                    item.get("recommendation"),
                ]
                for item in findings
            ],
        ),
        "## Protection Controls And Boundaries",
        "",
        _protection_controls_section(protection_controls, data.get("bypass_policy", {})),
        "## Limitations",
        "",
        _limitations(data),
    ]
    return "\n".join(lines).replace("\n\n\n", "\n\n")


def render_doc(title: str, body: str) -> str:
    return f"# {title}\n\n{body.strip()}\n"


def evidence_label(evidence_refs: list[dict[str, Any]]) -> str:
    if not evidence_refs:
        return "unknown"
    labels = []
    for ref in evidence_refs[:3]:
        path = ref.get("path") or ref.get("manifest_path") or ref.get("tool_output") or "evidence"
        line = f":{ref['line_number']}" if ref.get("line_number") else ""
        labels.append(f"{path}{line}")
    return ", ".join(labels)


def write_markdown(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _functional_summary(features: list[dict[str, Any]], screens: list[dict[str, Any]]) -> str:
    if not features and not screens:
        return "- Observed directly: unknown\n- Inferred: unknown\n- Unknown: no static feature evidence found\n"
    observed = [item["name"] for item in features if item.get("status") == "observed"]
    inferred = [item["name"] for item in features if item.get("status") == "inferred"]
    return "\n".join(
        [
            f"- Observed directly: {', '.join(observed) if observed else 'unknown'}",
            f"- Inferred by names/code/resources: {', '.join(inferred) if inferred else 'unknown'}",
            f"- Static screens mapped: {len(screens)}",
        ]
    )


def _app_understanding_section(
    understanding: dict[str, Any], source_metadata: dict[str, Any]
) -> str:
    if not understanding:
        return "- Qué es: unknown\n- Para qué sirve: unknown\n- Cómo funciona: unknown\n"
    how = understanding.get("how_it_works", [])
    flows = understanding.get("core_flows", [])
    lines = [
        f"- Qué es: {understanding.get('what_it_is') or 'unknown'}",
        f"- Para qué sirve: {understanding.get('purpose') or 'unknown'}",
        f"- Usuarios principales: {', '.join(understanding.get('primary_users', [])) or 'unknown'}",
        f"- Fuente de metadatos: {source_metadata.get('package_page_url') or source_metadata.get('metadata_source') or source_metadata.get('source') or 'unknown'}",
        f"- Confidence: {understanding.get('confidence_score', 'unknown')}",
        f"- Evidencia: {evidence_label(understanding.get('evidence_refs', []))}",
        "",
        "### Como funciona",
    ]
    if how:
        lines.extend(
            f"- {item.get('step')}: status={item.get('status')}, confidence={item.get('confidence_score')}"
            for item in how
        )
    else:
        lines.append("- unknown")
    lines.extend(["", "### Flujos principales"])
    if flows:
        lines.append(
            md_table(
                ["Flujo", "Descripcion", "Estado", "Confidence", "Evidencia"],
                [
                    [
                        item.get("name"),
                        item.get("description"),
                        item.get("status"),
                        item.get("confidence_score"),
                        evidence_label(item.get("evidence_refs", [])),
                    ]
                    for item in flows
                ],
            ).rstrip()
        )
    else:
        lines.append("- unknown")
    unknowns = understanding.get("unknowns", [])
    if unknowns:
        lines.extend(["", "### Unknowns"])
        lines.extend(f"- {item}" for item in unknowns)
    return "\n".join(lines)


def _reconstruction_brief_section(brief: dict[str, Any]) -> str:
    if not brief:
        return "- Objetivo Codex: unknown\n"
    lines = [
        f"- Objetivo Codex: {brief.get('codex_goal') or 'unknown'}",
        f"- Evidencia: {evidence_label(brief.get('evidence_refs', []))}",
        "",
        "### Alcance MVP recomendado",
    ]
    lines.extend(f"- {item}" for item in brief.get("recommended_mvp_scope", [])[:12])
    lines.extend(["", "### Pantallas sugeridas"])
    screens = brief.get("screen_blueprint", [])
    if screens:
        lines.append(
            md_table(
                ["Pantalla", "Descripcion", "Source", "Confidence"],
                [
                    [
                        item.get("name"),
                        item.get("description"),
                        item.get("source"),
                        item.get("confidence_score"),
                    ]
                    for item in screens
                ],
            ).rstrip()
        )
    else:
        lines.append("- unknown")
    lines.extend(["", "### Modelos de datos"])
    lines.extend(f"- {item}" for item in brief.get("core_data_models", [])[:20])
    lines.extend(["", "### Fuera de alcance"])
    lines.extend(f"- {item}" for item in brief.get("out_of_scope", [])[:10])
    return "\n".join(lines)


def _limitations(data: dict[str, Any]) -> str:
    limits = [
        "- Dynamic analysis was not executed for this static-only run.",
        "- Runtime behavior, login-gated flows, and server responses are unknown unless evidenced by static artifacts.",
        "- Decompilation quality depends on installed tools such as jadx and apktool.",
        "- Obfuscation can reduce confidence for class and feature inference.",
        "- Certificate pinning or hidden traffic is not bypassed.",
    ]
    missing_tools = [
        name for name, meta in data.get("tools", {}).items() if name in {"jadx", "apktool", "apkanalyzer"} and not meta.get("available")
    ]
    if missing_tools:
        limits.append(f"- Missing tools limited analysis depth: {', '.join(missing_tools)}.")
    return "\n".join(limits) + "\n"


def _protection_controls_section(
    controls: list[dict[str, Any]], policy: dict[str, Any]
) -> str:
    observed = [item for item in controls if item.get("status") != "unknown"]
    policy_rows = [
        f"- Bypass implemented: {str(policy.get('bypass_implemented', False)).lower()}",
        f"- Bypass attempted: {str(policy.get('bypass_attempted', False)).lower()}",
        f"- Policy: {policy.get('reason') or 'Protection controls are documented, not bypassed.'}",
        "",
    ]
    if not observed:
        return "\n".join(policy_rows + ["_No protection controls observed with sufficient evidence._", ""])
    table = md_table(
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
    )
    return "\n".join(policy_rows) + table


def _cell(value: Any) -> str:
    text = "unknown" if value is None or value == "" else str(value)
    return text.replace("\n", " ").replace("|", "\\|")
