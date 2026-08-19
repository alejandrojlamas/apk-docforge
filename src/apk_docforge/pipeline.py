from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apk_docforge.agents.app_understanding import AppUnderstandingAgent
from apk_docforge.agents.base import AgentContext
from apk_docforge.agents.codex_prompt_builder import CodexPromptBuilderAgent
from apk_docforge.agents.control_boundary_audit import ControlBoundaryAuditAgent
from apk_docforge.agents.documentation import DocumentationAgent
from apk_docforge.agents.dynamic_runner import DynamicRunnerAgent
from apk_docforge.agents.feature_inference import FeatureInferenceAgent
from apk_docforge.agents.intake import IntakeAgent
from apk_docforge.agents.network import NetworkConnectionAgent
from apk_docforge.agents.package_structure import PackageStructureAgent
from apk_docforge.agents.permissions_privacy import PermissionPrivacyAgent
from apk_docforge.agents.qa_validation import QAValidationAgent
from apk_docforge.agents.security_audit import SecurityAuditAgent
from apk_docforge.agents.static_re import StaticReverseEngineeringAgent
from apk_docforge.agents.ui_explorer import UIExplorerAgent
from apk_docforge.agents.ui_static import UIStaticMapperAgent
from apk_docforge.config import get_settings
from apk_docforge.db.models import Analysis, Artifact
from apk_docforge.db.session import session_scope
from apk_docforge.tools.android_sdk import android_tool_report
from apk_docforge.tools.archive import ensure_dir


STATIC_AGENTS = [
    IntakeAgent,
    PackageStructureAgent,
    StaticReverseEngineeringAgent,
    PermissionPrivacyAgent,
    NetworkConnectionAgent,
    UIStaticMapperAgent,
    FeatureInferenceAgent,
    SecurityAuditAgent,
    ControlBoundaryAuditAgent,
    AppUnderstandingAgent,
    DocumentationAgent,
    CodexPromptBuilderAgent,
    QAValidationAgent,
]

DYNAMIC_AGENTS = [
    IntakeAgent,
    PackageStructureAgent,
    StaticReverseEngineeringAgent,
    PermissionPrivacyAgent,
    NetworkConnectionAgent,
    UIStaticMapperAgent,
    DynamicRunnerAgent,
    UIExplorerAgent,
    FeatureInferenceAgent,
    SecurityAuditAgent,
    ControlBoundaryAuditAgent,
    AppUnderstandingAgent,
    DocumentationAgent,
    CodexPromptBuilderAgent,
    QAValidationAgent,
]


def make_analysis_id(input_path: Path) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = "".join(ch if ch.isalnum() else "-" for ch in input_path.stem).strip("-") or "artifact"
    return f"{safe_name}-{stamp}-{uuid.uuid4().hex[:8]}"


def run_analysis(
    input_path: Path,
    out: Path | None = None,
    mode: str = "static",
    device: str | None = None,
) -> dict[str, Any]:
    if mode not in {"static", "dynamic"}:
        raise ValueError("mode must be `static` or `dynamic`")
    if mode == "dynamic" and not device:
        raise ValueError("dynamic mode requires --device with an authorized emulator/test device serial")

    settings = get_settings()
    analysis_id = make_analysis_id(input_path)
    output_dir = out or (settings.output_root / analysis_id)
    output_dir = output_dir.expanduser().resolve()
    ensure_dir(output_dir)
    context = AgentContext(
        input_path=input_path,
        output_dir=output_dir,
        mode=mode,
        analysis_id=analysis_id,
        analysis_started_at=datetime.now(timezone.utc).isoformat(),
        quarantine_dir=settings.quarantine_dir.expanduser().resolve(),
        cache_dir=settings.cache_dir.expanduser().resolve(),
        tools=android_tool_report(),
        device=device,
    )
    (output_dir / "run_log.jsonl").write_text("", encoding="utf-8")
    agent_plan = DYNAMIC_AGENTS if mode == "dynamic" else STATIC_AGENTS
    for agent_cls in agent_plan:
        started = datetime.now(timezone.utc).isoformat()
        agent = agent_cls(context)
        _append_log(output_dir, {"event": "agent_started", "agent": agent.name, "timestamp": started})
        context = agent.run()
        _append_log(
            output_dir,
            {
                "event": "agent_completed",
                "agent": agent.name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    summary = {
        "schema_version": "1.0",
        "analysis_id": analysis_id,
        "status": "completed",
        "mode": mode,
        "output_dir": str(output_dir),
        "report_path": str(output_dir / "report.md"),
        "codex_prompt_path": str(output_dir / "codex_ingestion_prompt.md"),
        "qa_report_path": str(output_dir / "qa_report.json"),
        "package_name": context.data.get("manifest", {}).get("package_name"),
        "sha256": context.data.get("artifact", {}).get("sha256"),
        "dynamic_status": context.data.get("dynamic_session", {}).get("status") if mode == "dynamic" else None,
    }
    _record_analysis(summary, context)
    (output_dir / "analysis_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return summary


def _append_log(output_dir: Path, row: dict[str, Any]) -> None:
    with (output_dir / "run_log.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _record_analysis(summary: dict[str, Any], context: AgentContext) -> None:
    try:
        artifact_data = context.data.get("artifact", {})
        with session_scope() as session:
            artifact = Artifact(
                local_path=str(artifact_data.get("quarantined_path") or context.input_path),
                sha256=str(artifact_data.get("sha256") or ""),
                size_bytes=int(artifact_data.get("size_bytes") or 0),
                mime_type=artifact_data.get("mime_type"),
                package_name=summary.get("package_name"),
                version_name=context.data.get("manifest", {}).get("version_name"),
                version_code=context.data.get("manifest", {}).get("version_code"),
                provenance_json=json.dumps(artifact_data, ensure_ascii=False),
            )
            session.add(artifact)
            session.flush()
            analysis = Analysis(
                artifact_id=artifact.id,
                mode=str(summary.get("mode")),
                status=str(summary.get("status")),
                completed_at=datetime.now(timezone.utc),
                output_dir=str(summary.get("output_dir")),
                summary_json=json.dumps(summary, ensure_ascii=False),
            )
            session.add(analysis)
            session.flush()
            summary["db_artifact_id"] = artifact.id
            summary["db_analysis_id"] = analysis.id
    except Exception as exc:
        summary["db_index_error"] = str(exc)
