from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class EvidenceRef(BaseModel):
    path: str | None = None
    line_number: int | None = None
    class_name: str | None = None
    method_name: str | None = None
    screenshot_path: str | None = None
    uiautomator_node_id: str | None = None
    manifest_path: str | None = None
    tool_output: str | None = None
    kind: str = "file"
    description: str | None = None


class AgentArtifact(BaseModel):
    schema_version: str = "1.0"
    agent: str
    status: str = "completed"
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


@dataclass
class AgentContext:
    input_path: Path
    output_dir: Path
    mode: str
    analysis_id: str
    analysis_started_at: str
    quarantine_dir: Path
    cache_dir: Path
    tools: dict[str, dict[str, str | bool]]
    device: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def artifacts_dir(self) -> Path:
        return self.output_dir / "artifacts"

    @property
    def docs_dir(self) -> Path:
        return self.output_dir / "docs"


class BaseAgent:
    name = "BaseAgent"
    output_files: tuple[str, ...] = ()

    def __init__(self, context: AgentContext):
        self.context = context

    def run(self) -> AgentContext:
        raise NotImplementedError

    def path(self, relative: str) -> Path:
        return self.context.output_dir / relative

    def write_json(self, relative: str, payload: dict[str, Any]) -> Path:
        path = self.path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(json_safe(payload), indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def read_json(self, relative: str, default: Any = None) -> Any:
        path = self.path(relative)
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def artifact(
        self,
        data: dict[str, Any],
        status: str = "completed",
        evidence_refs: list[EvidenceRef | dict[str, Any]] | None = None,
        warnings: list[str] | None = None,
    ) -> dict[str, Any]:
        refs: list[EvidenceRef] = [
            ref if isinstance(ref, EvidenceRef) else EvidenceRef.model_validate(ref)
            for ref in evidence_refs or []
        ]
        artifact = AgentArtifact(
            agent=self.name,
            status=status,
            data=data,
            evidence_refs=refs,
            warnings=warnings or [],
        )
        return artifact.model_dump(mode="json", exclude_none=True)

    def evidence(
        self,
        path: str | Path | None = None,
        *,
        line_number: int | None = None,
        class_name: str | None = None,
        method_name: str | None = None,
        screenshot_path: str | Path | None = None,
        uiautomator_node_id: str | None = None,
        manifest_path: str | Path | None = None,
        tool_output: str | None = None,
        kind: str = "file",
        description: str | None = None,
    ) -> dict[str, Any]:
        ref = EvidenceRef(
            path=str(path) if path is not None else None,
            line_number=line_number,
            class_name=class_name,
            method_name=method_name,
            screenshot_path=str(screenshot_path) if screenshot_path is not None else None,
            uiautomator_node_id=uiautomator_node_id,
            manifest_path=str(manifest_path) if manifest_path is not None else None,
            tool_output=tool_output,
            kind=kind,
            description=description,
        )
        return ref.model_dump(mode="json", exclude_none=True)


def json_safe(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [json_safe(item) for item in value]
    return value
