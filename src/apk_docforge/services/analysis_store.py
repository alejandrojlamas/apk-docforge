from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select

from apk_docforge.config import get_settings
from apk_docforge.db.models import Analysis
from apk_docforge.db.session import session_scope


class AnalysisNotFoundError(FileNotFoundError):
    pass


SAFE_ANALYSIS_LOOKUP_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class AnalysisLocation:
    analysis_id: str
    output_dir: Path
    summary: dict[str, Any]


def list_analyses(limit: int = 100) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    with session_scope() as session:
        analyses = session.scalars(select(Analysis).order_by(Analysis.started_at.desc())).all()
        for analysis in analyses:
            summary = _loads_json(analysis.summary_json)
            analysis_id = str(summary.get("analysis_id") or analysis.id)
            if analysis_id in seen:
                continue
            seen.add(analysis_id)
            rows.append(
                {
                    **summary,
                    "db_analysis_id": analysis.id,
                    "db_artifact_id": analysis.artifact_id,
                    "mode": summary.get("mode") or analysis.mode,
                    "status": summary.get("status") or analysis.status,
                    "output_dir": summary.get("output_dir") or analysis.output_dir,
                }
            )
            if len(rows) >= limit:
                return rows

    output_root = get_settings().output_root
    for summary_path in sorted(output_root.glob("*/analysis_summary.json"), reverse=True):
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        analysis_id = str(summary.get("analysis_id") or summary_path.parent.name)
        if analysis_id in seen:
            continue
        seen.add(analysis_id)
        rows.append(summary)
        if len(rows) >= limit:
            break
    return rows


def locate_analysis(analysis_id: str) -> AnalysisLocation:
    requested = str(analysis_id).strip()
    if not requested:
        raise AnalysisNotFoundError("analysis_id is required")
    if not SAFE_ANALYSIS_LOOKUP_RE.fullmatch(requested):
        raise AnalysisNotFoundError("analysis_id contains unsupported characters")

    filesystem_match = _locate_from_filesystem(requested)
    if filesystem_match:
        return filesystem_match

    db_match = _locate_from_db(requested)
    if db_match:
        return db_match

    raise AnalysisNotFoundError(f"Analysis not found: {analysis_id}")


def get_analysis_summary(analysis_id: str) -> dict[str, Any]:
    location = locate_analysis(analysis_id)
    return {**location.summary, "output_dir": str(location.output_dir)}


def get_report(analysis_id: str) -> str:
    return read_text_artifact(analysis_id, "report.md")


def get_codex_prompt(analysis_id: str) -> str:
    return read_text_artifact(analysis_id, "codex_ingestion_prompt.md")


def list_findings(analysis_id: str) -> dict[str, Any]:
    return read_json_artifact(analysis_id, "security_findings.json")


def list_features(analysis_id: str) -> dict[str, Any]:
    return read_json_artifact(analysis_id, "features.json")


def list_screens(analysis_id: str) -> dict[str, Any]:
    return read_json_artifact(analysis_id, "static_screens.json")


def read_text_artifact(analysis_id: str, filename: str) -> str:
    location = locate_analysis(analysis_id)
    path = _safe_artifact_path(location.output_dir, filename)
    if not path.exists():
        raise AnalysisNotFoundError(f"Artifact not found for analysis {analysis_id}: {filename}")
    return path.read_text(encoding="utf-8")


def read_json_artifact(analysis_id: str, filename: str) -> dict[str, Any]:
    return json.loads(read_text_artifact(analysis_id, filename))


def _locate_from_filesystem(analysis_id: str) -> AnalysisLocation | None:
    output_root = get_settings().output_root
    candidates = [output_root / analysis_id / "analysis_summary.json"]
    candidates.extend(output_root.glob(f"*{analysis_id}*/analysis_summary.json"))
    for summary_path in candidates:
        if not summary_path.exists():
            continue
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if analysis_id in {summary.get("analysis_id"), summary_path.parent.name} or analysis_id in summary_path.parent.name:
            output_dir = Path(summary.get("output_dir") or summary_path.parent).expanduser().resolve()
            return AnalysisLocation(str(summary.get("analysis_id") or analysis_id), output_dir, summary)
    return None


def _locate_from_db(analysis_id: str) -> AnalysisLocation | None:
    with session_scope() as session:
        if analysis_id.isdigit():
            row = session.get(Analysis, int(analysis_id))
            if row:
                return _location_from_db_row(row, analysis_id)
        for row in session.scalars(select(Analysis).order_by(Analysis.started_at.desc())).all():
            summary = _loads_json(row.summary_json)
            summary_id = str(summary.get("analysis_id") or "")
            if analysis_id == summary_id or analysis_id in summary_id:
                return _location_from_db_row(row, analysis_id)
    return None


def _location_from_db_row(row: Analysis, fallback_id: str) -> AnalysisLocation:
    summary = _loads_json(row.summary_json)
    analysis_id = str(summary.get("analysis_id") or fallback_id)
    output_dir = Path(summary.get("output_dir") or row.output_dir).expanduser().resolve()
    summary_path = output_dir / "analysis_summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    return AnalysisLocation(analysis_id, output_dir, summary)


def _safe_artifact_path(output_dir: Path, filename: str) -> Path:
    if "/" in filename or "\\" in filename or filename.startswith("."):
        raise ValueError("Only top-level analysis artifact filenames are allowed")
    path = (output_dir / filename).resolve()
    if output_dir.resolve() not in path.parents and path != output_dir.resolve():
        raise ValueError("Artifact path escaped analysis output directory")
    return path


def _loads_json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}
