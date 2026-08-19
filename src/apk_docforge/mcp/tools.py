from __future__ import annotations

from pathlib import Path
from typing import Any

from apk_docforge.pipeline import run_analysis
from apk_docforge.services.analysis_store import (
    get_analysis_summary,
    get_codex_prompt as get_codex_prompt_text,
    get_report as get_report_text,
    list_features as list_analysis_features,
    list_findings as list_analysis_findings,
    list_screens as list_analysis_screens,
)
from apk_docforge.services.discovery import search_apps as search_apps_service
from apk_docforge.services.downloader import download_candidate


def search_apps(query: str, sources: list[str] | None = None, limit: int = 10) -> dict[str, Any]:
    return search_apps_service(query, sources or ["fdroid", "github"], limit=limit, persist=True)


def download_app(candidate_id: str, out: str = "downloads") -> dict[str, Any]:
    return download_candidate(candidate_id, out=Path(out))


def analyze_artifact(
    path: str,
    out: str | None = None,
    mode: str = "static",
    device: str | None = None,
) -> dict[str, Any]:
    return run_analysis(Path(path), out=Path(out) if out else None, mode=mode, device=device)


def get_analysis(analysis_id: str) -> dict[str, Any]:
    return get_analysis_summary(analysis_id)


def get_report(analysis_id: str) -> str:
    return get_report_text(analysis_id)


def get_codex_prompt(analysis_id: str) -> str:
    return get_codex_prompt_text(analysis_id)


def list_findings(analysis_id: str) -> dict[str, Any]:
    return list_analysis_findings(analysis_id)


def list_features(analysis_id: str) -> dict[str, Any]:
    return list_analysis_features(analysis_id)


def list_screens(analysis_id: str) -> dict[str, Any]:
    return list_analysis_screens(analysis_id)
