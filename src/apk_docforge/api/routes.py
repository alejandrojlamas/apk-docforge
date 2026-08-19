from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field

from apk_docforge.adapters.adb_importer import ADBImporter
from apk_docforge.config import get_settings
from apk_docforge.pipeline import run_analysis
from apk_docforge.services.analysis_store import (
    AnalysisNotFoundError,
    get_analysis_summary,
    get_codex_prompt as get_codex_prompt_text,
    get_report as get_report_text,
    list_analyses,
    list_features as list_analysis_features,
    list_findings as list_analysis_findings,
    list_screens as list_analysis_screens,
)
from apk_docforge.services.discovery import search_apps
from apk_docforge.services.downloader import download_candidate
from apk_docforge.services.settings_store import public_settings, update_local_settings
from apk_docforge.services.source_registry import list_sources, upsert_source
from apk_docforge.tools.android_sdk import android_tool_report
from apk_docforge.tools.archive import ensure_dir, guess_mime_type
from apk_docforge.tools.hashing import file_size, sha256_file


router = APIRouter(prefix="/api")
UPLOAD_SUFFIXES = {".apk", ".apks", ".xapk"}


class SearchRequest(BaseModel):
    query: str
    sources: list[str] = Field(default_factory=lambda: ["fdroid", "github"])
    limit: int = 10


class DownloadRequest(BaseModel):
    candidate_id: str
    out: str = "downloads"


class AnalyzeRequest(BaseModel):
    path: str
    out: str | None = None
    mode: str = "static"
    device: str | None = None


class ImportDeviceRequest(BaseModel):
    package: str
    out: str = "downloads"
    device: str | None = None


class SettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    documentation_provider: str | None = None
    deepseek_api_key: str | None = None
    clear_deepseek_api_key: bool = False
    official_url_allowlist: str | None = None
    google_play_credentials_json: str | None = None
    allow_dynamic: bool | None = None


@router.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "tools": android_tool_report()}


@router.post("/search")
def search(request: SearchRequest) -> dict[str, Any]:
    return search_apps(request.query, request.sources, limit=request.limit, persist=True)


@router.post("/download")
def download(request: DownloadRequest) -> dict[str, Any]:
    result = download_candidate(request.candidate_id, out=Path(request.out))
    if result.get("status") != "completed":
        raise HTTPException(status_code=400, detail=result)
    return result


@router.post("/analyze")
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    try:
        return run_analysis(
            Path(request.path),
            out=Path(request.out) if request.out else None,
            mode=request.mode,
            device=request.device,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/upload")
def upload_artifact(file: UploadFile = File(...)) -> dict[str, Any]:
    filename = _safe_upload_name(file.filename or "uploaded.apk")
    suffix = Path(filename).suffix.lower()
    if suffix not in UPLOAD_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {suffix or 'no extension'}. Use APK, APKS, or XAPK.",
        )
    settings = get_settings()
    if file.size is not None and file.size > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Artifact exceeds the configured upload size limit.")
    upload_dir = ensure_dir(settings.quarantine_dir.expanduser().resolve() / "uploads")
    target = upload_dir / (
        f"upload-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid4().hex[:8]}-{filename}"
    )
    try:
        _stream_upload_to_path(file, target, settings.max_upload_bytes)
    except ValueError as exc:
        target.unlink(missing_ok=True)
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    digest = sha256_file(target)
    return {
        "schema_version": "1.0",
        "status": "uploaded",
        "local_path": str(target),
        "filename": filename,
        "sha256": digest,
        "size_bytes": file_size(target),
        "mime_type": guess_mime_type(target),
        "quarantine": True,
        "message": "File saved to local quarantine and ready for static analysis.",
    }


@router.post("/import-device")
def import_device(request: ImportDeviceRequest) -> dict[str, Any]:
    result = ADBImporter().import_package(request.package, Path(request.out), device=request.device)
    if result.get("status") != "completed":
        raise HTTPException(status_code=400, detail=result)
    return result


@router.get("/analyses")
def get_analyses(limit: int = 100) -> dict[str, Any]:
    return {"analyses": list_analyses(limit=limit)}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str) -> dict[str, Any]:
    try:
        return get_analysis_summary(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/analyses/{analysis_id}/report")
def get_report(analysis_id: str) -> dict[str, str]:
    try:
        return {"report": get_report_text(analysis_id)}
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/analyses/{analysis_id}/codex-prompt")
def get_codex_prompt(analysis_id: str) -> dict[str, str]:
    try:
        return {"codex_prompt": get_codex_prompt_text(analysis_id)}
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/analyses/{analysis_id}/findings")
def get_findings(analysis_id: str) -> dict[str, Any]:
    try:
        return list_analysis_findings(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/analyses/{analysis_id}/features")
def get_features(analysis_id: str) -> dict[str, Any]:
    try:
        return list_analysis_features(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/analyses/{analysis_id}/screens")
def get_screens(analysis_id: str) -> dict[str, Any]:
    try:
        return list_analysis_screens(analysis_id)
    except AnalysisNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/sources")
def get_sources() -> dict[str, Any]:
    return {"sources": list_sources()}


@router.post("/sources")
def post_sources(payload: dict[str, Any]) -> dict[str, Any]:
    return {"status": "saved", "source": upsert_source(payload)}


@router.get("/settings")
def get_settings_public() -> dict[str, Any]:
    return public_settings()


@router.post("/settings")
def post_settings(request: SettingsRequest) -> dict[str, Any]:
    try:
        return update_local_settings(request.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _safe_upload_name(filename: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {".", "-", "_"} else "-" for ch in filename)
    cleaned = cleaned.strip(".-_")
    return cleaned or "uploaded.apk"


def _stream_upload_to_path(file: UploadFile, target: Path, max_bytes: int) -> None:
    written = 0
    with target.open("xb") as handle:
        while chunk := file.file.read(64 * 1024):
            written += len(chunk)
            if written > max_bytes:
                raise ValueError("Artifact exceeds the configured upload size limit.")
            handle.write(chunk)
