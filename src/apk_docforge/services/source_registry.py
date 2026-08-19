from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from apk_docforge.db.models import AppCandidate, Artifact, Source
from apk_docforge.db.session import session_scope


DEFAULT_SOURCES = [
    {
        "name": "F-Droid",
        "type": "fdroid",
        "base_url": "https://f-droid.org/repo/",
        "enabled": True,
        "policy_status": "ALLOWED",
        "auth_type": "none",
        "trust_level": "high",
        "notes": "Public open-source Android repository.",
    },
    {
        "name": "GitHub Releases",
        "type": "github",
        "base_url": "https://api.github.com/",
        "enabled": True,
        "policy_status": "ALLOWED",
        "auth_type": "none",
        "trust_level": "medium",
        "notes": "Public release assets. License/authorization must be reviewed.",
    },
    {
        "name": "Official URL Allowlist",
        "type": "official_url",
        "base_url": None,
        "enabled": True,
        "policy_status": "REQUIRES_ALLOWLIST",
        "auth_type": "none",
        "trust_level": "medium",
        "notes": "Allowed only when host is configured in APK_DOCFORGE_OFFICIAL_URL_ALLOWLIST.",
    },
    {
        "name": "Google Play Developer API",
        "type": "google_play_developer",
        "base_url": "https://androidpublisher.googleapis.com/",
        "enabled": False,
        "policy_status": "REQUIRES_EXPLICIT_AUTH",
        "auth_type": "service_account",
        "trust_level": "high_for_owned_apps",
        "notes": "Only for owned or explicitly authorized apps with credentials.",
    },
    {
        "name": "ADB Installed App Importer",
        "type": "adb",
        "base_url": None,
        "enabled": True,
        "policy_status": "ALLOWED_FOR_AUTHORIZED_DEVICE",
        "auth_type": "local_device",
        "trust_level": "local",
        "notes": "Imports APK paths from authorized test device via adb.",
    },
    {
        "name": "Manual Local File",
        "type": "local_file",
        "base_url": None,
        "enabled": True,
        "policy_status": "ALLOWED_WITH_DECLARED_AUTHORIZATION",
        "auth_type": "none",
        "trust_level": "local",
        "notes": "Local APK/APKS/XAPK provided by user.",
    },
    {
        "name": "Third-party APK Mirrors",
        "type": "third_party_mirror",
        "base_url": None,
        "enabled": False,
        "policy_status": "DISABLED_BY_POLICY",
        "auth_type": "none",
        "trust_level": "blocked",
        "notes": "Disabled by default to avoid unauthorized downloads.",
    },
]


def ensure_default_sources(session: Session) -> dict[str, Source]:
    existing = _dedupe_sources_by_type(session)
    for row in DEFAULT_SOURCES:
        source = existing.get(row["type"])
        if source is None:
            source = Source(**row)
            session.add(source)
            session.flush()
            existing[source.type] = source
    return existing


def list_sources() -> list[dict[str, Any]]:
    with session_scope() as session:
        ensure_default_sources(session)
        rows = session.scalars(select(Source).order_by(Source.type)).all()
        return [source_to_dict(row) for row in rows]


def upsert_source(payload: dict[str, Any]) -> dict[str, Any]:
    source_type = str(payload.get("type") or payload.get("name") or "").strip().lower()
    if not source_type:
        raise ValueError("Source `type` is required.")
    with session_scope() as session:
        ensure_default_sources(session)
        source = session.scalar(select(Source).where(Source.type == source_type))
        if source is None:
            source = Source(
                name=str(payload.get("name") or source_type),
                type=source_type,
                base_url=_optional_str(payload.get("base_url")),
                enabled=_coerce_bool(payload.get("enabled", True)),
                policy_status=str(payload.get("policy_status") or "UNKNOWN"),
                auth_type=str(payload.get("auth_type") or "none"),
                trust_level=str(payload.get("trust_level") or "unknown"),
                notes=_optional_str(payload.get("notes")),
            )
            session.add(source)
            session.flush()
        else:
            if "name" in payload:
                source.name = str(payload["name"])
            if "base_url" in payload:
                source.base_url = _optional_str(payload["base_url"])
            if "enabled" in payload:
                source.enabled = _coerce_bool(payload["enabled"])
            if "policy_status" in payload:
                source.policy_status = str(payload["policy_status"])
            if "auth_type" in payload:
                source.auth_type = str(payload["auth_type"])
            if "trust_level" in payload:
                source.trust_level = str(payload["trust_level"])
            if "notes" in payload:
                source.notes = _optional_str(payload["notes"])
            source.updated_at = datetime.now(timezone.utc)
        return source_to_dict(source)


def save_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    with session_scope() as session:
        sources = ensure_default_sources(session)
        saved: list[dict[str, Any]] = []
        for candidate in candidates:
            source_type = str(candidate.get("source") or "unknown").lower()
            source = sources.get(source_type)
            if source is None:
                source = Source(
                    name=source_type,
                    type=source_type,
                    base_url=None,
                    enabled=True,
                    policy_status=str(candidate.get("policy_status") or "UNKNOWN"),
                    auth_type="none",
                    trust_level="unknown",
                )
                session.add(source)
                session.flush()
                sources[source_type] = source
            existing = _find_existing_candidate(session, source, candidate)
            if existing is None:
                existing = AppCandidate(source_id=source.id)
                session.add(existing)
            _apply_candidate(existing, candidate)
            session.flush()
            row = candidate_to_dict(existing)
            row["id"] = existing.id
            row["external_id"] = candidate.get("id")
            saved.append(row)
        return saved


def get_candidate(candidate_id: str) -> dict[str, Any] | None:
    if not str(candidate_id).isdigit():
        return None
    with session_scope() as session:
        row = session.get(AppCandidate, int(candidate_id))
        if row is None:
            return None
        return candidate_to_dict(row)


def save_artifact_record(
    local_path: str,
    sha256: str,
    size_bytes: int,
    mime_type: str | None,
    provenance: dict[str, Any],
    candidate_id: int | None = None,
    source_id: int | None = None,
    package_name: str | None = None,
    version_name: str | None = None,
    version_code: str | None = None,
) -> dict[str, Any]:
    with session_scope() as session:
        artifact = Artifact(
            source_id=source_id,
            candidate_id=candidate_id,
            local_path=local_path,
            sha256=sha256,
            size_bytes=size_bytes,
            mime_type=mime_type,
            package_name=package_name,
            version_name=version_name,
            version_code=version_code,
            provenance_json=json.dumps(provenance, ensure_ascii=False),
        )
        session.add(artifact)
        session.flush()
        return artifact_to_dict(artifact)


def source_to_dict(source: Source) -> dict[str, Any]:
    return {
        "id": source.id,
        "name": source.name,
        "type": source.type,
        "base_url": source.base_url,
        "enabled": source.enabled,
        "policy_status": source.policy_status,
        "auth_type": source.auth_type,
        "trust_level": source.trust_level,
        "notes": source.notes,
        "created_at": source.created_at.isoformat() if source.created_at else None,
        "updated_at": source.updated_at.isoformat() if source.updated_at else None,
    }


def candidate_to_dict(candidate: AppCandidate) -> dict[str, Any]:
    return {
        "id": candidate.id,
        "source_id": candidate.source_id,
        "source": candidate.source.type if candidate.source else None,
        "package_name": candidate.package_name,
        "app_name": candidate.app_name,
        "developer": candidate.developer,
        "version_name": candidate.version_name,
        "version_code": candidate.version_code,
        "license": candidate.license,
        "source_url": candidate.source_url,
        "download_url": candidate.download_url,
        "checksum": candidate.checksum,
        "policy_status": candidate.policy_status,
        "discovered_at": candidate.discovered_at.isoformat() if candidate.discovered_at else None,
    }


def artifact_to_dict(artifact: Artifact) -> dict[str, Any]:
    return {
        "id": artifact.id,
        "source_id": artifact.source_id,
        "candidate_id": artifact.candidate_id,
        "local_path": artifact.local_path,
        "sha256": artifact.sha256,
        "size_bytes": artifact.size_bytes,
        "mime_type": artifact.mime_type,
        "package_name": artifact.package_name,
        "version_name": artifact.version_name,
        "version_code": artifact.version_code,
        "created_at": artifact.created_at.isoformat() if artifact.created_at else None,
    }


def _find_existing_candidate(
    session: Session, source: Source, candidate: dict[str, Any]
) -> AppCandidate | None:
    download_url = candidate.get("download_url")
    package_name = candidate.get("package_name")
    version_code = candidate.get("version_code")
    source_url = candidate.get("source_url")
    stmt = select(AppCandidate).where(AppCandidate.source_id == source.id)
    if download_url:
        found = session.scalar(stmt.where(AppCandidate.download_url == str(download_url)))
        if found:
            return found
    if package_name:
        found = session.scalar(
            stmt.where(
                AppCandidate.package_name == str(package_name),
                AppCandidate.version_code == (str(version_code) if version_code is not None else None),
            )
        )
        if found:
            return found
    if source_url:
        return session.scalar(stmt.where(AppCandidate.source_url == str(source_url)))
    return None


def _apply_candidate(model: AppCandidate, candidate: dict[str, Any]) -> None:
    model.package_name = _optional_str(candidate.get("package_name"))
    model.app_name = _optional_str(candidate.get("app_name"))
    model.developer = _optional_str(candidate.get("developer"))
    model.version_name = _optional_str(candidate.get("version_name"))
    model.version_code = _optional_str(candidate.get("version_code"))
    model.license = _optional_str(candidate.get("license"))
    model.source_url = _optional_str(candidate.get("source_url"))
    model.download_url = _optional_str(candidate.get("download_url"))
    model.checksum = _optional_str(candidate.get("checksum"))
    model.policy_status = str(candidate.get("policy_status") or "UNKNOWN")
    discovered_at = candidate.get("discovered_at")
    if isinstance(discovered_at, str):
        try:
            model.discovered_at = datetime.fromisoformat(discovered_at)
        except ValueError:
            model.discovered_at = datetime.now(timezone.utc)
    else:
        model.discovered_at = datetime.now(timezone.utc)


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    return bool(value)


def _dedupe_sources_by_type(session: Session) -> dict[str, Source]:
    grouped: dict[str, list[Source]] = {}
    for source in session.scalars(select(Source).order_by(Source.id)).all():
        grouped.setdefault(source.type, []).append(source)
    keepers: dict[str, Source] = {}
    for source_type, rows in grouped.items():
        keeper = rows[0]
        keepers[source_type] = keeper
        for duplicate in rows[1:]:
            for candidate in session.scalars(
                select(AppCandidate).where(AppCandidate.source_id == duplicate.id)
            ).all():
                candidate.source_id = keeper.id
            for artifact in session.scalars(
                select(Artifact).where(Artifact.source_id == duplicate.id)
            ).all():
                artifact.source_id = keeper.id
            session.delete(duplicate)
        if len(rows) > 1:
            session.flush()
    return keepers
