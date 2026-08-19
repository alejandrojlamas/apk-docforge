from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlparse
from uuid import uuid4

import httpx

from apk_docforge import USER_AGENT
from apk_docforge.config import get_settings
from apk_docforge.services.source_registry import get_candidate, save_artifact_record
from apk_docforge.tools.archive import ensure_dir, guess_mime_type
from apk_docforge.tools.hashing import checksum_matches, file_size, sha256_file
from apk_docforge.tools.policy import PolicyEngine


ALLOWED_DOWNLOAD_SUFFIXES = {".apk", ".apks", ".xapk"}
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
PROVENANCE_HEADERS = {
    "etag",
    "last-modified",
    "content-length",
    "content-type",
    "x-checksum-sha256",
    "digest",
}


class _DownloadRejected(Exception):
    def __init__(
        self,
        reason: str,
        *,
        status: str,
        final_url: str,
        redirect_chain: list[dict[str, Any]],
        policy_decision: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.final_url = final_url
        self.redirect_chain = redirect_chain
        self.policy_decision = policy_decision


def download_candidate(candidate_id: str, out: Path | None = None) -> dict[str, Any]:
    candidate = get_candidate(candidate_id)
    if candidate is None:
        return {
            "schema_version": "1.0",
            "status": "blocked",
            "reason": "Candidate id was not found in the local SQLite index. Run `apk-docforge search` first and use the numeric candidate id.",
        }
    return download_candidate_dict(candidate, out=out)


def download_candidate_dict(candidate: dict[str, Any], out: Path | None = None) -> dict[str, Any]:
    settings = get_settings()
    out_dir = ensure_dir((out or Path("downloads")).expanduser().resolve())
    quarantine_dir = ensure_dir(settings.quarantine_dir.expanduser().resolve())
    cache_dir = ensure_dir(settings.cache_dir.expanduser().resolve() / "downloads")
    url = str(candidate.get("download_url") or "")
    if not url:
        return {
            "schema_version": "1.0",
            "status": "blocked",
            "candidate": candidate,
            "reason": "Candidate has no download_url. GitHub repository candidates without APK release assets are not downloadable.",
        }
    suffix = Path(unquote(urlparse(url).path)).suffix.lower()
    if suffix not in ALLOWED_DOWNLOAD_SUFFIXES:
        return {
            "schema_version": "1.0",
            "status": "blocked",
            "candidate": candidate,
            "reason": f"Unsupported artifact suffix `{suffix or 'none'}`. Allowed: {', '.join(sorted(ALLOWED_DOWNLOAD_SUFFIXES))}.",
        }
    filename = _filename_from_url(url)

    decision = PolicyEngine().validate_source(str(candidate.get("source") or ""), url).to_json()
    if not decision["allowed"]:
        return {
            "schema_version": "1.0",
            "status": "blocked",
            "candidate": candidate,
            "policy_decision": decision,
            "reason": decision["reason"],
        }

    expected_from_candidate = _normalized_sha256(candidate.get("checksum"))
    if expected_from_candidate:
        cached = cache_dir / f"{expected_from_candidate}{suffix}"
        if cached.exists() and sha256_file(cached) == expected_from_candidate:
            if file_size(cached) > settings.max_download_bytes:
                return {
                    "schema_version": "1.0",
                    "status": "blocked_size_limit",
                    "candidate": candidate,
                    "policy_decision": decision,
                    "reason": "Cached artifact exceeds the configured download size limit.",
                }
            return _complete_from_cached_candidate(
                candidate=candidate,
                cached=cached,
                out_dir=out_dir,
                filename=filename,
                url=url,
                decision=decision,
            )

    started_at = datetime.now(timezone.utc).isoformat()
    quarantine_path = quarantine_dir / (
        f"download-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid4().hex[:8]}-{filename}"
    )
    try:
        stream_result = _stream_download_to_path(
            url=url,
            source_type=str(candidate.get("source") or ""),
            target=quarantine_path,
            max_bytes=settings.max_download_bytes,
            max_redirects=settings.max_download_redirects,
        )
    except _DownloadRejected as exc:
        quarantine_path.unlink(missing_ok=True)
        return {
            "schema_version": "1.0",
            "status": exc.status,
            "candidate": candidate,
            "policy_decision": decision,
            "final_policy_decision": exc.policy_decision,
            "final_url": exc.final_url,
            "redirect_chain": exc.redirect_chain,
            "reason": exc.reason,
        }
    headers = stream_result["headers"]
    final_url = str(stream_result["final_url"])
    redirect_chain = stream_result["redirect_chain"]
    final_decision = stream_result["final_policy_decision"]

    digest = sha256_file(quarantine_path)
    expected_checksum = _expected_checksum(candidate, headers)
    checksum_result = checksum_matches(quarantine_path, expected_checksum)
    provenance = _provenance(
        candidate=candidate,
        url=url,
        quarantine_path=quarantine_path,
        final_path=None,
        headers=headers,
        started_at=started_at,
        sha256=digest,
        expected_checksum=expected_checksum,
        checksum_result=checksum_result,
        decision=decision,
        final_url=final_url,
        redirect_chain=redirect_chain,
        final_decision=final_decision,
    )
    if checksum_result is False:
        provenance["status"] = "blocked_checksum_mismatch"
        provenance["reason"] = "Source-provided checksum did not match downloaded quarantine artifact."
        _write_provenance(quarantine_path.with_suffix(quarantine_path.suffix + ".provenance.json"), provenance)
        return provenance

    cache_path = cache_dir / f"{digest}{suffix}"
    if not cache_path.exists():
        shutil.copy2(quarantine_path, cache_path)
    final_path = _non_clobber_path(out_dir / filename)
    shutil.copy2(quarantine_path, final_path)
    provenance = _provenance(
        candidate=candidate,
        url=url,
        quarantine_path=quarantine_path,
        final_path=final_path,
        headers=headers,
        started_at=started_at,
        sha256=digest,
        expected_checksum=expected_checksum,
        checksum_result=checksum_result,
        decision=decision,
        final_url=final_url,
        redirect_chain=redirect_chain,
        final_decision=final_decision,
    )
    artifact = save_artifact_record(
        local_path=str(final_path),
        sha256=digest,
        size_bytes=file_size(final_path),
        mime_type=guess_mime_type(final_path),
        provenance=provenance,
        candidate_id=int(candidate["id"]) if str(candidate.get("id", "")).isdigit() else None,
        source_id=int(candidate["source_id"]) if str(candidate.get("source_id", "")).isdigit() else None,
        package_name=candidate.get("package_name"),
        version_name=candidate.get("version_name"),
        version_code=candidate.get("version_code"),
    )
    provenance["artifact_id"] = artifact["id"]
    provenance["artifact_record"] = artifact
    provenance["cache_path"] = str(cache_path)
    _write_provenance(final_path.with_suffix(final_path.suffix + ".provenance.json"), provenance)
    return provenance


def _complete_from_cached_candidate(
    *,
    candidate: dict[str, Any],
    cached: Path,
    out_dir: Path,
    filename: str,
    url: str,
    decision: dict[str, Any],
) -> dict[str, Any]:
    digest = sha256_file(cached)
    final_path = _non_clobber_path(out_dir / filename)
    shutil.copy2(cached, final_path)
    started_at = datetime.now(timezone.utc).isoformat()
    provenance = {
        "schema_version": "1.0",
        "status": "completed",
        "cache_hit": True,
        "source_url": candidate.get("source_url"),
        "download_url": url,
        "final_url": url,
        "redirect_chain": [],
        "downloaded_at": None,
        "cache_path": str(cached),
        "quarantine_path": None,
        "local_path": str(final_path),
        "sha256": digest,
        "size_bytes": file_size(final_path),
        "mime_type": guess_mime_type(final_path),
        "headers": {},
        "checksum_expected": candidate.get("checksum"),
        "checksum_matches": True,
        "candidate": candidate,
        "policy_decision": decision,
        "final_policy_decision": decision,
        "chain_of_custody": [
            {
                "event": "copied_from_local_cache_to_downloads",
                "timestamp": started_at,
                "path": str(final_path),
                "sha256": digest,
            }
        ],
    }
    artifact = save_artifact_record(
        local_path=str(final_path),
        sha256=digest,
        size_bytes=file_size(final_path),
        mime_type=guess_mime_type(final_path),
        provenance=provenance,
        candidate_id=int(candidate["id"]) if str(candidate.get("id", "")).isdigit() else None,
        source_id=int(candidate["source_id"]) if str(candidate.get("source_id", "")).isdigit() else None,
        package_name=candidate.get("package_name"),
        version_name=candidate.get("version_name"),
        version_code=candidate.get("version_code"),
    )
    provenance["artifact_id"] = artifact["id"]
    provenance["artifact_record"] = artifact
    _write_provenance(final_path.with_suffix(final_path.suffix + ".provenance.json"), provenance)
    return provenance


def _provenance(
    *,
    candidate: dict[str, Any],
    url: str,
    quarantine_path: Path,
    final_path: Path | None,
    headers: dict[str, str],
    started_at: str,
    sha256: str,
    expected_checksum: str | None,
    checksum_result: bool | None,
    decision: dict[str, Any],
    final_url: str,
    redirect_chain: list[dict[str, Any]],
    final_decision: dict[str, Any],
) -> dict[str, Any]:
    chain = [
        {
            "event": "download_redirect_validated",
            "timestamp": started_at,
            "from_url": redirect["from_url"],
            "to_url": redirect["to_url"],
            "status_code": redirect["status_code"],
        }
        for redirect in redirect_chain
    ]
    chain.append(
        {
            "event": "downloaded_to_quarantine",
            "timestamp": started_at,
            "path": str(quarantine_path),
            "sha256": sha256,
        }
    )
    if final_path is not None:
        chain.append(
            {
                "event": "copied_from_quarantine_to_downloads",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "path": str(final_path),
                "sha256": sha256,
            }
        )
    return {
        "schema_version": "1.0",
        "status": "completed",
        "source_url": candidate.get("source_url"),
        "download_url": url,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "downloaded_at": started_at,
        "quarantine_path": str(quarantine_path),
        "local_path": str(final_path) if final_path else None,
        "sha256": sha256,
        "size_bytes": file_size(quarantine_path),
        "mime_type": guess_mime_type(quarantine_path),
        "headers": headers,
        "checksum_expected": expected_checksum,
        "checksum_matches": checksum_result,
        "candidate": candidate,
        "policy_decision": decision,
        "final_policy_decision": final_decision,
        "chain_of_custody": chain,
    }


def _stream_download_to_path(
    *,
    url: str,
    source_type: str,
    target: Path,
    max_bytes: int,
    max_redirects: int,
) -> dict[str, Any]:
    policy = PolicyEngine()
    current_url = url
    redirect_chain: list[dict[str, Any]] = []
    request_headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}

    with httpx.Client(timeout=120, follow_redirects=False) as client:
        while True:
            request_decision = policy.validate_source(source_type, current_url).to_json()
            if not request_decision["allowed"]:
                raise _DownloadRejected(
                    str(request_decision["reason"]),
                    status="blocked_policy",
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    policy_decision=request_decision,
                )

            with client.stream("GET", current_url, headers=request_headers) as response:
                response_url = str(response.url)
                response_decision = policy.validate_source(source_type, response_url).to_json()
                if not response_decision["allowed"]:
                    raise _DownloadRejected(
                        str(response_decision["reason"]),
                        status="blocked_policy",
                        final_url=response_url,
                        redirect_chain=redirect_chain,
                        policy_decision=response_decision,
                    )

                if response.status_code in REDIRECT_STATUS_CODES:
                    location = response.headers.get("location")
                    if not location:
                        raise _DownloadRejected(
                            "Redirect response did not include a Location header.",
                            status="blocked_redirect",
                            final_url=response_url,
                            redirect_chain=redirect_chain,
                            policy_decision=response_decision,
                        )
                    if len(redirect_chain) >= max_redirects:
                        raise _DownloadRejected(
                            "Download exceeded the configured redirect limit.",
                            status="blocked_redirect",
                            final_url=response_url,
                            redirect_chain=redirect_chain,
                            policy_decision=response_decision,
                        )
                    next_url = urljoin(response_url, location)
                    next_decision = policy.validate_source(source_type, next_url).to_json()
                    redirect_chain.append(
                        {
                            "status_code": response.status_code,
                            "from_url": response_url,
                            "to_url": next_url,
                            "policy_decision": next_decision,
                        }
                    )
                    if not next_decision["allowed"]:
                        raise _DownloadRejected(
                            str(next_decision["reason"]),
                            status="blocked_policy",
                            final_url=next_url,
                            redirect_chain=redirect_chain,
                            policy_decision=next_decision,
                        )
                    current_url = next_url
                    continue

                response.raise_for_status()
                try:
                    _validate_download_content_length(response.headers.get("content-length"), max_bytes)
                except ValueError as exc:
                    raise _DownloadRejected(
                        str(exc),
                        status="blocked_size_limit",
                        final_url=response_url,
                        redirect_chain=redirect_chain,
                        policy_decision=response_decision,
                    ) from exc
                headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower() in PROVENANCE_HEADERS
                }
                written = 0
                try:
                    with target.open("xb") as handle:
                        for chunk in response.iter_bytes(chunk_size=64 * 1024):
                            written += len(chunk)
                            if written > max_bytes:
                                raise _DownloadRejected(
                                    "Downloaded artifact exceeds the configured size limit.",
                                    status="blocked_size_limit",
                                    final_url=response_url,
                                    redirect_chain=redirect_chain,
                                    policy_decision=response_decision,
                                )
                            handle.write(chunk)
                except Exception:
                    target.unlink(missing_ok=True)
                    raise
                return {
                    "headers": headers,
                    "final_url": response_url,
                    "redirect_chain": redirect_chain,
                    "final_policy_decision": response_decision,
                }


def _validate_download_content_length(value: str | None, max_bytes: int) -> None:
    if value is None:
        return
    try:
        declared_length = int(value)
    except ValueError as exc:
        raise ValueError("Download returned an invalid Content-Length header.") from exc
    if declared_length < 0:
        raise ValueError("Download returned an invalid Content-Length header.")
    if declared_length > max_bytes:
        raise ValueError("Download Content-Length exceeds the configured size limit.")


def _expected_checksum(candidate: dict[str, Any], headers: dict[str, str]) -> str | None:
    value = candidate.get("checksum")
    if value:
        return str(value)
    for key in ["x-checksum-sha256", "digest"]:
        header = headers.get(key) or headers.get(key.title())
        if header and "sha-256=" not in header.lower():
            return header
    return None


def _filename_from_url(url: str) -> str:
    name = Path(unquote(urlparse(url).path)).name
    return name or "download.apk"


def _non_clobber_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for index in range(1, 1000):
        candidate = path.with_name(f"{stem}-{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"Could not find available output filename for {path}")


def _write_provenance(path: Path, provenance: dict[str, Any]) -> None:
    path.write_text(json.dumps(provenance, indent=2, ensure_ascii=False), encoding="utf-8")


def _normalized_sha256(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip().lower().replace("sha256:", "")
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return text
    return None
