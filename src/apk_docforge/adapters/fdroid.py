from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from apk_docforge.adapters.base import AdapterSearchResult
from apk_docforge.tools.policy import PolicyEngine


FDROID_INDEX_URL = "https://f-droid.org/repo/index-v2.json"


class FDroidAdapter:
    source_name = "fdroid"

    def __init__(self, index_url: str = FDROID_INDEX_URL):
        self.index_url = index_url

    def search(self, query: str, limit: int = 20) -> AdapterSearchResult:
        decision = PolicyEngine().validate_source("fdroid").to_json()
        if not decision["allowed"]:
            return AdapterSearchResult(self.source_name, [], decision)
        try:
            response = httpx.get(self.index_url, timeout=30)
            response.raise_for_status()
            index = response.json()
        except Exception as exc:
            return AdapterSearchResult(self.source_name, [], decision, [str(exc)])
        return AdapterSearchResult(
            self.source_name,
            self._candidates(index, query, limit),
            decision,
        )

    def package_metadata(self, package_name: str) -> dict[str, Any] | None:
        decision = PolicyEngine().validate_source("fdroid").to_json()
        if not decision["allowed"]:
            return None
        response = httpx.get(self.index_url, timeout=30)
        response.raise_for_status()
        index = response.json()
        package_meta = index.get("packages", {}).get(package_name)
        if not isinstance(package_meta, dict):
            return None
        return self._metadata_for_package(package_name, package_meta, index.get("repo", {}))

    def _candidates(self, index: dict[str, Any], query: str, limit: int) -> list[dict[str, Any]]:
        query_l = query.lower()
        packages = index.get("packages", {})
        candidates: list[dict[str, Any]] = []
        for package_name, package_meta in packages.items():
            if not isinstance(package_meta, dict):
                continue
            metadata = self._metadata_for_package(package_name, package_meta, index.get("repo", {}))
            app_name = metadata.get("app_name") or package_name
            summary = metadata.get("summary") or ""
            if (
                query_l not in package_name.lower()
                and query_l not in app_name.lower()
                and query_l not in summary.lower()
            ):
                continue
            versions = package_meta.get("versions", {})
            latest = self._latest_version(versions)
            file_meta = latest.get("file", {}) if latest else {}
            apk_name = str(file_meta.get("name") or "").lstrip("/")
            candidates.append(
                {
                    "id": f"fdroid:{package_name}",
                    "source": self.source_name,
                    "source_id": package_name,
                    "package_name": package_name,
                    "app_name": app_name,
                    "summary": summary,
                    "description": metadata.get("description"),
                    "categories": metadata.get("categories", []),
                    "developer": metadata.get("developer"),
                    "version_name": latest.get("manifest", {}).get("versionName") if latest else None,
                    "version_code": latest.get("manifest", {}).get("versionCode") if latest else None,
                    "license": metadata.get("license"),
                    "source_url": metadata.get("website") or metadata.get("source_code"),
                    "download_url": f"https://f-droid.org/repo/{apk_name}" if apk_name else None,
                    "checksum": file_meta.get("sha256"),
                    "policy_status": "ALLOWED",
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                    "metadata_source": self.index_url,
                    "package_page_url": metadata.get("package_page_url"),
                    "source_code_url": metadata.get("source_code"),
                    "issue_tracker_url": metadata.get("issue_tracker"),
                }
            )
            if len(candidates) >= limit:
                break
        return candidates

    def _metadata_for_package(
        self, package_name: str, package_meta: dict[str, Any], repo_meta: dict[str, Any]
    ) -> dict[str, Any]:
        meta = package_meta.get("metadata", {})
        if not isinstance(meta, dict):
            meta = {}
        name = _localized_value(meta.get("name")) or _legacy_localized_value(meta, "name") or package_name
        summary = _localized_value(meta.get("summary")) or _legacy_localized_value(meta, "summary")
        description = _localized_value(meta.get("description")) or _legacy_localized_value(meta, "description")
        versions = package_meta.get("versions", {})
        latest = self._latest_version(versions)
        latest_manifest = latest.get("manifest", {}) if latest else {}
        return {
            "schema_version": "1.0",
            "source": self.source_name,
            "metadata_source": self.index_url,
            "package_page_url": f"https://f-droid.org/packages/{package_name}/",
            "repo_name": _localized_value(repo_meta.get("name")) or repo_meta.get("name"),
            "package_name": package_name,
            "app_name": name,
            "summary": summary,
            "description": description,
            "categories": meta.get("categories", []) if isinstance(meta.get("categories"), list) else [],
            "developer": meta.get("authorName") or meta.get("authorEmail"),
            "license": meta.get("license"),
            "website": meta.get("webSite"),
            "source_code": meta.get("sourceCode"),
            "issue_tracker": meta.get("issueTracker"),
            "changelog": meta.get("changelog"),
            "donate": meta.get("donate", []),
            "latest_version_name": latest_manifest.get("versionName"),
            "latest_version_code": latest_manifest.get("versionCode"),
            "min_sdk": latest_manifest.get("usesSdk", {}).get("minSdkVersion"),
            "target_sdk": latest_manifest.get("usesSdk", {}).get("targetSdkVersion"),
            "signer_sha256": latest_manifest.get("signer", {}).get("sha256", []),
        }

    def _latest_version(self, versions: dict[str, Any]) -> dict[str, Any] | None:
        if not versions:
            return None
        return max(
            versions.values(),
            key=lambda item: int(item.get("manifest", {}).get("versionCode") or 0),
        )


def _localized_value(value: Any, preferred: tuple[str, ...] = ("es-MX", "es", "en-US", "en-GB", "en")) -> str | None:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict) or not value:
        return None
    for locale in preferred:
        localized = value.get(locale)
        if isinstance(localized, str) and localized.strip():
            return localized.strip()
    for localized in value.values():
        if isinstance(localized, str) and localized.strip():
            return localized.strip()
    return None


def _legacy_localized_value(meta: dict[str, Any], field: str) -> str | None:
    localized = meta.get("localized", {})
    if not isinstance(localized, dict):
        return None
    for locale in ("es-MX", "es", "en-US", "en-GB", "en"):
        values = localized.get(locale)
        if isinstance(values, dict) and isinstance(values.get(field), str):
            return values[field].strip()
    for values in localized.values():
        if isinstance(values, dict) and isinstance(values.get(field), str):
            return values[field].strip()
    return None
