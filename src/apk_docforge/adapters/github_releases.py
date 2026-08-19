from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from apk_docforge import USER_AGENT
from apk_docforge.adapters.base import AdapterSearchResult
from apk_docforge.tools.policy import PolicyEngine


class GitHubReleasesAdapter:
    source_name = "github"
    asset_suffixes = (".apk", ".apks", ".xapk")

    def search(self, query: str, limit: int = 10) -> AdapterSearchResult:
        decision = PolicyEngine().validate_source("github").to_json()
        if not decision["allowed"]:
            return AdapterSearchResult(self.source_name, [], decision)
        try:
            repos = self._repositories(query, limit)
            candidates = self._release_candidates(repos, limit)
        except Exception as exc:
            return AdapterSearchResult(self.source_name, [], decision, [str(exc)])
        return AdapterSearchResult(self.source_name, candidates, decision)

    def _repositories(self, query: str, limit: int) -> list[dict[str, Any]]:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
        if "/" in query and " " not in query:
            response = httpx.get(f"https://api.github.com/repos/{query}", headers=headers, timeout=30)
            response.raise_for_status()
            return [response.json()]
        response = httpx.get(
            "https://api.github.com/search/repositories",
            params={"q": f"{query} android apk", "per_page": min(max(limit, 1), 20)},
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        return response.json().get("items", [])

    def _release_candidates(self, repos: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
        for repo in repos:
            full_name = repo.get("full_name")
            if not full_name:
                continue
            response = httpx.get(
                f"https://api.github.com/repos/{full_name}/releases",
                params={"per_page": 10},
                headers=headers,
                timeout=30,
            )
            if response.status_code == 404:
                continue
            response.raise_for_status()
            releases = response.json()
            for release in releases:
                for asset in release.get("assets", []):
                    name = str(asset.get("name") or "")
                    if not name.lower().endswith(self.asset_suffixes):
                        continue
                    candidates.append(self._asset_candidate(repo, release, asset))
                    if len(candidates) >= limit:
                        return candidates
        return candidates

    def _asset_candidate(
        self, repo: dict[str, Any], release: dict[str, Any], asset: dict[str, Any]
    ) -> dict[str, Any]:
        full_name = repo.get("full_name")
        asset_id = asset.get("id")
        return {
            "id": f"github:{full_name}:{release.get('id')}:{asset_id}",
            "source": self.source_name,
            "source_id": full_name,
            "package_name": None,
            "app_name": repo.get("name") or full_name,
            "developer": repo.get("owner", {}).get("login"),
            "version_name": release.get("tag_name") or release.get("name"),
            "version_code": None,
            "license": (repo.get("license") or {}).get("spdx_id"),
            "source_url": release.get("html_url") or repo.get("html_url"),
            "download_url": asset.get("browser_download_url"),
            "checksum": asset.get("digest"),
            "policy_status": "ALLOWED",
            "discovered_at": datetime.now(timezone.utc).isoformat(),
            "asset_name": asset.get("name"),
            "asset_size": asset.get("size"),
            "asset_content_type": asset.get("content_type"),
            "release_prerelease": release.get("prerelease", False),
            "release_draft": release.get("draft", False),
        }
