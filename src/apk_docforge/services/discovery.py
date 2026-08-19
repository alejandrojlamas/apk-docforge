from __future__ import annotations

from typing import Any

from apk_docforge.adapters.disabled_mirror import DisabledMirrorAdapter
from apk_docforge.adapters.fdroid import FDroidAdapter
from apk_docforge.adapters.github_releases import GitHubReleasesAdapter
from apk_docforge.adapters.google_play_developer import GooglePlayDeveloperAdapter
from apk_docforge.adapters.official_url import OfficialURLAdapter
from apk_docforge.services.source_registry import save_candidates


def search_apps(query: str, sources: list[str], limit: int = 10, persist: bool = True) -> dict[str, Any]:
    adapters = {
        "fdroid": FDroidAdapter(),
        "f-droid": FDroidAdapter(),
        "github": GitHubReleasesAdapter(),
        "github_releases": GitHubReleasesAdapter(),
        "official": OfficialURLAdapter(),
        "official_url": OfficialURLAdapter(),
        "google_play": GooglePlayDeveloperAdapter(),
        "google_play_developer": GooglePlayDeveloperAdapter(),
        "mirror": DisabledMirrorAdapter(),
        "third_party_mirror": DisabledMirrorAdapter(),
    }
    candidates: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    errors: list[str] = []
    for source in sources:
        key = source.strip().lower()
        if not key:
            continue
        adapter = adapters.get(key)
        if adapter is None:
            errors.append(f"Unknown source: {source}")
            decisions.append(
                {
                    "source": source,
                    "status": "UNKNOWN",
                    "allowed": False,
                    "reason": "No adapter configured for this source.",
                }
            )
            continue
        result = adapter.search(query, limit=limit)
        candidates.extend(result.candidates)
        decisions.append(result.policy_decision | {"source": result.source})
        errors.extend(result.errors)
    persisted = save_candidates(candidates) if persist and candidates else []
    return {
        "query": query,
        "sources": sources,
        "candidates": persisted if persist else candidates,
        "raw_candidates": candidates,
        "policy_decisions": decisions,
        "errors": errors,
    }
