from __future__ import annotations

from apk_docforge.adapters.base import AdapterSearchResult
from apk_docforge.tools.policy import PolicyEngine


class GooglePlayDeveloperAdapter:
    source_name = "google_play_developer"

    def search(self, query: str, limit: int = 20) -> AdapterSearchResult:
        decision = PolicyEngine().validate_source("google_play_developer").to_json()
        return AdapterSearchResult(
            self.source_name,
            [],
            decision,
            [
                "Google Play Developer API search is not implemented. "
                "The reserved adapter requires a future authorized integration."
            ],
        )
