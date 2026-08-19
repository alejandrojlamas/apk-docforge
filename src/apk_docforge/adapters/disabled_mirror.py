from __future__ import annotations

from apk_docforge.adapters.base import AdapterSearchResult
from apk_docforge.tools.policy import PolicyEngine


class DisabledMirrorAdapter:
    source_name = "third_party_mirror"

    def search(self, query: str, limit: int = 20) -> AdapterSearchResult:
        decision = PolicyEngine().validate_source("third_party_mirror").to_json()
        return AdapterSearchResult(self.source_name, [], decision)
