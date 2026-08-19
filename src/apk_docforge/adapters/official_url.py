from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar
from urllib.parse import unquote, urlparse

from apk_docforge.adapters.base import AdapterSearchResult
from apk_docforge.tools.policy import PolicyEngine


class OfficialURLAdapter:
    source_name = "official_url"
    allowed_suffixes: ClassVar[frozenset[str]] = frozenset({".apk", ".apks", ".xapk"})

    def search(self, query: str, limit: int = 20) -> AdapterSearchResult:
        decision = PolicyEngine().validate_official_url(query).to_json()
        candidates = []
        if decision["allowed"]:
            path = Path(unquote(urlparse(query).path))
            if path.suffix.lower() not in self.allowed_suffixes:
                return AdapterSearchResult(
                    self.source_name,
                    [],
                    {
                        **decision,
                        "allowed": False,
                        "status": "BLOCKED",
                        "reason": "Official URL must point to an APK/APKS/XAPK artifact.",
                    },
                )
            candidates.append(
                {
                    "id": f"official:{query}",
                    "source": self.source_name,
                    "source_url": query,
                    "download_url": query,
                    "policy_status": decision["status"],
                    "discovered_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        return AdapterSearchResult(self.source_name, candidates, decision)
