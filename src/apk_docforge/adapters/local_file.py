from __future__ import annotations

from pathlib import Path

from apk_docforge.tools.hashing import file_size, sha256_file
from apk_docforge.tools.policy import PolicyEngine


class LocalFileAdapter:
    source_name = "local_file"

    def inspect(self, path: Path) -> dict[str, object]:
        decision = PolicyEngine().validate_local_file(declared_authorized=True).to_json()
        return {
            "source": self.source_name,
            "path": str(path),
            "exists": path.exists(),
            "sha256": sha256_file(path) if path.exists() and path.is_file() else None,
            "size_bytes": file_size(path) if path.exists() and path.is_file() else None,
            "policy_decision": decision,
        }
