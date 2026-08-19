from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.tools.archive import copy_to_quarantine, ensure_dir, guess_mime_type
from apk_docforge.tools.hashing import file_size, sha256_file
from apk_docforge.tools.policy import PolicyEngine


class IntakeAgent(BaseAgent):
    name = "IntakeAgent"
    output_files = ("intake.json", "artifact_manifest.json")

    def run(self) -> AgentContext:
        input_path = self.context.input_path.expanduser().resolve()
        if not input_path.exists():
            raise FileNotFoundError(f"Input artifact not found: {input_path}")

        ensure_dir(self.context.output_dir)
        ensure_dir(self.context.artifacts_dir)
        ensure_dir(self.context.docs_dir)
        ensure_dir(self.context.quarantine_dir)

        policy_decision = PolicyEngine().validate_local_file(declared_authorized=True)
        if not policy_decision.allowed:
            raise PermissionError(policy_decision.reason)

        original_hash = sha256_file(input_path) if input_path.is_file() else None
        quarantined_path = (
            copy_to_quarantine(input_path, self.context.quarantine_dir)
            if input_path.is_file()
            else input_path
        )
        quarantined_hash = sha256_file(quarantined_path) if quarantined_path.is_file() else None
        if original_hash and quarantined_hash and original_hash != quarantined_hash:
            raise ValueError("Quarantine copy hash mismatch; refusing to continue.")

        provenance = _read_download_provenance(input_path)
        candidate = provenance.get("candidate", {}) if isinstance(provenance.get("candidate"), dict) else {}
        source_type = str(candidate.get("source") or provenance.get("source_type") or "local_file")
        artifact = {
            "schema_version": "1.0",
            "analysis_id": self.context.analysis_id,
            "source_type": source_type,
            "input_path": str(input_path),
            "quarantined_path": str(quarantined_path),
            "sha256": quarantined_hash,
            "size_bytes": file_size(quarantined_path) if quarantined_path.is_file() else None,
            "mime_type": guess_mime_type(quarantined_path) if quarantined_path.is_file() else "directory",
            "download_provenance": provenance or None,
            "source_url": provenance.get("source_url") or candidate.get("source_url"),
            "download_url": provenance.get("download_url") or candidate.get("download_url"),
            "candidate": candidate or None,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "mode": self.context.mode,
            "authorization": {
                "status": policy_decision.status.value,
                "reason": policy_decision.reason,
                "declared_scope": "owned_authorized_or_open_source",
            },
            "chain_of_custody": [
                {
                    "event": "received_local_input",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "path": str(input_path),
                    "sha256": original_hash,
                },
                {
                    "event": "copied_to_quarantine",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "path": str(quarantined_path),
                    "sha256": quarantined_hash,
                },
            ],
        }
        if provenance:
            artifact["chain_of_custody"].extend(provenance.get("chain_of_custody", []))

        self.context.data["artifact"] = artifact
        self.context.data["artifact_path"] = quarantined_path

        intake = self.artifact(
            {
                "artifact": artifact,
                "tool_detection": self.context.tools,
                "policy_decision": policy_decision.to_json(),
            },
            evidence_refs=[
                self.evidence(path=input_path, kind="input", description="Original local input path."),
                self.evidence(
                    path=quarantined_path,
                    kind="quarantine",
                    description="Quarantined artifact used for analysis.",
                ),
            ],
        )
        self.write_json("intake.json", intake)

        manifest = {
            "schema_version": "1.0",
            "analysis_id": self.context.analysis_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": [
                {
                    "name": "input_artifact",
                    "path": str(quarantined_path),
                    "sha256": quarantined_hash,
                    "size_bytes": artifact["size_bytes"],
                    "mime_type": artifact["mime_type"],
                    "source": "local_file",
                }
            ],
        }
        self.write_json("artifact_manifest.json", manifest)
        return self.context


def _read_download_provenance(input_path: Path) -> dict[str, Any]:
    sidecar = input_path.with_suffix(input_path.suffix + ".provenance.json")
    if not sidecar.exists():
        return {}
    try:
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}
