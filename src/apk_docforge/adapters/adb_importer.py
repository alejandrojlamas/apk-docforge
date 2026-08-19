from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apk_docforge.services.source_registry import save_artifact_record
from apk_docforge.tools.archive import guess_mime_type
from apk_docforge.tools.command_runner import run_command, which
from apk_docforge.tools.hashing import file_size, sha256_file


class ADBImporter:
    def import_package(self, package_name: str, out_dir: Path, device: str | None = None) -> dict[str, object]:
        if not which("adb"):
            return {"status": "failed", "reason": "adb is not installed or not on PATH."}
        out_dir.mkdir(parents=True, exist_ok=True)
        base = ["adb"]
        if device:
            base.extend(["-s", device])
        path_result = run_command([*base, "shell", "pm", "path", package_name], timeout=60)
        if not path_result.ok:
            return {"status": "failed", "reason": path_result.stderr or path_result.stdout}
        remote_paths = [
            line.replace("package:", "").strip()
            for line in path_result.stdout.splitlines()
            if line.strip().startswith("package:")
        ]
        pulled = []
        for remote in remote_paths:
            target = out_dir / f"{package_name}-{Path(remote).name}"
            pull_result = run_command([*base, "pull", remote, str(target)], timeout=180)
            row: dict[str, Any] = {
                "remote_path": remote,
                "local_path": str(target),
                "status": "completed" if pull_result.ok else "failed",
                "stderr": pull_result.stderr,
            }
            if pull_result.ok and target.exists():
                digest = sha256_file(target)
                provenance = {
                    "schema_version": "1.0",
                    "status": "completed",
                    "source_type": "adb",
                    "package_name": package_name,
                    "device": device or "default",
                    "remote_path": remote,
                    "local_path": str(target),
                    "sha256": digest,
                    "size_bytes": file_size(target),
                    "mime_type": guess_mime_type(target),
                    "imported_at": datetime.now(timezone.utc).isoformat(),
                    "chain_of_custody": [
                        {
                            "event": "adb_pm_path",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "package_name": package_name,
                            "remote_path": remote,
                        },
                        {
                            "event": "adb_pull_to_local_downloads",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "path": str(target),
                            "sha256": digest,
                        },
                    ],
                }
                provenance_path = target.with_suffix(target.suffix + ".provenance.json")
                provenance_path.write_text(
                    json.dumps(provenance, indent=2, ensure_ascii=False), encoding="utf-8"
                )
                artifact = save_artifact_record(
                    local_path=str(target),
                    sha256=digest,
                    size_bytes=file_size(target),
                    mime_type=guess_mime_type(target),
                    provenance=provenance,
                    package_name=package_name,
                )
                row.update(
                    {
                        "sha256": digest,
                        "size_bytes": file_size(target),
                        "mime_type": guess_mime_type(target),
                        "provenance_path": str(provenance_path),
                        "artifact_id": artifact["id"],
                    }
                )
            pulled.append(
                row
            )
        status = "completed" if pulled and all(item["status"] == "completed" for item in pulled) else "failed"
        return {"status": status, "package_name": package_name, "device": device, "artifacts": pulled}
