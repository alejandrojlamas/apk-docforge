from __future__ import annotations

from pathlib import Path
from typing import Any

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.config import get_settings
from apk_docforge.tools.apkanalyzer import manifest_print
from apk_docforge.tools.archive import (
    ZipEntry,
    classify_android_artifact,
    ensure_dir,
    extract_zip_member_limited,
    inspect_zip_limited,
    read_zip_member,
)
from apk_docforge.tools.hashing import file_size, sha256_file
from apk_docforge.tools.manifest_parser import ParsedManifest, parse_manifest_bytes, write_manifest_files


MAX_MANIFEST_BYTES = 16 * 1024 * 1024


class PackageStructureAgent(BaseAgent):
    name = "PackageStructureAgent"
    output_files = (
        "package_structure.json",
        "manifest_raw.xml",
        "manifest.json",
        "resources_index.json",
        "dex_index.json",
        "native_libs.json",
    )

    def run(self) -> AgentContext:
        settings = get_settings()
        artifact_path = Path(self.context.data.get("artifact_path", self.context.input_path))
        package_dir = ensure_dir(self.context.artifacts_dir / "package")
        original_entries = inspect_zip_limited(
            artifact_path,
            max_members=settings.max_archive_members,
            max_total_uncompressed_bytes=settings.max_archive_uncompressed_bytes,
        )
        original_artifact_type = classify_android_artifact(artifact_path, original_entries)
        primary_apk_path = self._prepare_primary_apk(
            artifact_path,
            package_dir,
            original_entries,
            settings.max_nested_artifact_bytes,
        )
        entries = inspect_zip_limited(
            primary_apk_path,
            max_members=settings.max_archive_members,
            max_total_uncompressed_bytes=settings.max_archive_uncompressed_bytes,
        )
        primary_artifact_type = classify_android_artifact(primary_apk_path, entries)

        manifest_entry = next(
            (entry for entry in entries if entry.path == "AndroidManifest.xml"),
            None,
        )
        if manifest_entry is not None and manifest_entry.size > MAX_MANIFEST_BYTES:
            raise ValueError("AndroidManifest.xml exceeds the supported 16 MiB limit.")
        manifest_bytes = (
            read_zip_member(
                primary_apk_path,
                "AndroidManifest.xml",
                limit=MAX_MANIFEST_BYTES + 1,
            )
            or b""
        )
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ValueError("AndroidManifest.xml exceeds the supported 16 MiB limit.")
        raw_manifest_path = self.path("manifest_raw.xml")
        raw_manifest_path.write_bytes(manifest_bytes)
        parsed = self._parse_manifest(primary_apk_path, manifest_bytes)
        write_manifest_files(parsed, self.context.output_dir)

        entry_payloads = [self._entry_to_json(entry) for entry in entries]
        resources = self._resources(entries)
        dex = self._dex(entries)
        native_libs = self._native_libs(entries)

        package_structure = self.artifact(
            {
                "artifact_type": original_artifact_type,
                "primary_artifact_type": primary_artifact_type,
                "primary_apk_path": str(primary_apk_path),
                "sha256": sha256_file(primary_apk_path),
                "size_bytes": file_size(primary_apk_path),
                "entry_count": len(entries),
                "entries": entry_payloads,
                "manifest_parser": parsed.parser,
                "manifest_error": parsed.error,
                "package_name": parsed.manifest.get("package_name"),
                "version_name": parsed.manifest.get("version_name"),
                "version_code": parsed.manifest.get("version_code"),
            },
            evidence_refs=[
                self.evidence(
                    path=primary_apk_path,
                    manifest_path=raw_manifest_path,
                    kind="apk",
                    description="Primary APK selected for static package analysis.",
                )
            ],
            warnings=[parsed.error] if parsed.error else [],
        )
        self.write_json("package_structure.json", package_structure)
        self.write_json("resources_index.json", {"schema_version": "1.0", "resources": resources})
        self.write_json("dex_index.json", {"schema_version": "1.0", "dex_files": dex})
        self.write_json("native_libs.json", {"schema_version": "1.0", "native_libs": native_libs})

        self.context.data["primary_apk_path"] = primary_apk_path
        self.context.data["zip_entries"] = entry_payloads
        self.context.data["manifest"] = parsed.manifest
        self.context.data["manifest_parser"] = parsed.parser
        self.context.data["resources"] = resources
        self.context.data["dex_files"] = dex
        self.context.data["native_libs"] = native_libs
        return self.context

    def _prepare_primary_apk(
        self,
        artifact_path: Path,
        package_dir: Path,
        entries: list[ZipEntry],
        max_nested_artifact_bytes: int,
    ) -> Path:
        if artifact_path.is_dir():
            apks = sorted(artifact_path.glob("*.apk"))
            if not apks:
                raise ValueError(f"No APK files found in directory: {artifact_path}")
            if apks[0].stat().st_size > max_nested_artifact_bytes:
                raise ValueError("Nested APK exceeds the configured artifact size limit.")
            return apks[0]
        artifact_type = classify_android_artifact(artifact_path, entries)
        if artifact_type == "apk":
            return artifact_path
        nested = [entry.path for entry in entries if entry.path.endswith(".apk")]
        if not nested:
            return artifact_path
        preferred = sorted(
            nested,
            key=lambda name: (not any(token in name for token in ("base", "universal", "master")), name),
        )[0]
        nested_dir = ensure_dir(package_dir / "nested_apks")
        target = nested_dir / Path(preferred).name
        extract_zip_member_limited(
            artifact_path,
            preferred,
            target,
            max_bytes=max_nested_artifact_bytes,
        )
        return target

    def _parse_manifest(self, apk_path: Path, manifest_bytes: bytes) -> ParsedManifest:
        parsed = parse_manifest_bytes(manifest_bytes)
        if parsed.manifest.get("status") != "unknown":
            return parsed

        tool_result = manifest_print(apk_path)
        tool_dir = ensure_dir(self.context.artifacts_dir / "tool_outputs")
        if tool_result is None:
            (tool_dir / "apkanalyzer_manifest.txt").write_text(
                "apkanalyzer not available\n", encoding="utf-8"
            )
            return parsed

        output = tool_result.stdout if tool_result.ok else tool_result.stderr
        (tool_dir / "apkanalyzer_manifest.txt").write_text(output, encoding="utf-8")
        if tool_result.ok and output.lstrip().startswith("<"):
            return parse_manifest_bytes(output.encode("utf-8"))
        return parsed

    def _entry_to_json(self, entry: ZipEntry) -> dict[str, Any]:
        return {
            "path": entry.path,
            "size": entry.size,
            "compressed_size": entry.compressed_size,
            "crc": entry.crc,
            "is_dir": entry.is_dir,
        }

    def _resources(self, entries: list[ZipEntry]) -> list[dict[str, Any]]:
        resources = []
        for entry in entries:
            if entry.path.startswith("res/") or entry.path in {"resources.arsc", "assets/"}:
                resources.append(
                    {
                        "path": entry.path,
                        "size": entry.size,
                        "type": self._resource_type(entry.path),
                        "evidence_refs": [
                            self.evidence(path=entry.path, kind="archive_entry", description="Resource entry.")
                        ],
                    }
                )
        return resources

    def _dex(self, entries: list[ZipEntry]) -> list[dict[str, Any]]:
        return [
            {
                "path": entry.path,
                "size": entry.size,
                "evidence_refs": [
                    self.evidence(path=entry.path, kind="archive_entry", description="DEX entry.")
                ],
            }
            for entry in entries
            if entry.path.startswith("classes") and entry.path.endswith(".dex")
        ]

    def _native_libs(self, entries: list[ZipEntry]) -> list[dict[str, Any]]:
        return [
            {
                "abi": Path(entry.path).parts[1] if len(Path(entry.path).parts) > 1 else "unknown",
                "path": entry.path,
                "size": entry.size,
                "library": Path(entry.path).name,
                "evidence_refs": [
                    self.evidence(path=entry.path, kind="archive_entry", description="Native library entry.")
                ],
            }
            for entry in entries
            if entry.path.startswith("lib/") and entry.path.endswith(".so")
        ]

    def _resource_type(self, path: str) -> str:
        if path == "resources.arsc":
            return "compiled_resources"
        parts = Path(path).parts
        if len(parts) > 1 and parts[0] == "res":
            return parts[1].split("-")[0]
        if path.startswith("assets/"):
            return "asset"
        return "resource"
