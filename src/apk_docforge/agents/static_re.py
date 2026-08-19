from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.tools.apktool import decode as apktool_decode
from apk_docforge.tools.archive import ensure_dir
from apk_docforge.tools.jadx import decompile as jadx_decompile
from apk_docforge.tools.static_extractors import ExtractedString, iter_archive_text, iter_files_text


CLASS_DESCRIPTOR_RE = re.compile(r"L([A-Za-z_$][A-Za-z0-9_$/]*(?:/[A-Za-z_$][A-Za-z0-9_$]*)+);")
JAVA_CLASS_RE = re.compile(r"\b(?:class|interface|enum|object)\s+([A-Za-z_$][A-Za-z0-9_$]*)")
PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z_$][A-Za-z0-9_$.]*)")


class StaticReverseEngineeringAgent(BaseAgent):
    name = "StaticReverseEngineeringAgent"
    output_files = (
        "decompile_summary.json",
        "class_index.json",
        "smali_index.json",
        "framework_detection.json",
        "obfuscation_report.json",
    )

    def run(self) -> AgentContext:
        apk_path = Path(self.context.data["primary_apk_path"])
        re_dir = ensure_dir(self.context.artifacts_dir / "reverse_engineering")
        tool_outputs = ensure_dir(self.context.artifacts_dir / "tool_outputs")
        jadx_dir = re_dir / "jadx"
        apktool_dir = re_dir / "apktool"

        jadx_result = jadx_decompile(apk_path, jadx_dir)
        apktool_result = apktool_decode(apk_path, apktool_dir)
        self._write_tool_result(tool_outputs / "jadx.json", jadx_result, "jadx")
        self._write_tool_result(tool_outputs / "apktool.json", apktool_result, "apktool")

        strings = self._collect_strings(apk_path, jadx_dir, apktool_dir)
        class_index = self._class_index(strings, jadx_dir)
        smali_index = self._smali_index(apktool_dir)
        framework_detection = self._framework_detection(strings, self.context.data.get("zip_entries", []))
        obfuscation_report = self._obfuscation_report(class_index)

        summary = self.artifact(
            {
                "jadx": self._result_summary(jadx_result, "jadx", jadx_dir),
                "apktool": self._result_summary(apktool_result, "apktool", apktool_dir),
                "fallback_static_string_count": len(strings),
                "class_count": len(class_index["classes"]),
                "smali_file_count": len(smali_index["smali_files"]),
                "frameworks_detected": [
                    item["name"]
                    for item in framework_detection["frameworks"]
                    if item["status"] == "observed"
                ],
            },
            evidence_refs=[
                self.evidence(path=apk_path, kind="apk", description="APK used for static reverse engineering.")
            ],
        )
        self.write_json("decompile_summary.json", summary)
        self.write_json("class_index.json", class_index)
        self.write_json("smali_index.json", smali_index)
        self.write_json("framework_detection.json", framework_detection)
        self.write_json("obfuscation_report.json", obfuscation_report)

        self.context.data["static_strings"] = [
            {
                "value": item.value,
                "path": item.path,
                "line_number": item.line_number,
                "source": item.source,
            }
            for item in strings
        ]
        self.context.data["class_index"] = class_index
        self.context.data["framework_detection"] = framework_detection
        self.context.data["apktool_dir"] = str(apktool_dir) if apktool_dir.exists() else None
        self.context.data["jadx_dir"] = str(jadx_dir) if jadx_dir.exists() else None
        return self.context

    def _write_tool_result(self, path: Path, result: Any, tool_name: str) -> None:
        payload = (
            {
                "tool": tool_name,
                "available": False,
                "status": "missing",
                "message": f"{tool_name} is not installed or not on PATH.",
            }
            if result is None
            else {
                "tool": tool_name,
                "available": True,
                "status": "completed" if result.ok else "failed",
                "returncode": result.returncode,
                "command": result.command,
                "stdout_tail": result.stdout[-4000:],
                "stderr_tail": result.stderr[-4000:],
                "timed_out": result.timed_out,
            }
        )
        self.write_json(str(path.relative_to(self.context.output_dir)), payload)

    def _result_summary(self, result: Any, tool_name: str, output_dir: Path) -> dict[str, Any]:
        if result is None:
            return {
                "tool": tool_name,
                "available": False,
                "status": "missing",
                "output_dir": str(output_dir),
            }
        return {
            "tool": tool_name,
            "available": True,
            "status": "completed" if result.ok else "failed",
            "returncode": result.returncode,
            "output_dir": str(output_dir),
        }

    def _collect_strings(
        self, apk_path: Path, jadx_dir: Path, apktool_dir: Path, limit: int = 20000
    ) -> list[ExtractedString]:
        collected: list[ExtractedString] = []
        for item in iter_archive_text(apk_path):
            collected.append(item)
            if len(collected) >= limit:
                return collected
        for root in [jadx_dir, apktool_dir]:
            if not root.exists():
                continue
            for item in iter_files_text(root):
                collected.append(item)
                if len(collected) >= limit:
                    return collected
        return collected

    def _class_index(self, strings: list[ExtractedString], jadx_dir: Path) -> dict[str, Any]:
        classes: dict[str, dict[str, Any]] = {}
        packages: set[str] = set()
        for item in strings:
            for match in CLASS_DESCRIPTOR_RE.finditer(item.value):
                class_name = match.group(1).replace("/", ".").replace("$", ".")
                package = class_name.rsplit(".", 1)[0] if "." in class_name else ""
                if package:
                    packages.add(package)
                classes.setdefault(
                    class_name,
                    {
                        "class_name": class_name,
                        "package": package,
                        "source": "dex_string",
                        "evidence_refs": [
                            {
                                "path": item.path,
                                "line_number": item.line_number,
                                "kind": "class_descriptor",
                                "description": "Class descriptor-like string.",
                            }
                        ],
                    },
                )

        if jadx_dir.exists():
            for file_path in list(jadx_dir.rglob("*.java")) + list(jadx_dir.rglob("*.kt")):
                text = file_path.read_text(encoding="utf-8", errors="replace")
                package_match = PACKAGE_RE.search(text)
                package = package_match.group(1) if package_match else ""
                if package:
                    packages.add(package)
                for class_match in JAVA_CLASS_RE.finditer(text):
                    class_name = class_match.group(1)
                    fqcn = f"{package}.{class_name}" if package else class_name
                    classes[fqcn] = {
                        "class_name": fqcn,
                        "package": package,
                        "source": "jadx",
                        "path": str(file_path),
                        "evidence_refs": [
                            {
                                "path": str(file_path),
                                "line_number": text[: class_match.start()].count("\n") + 1,
                                "kind": "source",
                                "description": "Class declaration from decompiled source.",
                            }
                        ],
                    }

        return {
            "schema_version": "1.0",
            "classes": sorted(classes.values(), key=lambda item: item["class_name"]),
            "packages": sorted(packages),
        }

    def _smali_index(self, apktool_dir: Path) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        if apktool_dir.exists():
            for file_path in apktool_dir.rglob("*.smali"):
                rel = str(file_path.relative_to(apktool_dir))
                files.append(
                    {
                        "path": str(file_path),
                        "relative_path": rel,
                        "class_name": rel.replace("/", ".").removesuffix(".smali"),
                        "evidence_refs": [
                            {
                                "path": str(file_path),
                                "kind": "smali",
                                "description": "Smali file decoded by apktool.",
                            }
                        ],
                    }
                )
        return {"schema_version": "1.0", "smali_files": sorted(files, key=lambda item: item["path"])}

    def _framework_detection(
        self, strings: list[ExtractedString], entries: list[dict[str, Any]]
    ) -> dict[str, Any]:
        haystack = "\n".join(item.value for item in strings[:10000]).lower()
        entry_text = "\n".join(str(entry.get("path", "")).lower() for entry in entries)
        combined = f"{haystack}\n{entry_text}"
        patterns = {
            "Kotlin": ["kotlin/metadata", "kotlin.jvm", "kotlinx."],
            "Jetpack Compose": ["androidx.compose", "compose.runtime"],
            "Flutter": ["flutter_assets", "libflutter.so", "dart.vm"],
            "React Native": ["com.facebook.react", "index.android.bundle"],
            "Unity": ["libunity.so", "assets/bin/data", "unityplayer"],
            "Cordova/Ionic": ["cordova", "ionic.webview", "capacitor"],
            "Firebase": ["firebase", "google.firebase"],
            "Room": ["androidx.room", "roomdatabase"],
        }
        frameworks = []
        for name, needles in patterns.items():
            evidence = []
            for needle in needles:
                if needle in combined:
                    evidence.append(
                        {
                            "kind": "string",
                            "description": f"Detected marker `{needle}` for {name}.",
                        }
                    )
            frameworks.append(
                {
                    "name": name,
                    "status": "observed" if evidence else "unknown",
                    "confidence": 0.8 if evidence else 0.0,
                    "evidence_refs": evidence,
                }
            )
        return {"schema_version": "1.0", "frameworks": frameworks}

    def _obfuscation_report(self, class_index: dict[str, Any]) -> dict[str, Any]:
        classes = class_index.get("classes", [])
        if not classes:
            return {
                "schema_version": "1.0",
                "status": "unknown",
                "obfuscation_level": "unknown",
                "confidence": 0.0,
                "evidence_refs": [],
                "notes": ["No class index available; install jadx/apktool for stronger signal."],
            }
        short = 0
        for item in classes:
            simple = str(item["class_name"]).rsplit(".", 1)[-1]
            if len(simple) <= 2:
                short += 1
        ratio = short / max(len(classes), 1)
        level = "high" if ratio > 0.55 else "medium" if ratio > 0.25 else "low"
        return {
            "schema_version": "1.0",
            "status": "inferred",
            "obfuscation_level": level,
            "short_name_ratio": ratio,
            "class_count": len(classes),
            "confidence": 0.7,
            "evidence_refs": [
                {
                    "path": "class_index.json",
                    "kind": "derived",
                    "description": "Obfuscation inferred from short class-name ratio.",
                }
            ],
        }
