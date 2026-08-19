from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator

from apk_docforge.agents.base import AgentContext, BaseAgent
from apk_docforge.renderers.markdown import write_markdown


SCHEMA_MAP = {
    "artifact_manifest.json": "artifact.schema.json",
    "features.json": "features.schema.json",
    "static_screens.json": "screens.schema.json",
    "network_endpoints.json": "network.schema.json",
    "security_findings.json": "findings.schema.json",
}
OPTIONAL_SCHEMA_MAP = {
    "dynamic_session.json": "dynamic_session.schema.json",
    "screens_dynamic.json": "dynamic_ui.schema.json",
    "ui_elements_dynamic.json": "dynamic_ui.schema.json",
    "navigation_graph.json": "dynamic_ui.schema.json",
    "blocked_flows.json": "dynamic_ui.schema.json",
    "runtime_errors.json": "dynamic_ui.schema.json",
}


class QAValidationAgent(BaseAgent):
    name = "QAValidationAgent"
    output_files = ("qa_report.json", "coverage.md")

    def run(self) -> AgentContext:
        schema_results = self._validate_schemas()
        evidence_results = self._validate_evidence()
        contradiction_results = self._detect_contradictions()
        coverage = self._coverage(schema_results, evidence_results, contradiction_results)
        report = {
            "schema_version": "1.0",
            "status": "passed" if not coverage["blocking_issues"] else "needs_review",
            "schema_results": schema_results,
            "evidence_results": evidence_results,
            "contradictions": contradiction_results,
            "coverage": coverage,
        }
        self.write_json("qa_report.json", report)
        write_markdown(self.path("coverage.md"), self._coverage_markdown(report))
        self.context.data["qa_report"] = report
        return self.context

    def _validate_schemas(self) -> list[dict[str, Any]]:
        rows = []
        for output_name, schema_name in {**SCHEMA_MAP, **OPTIONAL_SCHEMA_MAP}.items():
            output_path = self.path(output_name)
            if not output_path.exists():
                if output_name in OPTIONAL_SCHEMA_MAP:
                    continue
                rows.append(
                    {
                        "file": output_name,
                        "schema": schema_name,
                        "status": "missing",
                        "errors": [f"{output_name} was not produced."],
                    }
                )
                continue
            instance = json.loads(output_path.read_text(encoding="utf-8"))
            schema = json.loads(
                files("apk_docforge.schemas").joinpath(schema_name).read_text(encoding="utf-8")
            )
            validator = Draft202012Validator(schema)
            errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
            rows.append(
                {
                    "file": output_name,
                    "schema": schema_name,
                    "status": "passed" if not errors else "failed",
                    "errors": [
                        {
                            "path": ".".join(str(part) for part in error.path),
                            "message": error.message,
                        }
                        for error in errors
                    ],
                }
            )
        return rows

    def _validate_evidence(self) -> list[dict[str, Any]]:
        checks = []
        checks.extend(self._evidence_for_file("features.json", "features"))
        checks.extend(self._evidence_for_file("security_findings.json", "findings"))
        checks.extend(self._evidence_for_file("network_endpoints.json", "endpoints"))
        checks.extend(self._evidence_for_file("static_screens.json", "screens"))
        checks.extend(self._evidence_for_file("control_boundary_assessment.json", "controls"))
        checks.extend(self._evidence_for_file("app_understanding.json", "core_flows"))
        checks.extend(self._evidence_for_file("reconstruction_brief.json", "functional_requirements"))
        checks.append(self._top_level_evidence("app_understanding.json"))
        checks.append(self._top_level_evidence("reconstruction_brief.json"))
        return checks

    def _evidence_for_file(self, filename: str, key: str) -> list[dict[str, Any]]:
        path = self.path(filename)
        if not path.exists():
            return [{"file": filename, "item": key, "status": "missing_file"}]
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = []
        for index, item in enumerate(payload.get(key, [])):
            evidence = item.get("evidence_refs", [])
            status = item.get("status")
            ok = bool(evidence) or status == "unknown"
            rows.append(
                {
                    "file": filename,
                    "index": index,
                    "name": item.get("name") or item.get("title") or item.get("url") or item.get("domain"),
                    "status": "passed" if ok else "failed",
                    "item_status": status or "unknown",
                    "evidence_count": len(evidence),
                }
            )
        return rows

    def _top_level_evidence(self, filename: str) -> dict[str, Any]:
        path = self.path(filename)
        if not path.exists():
            return {"file": filename, "item": "top_level", "status": "missing_file"}
        payload = json.loads(path.read_text(encoding="utf-8"))
        evidence = payload.get("evidence_refs", [])
        status = payload.get("status")
        ok = bool(evidence) or status == "unknown"
        return {
            "file": filename,
            "item": "top_level",
            "name": payload.get("app_name") or payload.get("codex_goal") or filename,
            "status": "passed" if ok else "failed",
            "item_status": status or "inferred",
            "evidence_count": len(evidence),
        }

    def _detect_contradictions(self) -> list[dict[str, Any]]:
        contradictions = []
        manifest = self.context.data.get("manifest", {})
        endpoints = self.context.data.get("network_endpoints", [])
        cleartext_flag = manifest.get("application", {}).get("uses_cleartext_traffic")
        if cleartext_flag == "false" and any(item.get("scheme") == "http" for item in endpoints):
            contradictions.append(
                {
                    "status": "needs_review",
                    "description": "Manifest disallows cleartext traffic but static HTTP strings were found. They may be dead/test strings or blocked at runtime.",
                    "evidence_refs": [
                        self.evidence(path="manifest.json", kind="manifest"),
                        self.evidence(path="network_endpoints.json", kind="derived"),
                    ],
                }
            )
        return contradictions

    def _coverage(
        self,
        schema_results: list[dict[str, Any]],
        evidence_results: list[dict[str, Any]],
        contradiction_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        blocking = []
        blocking.extend(item for item in schema_results if item["status"] not in {"passed"})
        blocking.extend(item for item in evidence_results if item["status"] == "failed")
        return {
            "schema_files_checked": len(schema_results),
            "schema_files_passed": sum(1 for item in schema_results if item["status"] == "passed"),
            "evidence_items_checked": len(evidence_results),
            "evidence_items_passed": sum(1 for item in evidence_results if item["status"] == "passed"),
            "contradiction_count": len(contradiction_results),
            "blocking_issues": blocking,
            "data_status_labels": ["observed", "inferred", "unknown"],
        }

    def _coverage_markdown(self, report: dict[str, Any]) -> str:
        coverage = report["coverage"]
        lines = [
            "# QA Coverage",
            "",
            f"- Status: {report['status']}",
            f"- Schema files passed: {coverage['schema_files_passed']}/{coverage['schema_files_checked']}",
            f"- Evidence items passed: {coverage['evidence_items_passed']}/{coverage['evidence_items_checked']}",
            f"- Contradictions: {coverage['contradiction_count']}",
            "",
            "## Blocking Issues",
            "",
        ]
        if not coverage["blocking_issues"]:
            lines.append("No blocking QA issues detected.")
        else:
            for issue in coverage["blocking_issues"]:
                lines.append(f"- {issue}")
        return "\n".join(lines) + "\n"
