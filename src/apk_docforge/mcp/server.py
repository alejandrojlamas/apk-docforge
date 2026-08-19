from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, Callable, TextIO

from apk_docforge import __version__
from apk_docforge.mcp import tools


JSON = dict[str, Any]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: JSON
    handler: Callable[..., Any]

    def to_mcp_tool(self) -> JSON:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


TOOL_SPECS: dict[str, ToolSpec] = {
    "search_apps": ToolSpec(
        name="search_apps",
        description="Search allowed app sources without downloading, then persist candidates locally.",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "sources": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["fdroid", "github"],
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        handler=tools.search_apps,
    ),
    "download_app": ToolSpec(
        name="download_app",
        description="Download a persisted allowed candidate by numeric candidate id with quarantine and provenance.",
        input_schema={
            "type": "object",
            "properties": {
                "candidate_id": {"type": "string"},
                "out": {"type": "string", "default": "downloads"},
            },
            "required": ["candidate_id"],
            "additionalProperties": False,
        },
        handler=tools.download_app,
    ),
    "analyze_artifact": ToolSpec(
        name="analyze_artifact",
        description="Run static apk-docforge analysis for a local APK/APKS/XAPK artifact.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "out": {"type": ["string", "null"], "default": None},
                "mode": {"type": "string", "enum": ["static", "dynamic"], "default": "static"},
                "device": {"type": ["string", "null"], "default": None},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        handler=tools.analyze_artifact,
    ),
    "get_analysis": ToolSpec(
        name="get_analysis",
        description="Get analysis summary and output paths by analysis id or database id.",
        input_schema={
            "type": "object",
            "properties": {"analysis_id": {"type": "string"}},
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
        handler=tools.get_analysis,
    ),
    "get_report": ToolSpec(
        name="get_report",
        description="Get the Markdown report for an analysis.",
        input_schema={
            "type": "object",
            "properties": {"analysis_id": {"type": "string"}},
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
        handler=tools.get_report,
    ),
    "get_codex_prompt": ToolSpec(
        name="get_codex_prompt",
        description="Get the generated Codex ingestion prompt for an analysis.",
        input_schema={
            "type": "object",
            "properties": {"analysis_id": {"type": "string"}},
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
        handler=tools.get_codex_prompt,
    ),
    "list_findings": ToolSpec(
        name="list_findings",
        description="List security findings for an analysis.",
        input_schema={
            "type": "object",
            "properties": {"analysis_id": {"type": "string"}},
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
        handler=tools.list_findings,
    ),
    "list_features": ToolSpec(
        name="list_features",
        description="List inferred and observed features for an analysis.",
        input_schema={
            "type": "object",
            "properties": {"analysis_id": {"type": "string"}},
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
        handler=tools.list_features,
    ),
    "list_screens": ToolSpec(
        name="list_screens",
        description="List static screens mapped for an analysis.",
        input_schema={
            "type": "object",
            "properties": {"analysis_id": {"type": "string"}},
            "required": ["analysis_id"],
            "additionalProperties": False,
        },
        handler=tools.list_screens,
    ),
}


def handle_message(message: JSON) -> JSON | None:
    if "jsonrpc" not in message and "tool" in message:
        return _handle_legacy_tool_message(message)

    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}

    if method == "initialize":
        return _result(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "apk-docforge", "version": __version__},
            },
        )
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": [spec.to_mcp_tool() for spec in TOOL_SPECS.values()]})
    if method == "tools/call":
        return _handle_tools_call(request_id, params)
    return _error(request_id, -32601, f"Method not found: {method}")


def run_stdio_server(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    """Run a small MCP-compatible JSON-RPC stdio server."""
    input_stream = stdin or sys.stdin
    output_stream = stdout or sys.stdout
    for line in input_stream:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
            response = handle_message(message)
        except Exception as exc:
            response = _error(None, -32700, f"Parse or dispatch error: {exc}")
        if response is not None:
            output_stream.write(json.dumps(response, ensure_ascii=False) + "\n")
            output_stream.flush()


def _handle_tools_call(request_id: Any, params: JSON) -> JSON:
    name = params.get("name")
    arguments = params.get("arguments") or {}
    spec = TOOL_SPECS.get(str(name))
    if spec is None:
        return _error(request_id, -32602, f"Unknown tool: {name}")
    try:
        result = spec.handler(**arguments)
        return _result(
            request_id,
            {
                "content": [{"type": "text", "text": _json_text(result)}],
                "isError": False,
            },
        )
    except Exception as exc:
        return _result(
            request_id,
            {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
            },
        )


def _handle_legacy_tool_message(message: JSON) -> JSON:
    name = message.get("tool")
    args = message.get("args", {})
    spec = TOOL_SPECS.get(str(name))
    if spec is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        return {"result": spec.handler(**args)}
    except Exception as exc:
        return {"error": str(exc)}


def _result(request_id: Any, result: JSON) -> JSON:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> JSON:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _json_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, ensure_ascii=False)
