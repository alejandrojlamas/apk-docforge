from __future__ import annotations

import json

from apk_docforge.mcp.server import handle_message
from apk_docforge.pipeline import run_analysis


def test_mcp_initialize_and_tools_list(isolated_app_env) -> None:
    initialize = handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    assert initialize is not None
    assert initialize["result"]["serverInfo"]["name"] == "apk-docforge"

    tools = handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert tools is not None
    names = {item["name"] for item in tools["result"]["tools"]}
    assert {
        "search_apps",
        "download_app",
        "analyze_artifact",
        "get_analysis",
        "get_report",
        "get_codex_prompt",
        "list_findings",
        "list_features",
        "list_screens",
    }.issubset(names)


def test_mcp_tool_calls(sample_apk, tmp_path, isolated_app_env) -> None:
    out = tmp_path / "mcp-analysis"
    summary = run_analysis(sample_apk, out=out, mode="static")

    report = handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_report",
                "arguments": {"analysis_id": summary["analysis_id"]},
            },
        }
    )
    assert report is not None
    assert report["result"]["isError"] is False
    assert "# apk-docforge static analysis report" in report["result"]["content"][0]["text"]

    features = handle_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "list_features",
                "arguments": {"analysis_id": summary["analysis_id"]},
            },
        }
    )
    assert features is not None
    payload = json.loads(features["result"]["content"][0]["text"])
    assert any(item["name"] == "login/auth" for item in payload["features"])

    search = handle_message(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "search_apps",
                "arguments": {
                    "query": "https://example.com/app.apk",
                    "sources": ["official"],
                    "limit": 1,
                },
            },
        }
    )
    assert search is not None
    search_payload = json.loads(search["result"]["content"][0]["text"])
    assert search_payload["candidates"][0]["source"] == "official_url"
