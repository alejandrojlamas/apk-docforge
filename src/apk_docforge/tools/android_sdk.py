from __future__ import annotations

from apk_docforge.tools.command_runner import detect_tools


def android_tool_report() -> dict[str, dict[str, str | bool]]:
    return detect_tools()
