from __future__ import annotations

from pathlib import Path

from apk_docforge.tools.command_runner import CommandResult, run_command, which


def manifest_print(apk_path: Path, timeout: int = 120) -> CommandResult | None:
    if not which("apkanalyzer"):
        return None
    return run_command(["apkanalyzer", "manifest", "print", str(apk_path)], timeout=timeout)
