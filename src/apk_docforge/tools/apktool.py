from __future__ import annotations

from pathlib import Path

from apk_docforge.tools.command_runner import CommandResult, run_command, which


def decode(apk_path: Path, output_dir: Path, timeout: int = 600) -> CommandResult | None:
    if not which("apktool"):
        return None
    output_dir.mkdir(parents=True, exist_ok=True)
    return run_command(["apktool", "d", "-f", str(apk_path), "-o", str(output_dir)], timeout=timeout)
