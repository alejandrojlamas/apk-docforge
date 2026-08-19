from __future__ import annotations

from pathlib import Path

from apk_docforge.tools.command_runner import CommandResult, run_command, which


def decompile(apk_path: Path, output_dir: Path, timeout: int = 900) -> CommandResult | None:
    if not which("jadx"):
        return None
    output_dir.mkdir(parents=True, exist_ok=True)
    return run_command(["jadx", "-d", str(output_dir), str(apk_path)], timeout=timeout)
