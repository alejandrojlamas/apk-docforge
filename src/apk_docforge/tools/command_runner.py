from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


ANDROID_TOOL_NAMES = [
    "adb",
    "apkanalyzer",
    "aapt2",
    "bundletool",
    "jadx",
    "jadx-gui",
    "apktool",
    "java",
    "docker",
    "mobsfscan",
    "appium",
    "node",
    "npm",
    "mitmproxy",
    "frida",
]


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def which(command: str) -> str | None:
    return shutil.which(command)


def detect_tools(tool_names: Sequence[str] = ANDROID_TOOL_NAMES) -> dict[str, dict[str, str | bool]]:
    detected: dict[str, dict[str, str | bool]] = {}
    for name in tool_names:
        path = which(name)
        detected[name] = {"available": bool(path), "path": path or ""}
    return detected


def run_command(
    command: Sequence[str],
    cwd: Path | None = None,
    timeout: int = 120,
) -> CommandResult:
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
            check=False,
            capture_output=True,
            text=True,
        )
        return CommandResult(
            command=list(command),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            command=list(command),
            returncode=124,
            stdout=_coerce_output(exc.stdout),
            stderr=_coerce_output(exc.stderr) or f"Command timed out after {timeout}s",
            timed_out=True,
        )


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
